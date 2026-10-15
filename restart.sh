#!/usr/bin/env bash
# ARTEX 开机重启脚本：按依赖链自底向上拉起 ① colima ② Postgres 容器 ③ 出口隧道 ④ ARTEX 后端。
# 与 start.sh 对应：start.sh 只管 artex 本体的守护重启；本脚本负责开机后把整条
# 依赖链恢复起来（Mac 上 Docker 跑在 colima 虚拟机里，开机后一定停着）。
# 数据不受影响：Postgres 数据在 artex-pgdata 卷，ARTEX 数据在 ./data 与 PG。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

PG_CONTAINER=artex-pg
PG_PORT=5433
ARTEX_PORT=8787
PROXY_PORT=8788
# 全局出口代理的本地 SOCKS5 端口。与 settings.global_proxy 里的端口一致——
# 改了配置里的端口，这里也要跟着改。
SOCKS_PORT=1080
WATCHDOG=scripts/socks5-watchdog.sh
WATCHDOG_LOG=scripts/socks5-watchdog.log
LOG=artex.log

# ── ① Docker 运行时（colima）─────────────────────
# Mac 上 Docker 靠 colima 虚拟机，开机后必然停着，它是依赖链最底端。
start_runtime(){
  if ! command -v colima >/dev/null 2>&1; then
    # 没有 colima 时可能装的是 Docker Desktop，直接看 docker 是否可用。
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
      || die "未检测到可用的 Docker 运行时（colima 或 Docker Desktop）"
    ok "Docker 运行时已在运行"
    return
  fi
  if colima status >/dev/null 2>&1; then
    ok "colima 已在运行"
  else
    info "启动 colima（首次可能较慢）…"
    colima start
    ok "colima 已启动"
  fi
}

# ── ② Postgres 容器 ─────────────────────────────
# 容器设了 restart: unless-stopped，但 colima 重启后 Docker 守护进程一并重启，
# 容器不会自动恢复，必须显式 start。
start_pg(){
  docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER" \
    || die "未找到容器 ${PG_CONTAINER}，请先运行 ./install.sh 完成首次部署"

  if docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
    ok "Postgres 容器已在运行"
  else
    info "启动 Postgres 容器 $PG_CONTAINER …"
    docker start "$PG_CONTAINER" >/dev/null
    ok "Postgres 容器已启动"
  fi

  # 等待端口就绪（容器起来到接受连接有几秒延迟）。
  for _ in $(seq 1 20); do
    nc -z 127.0.0.1 "$PG_PORT" 2>/dev/null && { ok "Postgres 就绪 (127.0.0.1:$PG_PORT)"; return; }
    sleep 1
  done
  die "Postgres 端口 $PG_PORT 未就绪，请检查：docker logs $PG_CONTAINER"
}

# ── ③ 全局 SOCKS5 出口隧道 ──────────────────────
# redteam_env 由 ARTEX 保存于 PostgreSQL；开机时读出 VPS 地址和私钥路径，
# 使宿主机上的 watchdog 与 Agent 使用同一组隧道配置。
load_socks5_config(){
  local db_user="${POSTGRES_USER:-artex}"
  local db_name="${POSTGRES_DB:-artex}"
  local host key dsh_home
  host="$(docker exec "$PG_CONTAINER" psql -X -A -t -q -U "$db_user" -d "$db_name" \
    -c "SELECT COALESCE(value::jsonb ->> 'REDTEAM_VPS_HOST', '') FROM settings WHERE key = 'redteam_env';" 2>/dev/null | tr -d '\r')" \
    || warn "读取 REDTEAM_VPS_HOST 失败，watchdog 将使用内置默认地址"
  key="$(docker exec "$PG_CONTAINER" psql -X -A -t -q -U "$db_user" -d "$db_name" \
    -c "SELECT COALESCE(value::jsonb ->> 'REDTEAM_VPS_KEY', '') FROM settings WHERE key = 'redteam_env';" 2>/dev/null | tr -d '\r')" \
    || warn "读取 REDTEAM_VPS_KEY 失败，watchdog 将尝试默认私钥路径"
  dsh_home="$(docker exec "$PG_CONTAINER" psql -X -A -t -q -U "$db_user" -d "$db_name" \
    -c "SELECT COALESCE(value::jsonb ->> 'DSH_HOME', '') FROM settings WHERE key = 'redteam_env';" 2>/dev/null | tr -d '\r')" \
    || dsh_home=""

  [ -z "$host" ] || export REDTEAM_VPS_HOST="$host"
  dsh_home="${dsh_home:-$HOME/.dsh}"
  case "$dsh_home" in
    /root/.dsh) dsh_home="$HOME/.dsh" ;;
    /root/.dsh/*) dsh_home="$HOME/.dsh/${dsh_home#/root/.dsh/}" ;;
    /root/*) dsh_home="$HOME/${dsh_home#/root/}" ;;
  esac
  # DB 中配置的是容器内路径；宿主机复用绑定挂载的 ~/.dsh 工具链。
  case "$key" in
    /root/.dsh/*) key="$HOME/.dsh/${key#/root/.dsh/}" ;;
    /root/*) key="$HOME/${key#/root/}" ;;
    '$DSH_HOME/'*) key="$dsh_home/${key#\$DSH_HOME/}" ;;
    '${DSH_HOME}/'*) key="$dsh_home/${key#\$\{DSH_HOME\}/}" ;;
    '~/'*) key="$HOME/${key#\~/}" ;;
  esac
  [ -z "$key" ] || export REDTEAM_VPS_KEY="$key"
}

start_socks5_watchdog(){
  [ -f "$WATCHDOG" ] || die "找不到 watchdog 脚本 $WATCHDOG"
  load_socks5_config

  if pgrep -f '[s]ocks5-watchdog.sh' >/dev/null 2>&1; then
    warn "watchdog 进程已存在；先结束旧实例以刷新数据库配置"
    pkill -f '[s]ocks5-watchdog.sh' 2>/dev/null || true
  fi
  # 清除其脱离 watchdog 生命周期的 SSH 子进程，确保新配置会建立新隧道。
  pkill -f "[s]sh .*-D ${SOCKS_PORT}" 2>/dev/null || true
  sleep 1
  info "启动 SOCKS5 watchdog（日志 → ${WATCHDOG_LOG}）…"
  SOCKS_PORT="$SOCKS_PORT" REDTEAM_VPS_HOST="${REDTEAM_VPS_HOST:-}" \
    REDTEAM_VPS_KEY="${REDTEAM_VPS_KEY:-}" DSH_HOME="${DSH_HOME:-$HOME/.dsh}" \
    nohup bash "$WATCHDOG" >>"$WATCHDOG_LOG" 2>&1 &
  disown 2>/dev/null || true

  for _ in $(seq 1 12); do
    nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null && {
      ok "SOCKS5 监听就绪 (127.0.0.1:$SOCKS_PORT)"
      return
    }
    sleep 1
  done
  warn "SOCKS5 隧道尚未就绪；ARTEX 仍继续启动。检查：tail -30 $WATCHDOG_LOG"
}

stop_socks5_watchdog(){
  pkill -f '[s]ocks5-watchdog.sh' 2>/dev/null || true
  pkill -f "[s]sh .*-D ${SOCKS_PORT}" 2>/dev/null || true
}

# ── 停止 ARTEX（本体 + 守护脚本）─────────────────
# 模式锚定 "./start.sh" 与 "./artex"，用 [.] 转义点号：
#   - 避免匹配到本脚本自身（"restart.sh" 含 "start.sh" 子串，宽匹配会自杀）
#   - 避免 pkill 匹配到自己的命令行
stop_artex(){
  pkill -f '[.]/start\.sh' 2>/dev/null || true
  pkill -f '[.]/artex'     2>/dev/null || true
  # start.sh 退出码非 0 会退避重启，等它停稳再返回。
  sleep 2
  pkill -9 -f '[.]/artex' 2>/dev/null || true
}

# ── ④ ARTEX 后端 ────────────────────────────────
start_artex(){
  # 端口被占说明上一次的 artex 还在跑，先清掉再起，避免 "address already in use"。
  if nc -z 127.0.0.1 "$ARTEX_PORT" 2>/dev/null; then
    warn "端口 $ARTEX_PORT 已被占用，先停止旧进程"
    stop_artex
  fi

  [ -x ./artex ] || die "找不到可执行文件 ./artex，请先运行 ./build.sh 或 ./update.sh"
  info "启动 ARTEX（守护模式，日志 → ${LOG}）…"
  nohup ./start.sh >"$LOG" 2>&1 &
  disown 2>/dev/null || true

  for _ in $(seq 1 20); do
    nc -z 127.0.0.1 "$ARTEX_PORT" 2>/dev/null && break
    sleep 1
  done
  nc -z 127.0.0.1 "$ARTEX_PORT" 2>/dev/null \
    || { tail -20 "$LOG" >&2; die "ARTEX 未在 $ARTEX_PORT 就绪，见上方日志"; }
  ok "ARTEX 就绪 → http://127.0.0.1:$ARTEX_PORT"
}

case "${1:-start}" in
  start)
    info "═══ ARTEX 重启 ═══"
    start_runtime
    start_pg
    start_socks5_watchdog
    start_artex
    echo
    ok "全部就绪：控制台 http://127.0.0.1:$ARTEX_PORT  ·  代理 127.0.0.1:$PROXY_PORT"
    info "查看日志： tail -f $LOG   停止： ./restart.sh stop"
    ;;
  stop)
    info "停止 ARTEX 与 SOCKS5 出口 watchdog …"
    stop_socks5_watchdog
    stop_artex
    ok "ARTEX 与 SOCKS5 watchdog 已停止（Postgres / colima 保持运行）"
    ;;
  *)
    die "用法：./restart.sh [start|stop]（缺省 start）"
    ;;
esac
