#!/bin/sh
# ARTEX 守护启动脚本（Linux / macOS / Docker ENTRYPOINT）
#
# 用法：
#   ./start.sh                       前台运行（Ctrl-C 停止）
#   nohup ./start.sh >artex.log 2>&1 &   后台常驻
#   ./start.sh -addr :9000           额外参数原样透传给 artex
#
# 它只做一件事：把 artex 跑起来，进程退出后按退出码决定要不要再拉起。
#
#   0      用户正常停止        → 退出循环
#   75     程序请求重启        → 立刻重跑（页面点了"一键更新"或"回滚"）
#   其他   崩溃                → 退避后重跑（1→2→4…最多 60 秒）
#
# 刻意不在这里做下载、SHA256 校验或换装：那些逻辑在 sh 和 bat 上要写两套，
# 而它们恰恰是最不能出错的一环——一旦换上跑不起来的二进制，本脚本会忠实地
# 反复拉起它，用户只能上机器手工救。所以校验/换装全部留在 Go 里（selfupdate 包），
# 由 artex 自己在启动时完成，脚本保持傻瓜化。
set -u

cd "$(dirname "$0")" || exit 1

# 红队工具链未装时提示一条命令（不自动下载——几十 MB 由用户决定时机）。
dsh="${DSH_HOME:-$HOME/.dsh}"
if [ ! -d "$dsh/redteam/toolkit" ] && [ -f ./scripts/redteam-setup.sh ]; then
  echo "[artex] 红队工具链未安装（扫描/隧道二进制）——安装：bash scripts/redteam-setup.sh" >&2
fi

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] 找不到可执行文件 $BIN" >&2; exit 1; }

# ── SOCKS5 出口隧道自愈 ──────────────────────────
# 直接跑 ./start.sh（而不是 ./restart.sh）时，依赖链里没有人拉起隧道，
# 结果 settings 页一片"127.0.0.1:1080 connection refused"。
# 这一段让 start.sh 自己也兜住：隧道不在就补起来，已在就什么都不做。
# 配置来源与逻辑和 restart.sh 的 start_socks5_watchdog 一致，两处需同步修改。
SOCKS_PORT="${SOCKS_PORT:-1080}"
PG_CONTAINER="${PG_CONTAINER:-artex-pg}"
WATCHDOG=scripts/socks5-watchdog.sh
WATCHDOG_LOG=scripts/socks5-watchdog.log

# redteam_env 由 ARTEX 存在 PostgreSQL。宿主机裸进程要复用同一组配置，
# 因此把 VPS 地址与私钥路径读出来；DB 里存的是容器内路径，需映射到宿主机
# （~/.dsh 是绑定挂载，两边同一份文件）。
load_socks5_config(){
	host=""
	key=""
	dsh_home=""
	host="$(docker exec "$PG_CONTAINER" psql -X -A -t -q -U "${POSTGRES_USER:-artex}" -d "${POSTGRES_DB:-artex}" \
		-c "SELECT COALESCE(value::jsonb ->> 'REDTEAM_VPS_HOST', '') FROM settings WHERE key = 'redteam_env';" 2>/dev/null | tr -d '\r')"
	key="$(docker exec "$PG_CONTAINER" psql -X -A -t -q -U "${POSTGRES_USER:-artex}" -d "${POSTGRES_DB:-artex}" \
		-c "SELECT COALESCE(value::jsonb ->> 'REDTEAM_VPS_KEY', '') FROM settings WHERE key = 'redteam_env';" 2>/dev/null | tr -d '\r')"
	dsh_home="$(docker exec "$PG_CONTAINER" psql -X -A -t -q -U "${POSTGRES_USER:-artex}" -d "${POSTGRES_DB:-artex}" \
		-c "SELECT COALESCE(value::jsonb ->> 'DSH_HOME', '') FROM settings WHERE key = 'redteam_env';" 2>/dev/null | tr -d '\r')"

	[ -z "$host" ] || export REDTEAM_VPS_HOST="$host"
	dsh_home="${dsh_home:-$HOME/.dsh}"
	case "$dsh_home" in
		/root/.dsh)   dsh_home="$HOME/.dsh" ;;
		/root/.dsh/*) dsh_home="$HOME/.dsh/${dsh_home#/root/.dsh/}" ;;
		/root/*)      dsh_home="$HOME/${dsh_home#/root/}" ;;
	esac
	case "$key" in
		/root/.dsh/*)    key="$HOME/.dsh/${key#/root/.dsh/}" ;;
		/root/*)         key="$HOME/${key#/root/}" ;;
		'$DSH_HOME/'*)   key="$dsh_home/${key#\$DSH_HOME/}" ;;
		'${DSH_HOME}/'*) key="$dsh_home/${key#\$\{DSH_HOME\}/}" ;;
		'~/'*)           key="$HOME/${key#\~/}" ;;
	esac
	[ -z "$key" ] || export REDTEAM_VPS_KEY="$key"
}

# watchdog 在跑且端口在听才算就绪——只看端口会漏掉"监听还在但进程已僵"的情况。
socks5_ready(){
	pgrep -f '[s]ocks5-watchdog.sh' >/dev/null 2>&1 || return 1
	nc -z -w1 127.0.0.1 "$SOCKS_PORT" 2>/dev/null
}

ensure_socks5(){
	socks5_ready && return 0
	[ -f "$WATCHDOG" ] || { echo "[artex] 找不到 $WATCHDOG，跳过隧道自愈" >&2; return 0; }

	load_socks5_config
	# 残留实例会带着旧配置继续跑，且挡住新实例读 DB，先清干净。
	pkill -f '[s]ocks5-watchdog.sh' 2>/dev/null || true
	pkill -f "[s]sh .*-D ${SOCKS_PORT}" 2>/dev/null || true
	sleep 1

	echo "[artex] 启动 SOCKS5 出口 watchdog（日志 → ${WATCHDOG_LOG}）"
	SOCKS_PORT="$SOCKS_PORT" REDTEAM_VPS_HOST="${REDTEAM_VPS_HOST:-}" \
		REDTEAM_VPS_KEY="${REDTEAM_VPS_KEY:-}" DSH_HOME="${DSH_HOME:-$HOME/.dsh}" \
		nohup bash "$WATCHDOG" >>"$WATCHDOG_LOG" 2>&1 &
	disown 2>/dev/null || true

	i=0
	while [ "$i" -lt 12 ]; do
		if nc -z -w1 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then
			echo "[artex] SOCKS5 隧道就绪 (127.0.0.1:$SOCKS_PORT)"
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	echo "[artex] SOCKS5 隧道尚未就绪，继续启动 artex；检查：tail -30 $WATCHDOG_LOG" >&2
	return 0
}

ensure_socks5

RESTART_CODE=75
MAX_DELAY=60

child=0
stopping=0

# 转发停止信号给 artex 本体。
#
# Docker 下这是必需的：docker stop 只把 SIGTERM 发给 PID 1（也就是本脚本），
# 不会发给子进程。不转发的话 artex 收不到信号、做不了优雅关闭，10 秒后被 SIGKILL
# 硬杀，正在跑的任务直接断在半路。
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# 信号会打断 wait 并让它返回 >128。此时子进程其实还在做优雅关闭，
	# 必须再 wait 一次才能拿到它真正的退出码。
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[artex] 已停止"
		exit 0
	fi

	case "$code" in
		0)
			echo "[artex] 正常退出"
			exit 0
			;;
		"$RESTART_CODE")
			# 更新/回滚已就绪：重跑后 artex 会在启动时完成换装（见 selfupdate.Bootstrap）。
			echo "[artex] 请求重启（应用新版本）…"
			delay=1
			;;
		*)
			echo "[artex] 异常退出 (code=$code)，${delay}s 后重启" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac

	# 长跑过程中隧道可能单独死掉（SSH 掉线、watchdog 被误杀），
	# 每次重启循环顺手补一次；已在跑时这里是一次 pgrep，开销可忽略。
	ensure_socks5
done
