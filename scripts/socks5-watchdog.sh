#!/usr/bin/env bash
# 守护 ssh -D 动态 SOCKS5：断则自动重建。
#
# ARTEX「全局出口代理」指到 127.0.0.1:1080 后，隧道一断 agent 出网就硬失败
# （ALL_PROXY 指着没人听的端口），所以必须有人看门。本脚本每 15s 探活一次，
# 死了先清残留再带保活参数重建。
#
# 用法：nohup bash scripts/socks5-watchdog.sh > scripts/socks5-watchdog.log 2>&1 &
# 停止：pkill -f socks5-watchdog
set -u

DEST="${REDTEAM_VPS_HOST:-root@206.187.222.141}"
PORT="${SOCKS_PORT:-1080}"
INTERVAL=15

# 私钥候选：优先环境变量（ARTEX 红队环境变量的 REDTEAM_VPS_KEY），再试 toolkit
# 下的 x / id_rsa——启动时逐个实测认证，选通的那个（id_rsa 可能已不在 VPS 上）。
KEY="${REDTEAM_VPS_KEY:-}"
if [ -z "${KEY}" ] || [ ! -f "${KEY}" ]; then
  KEY=""
  for k in "$HOME/.dsh/redteam/toolkit/vps/x" "$HOME/.dsh/redteam/toolkit/vps/id_rsa"; do
    [ -f "${k}" ] || continue
    if ssh -i "${k}" -o BatchMode=yes -o ConnectTimeout=6 "${DEST}" true 2>/dev/null; then
      KEY="${k}"
      break
    fi
  done
fi
if [ -z "${KEY}" ]; then
  echo "无可用私钥（试过 REDTEAM_VPS_KEY / vps/x / vps/id_rsa），退出"
  exit 1
fi

# 主机 key 自动接受（VPS 重装后指纹变了也能自愈）；ExitOnForwardFailure：
# 端口被占/转发失败时 ssh 自己退出，不留僵尸。
run_ssh() {
  ssh -i "${KEY}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -D "${PORT}" -f -N "${DEST}"
}

log() { echo "[$(date '+%F %T')] $*"; }

log "watchdog 启动：${DEST}:${PORT}（key=${KEY}）"
while true; do
  if nc -z -w1 127.0.0.1 "${PORT}" 2>/dev/null; then
    sleep "${INTERVAL}"
    continue
  fi
  # 死了：清掉可能的残留进程（半死连接、重复实例），再重建
  pkill -f "ssh .*-D ${PORT}" 2>/dev/null
  sleep 1
  err="$(run_ssh 2>&1 >/dev/null)"
  if [ $? -eq 0 ]; then
    log "隧道已重建 :${PORT}"
  else
    log "重建失败：${err} —— ${INTERVAL}s 后重试"
  fi
  sleep "${INTERVAL}"
done
