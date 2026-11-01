#!/system/bin/sh
# 用 PID 文件和精确路径保持 daemon/iptables，不用可能误杀 ssh 的 pkill。

MODDIR=${0%/*}
MODROOT=${MODDIR%/*}
DATA=/data/adb/routeproxy
CONF="$DATA/config.toml"
BIN="$MODROOT/bin/routeproxy"
SERVICE="$MODROOT/service.sh"
CHAIN=ROUTEPROXY_TP
PIDFILE="$DATA/routeproxy.pid"
WATCHDOG_PID="$DATA/watchdog.pid"
LOCK="$DATA/watchdog.lock"
LOG="$DATA/logs/watchdog.log"

unset LD_PRELOAD
mkdir -p "$DATA/logs"
. "$MODDIR/common.sh"

if ! mkdir "$LOCK" 2>/dev/null; then
    old_pid="$(cat "$LOCK/pid" 2>/dev/null)"
    if is_pid_for "$old_pid" "/system/bin/sh" "$MODDIR/watchdog.sh"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') watchdog: 已在运行 (pid=$old_pid)" >> "$LOG"
        exit 0
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') watchdog: 清理陈旧锁 (pid=${old_pid:-无})" >> "$LOG"
    # 先移走再删除：竞态中的另一个 watchdog 可能已替换该锁。
    stale="$LOCK.stale.$$"
    if mv "$LOCK" "$stale" 2>/dev/null; then
        rm -rf "$stale"
    fi
    if ! mkdir "$LOCK" 2>/dev/null; then
        rm -rf "$stale"
        echo "$(date '+%Y-%m-%d %H:%M:%S') watchdog: 锁竞争，退出" >> "$LOG"
        exit 0
    fi
fi
echo $$ > "$WATCHDOG_PID"
echo $$ > "$LOCK/pid"

cleanup() {
    if [ "$(cat "$WATCHDOG_PID" 2>/dev/null)" = "$$" ]; then
        rm -f "$WATCHDOG_PID"
    fi
    if [ "$(cat "$LOCK/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$LOCK"
    fi
}
trap cleanup EXIT
trap 'exit 0' TERM INT

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') watchdog: $*" >> "$LOG"
}

daemon_alive() {
    is_pid_for "$1" "$BIN" run "$CONF"
}

port_open() {
    # 不要用 nc/curl 探测：到 transparent 监听器的 TCP 连接本身会被
    # routeproxy 接受，形成自转发环。要求 /proc/net/tcp 中存在 LISTEN
    # (st=0A)，而不是仅有本地端点为 127.0.0.1:6045 的连接。
    hex="$(printf '%04X' "$1")"
    awk -v want="0100007F:$hex" '
        $2 == want && $4 == "0A" { found = 1 }
        END { exit !found }
    ' /proc/net/tcp 2>/dev/null
}

ensure_iptables() {
    if iptables -w -t nat -C OUTPUT -p tcp -j "$CHAIN" 2>/dev/null \
        && iptables -w -t nat -C "$CHAIN" -d 127.0.0.0/8 -j RETURN 2>/dev/null \
        && iptables -w -t nat -C "$CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w -t nat -C "$CHAIN" -p tcp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w -t nat -C "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" 2>/dev/null; then
        return 0
    fi

    setup_iptables || return 1
    log "已重新添加 iptables $CHAIN port=$PORT"
}

tries=0
while true; do
    sleep 30

    PORT="$(read_port "$CONF")" || {
        log "监听地址无效: $CONF"
        continue
    }
    PID="$(cat "$PIDFILE" 2>/dev/null)"

    if daemon_alive "$PID" && port_open "$PORT"; then
        ensure_iptables || log "iptables 修复失败"
        tries=0
        continue
    fi

    tries=$((tries + 1))
    log "daemon 不健康 (pid=${PID:-无}, port=$PORT, attempt=$tries)"
    if [ "$tries" -ge 3 ]; then
        log "连续失败 3 次，退避 5 分钟"
        sleep 300
        tries=0
        continue
    fi

    # 只启动 daemon 和 iptables；本 watchdog 继续运行。不要走 service.sh
    # 的常规 watchdog 重启路径，否则启动失败时设备可能没有 supervisor。
    if ROUTEPROXY_NO_WATCHDOG=1 "$SERVICE" start \
        >> "$DATA/logs/service.log" 2>&1; then
        log "重启成功"
        tries=0
    else
        log "重启失败，稍后重试"
        sleep 30
    fi
done
