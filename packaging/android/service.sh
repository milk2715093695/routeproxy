#!/system/bin/sh
# Magisk late_start 会无参数调用；编辑 /data/adb/routeproxy/config.toml 后，
# 可手动使用 start 或 stop。

MODDIR=${0%/*}
DATA=/data/adb/routeproxy
CONF="$DATA/config.toml"
BIN="$MODDIR/bin/routeproxy"
WATCHDOG_SCRIPT="$MODDIR/scripts/watchdog.sh"
CHAIN=ROUTEPROXY_TP
PIDFILE="$DATA/routeproxy.pid"
WATCHDOG_PID="$DATA/watchdog.pid"
LOG="$DATA/logs/service.log"

unset LD_PRELOAD
mkdir -p "$DATA/logs"
. "$MODDIR/scripts/common.sh"

log() {
    _msg="$(date '+%Y-%m-%d %H:%M:%S') service: $*"
    echo "$_msg" >> "$LOG"
    # Magisk 调用 service.sh 时没有终端；保留手动运行的可见输出。
    if [ -t 2 ]; then
        echo "routeproxy-tp: $*" >&2
    fi
}

read_pid() {
    [ -f "$1" ] && cat "$1" 2>/dev/null
}

is_routeproxy_pid() {
    is_pid_for "$1" "$BIN" run "$CONF"
}

is_watchdog_pid() {
    # 带 shebang 的脚本在 Android 上以 `/system/bin/sh <script>` 运行。
    is_pid_for "$1" "/system/bin/sh" "$WATCHDOG_SCRIPT"
}

stop_watchdog() {
    [ "${ROUTEPROXY_NO_WATCHDOG:-0}" = "1" ] && return 0

    pid="$(read_pid "$WATCHDOG_PID")"
    if ! is_watchdog_pid "$pid"; then
        pid="$(find_pid_for "/system/bin/sh" "$WATCHDOG_SCRIPT")" || pid=""
    fi
    if [ -n "$pid" ] && is_watchdog_pid "$pid"; then
        kill "$pid" 2>/dev/null
        i=0
        while [ "$i" -lt 5 ] && kill -0 "$pid" 2>/dev/null; do
            sleep 1
            i=$((i + 1))
        done
        kill -9 "$pid" 2>/dev/null
        # 只有在旧 watchdog 确实退出后才清锁/pid；提前清锁会让两个
        # supervisor 同时存在。
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        rm -f "$WATCHDOG_PID"
        rm -rf "$DATA/watchdog.lock"
    fi
}

stop_proxy() {
    stop_pid "$PIDFILE" "$BIN" run "$CONF"
}

start_service() {
    if [ ! -x "$BIN" ]; then
        log "可执行文件缺失: $BIN"
        return 1
    fi
    if [ ! -f "$CONF" ]; then
        log "配置文件缺失: $CONF"
        return 1
    fi
    PORT="$(read_port "$CONF")" || {
        log "监听地址无效: $CONF"
        return 1
    }

    stop_watchdog
    stop_proxy
    remove_iptables

    setsid sh -c 'echo $$ > "$1"; exec "$2" run --config "$3"' sh \
        "$PIDFILE" "$BIN" "$CONF" >> "$DATA/logs/stdout.log" 2>&1 &
    sleep 1
    pid="$(read_pid "$PIDFILE")"
    if ! is_routeproxy_pid "$pid"; then
        log "routeproxy 启动失败 (pid=${pid:-无})"
        stop_proxy
        remove_iptables
        return 1
    fi

    if ! setup_iptables; then
        log "iptables 设置失败，停止 routeproxy"
        stop_proxy
        remove_iptables
        return 1
    fi

    if [ "${ROUTEPROXY_NO_WATCHDOG:-0}" != "1" ]; then
        setsid /system/bin/sh "$WATCHDOG_SCRIPT" >> "$DATA/logs/watchdog.log" 2>&1 &
        sleep 1
        watchdog="$(read_pid "$WATCHDOG_PID")"
        if ! is_watchdog_pid "$watchdog"; then
            log "watchdog 启动失败"
            stop_watchdog
            stop_proxy
            remove_iptables
            return 1
        fi
    fi

    log "已启动 pid=$pid port=$PORT"
    return 0
}

stop_service() {
    stop_watchdog
    remove_iptables
    stop_proxy
    log "已停止"
}

case "$1" in
    start) start_service ;;
    stop) stop_service ;;
    "") start_service ;;
    *)
        echo "用法: $0 [start|stop]" >&2
        exit 2
        ;;
esac
