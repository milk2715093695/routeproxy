#!/system/bin/sh
# Magisk late_start 无参数调用；也可手动执行 start/stop。

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
# 放宽 fd 上限；失败时保留系统默认值，不阻止启动。
if ! ulimit -n 65536 2>/dev/null; then
    if ! ulimit -n 16384 2>/dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') service: 无法提高 fd 上限，当前 $(ulimit -n)" >> "$LOG" 2>/dev/null || true
    fi
fi
. "$MODDIR/scripts/common.sh"

log() {
    _msg="$(date '+%Y-%m-%d %H:%M:%S') service: $*"
    echo "$_msg" >> "$LOG"
    # Magisk 调用时没有终端；手动运行时仍输出到 stderr。
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
        # 旧 watchdog 退出后才清锁/pid，避免两个 supervisor 同时存在。
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

# 启动失败时保留 UDP fail-closed；仅 UDP 未启用才彻底拆除规则。
cleanup_start_failure() {
    stop_proxy
    if [ "${udp_enabled:-0}" = "1" ]; then
        remove_iptables_keep_udp_fail_closed
        # setup_udp_iptables 可能已移除 fail-closed，这里重新装回。
        if ! install_udp_fail_closed; then
            log "启动失败后 UDP fail-closed 安装失败，请检查 iptables"
        fi
    else
        remove_iptables
    fi
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

    udp_enabled=0
    read_udp_enabled "$CONF" && udp_enabled=1

    stop_watchdog
    stop_proxy
    if [ "$udp_enabled" = "1" ]; then
        # 先装 fail-closed 再拆旧 TPROXY，避免重启窗口内 UDP 直连。
        if ! install_udp_fail_closed; then
            log "UDP fail-closed 安装失败，拒绝启动以免 UDP 直连"
            return 1
        fi
        remove_iptables_keep_udp_fail_closed
    else
        remove_iptables
    fi

    setsid sh -c 'echo $$ > "$1"; exec "$2" run --config "$3"' sh \
        "$PIDFILE" "$BIN" "$CONF" >> "$DATA/logs/stdout.log" 2>&1 &
    # pidfile 由子 shell 写入；不要用固定 1 秒赌它已经落盘。
    _wait=0
    while [ "$_wait" -lt 10 ]; do
        pid="$(read_pid "$PIDFILE")"
        is_routeproxy_pid "$pid" && break
        sleep 0.2
        _wait=$((_wait + 1))
    done
    if ! is_routeproxy_pid "$pid"; then
        log "routeproxy 启动失败 (pid=${pid:-无})"
        cleanup_start_failure
        return 1
    fi

    if ! setup_iptables; then
        log "iptables 设置失败，停止 routeproxy"
        cleanup_start_failure
        return 1
    fi

    if [ "$udp_enabled" = "1" ]; then
        if ! wait_udp_port "$PORT" "$pid"; then
            # TCP 已建立；UDP 独立失败不拆 TCP，但不能 TPROXY 到无 listener 的端口。
            log "UDP ingress 未监听，安装 UDP fail-closed；TCP 继续"
            if ! install_udp_fail_closed; then
                log "UDP fail-closed 也失败，请检查 iptables"
            fi
        elif ! setup_udp_iptables; then
            log "UDP iptables 设置失败，安装 UDP fail-closed；TCP 继续"
            if ! install_udp_fail_closed; then
                log "UDP fail-closed 也失败，请检查 iptables"
            fi
        else
            log "UDP 透明链已启用 port=$PORT"
        fi
    fi

    if [ "${ROUTEPROXY_NO_WATCHDOG:-0}" != "1" ]; then
        setsid /system/bin/sh "$WATCHDOG_SCRIPT" >> "$DATA/logs/watchdog.log" 2>&1 &
        _wait=0
        while [ "$_wait" -lt 10 ]; do
            watchdog="$(read_pid "$WATCHDOG_PID")"
            is_watchdog_pid "$watchdog" && break
            sleep 0.2
            _wait=$((_wait + 1))
        done
        if ! is_watchdog_pid "$watchdog"; then
            log "watchdog 启动失败"
            stop_watchdog
            cleanup_start_failure
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
