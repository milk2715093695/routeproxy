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
SERVICE_LOCK="$DATA/service.lock"
STOP_FLAG="$DATA/stop.requested"
LOG="$DATA/logs/service.log"

unset LD_PRELOAD
export ROUTEPROXY_NFQ_READY="$DATA/udp-nfq.ready"
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

acquire_lock() {
    if mkdir "$SERVICE_LOCK" 2>/dev/null; then
        echo $$ > "$SERVICE_LOCK/pid" || return 1
        [ "$(cat "$SERVICE_LOCK/pid" 2>/dev/null)" = "$$" ] || return 1
        return 0
    fi
    _lock_pid="$(cat "$SERVICE_LOCK/pid" 2>/dev/null)"
    # 另一个进程可能刚 mkdir、尚未写 pid；先等它写完，避免误判陈旧锁。
    _lock_wait=0
    while [ -z "$_lock_pid" ] && [ "$_lock_wait" -lt 20 ]; do
        sleep 0.1
        _lock_pid="$(cat "$SERVICE_LOCK/pid" 2>/dev/null)"
        _lock_wait=$((_lock_wait + 1))
    done
    _self="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
    if [ -n "$_lock_pid" ] \
        && { is_pid_for "$_lock_pid" "/system/bin/sh" "$_self" \
            || is_pid_for "$_lock_pid" "/system/bin/sh" "$0"; }; then
        log "已有 service 操作在运行 (pid=$_lock_pid)"
        return 1
    fi
    # 先移走再删除，避免和另一个 service 的锁替换竞态。
    _stale="$SERVICE_LOCK.stale.$$"
    if mv "$SERVICE_LOCK" "$_stale" 2>/dev/null; then
        _stale_pid="$(cat "$_stale/pid" 2>/dev/null)"
        if [ -n "$_stale_pid" ] \
            && { is_pid_for "$_stale_pid" "/system/bin/sh" "$_self" \
                || is_pid_for "$_stale_pid" "/system/bin/sh" "$0"; }; then
            # mv 期间另一个实例刚写好锁，放回去并放弃竞争。
            mv "$_stale" "$SERVICE_LOCK" 2>/dev/null || rm -rf "$_stale"
            log "service 锁已被新实例持有 (pid=$_stale_pid)"
            return 1
        fi
        rm -rf "$_stale"
    fi
    mkdir "$SERVICE_LOCK" 2>/dev/null || return 1
    echo $$ > "$SERVICE_LOCK/pid" || return 1
    [ "$(cat "$SERVICE_LOCK/pid" 2>/dev/null)" = "$$" ] || return 1
}

release_lock() {
    [ "$(cat "$SERVICE_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$SERVICE_LOCK"
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

# 启动失败保留 TCP fail-closed；UDP 保留兜底，无兜底才拆 TPROXY。
cleanup_start_failure() {
    if [ "${udp_enabled:-0}" = "1" ]; then
        if ! udp_v4_protected_ready; then
            install_udp_fail_closed_or_443
            _udp_rc=$?
            if [ "$_udp_rc" -eq 1 ]; then
                # 没有兜底时不能留下指向已停 daemon 的 TPROXY，否则 UDP 会静默黑洞。
                log "启动失败后 UDP 兜底规则安装失败，拆除 TPROXY 后停止"
                remove_udp_tproxy_only || log "拆除 UDP TPROXY 失败"
                stop_proxy
                rm -f "$ROUTEPROXY_NFQ_READY"
                return 1
            fi
        fi
        if udp_v4_protected_ready; then
            remove_udp_tproxy_only || log "拆除 UDP TPROXY 失败"
            # setup_udp_iptables 可能已移除 fail-closed，这里只补缺失的兜底。
            refresh_udp_local_bypass || log "刷新 UDP 本地地址 bypass 失败"
        else
            remove_udp_iptables
        fi
    else
        remove_udp_iptables
    fi
    stop_proxy
    rm -f "$ROUTEPROXY_NFQ_READY"
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

    # 规则已就绪时不要重建；正常重启不会出现 TCP 直连窗口。
    if ! tcp_iptables_ready; then
        if ! setup_iptables; then
            log "TCP iptables 设置失败，保留现有规则和进程"
            return 1
        fi
    fi

    stop_watchdog

    if [ "$udp_enabled" = "1" ]; then
        # 先装 UDP 兜底再拆旧 TPROXY；完整 fail-closed 不可用时只挡 443。
        refresh_udp_local_bypass || log "刷新 UDP 本地地址 bypass 失败"
        if ! udp_v4_protected_ready; then
            install_udp_fail_closed_or_443
            _udp_rc=$?
            if [ "$_udp_rc" -eq 1 ]; then
                log "UDP 兜底规则安装失败，拒绝启动"
                cleanup_start_failure
                return 1
            fi
        elif ! udp_v4_fail_closed_ready; then
            log "IPv4 完整 fail-closed 不可用，当前仅挡 UDP 443"
        fi
        remove_udp_tproxy_only || log "拆除旧 UDP TPROXY 失败"
    else
        remove_udp_iptables
    fi

    stop_proxy

    rm -f "$ROUTEPROXY_NFQ_READY"
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

    if [ "$udp_enabled" = "1" ]; then
        _wait=0
        while [ "$_wait" -lt 150 ] && ! udp_nfq_ready; do
            sleep 0.1
            _wait=$((_wait + 1))
        done
        if ! udp_nfq_ready; then
            log "NFQUEUE 未就绪，保留/安装 UDP 兜底规则；TCP 继续"
            if ! udp_v4_protected_ready; then
                install_udp_fail_closed_or_443
                _udp_rc=$?
                if [ "$_udp_rc" -eq 1 ]; then
                    log "UDP 兜底规则也失败，请检查 iptables"
                fi
            fi
        elif ! wait_udp_port "$PORT" "$pid"; then
            # TCP 已建立；UDP 独立失败不拆 TCP，但不能 TPROXY 到无 listener 的端口。
            log "UDP ingress 未监听，保留/安装 UDP 兜底规则；TCP 继续"
            if ! udp_v4_protected_ready; then
                install_udp_fail_closed_or_443
                _udp_rc=$?
                if [ "$_udp_rc" -eq 1 ]; then
                    log "UDP 兜底规则也失败，请检查 iptables"
                fi
            fi
        elif ! setup_udp_iptables; then
            log "UDP iptables 设置失败，保留/安装 UDP 兜底规则；TCP 继续"
            if ! udp_v4_protected_ready; then
                install_udp_fail_closed_or_443
                _udp_rc=$?
                if [ "$_udp_rc" -eq 1 ]; then
                    log "UDP 兜底规则也失败，请检查 iptables"
                fi
            fi
        else
            if [ "${_udp_forward_ok:-1}" = "0" ]; then
                log "UDP 本机 NFQUEUE 已启用；转发规则未安装（ip rule priority 冲突）"
            else
                log "UDP 透明链已启用 port=$PORT"
            fi
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
    rm -f "$ROUTEPROXY_NFQ_READY" "$STOP_FLAG"
    log "已停止"
}

case "$1" in
    start)
        rm -f "$STOP_FLAG"
        acquire_lock || exit 1
        start_service
        rc=$?
        release_lock
        exit "$rc"
        ;;
    stop)
        mkdir -p "$DATA"
        acquire_lock || exit 1
        : > "$STOP_FLAG"
        stop_service
        release_lock
        ;;
    "")
        rm -f "$STOP_FLAG"
        acquire_lock || exit 1
        start_service
        rc=$?
        release_lock
        exit "$rc"
        ;;
    *)
        echo "用法: $0 [start|stop]" >&2
        exit 2
        ;;
esac
