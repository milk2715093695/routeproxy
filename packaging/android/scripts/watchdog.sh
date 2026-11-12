#!/system/bin/sh
# 用 PID 文件和精确路径维护 daemon/iptables，避免 pkill 误杀 ssh。

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
STOP_FLAG="$DATA/stop.requested"
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
    # 不用 nc/curl 探测，避免自转发环；只查 /proc/net/tcp 的 LISTEN。
    hex="$(printf '%04X' "$1")"
    awk -v want="0100007F:$hex" '
        $2 == want && $4 == "0A" { found = 1 }
        END { exit !found }
    ' /proc/net/tcp 2>/dev/null
}

ensure_iptables() {
    if iptables -w 5 -t nat -C OUTPUT -p tcp -j "$CHAIN" 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -d 127.0.0.0/8 -j RETURN 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -p tcp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" 2>/dev/null; then
        return 0
    fi

    setup_iptables || return 1
    log "已重新添加 iptables $CHAIN port=$PORT"
}

ensure_udp_iptables() {
    if ! udp_nfq_ready; then
        log "NFQUEUE 未就绪，保持/安装 UDP 兜底"
        if ! udp_v4_protected_ready; then
            if ! install_udp_fail_closed_or_443; then
                log "UDP 兜底规则安装失败，保留现有规则"
                return 1
            fi
        fi
        if udp_tproxy_active; then
            if ! install_udp443_drop; then
                log "UDP 443 降级规则安装失败，保留 NFQUEUE 内核拦截"
                return 1
            fi
        fi
        # 保留 NFQUEUE 内核拦截；队列无人读取时内核直接丢包，不能拆成本机直连。
        return 1
    fi
    udp_local_state_changed
    _udp_state=$?
    if [ "$_udp_state" = "2" ]; then
        log "读取 UDP 本地地址失败，保持现有规则"
        return 0
    fi
    if [ "$_udp_state" = "0" ]; then
        if refresh_udp_local_bypass; then
            log "UDP 本地地址变化，已刷新 bypass"
            if udp_tproxy_ready; then
                return 0
            fi
            log "UDP 本地 bypass 刷新后规则仍不完整，继续重建"
        else
            if ! udp_v4_protected_ready; then
                log "UDP 无有效保护，安装兜底"
                install_udp_fail_closed_or_443 || return 1
                return 0
            fi
            log "UDP 本地 bypass 刷新失败，保持现有规则"
            return 0
        fi
    fi

    if udp_tproxy_ready; then
        ensure_udp6_protected || log "IPv6 UDP 保护安装失败，IPv4 继续"
        return 0
    fi

    log "UDP iptables 规则不完整，尝试重建"
    if setup_udp_iptables; then
        log "已重建 UDP iptables $UDP_CHAIN port=$PORT"
        return 0
    fi
    if udp_v4_protected_ready; then
        return 0
    fi
    log "UDP 兜底规则安装失败"
    return 1
}

tries=0
udp_fail_tries=0
udp_ever_ready=0
udp_restart_tries=0
ingress_tries=0
ingress_restart_tries=0
udp_ingress_fail_tries=0
while true; do
    if [ -f "$STOP_FLAG" ]; then
        log "收到停止请求，退出 watchdog"
        exit 0
    fi
    sleep 5

    PORT="$(read_port "$CONF")" || {
        log "监听地址无效: $CONF"
        continue
    }
    PID="$(cat "$PIDFILE" 2>/dev/null)"

    if daemon_alive "$PID" && port_open "$PORT"; then
        ensure_iptables || log "iptables 修复失败"
        if read_udp_enabled "$CONF"; then
            if udp_port_open "$PORT" "$PID"; then
                ingress_tries=0
                ingress_restart_tries=0
                udp_ingress_fail_tries=0
                if ! udp_nfq_ready; then
                    udp_fail_tries=$((udp_fail_tries + 1))
                    ensure_udp_iptables "$PID" || log "UDP iptables 修复失败"
                    if [ "$udp_fail_tries" -ge 3 ]; then
                        if [ "$udp_ever_ready" -eq 0 ]; then
                            log "NFQUEUE 从未就绪，保持兜底，不再重启 daemon"
                        elif [ "$udp_restart_tries" -ge 3 ]; then
                            log "NFQUEUE 多次重启失败，保持兜底，不再重启 daemon"
                        else
                            udp_restart_tries=$((udp_restart_tries + 1))
                            log "NFQUEUE 未就绪，第 $udp_restart_tries 次重启 daemon"
                            ROUTEPROXY_NO_WATCHDOG=1 "$SERVICE" start \
                                >> "$DATA/logs/service.log" 2>&1 || log "重启 daemon 失败"
                        fi
                        udp_fail_tries=0
                    fi
                    tries=0
                    continue
                fi
                udp_ever_ready=1
                udp_restart_tries=0
                udp_fail_tries=0
                ensure_udp_iptables "$PID" || log "UDP iptables 修复失败"
            else
                udp_ingress_fail_tries=$((udp_ingress_fail_tries + 1))
                if [ "$udp_ingress_fail_tries" -lt 2 ]; then
                    log "UDP ingress 未监听，等待下一轮确认 (attempt=$udp_ingress_fail_tries)"
                    tries=0
                    continue
                fi
                # ingress 不属于本 daemon：先确保兜底，再拆 TPROXY，避免直连窗口。
                if ! udp_v4_protected_ready; then
                    log "UDP ingress 未监听，安装 UDP 兜底规则 (port=$PORT)"
                    if ! install_udp_fail_closed_or_443; then
                        log "UDP 兜底规则安装失败，保留现有规则"
                        tries=0
                        continue
                    fi
                fi
                remove_udp_tproxy_only
                ingress_tries=$((ingress_tries + 1))
                if [ "$ingress_tries" -ge 3 ] && [ "$ingress_restart_tries" -lt 3 ]; then
                    ingress_restart_tries=$((ingress_restart_tries + 1))
                    log "UDP ingress 连续缺失，第 $ingress_restart_tries 次重启 daemon"
                    ROUTEPROXY_NO_WATCHDOG=1 "$SERVICE" start \
                        >> "$DATA/logs/service.log" 2>&1 || log "重启 daemon 失败"
                    ingress_tries=0
                fi
            fi
        fi
        tries=0
        continue
    fi

    tries=$((tries + 1))
    log "daemon 不健康 (pid=${PID:-无}, port=$PORT, attempt=$tries)"
    if read_udp_enabled "$CONF"; then
        if ! udp_v4_protected_ready; then
            install_udp_fail_closed_or_443 || log "UDP 兜底规则安装失败"
        fi
        udp_v4_protected_ready && remove_udp_tproxy_only
    fi
    if [ "$tries" -ge 3 ]; then
        log "连续失败 3 次，退避 5 分钟"
        sleep 300
        tries=0
        continue
    fi

    if ROUTEPROXY_NO_WATCHDOG=1 "$SERVICE" start \
        >> "$DATA/logs/service.log" 2>&1; then
        log "重启成功"
        tries=0
    else
        log "重启失败，稍后重试"
        sleep 30
    fi
done
