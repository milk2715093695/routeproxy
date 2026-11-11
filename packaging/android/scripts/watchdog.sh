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
    _udp6_ok=1
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -L OUTPUT >/dev/null 2>&1; then
        ip6tables -w 5 -t filter -C OUTPUT -p udp -j "$UDP6_CHAIN" 2>/dev/null \
            && ip6tables -w 5 -t filter -C FORWARD -p udp -j "$UDP6_CHAIN" 2>/dev/null \
            && ip6tables -w 5 -t filter -C "$UDP6_CHAIN" -p udp -j DROP 2>/dev/null \
            || _udp6_ok=0
    fi

    if ip rule show 2>/dev/null | grep -Eq "fwmark $UDP_MARK(/[^ ]+)?[[:space:]].*lookup $UDP_TABLE([[:space:]]|$)" \
        && ip route show table "$UDP_TABLE" 2>/dev/null \
            | grep -Eq '^local[[:space:]]+0\.0\.0\.0/0[[:space:]]+dev[[:space:]]+lo' \
        && iptables -w 5 -t mangle -C OUTPUT -p udp -j "$UDP_OUT_CHAIN" 2>/dev/null \
        && iptables -w 5 -t mangle -C PREROUTING -p udp -m mark --mark "$UDP_MARK/$UDP_MARK" \
            -j "$UDP_CHAIN" 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -d 127.0.0.0/8 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -d 224.0.0.0/4 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -d 255.255.255.255/32 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -d 169.254.0.0/16 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -p udp \
            -j TPROXY --on-port "$PORT" --tproxy-mark "$UDP_MARK/$UDP_MARK" 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -d 127.0.0.0/8 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -d 224.0.0.0/4 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -d 255.255.255.255/32 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -d 169.254.0.0/16 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_OUT_CHAIN" -p udp \
            -j MARK --set-mark "$UDP_MARK/$UDP_MARK" 2>/dev/null \
        && [ "$_udp6_ok" = "1" ]; then
        return 0
    fi

    if setup_udp_iptables; then
        log "已重新添加 UDP iptables $UDP_CHAIN port=$PORT"
        return 0
    fi
    install_udp_fail_closed || log "UDP fail-closed 安装失败"
    return 1
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
        if read_udp_enabled "$CONF"; then
            if udp_port_open "$PORT" "$PID"; then
                ensure_udp_iptables || log "UDP iptables 修复失败"
            else
                # ingress 不属于本 daemon：拆 TPROXY、装 fail-closed，不自动重启。
                remove_udp_partial
                _fail_ready=1
                iptables -w 5 -t filter -C OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null \
                    && iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -p udp -j DROP 2>/dev/null \
                    || _fail_ready=0
                iptables -w 5 -t filter -C FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null \
                    && iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP 2>/dev/null \
                    || _fail_ready=0
                if command -v ip6tables >/dev/null 2>&1 \
                    && ip6tables -w 5 -L OUTPUT >/dev/null 2>&1; then
                    ip6tables -w 5 -t filter -C OUTPUT -p udp -j "$UDP6_FAIL_CHAIN" 2>/dev/null \
                        && ip6tables -w 5 -t filter -C "$UDP6_FAIL_CHAIN" -p udp -j DROP 2>/dev/null \
                        || _fail_ready=0
                    ip6tables -w 5 -t filter -C FORWARD -p udp -j "$UDP6_FAIL_FWD_CHAIN" 2>/dev/null \
                        && ip6tables -w 5 -t filter -C "$UDP6_FAIL_FWD_CHAIN" -p udp -j DROP 2>/dev/null \
                        || _fail_ready=0
                fi
                if [ "$_fail_ready" = "0" ]; then
                    log "UDP ingress 未监听，安装 fail-closed (port=$PORT)"
                    install_udp_fail_closed || log "UDP fail-closed 安装失败"
                fi
            fi
        fi
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

    # 只启动 daemon 和 iptables；本 watchdog 继续运行。
    if ROUTEPROXY_NO_WATCHDOG=1 "$SERVICE" start \
        >> "$DATA/logs/service.log" 2>&1; then
        log "重启成功"
        tries=0
    else
        log "重启失败，稍后重试"
        sleep 30
    fi
done
