#!/system/bin/sh
# routeproxy-tp 共用函数；透明模式只有一个 IPv4 回环监听。

read_port() {
    # 读取 listen 的第一个条目，支持单行和多行数组。
    _listen_block="$(sed -n '/^[[:space:]]*listen[[:space:]]*=/p' "$1")"
    case "$_listen_block" in
        *']'*) ;;
        *) _listen_block="$(sed -n '/^[[:space:]]*listen[[:space:]]*=/,/]/p' "$1")" ;;
    esac
    [ -n "$_listen_block" ] || return 1

    _entries="$(
        printf '%s\n' "$_listen_block" \
            | sed 's/#.*//' \
            | tr ',' '\n' \
            | sed -n "s/.*[\"']\([^\"']*\)[\"'].*/\1/p"
    )"
    _count="$(printf '%s\n' "$_entries" | sed '/^$/d' | wc -l | tr -d ' ')"
    [ "$_count" = "1" ] || return 1

    _listen="$(printf '%s\n' "$_entries" | sed -n '1p')"
    [ -n "$_listen" ] || return 1
    _port="${_listen##*:}"
    case "$_port" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$_port" -ge 1 ] && [ "$_port" -le 65535 ] || return 1
    printf '%s\n' "$_port"
}

# 按 argv 精确匹配，避免把 tail/vi 或一次性的 doctor 误认成 daemon。
is_pid_for() {
    [ -n "$1" ] || return 1
    kill -0 "$1" 2>/dev/null || return 1

    _cmdline="$(tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null)" || return 1
    [ "$(printf '%s\n' "$_cmdline" | sed -n '1p')" = "$2" ] || return 1
    if [ -n "${3:-}" ]; then
        [ "$(printf '%s\n' "$_cmdline" | sed -n '2p')" = "$3" ] || return 1
    fi
    if [ -n "${4:-}" ]; then
        [ "$(printf '%s\n' "$_cmdline" | sed -n '3p')" = "--config" ] || return 1
        [ "$(printf '%s\n' "$_cmdline" | sed -n '4p')" = "$4" ] || return 1
    fi
    return 0
}

find_pid_for() {
    # 先 ps 过滤，再精确校验，避免逐个扫描 /proc 拖慢启动。
    _ps="$(ps -A -o PID,ARGS 2>/dev/null)"
    while read -r _pid _cmdline; do
        case "$_cmdline" in
            *"$1"*) ;;
            *) continue ;;
        esac
        if is_pid_for "$_pid" "$1" "${2:-}" "${3:-}"; then
            printf '%s\n' "$_pid"
            return 0
        fi
    done <<EOF
$_ps
EOF
    return 1
}

# service.sh、watchdog.sh、uninstall.sh 共用的 iptables 链。
# 调用 setup_iptables 前必须设置 CHAIN 和 PORT。
setup_iptables() {
    iptables -w 5 -t nat -N "$CHAIN" 2>/dev/null || true
    iptables -w 5 -t nat -F "$CHAIN" || return 1
    iptables -w 5 -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN || return 1
    iptables -w 5 -t nat -A "$CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    iptables -w 5 -t nat -A "$CHAIN" -p tcp --dport 53 -j RETURN || return 1
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" || return 1
    iptables -w 5 -t nat -C OUTPUT -p tcp -j "$CHAIN" 2>/dev/null \
        || iptables -w 5 -t nat -A OUTPUT -p tcp -j "$CHAIN" || return 1
}

remove_tcp_iptables() {
    iptables -w 5 -t nat -D OUTPUT -p tcp -j "$CHAIN" 2>/dev/null
    iptables -w 5 -t nat -F "$CHAIN" 2>/dev/null
    iptables -w 5 -t nat -X "$CHAIN" 2>/dev/null
}

remove_iptables() {
    remove_udp_iptables
    remove_tcp_iptables
}

# 重启时保留 UDP fail-closed，只拆 TPROXY/mangle 和 TCP 规则。
remove_iptables_keep_udp_fail_closed() {
    remove_udp_partial
    remove_tcp_iptables
}

# UDP 用独立 mangle 链，不影响 TCP 的 nat 链。
UDP_CHAIN=ROUTEPROXY_UDP
UDP_OUT_CHAIN=ROUTEPROXY_UDP_OUT
UDP6_CHAIN=ROUTEPROXY_UDP6
UDP6_FAIL_CHAIN=ROUTEPROXY_UDP6_FAIL
UDP6_FAIL_FWD_CHAIN=ROUTEPROXY_UDP6_FAIL_FWD
UDP_FAIL_CHAIN=ROUTEPROXY_UDP_FAIL
UDP_FAIL_FWD_CHAIN=ROUTEPROXY_UDP_FAIL_FWD
# 独立 table/priority，避开 Clash、v2rayNG 等常见的 100。
UDP_TABLE=21072
UDP_PRIORITY=21072
# 高位 fwmark，避开 netd 的低位网络 ID。
UDP_MARK=0x40000000

_udp_log() {
    if command -v log >/dev/null 2>&1; then
        log "$*"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') udp: $*" >&2
    fi
}

read_udp_enabled() {
    # 支持 [udp]/["udp"]、udp.enabled 和 inline table；只认明确的 true。
    _udp_section="$(
        awk '
            /^[[:space:]]*\[/ {
                line = $0
                sub(/#.*/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (line ~ /^\[[[:space:]]*["\047]?[A-Za-z_][A-Za-z0-9_.-]*["\047]?[[:space:]]*\]$/) {
                    name = line
                    sub(/^\[[[:space:]]*["\047]?/, "", name)
                    sub(/["\047]?[[:space:]]*\]$/, "", name)
                    in_udp = (name == "udp")
                    next
                }
            }
            in_udp && $0 ~ /^[[:space:]]*["\047]?enabled["\047]?[[:space:]]*=[[:space:]]*true([[:space:]]*(#.*)?)?$/ { print; exit }
        ' "$1" 2>/dev/null
    )"
    _udp_flat="$(printf '%s\n' "$_udp_section" | sed 's/#.*//' | tr '\n' ' ')"
    if printf '%s\n' "$_udp_flat" \
        | grep -Eq '(^|[[:space:]])["'\'']?enabled["'\'']?[[:space:]]*=[[:space:]]*true([[:space:]]|$)'; then
        return 0
    fi
    if grep -Eq '^[[:space:]]*udp[[:space:]]*=[[:space:]]*\{[^}]*["'\'']?enabled["'\'']?[[:space:]]*=[[:space:]]*true([[:space:],}]|$)' \
        "$1" 2>/dev/null; then
        return 0
    fi
    grep -Eq '^[[:space:]]*["'\'']?udp["'\'']?[[:space:]]*\.[[:space:]]*["'\'']?enabled["'\'']?[[:space:]]*=[[:space:]]*true([[:space:]]*(#.*)?)?$' \
        "$1" 2>/dev/null
}

udp_port_open() {
    # 确认 0.0.0.0:PORT 已监听；给出 PID 时还校验 socket 属于该 daemon。
    _udp_hex="$(printf '%04X' "$1")"
    _udp_inode="$(awk -v want="00000000:$_udp_hex" '
        $2 == want { print $10; exit }
    ' /proc/net/udp 2>/dev/null)"
    [ -n "$_udp_inode" ] || return 1
    if [ -n "${2:-}" ]; then
        for _udp_fd in /proc/"$2"/fd/*; do
            [ "$(readlink "$_udp_fd" 2>/dev/null)" = "socket:[$_udp_inode]" ] && return 0
        done
        return 1
    fi
    return 0
}

wait_udp_port() {
    # 给 daemon 一点时间完成 UDP bind；最多等约 5 秒。
    _udp_wait=0
    while [ "$_udp_wait" -lt 25 ]; do
        udp_port_open "$1" "${2:-}" && return 0
        sleep 0.2
        _udp_wait=$((_udp_wait + 1))
    done
    return 1
}

setup_udp_iptables() {
    if setup_udp_iptables_inner; then
        remove_udp4_fail_closed
        # IPv4 成功不代表 IPv6 已就绪；v6 未就绪时保留 fail-closed。
        if udp6_rules_ready; then
            remove_udp6_fail_closed
        elif command -v ip6tables >/dev/null 2>&1; then
            install_udp6_fail_closed || _udp_log "IPv6 fail-closed 安装失败"
        fi
        return 0
    fi
    # 清掉半成品，避免“已打 mark 但未 TPROXY”的黑洞；fail-closed 保留。
    remove_udp_partial
    return 1
}

setup_udp6_iptables() {
    ip6tables -w 5 -t filter -N "$UDP6_CHAIN" 2>/dev/null || true
    ip6tables -w 5 -t filter -F "$UDP6_CHAIN" || return 1
    ip6tables -w 5 -t filter -A "$UDP6_CHAIN" -d ::1/128 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_CHAIN" -d fe80::/10 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_CHAIN" -d ff00::/8 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_CHAIN" -p udp --dport 53 -j RETURN || return 1
    # 与 IPv4 一致用 DROP：Android 上 REJECT target 不保证存在。
    ip6tables -w 5 -t filter -A "$UDP6_CHAIN" -p udp -j DROP || return 1
    ip6tables -w 5 -t filter -C OUTPUT -p udp -j "$UDP6_CHAIN" 2>/dev/null \
        || ip6tables -w 5 -t filter -I OUTPUT 1 -p udp -j "$UDP6_CHAIN" || return 1
    # FORWARD 没有 owner 匹配，也必须挂载，否则热点/容器可绕过 IPv6 兜底。
    ip6tables -w 5 -t filter -C FORWARD -p udp -j "$UDP6_CHAIN" 2>/dev/null \
        || ip6tables -w 5 -t filter -I FORWARD 1 -p udp -j "$UDP6_CHAIN" || return 1
}

udp6_rules_ready() {
    command -v ip6tables >/dev/null 2>&1 \
        && ip6tables -w 5 -t filter -C OUTPUT -p udp -j "$UDP6_CHAIN" 2>/dev/null \
        && ip6tables -w 5 -t filter -C FORWARD -p udp -j "$UDP6_CHAIN" 2>/dev/null \
        && ip6tables -w 5 -t filter -C "$UDP6_CHAIN" -p udp -j DROP 2>/dev/null
}

remove_udp6_partial() {
    ip6tables -w 5 -t filter -D OUTPUT -p udp -j "$UDP6_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -D FORWARD -p udp -j "$UDP6_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -F "$UDP6_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -X "$UDP6_CHAIN" 2>/dev/null
}

setup_udp_iptables_inner() {
    _udp_rule="$(ip rule show 2>/dev/null | grep "^$UDP_PRIORITY:")"
    if [ -n "$_udp_rule" ] \
        && ! printf '%s\n' "$_udp_rule" \
            | grep -Eq "fwmark $UDP_MARK(/[^ ]+)?[[:space:]].*lookup $UDP_TABLE([[:space:]]|$)"; then
        _udp_log "ip rule priority $UDP_PRIORITY 已被其它规则占用"
        return 1
    fi
    ip rule show 2>/dev/null | grep -Eq "fwmark $UDP_MARK(/[^ ]+)?[[:space:]].*lookup $UDP_TABLE([[:space:]]|$)" \
        || ip rule add fwmark "$UDP_MARK/$UDP_MARK" table "$UDP_TABLE" priority "$UDP_PRIORITY" \
        || return 1
    ip route replace local 0.0.0.0/0 dev lo table "$UDP_TABLE" || return 1

    iptables -w 5 -t mangle -N "$UDP_CHAIN" 2>/dev/null || true
    iptables -w 5 -t mangle -F "$UDP_CHAIN" || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -d 127.0.0.0/8 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -d 224.0.0.0/4 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -d 255.255.255.255/32 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -d 169.254.0.0/16 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -p udp --dport 53 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_CHAIN" -p udp \
        -j TPROXY --on-port "$PORT" --tproxy-mark "$UDP_MARK/$UDP_MARK" || return 1

    iptables -w 5 -t mangle -N "$UDP_OUT_CHAIN" 2>/dev/null || true
    iptables -w 5 -t mangle -F "$UDP_OUT_CHAIN" || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -d 127.0.0.0/8 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -d 224.0.0.0/4 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -d 255.255.255.255/32 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -d 169.254.0.0/16 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -p udp --dport 53 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_OUT_CHAIN" -p udp \
        -j MARK --set-mark "$UDP_MARK/$UDP_MARK" || return 1

    # 先装 PREROUTING 再装 OUTPUT mark：任一步失败都不会留下“只打 mark 无 TPROXY”。
    iptables -w 5 -t mangle -C PREROUTING -p udp -m mark --mark "$UDP_MARK/$UDP_MARK" \
        -j "$UDP_CHAIN" 2>/dev/null \
        || iptables -w 5 -t mangle -A PREROUTING -p udp -m mark --mark "$UDP_MARK/$UDP_MARK" \
        -j "$UDP_CHAIN" || return 1
    iptables -w 5 -t mangle -C OUTPUT -p udp -j "$UDP_OUT_CHAIN" 2>/dev/null \
        || iptables -w 5 -t mangle -A OUTPUT -p udp -j "$UDP_OUT_CHAIN" || return 1

    # 无 IPv6 ingress：拒绝 IPv6 UDP；v6 安装失败只清 v6 半成品。
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -L OUTPUT >/dev/null 2>&1; then
        if ! setup_udp6_iptables; then
            _udp_log "IPv6 UDP 规则安装失败，清理 IPv6 半成品；IPv4 继续"
            remove_udp6_partial
        fi
    fi
}

remove_udp4_fail_closed() {
    iptables -w 5 -t filter -D OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -D FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP_FAIL_FWD_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP_FAIL_FWD_CHAIN" 2>/dev/null
}

remove_udp_fail_closed() {
    remove_udp4_fail_closed
    remove_udp6_fail_closed
}

# UDP 安装失败时的兜底：除本机/回环/组播/链路本地、root、UDP 53 外全部 DROP；
# FORWARD 不能用 owner，单独建链。
install_udp_fail_closed() {
    remove_udp_fail_closed
    iptables -w 5 -t filter -N "$UDP_FAIL_CHAIN" 2>/dev/null || true
    iptables -w 5 -t filter -F "$UDP_FAIL_CHAIN" || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -d 127.0.0.0/8 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -d 224.0.0.0/4 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -d 255.255.255.255/32 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -d 169.254.0.0/16 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -p udp --dport 53 -j RETURN || return 1
    # IPv4 用 DROP：Android 上 REJECT target 不保证存在，兜底规则必须能装上。
    iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -p udp -j DROP || return 1

    iptables -w 5 -t filter -N "$UDP_FAIL_FWD_CHAIN" 2>/dev/null || true
    iptables -w 5 -t filter -F "$UDP_FAIL_FWD_CHAIN" || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -d 127.0.0.0/8 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -d 224.0.0.0/4 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -d 255.255.255.255/32 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -d 169.254.0.0/16 -j RETURN || return 1
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -p udp --dport 53 -j RETURN || return 1
    # FORWARD 没有 owner 匹配；同样用 DROP，保证 fail-closed 一定能安装。
    iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP || return 1

    iptables -w 5 -t filter -C OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I OUTPUT 1 -p udp -j "$UDP_FAIL_CHAIN" || return 1
    iptables -w 5 -t filter -C FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I FORWARD 1 -p udp -j "$UDP_FAIL_FWD_CHAIN" || return 1

    if command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -L OUTPUT >/dev/null 2>&1; then
        if ! install_udp6_fail_closed; then
            _udp_log "IPv6 UDP fail-closed 安装失败，清理 IPv6 半成品；IPv4 继续"
            remove_udp6_fail_closed
        fi
    fi
    return 0
}

install_udp6_fail_closed() {
    ip6tables -w 5 -t filter -N "$UDP6_FAIL_CHAIN" 2>/dev/null || true
    ip6tables -w 5 -t filter -F "$UDP6_FAIL_CHAIN" || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -d ::1/128 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -d fe80::/10 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -d ff00::/8 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -p udp --dport 53 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_CHAIN" -p udp -j DROP || return 1

    ip6tables -w 5 -t filter -N "$UDP6_FAIL_FWD_CHAIN" 2>/dev/null || true
    ip6tables -w 5 -t filter -F "$UDP6_FAIL_FWD_CHAIN" || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_FWD_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_FWD_CHAIN" -d ::1/128 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_FWD_CHAIN" -d fe80::/10 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_FWD_CHAIN" -d ff00::/8 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_FWD_CHAIN" -p udp --dport 53 -j RETURN || return 1
    ip6tables -w 5 -t filter -A "$UDP6_FAIL_FWD_CHAIN" -p udp -j DROP || return 1

    ip6tables -w 5 -t filter -C OUTPUT -p udp -j "$UDP6_FAIL_CHAIN" 2>/dev/null \
        || ip6tables -w 5 -t filter -I OUTPUT 1 -p udp -j "$UDP6_FAIL_CHAIN" || return 1
    ip6tables -w 5 -t filter -C FORWARD -p udp -j "$UDP6_FAIL_FWD_CHAIN" 2>/dev/null \
        || ip6tables -w 5 -t filter -I FORWARD 1 -p udp -j "$UDP6_FAIL_FWD_CHAIN" || return 1
}

remove_udp6_fail_closed() {
    ip6tables -w 5 -t filter -D OUTPUT -p udp -j "$UDP6_FAIL_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -D FORWARD -p udp -j "$UDP6_FAIL_FWD_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -F "$UDP6_FAIL_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -X "$UDP6_FAIL_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -F "$UDP6_FAIL_FWD_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -X "$UDP6_FAIL_FWD_CHAIN" 2>/dev/null
}

remove_udp_partial() {
    iptables -w 5 -t mangle -D OUTPUT -p udp -j "$UDP_OUT_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -D PREROUTING -p udp -m mark --mark "$UDP_MARK/$UDP_MARK" \
        -j "$UDP_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -F "$UDP_OUT_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -X "$UDP_OUT_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -F "$UDP_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -X "$UDP_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -D OUTPUT -p udp -j "$UDP6_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -F "$UDP6_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -X "$UDP6_CHAIN" 2>/dev/null
    # 旧版本/异常退出可能留下不同 priority 的同 table 规则；有界循环删干净。
    _rule_retry=0
    while [ "$_rule_retry" -lt 16 ] \
        && ip rule del fwmark "$UDP_MARK/$UDP_MARK" table "$UDP_TABLE" 2>/dev/null; do
        _rule_retry=$((_rule_retry + 1))
    done
    if ip route show table "$UDP_TABLE" 2>/dev/null \
        | grep -Eq '^local[[:space:]]+0\.0\.0\.0/0[[:space:]]+dev[[:space:]]+lo'; then
        ip route del local 0.0.0.0/0 dev lo table "$UDP_TABLE" 2>/dev/null
    fi
}

remove_udp_iptables() {
    remove_udp_fail_closed
    remove_udp_partial
}

# 按 pidfile 或精确 argv 停止进程，使用与 service/uninstall 相同的
# 有界 TERM/KILL 流程。
stop_pid() {
    _pidfile="$1"
    shift
    _pid="$(cat "$_pidfile" 2>/dev/null)"
    if ! is_pid_for "$_pid" "$@"; then
        _pid="$(find_pid_for "$@")" || _pid=""
    fi
    if [ -n "$_pid" ] && is_pid_for "$_pid" "$@"; then
        kill "$_pid" 2>/dev/null
        _i=0
        while [ "$_i" -lt 5 ] && kill -0 "$_pid" 2>/dev/null; do
            sleep 1
            _i=$((_i + 1))
        done
        kill -9 "$_pid" 2>/dev/null
    fi
    rm -f "$_pidfile"
}
