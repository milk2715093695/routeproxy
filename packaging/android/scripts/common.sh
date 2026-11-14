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
tcp_iptables_ready() {
    iptables -w 5 -t nat -C OUTPUT -p tcp -j "$CHAIN" 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -d 127.0.0.0/8 -j RETURN 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -p tcp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t nat -C "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" 2>/dev/null
}

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

UDP_CHAIN=ROUTEPROXY_UDP
UDP_NFQ_CHAIN=ROUTEPROXY_UDP_NFQ
# 必须与 src/udp/linux.rs 的 NFQUEUE_NUM 保持一致。
UDP_NFQ_QUEUE=21072
UDP_FAIL_CHAIN=ROUTEPROXY_UDP_FAIL
UDP_FAIL_FWD_CHAIN=ROUTEPROXY_UDP_FAIL_FWD
UDP443_CHAIN=ROUTEPROXY_UDP443
UDP443_FWD_CHAIN=ROUTEPROXY_UDP443_FWD
UDP4436_CHAIN=ROUTEPROXY_UDP4436
UDP4436_FWD_CHAIN=ROUTEPROXY_UDP4436_FWD
# 保存排序后的本地地址列表，watchdog 用文本比较判断变化。
UDP_LOCAL_HASH_FILE="${DATA:-/data/adb/routeproxy}/udp-local.hash"
UDP_LOCAL6_HASH_FILE="${DATA:-/data/adb/routeproxy}/udp-local6.hash"
UDP_NFQ_READY_FILE="${ROUTEPROXY_NFQ_READY:-${DATA:-/data/adb/routeproxy}/udp-nfq.ready}"
UDP_LOCAL_CIDRS="127.0.0.0/8 224.0.0.0/4 255.255.255.255/32 169.254.0.0/16"
# 独立 table；priority 必须早于 netd 的 `iif ap0 lookup wlan0`(21000)。
UDP_TABLE=21072
UDP_PRIORITY=1000
# 高位 fwmark，避开 netd 的低位网络 ID。
UDP_MARK=0x40000000

_udp_log() {
    _udp_line="$(date '+%Y-%m-%d %H:%M:%S') udp: $*"
    printf '%s\n' "$_udp_line" >> "${LOG:-${DATA:-/data/adb/routeproxy}/logs/udp.log}" 2>/dev/null || true
    if command -v log >/dev/null 2>&1; then
        command log -t routeproxy "$*" 2>/dev/null || true
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

udp_local_addrs() {
    # 本地地址列表不依赖 addrtype。
    command -v ip >/dev/null 2>&1 || return 1
    _udp_ip_output="$(ip addr show 2>/dev/null)" || return 1
    printf '%s\n' "$_udp_ip_output" \
        | awk '$1 == "inet" {
            sub(/\/.*/, "", $2); print $2
            if ($3 == "brd") { sub(/\/.*/, "", $4); print $4 }
        }' \
        | sort -u
}

udp_local_addrs6() {
    command -v ip >/dev/null 2>&1 || return 1
    _udp_ip6_output="$(ip addr show 2>/dev/null)" || return 1
    printf '%s\n' "$_udp_ip6_output" \
        | awk '$1 == "inet6" {
            sub(/\/.*/, "", $2); sub(/%.*/, "", $2)
            if ($2 != "::1" && $2 !~ /^fe[89ab]/ && $2 !~ /^ff00:/) print $2
        }' \
        | sort -u
}

write_udp_local_state() {
    _udp_addrs="$1"
    _udp6_addrs="$(udp_local_addrs6)" || return 1
    mkdir -p "${UDP_LOCAL_HASH_FILE%/*}" 2>/dev/null || true
    printf '%s\n' "$_udp_addrs" > "$UDP_LOCAL_HASH_FILE"
    printf '%s\n' "$_udp6_addrs" > "$UDP_LOCAL6_HASH_FILE"
}

udp_local_state_changed() {
    [ -f "$UDP_LOCAL_HASH_FILE" ] && [ -f "$UDP_LOCAL6_HASH_FILE" ] || return 0
    _udp_addrs="$(udp_local_addrs)" || return 2
    _udp6_addrs="$(udp_local_addrs6)" || return 2
    [ "$_udp_addrs" != "$(cat "$UDP_LOCAL_HASH_FILE" 2>/dev/null)" ] \
        || [ "$_udp6_addrs" != "$(cat "$UDP_LOCAL6_HASH_FILE" 2>/dev/null)" ]
}

fill_udp_local_bypass() {
    # $1=table，$2=chain，$3=地址列表，$4=verdict（默认 RETURN）。
    _udp_table="$1"
    _udp_chain="$2"
    _udp_addrs="$3"
    _udp_verdict="${4:-RETURN}"
    iptables -w 5 -t "$_udp_table" -F "$_udp_chain" || return 1
    for _udp_cidr in $UDP_LOCAL_CIDRS; do
        iptables -w 5 -t "$_udp_table" -A "$_udp_chain" -d "$_udp_cidr" -j "$_udp_verdict" || return 1
    done
    for _udp_addr in $_udp_addrs; do
        iptables -w 5 -t "$_udp_table" -A "$_udp_chain" -d "$_udp_addr/32" -j "$_udp_verdict" || return 1
    done
}

udp_local_rules_ready() {
    # $1=table，$2=chain，$3=地址列表，$4=verdict（默认 RETURN）。
    _udp_table="$1"
    _udp_chain="$2"
    _udp_addrs="$3"
    _udp_verdict="${4:-RETURN}"
    for _udp_cidr in $UDP_LOCAL_CIDRS; do
        iptables -w 5 -t "$_udp_table" -C "$_udp_chain" -d "$_udp_cidr" -j "$_udp_verdict" 2>/dev/null || return 1
    done
    for _udp_addr in $_udp_addrs; do
        iptables -w 5 -t "$_udp_table" -C "$_udp_chain" -d "$_udp_addr/32" -j "$_udp_verdict" 2>/dev/null || return 1
    done
}

udp6_local_rules_ready() {
    _udp6_chain="$1"
    _udp6_addrs="$2"
    for _udp6_cidr in ::1/128 fe80::/10 ff00::/8; do
        ip6tables -w 5 -t filter -C "$_udp6_chain" -d "$_udp6_cidr" -j RETURN 2>/dev/null || return 1
    done
    for _udp6_addr in $_udp6_addrs; do
        ip6tables -w 5 -t filter -C "$_udp6_chain" -d "$_udp6_addr/128" -j RETURN 2>/dev/null || return 1
    done
}

add_udp_local_bypass() {
    # 只补缺失规则，不 flush 活链；地址变化时避免短暂直连/黑洞。
    _udp_table="$1"
    _udp_chain="$2"
    _udp_addrs="$3"
    _udp_verdict="${4:-RETURN}"
    for _udp_cidr in $UDP_LOCAL_CIDRS; do
        iptables -w 5 -t "$_udp_table" -C "$_udp_chain" -d "$_udp_cidr" -j "$_udp_verdict" 2>/dev/null \
            || iptables -w 5 -t "$_udp_table" -I "$_udp_chain" 1 -d "$_udp_cidr" -j "$_udp_verdict" || return 1
    done
    for _udp_addr in $_udp_addrs; do
        iptables -w 5 -t "$_udp_table" -C "$_udp_chain" -d "$_udp_addr/32" -j "$_udp_verdict" 2>/dev/null \
            || iptables -w 5 -t "$_udp_table" -I "$_udp_chain" 1 -d "$_udp_addr/32" -j "$_udp_verdict" || return 1
    done
}

remove_udp_local_bypass() {
    # 删除已不在当前地址集合中的旧 /32，避免旧地址长期绕过 TPROXY/fail-closed。
    _udp_table="$1"
    _udp_chain="$2"
    _udp_old_addrs="$3"
    _udp_new_addrs="$4"
    _udp_verdict="$5"
    for _udp_addr in $_udp_old_addrs; do
        _udp_keep=0
        for _udp_new in $_udp_new_addrs; do
            if [ "$_udp_new" = "$_udp_addr" ]; then
                _udp_keep=1
                break
            fi
        done
        [ "$_udp_keep" = "1" ] && continue
        iptables -w 5 -t "$_udp_table" -D "$_udp_chain" -d "$_udp_addr/32" -j "$_udp_verdict" 2>/dev/null || true
    done
}

remove_udp6_local_bypass() {
    _udp6_old_addrs="$1"
    _udp6_new_addrs="$2"
    _udp6_chain="$3"
    for _udp6_addr in $_udp6_old_addrs; do
        _udp6_keep=0
        for _udp6_new in $_udp6_new_addrs; do
            if [ "$_udp6_new" = "$_udp6_addr" ]; then
                _udp6_keep=1
                break
            fi
        done
        [ "$_udp6_keep" = "1" ] && continue
        ip6tables -w 5 -t filter -D "$_udp6_chain" -d "$_udp6_addr/128" -j RETURN 2>/dev/null || true
    done
}

udp6_available() {
    command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -L OUTPUT >/dev/null 2>&1
}

remove_udp443_drop6() {
    ip6tables -w 5 -t filter -D OUTPUT -p udp --dport 443 -j "$UDP4436_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -D FORWARD -p udp --dport 443 -j "$UDP4436_FWD_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -F "$UDP4436_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -X "$UDP4436_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -F "$UDP4436_FWD_CHAIN" 2>/dev/null
    ip6tables -w 5 -t filter -X "$UDP4436_FWD_CHAIN" 2>/dev/null
    return 0
}

remove_udp443_drop() {
    iptables -w 5 -t filter -D OUTPUT -p udp --dport 443 -j "$UDP443_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -D FORWARD -p udp --dport 443 -j "$UDP443_FWD_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP443_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP443_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP443_FWD_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP443_FWD_CHAIN" 2>/dev/null
    return 0
}

fill_udp4436_chain() {
    # $1=chain，$2=1 时允许 owner 豁免（仅 OUTPUT 链）。
    _udp_chain="$1"
    _udp_owner="$2"
    ip6tables -w 5 -t filter -N "$_udp_chain" 2>/dev/null || true
    for _udp_cidr in ::1/128 fe80::/10 ff00::/8; do
        ip6tables -w 5 -t filter -C "$_udp_chain" -d "$_udp_cidr" -j RETURN 2>/dev/null \
            || ip6tables -w 5 -t filter -I "$_udp_chain" 1 -d "$_udp_cidr" -j RETURN || return 1
    done
    if [ "$_udp_owner" = "1" ]; then
        ip6tables -w 5 -t filter -C "$_udp_chain" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
            || ip6tables -w 5 -t filter -I "$_udp_chain" 1 -m owner --uid-owner 0 -j RETURN || return 1
    fi
    add_udp6_local_bypass filter "$_udp_chain" "$_udp6_addrs" || return 1
    ip6tables -w 5 -t filter -C "$_udp_chain" -p udp --dport 443 -j DROP 2>/dev/null \
        || ip6tables -w 5 -t filter -A "$_udp_chain" -p udp --dport 443 -j DROP || return 1
}

install_udp443_drop6() {
    _udp6_addrs="$(udp_local_addrs6)" || {
        _udp6_addrs=""
        _udp_log "读取本地 IPv6 地址失败，UDP 443 仅保留固定豁免"
    }
    fill_udp4436_chain "$UDP4436_CHAIN" 1 || return 1
    fill_udp4436_chain "$UDP4436_FWD_CHAIN" 0 || return 1
    if ! { ip6tables -w 5 -t filter -C OUTPUT -p udp --dport 443 -j "$UDP4436_CHAIN" 2>/dev/null \
        || ip6tables -w 5 -t filter -I OUTPUT 1 -p udp --dport 443 -j "$UDP4436_CHAIN"; }; then
        remove_udp443_drop6
        return 1
    fi
    if ! { ip6tables -w 5 -t filter -C FORWARD -p udp --dport 443 -j "$UDP4436_FWD_CHAIN" 2>/dev/null \
        || ip6tables -w 5 -t filter -I FORWARD 1 -p udp --dport 443 -j "$UDP4436_FWD_CHAIN"; }; then
        remove_udp443_drop6
        return 1
    fi
}

fill_udp443_chain() {
    # $1=chain，$2=1 时允许 owner 豁免（仅 OUTPUT 链）。
    _udp_chain="$1"
    _udp_owner="$2"
    iptables -w 5 -t filter -N "$_udp_chain" 2>/dev/null || true
    for _udp_cidr in $UDP_LOCAL_CIDRS; do
        iptables -w 5 -t filter -C "$_udp_chain" -d "$_udp_cidr" -j RETURN 2>/dev/null \
            || iptables -w 5 -t filter -I "$_udp_chain" 1 -d "$_udp_cidr" -j RETURN || return 1
    done
    if [ "$_udp_owner" = "1" ]; then
        iptables -w 5 -t filter -C "$_udp_chain" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
            || iptables -w 5 -t filter -I "$_udp_chain" 1 -m owner --uid-owner 0 -j RETURN || return 1
    fi
    add_udp_local_bypass filter "$_udp_chain" "$_udp_addrs" RETURN || return 1
    iptables -w 5 -t filter -C "$_udp_chain" -p udp --dport 443 -j DROP 2>/dev/null \
        || iptables -w 5 -t filter -A "$_udp_chain" -p udp --dport 443 -j DROP || return 1
}

install_udp443_drop() {
    # 完整 fail-closed 无法安装时的最后兜底；只挡 QUIC，不阻止其他 UDP。
    _udp_addrs="$(udp_local_addrs)" || {
        _udp_addrs=""
        _udp_log "读取本地 IPv4 地址失败，UDP 443 仅保留固定豁免"
    }
    if udp_v4_443_ready; then
        write_udp_local_state "$_udp_addrs" || _udp_log "写入 UDP 本地地址状态失败"
        ensure_udp6_protected || _udp_log "IPv6 UDP 443 兜底安装失败"
        return 0
    fi
    fill_udp443_chain "$UDP443_CHAIN" 1 || return 1
    fill_udp443_chain "$UDP443_FWD_CHAIN" 0 || return 1
    if ! { iptables -w 5 -t filter -C OUTPUT -p udp --dport 443 -j "$UDP443_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I OUTPUT 1 -p udp --dport 443 -j "$UDP443_CHAIN"; }; then
        remove_udp443_drop
        return 1
    fi
    if ! { iptables -w 5 -t filter -C FORWARD -p udp --dport 443 -j "$UDP443_FWD_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I FORWARD 1 -p udp --dport 443 -j "$UDP443_FWD_CHAIN"; }; then
        remove_udp443_drop
        return 1
    fi
    write_udp_local_state "$_udp_addrs" || _udp_log "写入 UDP 本地地址状态失败"
    if udp6_available; then
        if ! install_udp443_drop6; then
            _udp_log "IPv6 UDP 443 兜底规则安装失败"
            remove_udp443_drop6
        fi
    fi
    return 0
}

udp_v4_443_base_ready() {
    iptables -w 5 -t filter -C OUTPUT -p udp --dport 443 -j "$UDP443_CHAIN" 2>/dev/null \
        && iptables -w 5 -t filter -C FORWARD -p udp --dport 443 -j "$UDP443_FWD_CHAIN" 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP443_CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP443_CHAIN" -p udp --dport 443 -j DROP 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP443_FWD_CHAIN" -p udp --dport 443 -j DROP 2>/dev/null
}

udp_v4_443_ready() {
    _udp_addrs="$(udp_local_addrs)" || return 1
    udp_v4_443_base_ready \
        && udp_local_rules_ready filter "$UDP443_CHAIN" "$_udp_addrs" RETURN \
        && udp_local_rules_ready filter "$UDP443_FWD_CHAIN" "$_udp_addrs" RETURN
}

udp_v6_443_ready() {
    udp6_available || return 0
    _udp6_addrs="$(udp_local_addrs6)" || return 1
    ip6tables -w 5 -t filter -C OUTPUT -p udp --dport 443 -j "$UDP4436_CHAIN" 2>/dev/null \
        && ip6tables -w 5 -t filter -C FORWARD -p udp --dport 443 -j "$UDP4436_FWD_CHAIN" 2>/dev/null \
        && udp6_local_rules_ready "$UDP4436_CHAIN" "$_udp6_addrs" \
        && udp6_local_rules_ready "$UDP4436_FWD_CHAIN" "$_udp6_addrs" \
        && ip6tables -w 5 -t filter -C "$UDP4436_CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && ip6tables -w 5 -t filter -C "$UDP4436_CHAIN" -p udp --dport 443 -j DROP 2>/dev/null \
        && ip6tables -w 5 -t filter -C "$UDP4436_FWD_CHAIN" -p udp --dport 443 -j DROP 2>/dev/null
}

udp_v4_fail_closed_base_ready() {
    iptables -w 5 -t filter -C OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -p udp -j DROP 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t filter -C FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP 2>/dev/null \
        && iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null
}

udp_v4_fail_closed_ready() {
    _udp_addrs="$(udp_local_addrs)" || return 1
    udp_v4_fail_closed_base_ready \
        && udp_local_rules_ready filter "$UDP_FAIL_CHAIN" "$_udp_addrs" RETURN \
        && udp_local_rules_ready filter "$UDP_FAIL_FWD_CHAIN" "$_udp_addrs" RETURN
}

refresh_udp_local_bypass() {
    _udp_addrs="$(udp_local_addrs)" || return 1
    _udp6_addrs="$(udp_local_addrs6)" || return 1
    _udp_old_addrs="$(cat "$UDP_LOCAL_HASH_FILE" 2>/dev/null)"
    _udp_old6_addrs="$(cat "$UDP_LOCAL6_HASH_FILE" 2>/dev/null)"
    _udp_refreshed=0

    if udp_v4_fail_closed_base_ready; then
        add_udp_local_bypass filter "$UDP_FAIL_CHAIN" "$_udp_addrs" RETURN || return 1
        add_udp_local_bypass filter "$UDP_FAIL_FWD_CHAIN" "$_udp_addrs" RETURN || return 1
        _udp_refreshed=1
    elif udp_v4_443_base_ready; then
        add_udp_local_bypass filter "$UDP443_CHAIN" "$_udp_addrs" RETURN || return 1
        add_udp_local_bypass filter "$UDP443_FWD_CHAIN" "$_udp_addrs" RETURN || return 1
        _udp_refreshed=1
    fi

    if iptables -w 5 -t mangle -C PREROUTING -p udp -j "$UDP_CHAIN" 2>/dev/null; then
        add_udp_local_bypass mangle "$UDP_CHAIN" "$_udp_addrs" RETURN || return 1
        _udp_refreshed=1
    fi
    if iptables -w 5 -t mangle -C OUTPUT -p udp -j "$UDP_NFQ_CHAIN" 2>/dev/null; then
        add_udp_local_bypass mangle "$UDP_NFQ_CHAIN" "$_udp_addrs" RETURN || return 1
        _udp_refreshed=1
    fi
    [ "$_udp_refreshed" = "1" ] || return 1

    # 地址减少时清掉旧 /32；先加新地址再删旧地址，不产生空窗。
    for _udp_chain in "$UDP_FAIL_CHAIN" "$UDP_FAIL_FWD_CHAIN" "$UDP443_CHAIN" "$UDP443_FWD_CHAIN"; do
        remove_udp_local_bypass filter "$_udp_chain" "$_udp_old_addrs" "$_udp_addrs" RETURN
    done
    remove_udp_local_bypass mangle "$UDP_CHAIN" "$_udp_old_addrs" "$_udp_addrs" RETURN
    remove_udp_local_bypass mangle "$UDP_NFQ_CHAIN" "$_udp_old_addrs" "$_udp_addrs" RETURN

    if udp6_available && udp_v6_443_ready; then
        add_udp6_local_bypass filter "$UDP4436_CHAIN" "$_udp6_addrs" || return 1
        add_udp6_local_bypass filter "$UDP4436_FWD_CHAIN" "$_udp6_addrs" || return 1
    fi
    for _udp6_chain in "$UDP4436_CHAIN" "$UDP4436_FWD_CHAIN"; do
        remove_udp6_local_bypass "$_udp_old6_addrs" "$_udp6_addrs" "$_udp6_chain"
    done

    write_udp_local_state "$_udp_addrs" || _udp_log "写入 UDP 本地地址状态失败"
    return 0
}

udp_v4_protected_ready() {
    udp_v4_fail_closed_ready || udp_v4_443_ready
}

ensure_udp6_protected() {
    udp6_available || return 0
    udp_v6_443_ready && return 0
    install_udp443_drop6
}

install_udp_fail_closed_or_443() {
    # IPv6 是可选能力，失败不能否决 IPv4，也不能让 TCP 跟着停。
    # 返回 0=完整 fail-closed，2=仅 UDP 443，1=失败；调用方不能把 2 当完整保护。
    if udp_v4_fail_closed_ready; then
        ensure_udp6_protected || _udp_log "IPv6 UDP 保护安装失败，IPv4 继续"
        return 0
    fi
    if install_udp_fail_closed; then
        ensure_udp6_protected || _udp_log "IPv6 UDP 保护安装失败，IPv4 继续"
        return 0
    fi
    if udp_v4_443_base_ready; then
        if _udp_addrs="$(udp_local_addrs)"; then
            add_udp_local_bypass filter "$UDP443_CHAIN" "$_udp_addrs" RETURN \
                || _udp_log "刷新 IPv4 UDP 443 本地 bypass 失败"
            add_udp_local_bypass filter "$UDP443_FWD_CHAIN" "$_udp_addrs" RETURN \
                || _udp_log "刷新 IPv4 UDP 443 FORWARD bypass 失败"
            write_udp_local_state "$_udp_addrs" || _udp_log "写入 UDP 本地地址状态失败"
        fi
        ensure_udp6_protected || _udp_log "IPv6 UDP 保护安装失败，IPv4 443 继续"
        _udp_log "IPv4 完整 fail-closed 不可用，仅 UDP 443 受保护"
        return 2
    fi
    if install_udp443_drop; then
        ensure_udp6_protected || _udp_log "IPv6 UDP 443 兜底安装失败"
        _udp_log "IPv4 完整 fail-closed 不可用，仅 UDP 443 受保护"
        return 2
    fi
    return 1
}

udp_nfq_ready() {
    _udp_nfq_pid="$(sed -n '1p' "$UDP_NFQ_READY_FILE" 2>/dev/null)" || return 1
    _udp_nfq_uptime="$(sed -n '2p' "$UDP_NFQ_READY_FILE" 2>/dev/null)" || return 1
    [ -n "$_udp_nfq_pid" ] && [ -n "$_udp_nfq_uptime" ] || return 1
    _udp_nfq_now="$(cut -d' ' -f1 /proc/uptime 2>/dev/null)" || return 1
    awk -v now="$_udp_nfq_now" -v up="$_udp_nfq_uptime" \
        'BEGIN { exit !(now - up >= 0 && now - up <= 60) }' || return 1
    [ -n "${BIN:-}" ] && [ -n "${CONF:-}" ] || return 1
    is_pid_for "$_udp_nfq_pid" "$BIN" run "$CONF"
}

udp_tproxy_active() {
    iptables -w 5 -t mangle -C OUTPUT -p udp -j "$UDP_NFQ_CHAIN" 2>/dev/null \
        && iptables -w 5 -t mangle -C PREROUTING -p udp -j "$UDP_CHAIN" 2>/dev/null
}

udp_local_ready() {
    _udp_addrs="$(udp_local_addrs)" || return 1
    iptables -w 5 -t mangle -C OUTPUT -p udp -j "$UDP_NFQ_CHAIN" 2>/dev/null \
        && udp_local_rules_ready mangle "$UDP_NFQ_CHAIN" "$_udp_addrs" RETURN \
        && iptables -w 5 -t mangle -C "$UDP_NFQ_CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_NFQ_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_NFQ_CHAIN" -p udp \
            -j NFQUEUE --queue-num "$UDP_NFQ_QUEUE" 2>/dev/null
}

udp_rule_ok() {
    ip rule show 2>/dev/null | grep -Eq "^$UDP_PRIORITY:.*fwmark $UDP_MARK(/[^ ]+)?[[:space:]].*lookup $UDP_TABLE([[:space:]]|$)"
}

udp_forward_available() {
    _udp_rule="$(ip rule show 2>/dev/null | grep "^$UDP_PRIORITY:")"
    [ -z "$_udp_rule" ] || udp_rule_ok
}

udp_tproxy_ready() {
    _udp_addrs="$(udp_local_addrs)" || return 1
    udp_local_ready \
        && udp_rule_ok \
        && ip route show table "$UDP_TABLE" 2>/dev/null \
            | grep -Eq '^local[[:space:]]+(default|0\.0\.0\.0/0)[[:space:]]+dev[[:space:]]+lo' \
        && iptables -w 5 -t mangle -C PREROUTING -p udp -j "$UDP_CHAIN" 2>/dev/null \
        && udp_local_rules_ready mangle "$UDP_CHAIN" "$_udp_addrs" RETURN \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
        && iptables -w 5 -t mangle -C "$UDP_CHAIN" -p udp \
            -j TPROXY --on-port "$PORT" --tproxy-mark "$UDP_MARK/$UDP_MARK" 2>/dev/null
}

setup_udp_iptables() {
    # 地址读取失败时不做任何规则变更，避免拆掉正常 TPROXY。
    _udp_addrs="$(udp_local_addrs)" || {
        _udp_log "读取 UDP 本地地址失败，保持现有规则"
        return 1
    }
    # 已经完整安装时不要因为 fail-closed 已移除而误判为需要重建。
    if udp_tproxy_ready; then
        return 0
    fi
    # priority 被外部规则占用时只保留本机 NFQUEUE；转发方向单独 fail-closed。
    if udp_local_ready && ! udp_forward_available; then
        _udp_forward_ok=0
        install_udp4_forward_fail_closed "$_udp_addrs" \
            || { _udp_log "转发方向 UDP fail-closed 安装失败"; return 1; }
        ensure_udp6_protected || _udp_log "IPv6 UDP 保护安装失败，IPv4 继续"
        return 0
    fi
    if udp_tproxy_active && ! udp_v4_fail_closed_ready; then
        # 先补兜底再重建；否则重建失败会留下无保护窗口。
        install_udp_fail_closed_or_443
        _udp_rc=$?
        if [ "$_udp_rc" -eq 1 ]; then
            _udp_log "完整 IPv4 fail-closed 未就绪，且兜底安装失败；保留现有 TPROXY"
            return 1
        fi
    fi
    if ! udp_tproxy_active && ! udp_v4_protected_ready; then
        install_udp_fail_closed_or_443
        _udp_rc=$?
        if [ "$_udp_rc" -eq 1 ]; then
            _udp_log "UDP 兜底规则安装失败，拒绝重建"
            return 1
        fi
    fi
    if setup_udp_iptables_inner "$_udp_addrs"; then
        if [ "${_udp_forward_ok:-1}" = "0" ]; then
            # 本机 NFQUEUE 已接管；转发方向保持 fail-closed，避免热点 UDP 直连。
            remove_udp4_fail_closed_local
            install_udp4_forward_fail_closed "$_udp_addrs" \
                || _udp_log "转发方向 UDP fail-closed 安装失败"
        else
            remove_udp4_fail_closed
        fi
        ensure_udp6_protected || _udp_log "IPv6 UDP 443 兜底规则安装失败"
        return 0
    fi
    # 清掉半成品，避免留下半套入口；IPv6 正常链保留。
    remove_udp_tproxy_only
    # 降级状态也记录本次地址，避免 watchdog 因地址变化反复重试。
    if udp_v4_protected_ready; then
        _udp_addrs="$(udp_local_addrs)" && write_udp_local_state "$_udp_addrs" \
            || _udp_log "写入 UDP 本地地址状态失败"
    fi
    return 1
}

setup_udp_iptables_inner() {
    _udp_addrs="${1:-$(udp_local_addrs)}" || return 1
    _udp_forward_ok=1
    _udp_rule="$(ip rule show 2>/dev/null | grep "^$UDP_PRIORITY:")"
    if [ -n "$_udp_rule" ] && ! udp_rule_ok; then
        _udp_log "ip rule priority $UDP_PRIORITY 已被其它规则占用，仅保留本机 UDP"
        _udp_forward_ok=0
    fi

    # 先摘跳转再重建链，避免 flush 时留下半套入口。
    iptables -w 5 -t mangle -D OUTPUT -p udp -j "$UDP_NFQ_CHAIN" 2>/dev/null || true
    iptables -w 5 -t mangle -D PREROUTING -p udp -j "$UDP_CHAIN" 2>/dev/null || true

    # 本机 App 的 UDP 在 mangle OUTPUT 交给 NFQUEUE；原目标直接从 IP 头读取。
    # 这条路径不依赖 ip rule，priority 冲突时仍要保留。
    iptables -w 5 -t mangle -N "$UDP_NFQ_CHAIN" 2>/dev/null || true
    iptables -w 5 -t mangle -F "$UDP_NFQ_CHAIN" || return 1
    fill_udp_local_bypass mangle "$UDP_NFQ_CHAIN" "$_udp_addrs" RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_NFQ_CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_NFQ_CHAIN" -p udp --dport 53 -j RETURN || return 1
    iptables -w 5 -t mangle -A "$UDP_NFQ_CHAIN" -p udp \
        -j NFQUEUE --queue-num "$UDP_NFQ_QUEUE" || return 1
    iptables -w 5 -t mangle -C OUTPUT -p udp -j "$UDP_NFQ_CHAIN" 2>/dev/null \
        || iptables -w 5 -t mangle -I OUTPUT 1 -p udp -j "$UDP_NFQ_CHAIN" || return 1

    if [ "$_udp_forward_ok" = "1" ]; then
        udp_rule_ok \
            || ip rule add fwmark "$UDP_MARK/$UDP_MARK" table "$UDP_TABLE" priority "$UDP_PRIORITY" \
            || return 1
        ip route replace local 0.0.0.0/0 dev lo table "$UDP_TABLE" || return 1

        iptables -w 5 -t mangle -N "$UDP_CHAIN" 2>/dev/null || true
        iptables -w 5 -t mangle -F "$UDP_CHAIN" || return 1
        fill_udp_local_bypass mangle "$UDP_CHAIN" "$_udp_addrs" RETURN || return 1
        iptables -w 5 -t mangle -A "$UDP_CHAIN" -p udp --dport 53 -j RETURN || return 1
        iptables -w 5 -t mangle -A "$UDP_CHAIN" -p udp \
            -j TPROXY --on-port "$PORT" --tproxy-mark "$UDP_MARK/$UDP_MARK" || return 1
        iptables -w 5 -t mangle -C PREROUTING -p udp -j "$UDP_CHAIN" 2>/dev/null \
            || iptables -w 5 -t mangle -A PREROUTING -p udp -j "$UDP_CHAIN" || return 1
    fi

    # 无 IPv6 ingress：只保留 IPv6 UDP 443 DROP。
    ensure_udp6_protected || _udp_log "IPv6 UDP 443 兜底规则安装失败"
    write_udp_local_state "$_udp_addrs" || _udp_log "写入 UDP 本地地址状态失败"
}

remove_udp4_fail_closed_chains() {
    iptables -w 5 -t filter -D OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -D FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP_FAIL_FWD_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP_FAIL_FWD_CHAIN" 2>/dev/null
}

remove_udp4_fail_closed() {
    remove_udp443_drop
    remove_udp4_fail_closed_chains
}

remove_udp4_fail_closed_local() {
    iptables -w 5 -t filter -D OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -F "$UDP_FAIL_CHAIN" 2>/dev/null
    iptables -w 5 -t filter -X "$UDP_FAIL_CHAIN" 2>/dev/null
}

# 只保留转发方向的 fail-closed；本机方向由 NFQUEUE 接管。
install_udp4_forward_fail_closed() {
    _udp_addrs="$1"
    iptables -w 5 -t filter -N "$UDP_FAIL_FWD_CHAIN" 2>/dev/null || true
    # 链可能已挂在 FORWARD 上，先保证终止 DROP 存在，再补豁免；
    # flush 活链会在重建期间留下 fail-open 窗口。
    iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP 2>/dev/null \
        || iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP || return 1
    iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
        || iptables -w 5 -t filter -I "$UDP_FAIL_FWD_CHAIN" 1 -p udp --dport 53 -j RETURN || return 1
    add_udp_local_bypass filter "$UDP_FAIL_FWD_CHAIN" "$_udp_addrs" RETURN || return 1
    iptables -w 5 -t filter -C FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I FORWARD 1 -p udp -j "$UDP_FAIL_FWD_CHAIN" || return 1
}

remove_udp_fail_closed() {
    remove_udp4_fail_closed
    remove_udp443_drop6
}

# filter 的本地/链路本地/组播豁免必须写在父链里用 RETURN；
# 子链 RETURN 只会回到父链继续 DROP，ACCEPT 又会跳过 netd/AFWall。
install_udp4_fail_closed_chains() {
    _udp_addrs="$1"
    if iptables -w 5 -t filter -S "$UDP_FAIL_CHAIN" >/dev/null 2>&1; then
        iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -p udp -j DROP 2>/dev/null \
            || iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -p udp -j DROP || return 1
        iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -m owner --uid-owner 0 -j RETURN 2>/dev/null \
            || iptables -w 5 -t filter -I "$UDP_FAIL_CHAIN" 1 -m owner --uid-owner 0 -j RETURN || return 1
        iptables -w 5 -t filter -C "$UDP_FAIL_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
            || iptables -w 5 -t filter -I "$UDP_FAIL_CHAIN" 1 -p udp --dport 53 -j RETURN || return 1
        add_udp_local_bypass filter "$UDP_FAIL_CHAIN" "$_udp_addrs" RETURN || return 1
    else
        iptables -w 5 -t filter -N "$UDP_FAIL_CHAIN" 2>/dev/null || true
        fill_udp_local_bypass filter "$UDP_FAIL_CHAIN" "$_udp_addrs" RETURN || return 1
        iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
        iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -p udp --dport 53 -j RETURN || return 1
        iptables -w 5 -t filter -A "$UDP_FAIL_CHAIN" -p udp -j DROP || return 1
    fi

    if iptables -w 5 -t filter -S "$UDP_FAIL_FWD_CHAIN" >/dev/null 2>&1; then
        iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP 2>/dev/null \
            || iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP || return 1
        iptables -w 5 -t filter -C "$UDP_FAIL_FWD_CHAIN" -p udp --dport 53 -j RETURN 2>/dev/null \
            || iptables -w 5 -t filter -I "$UDP_FAIL_FWD_CHAIN" 1 -p udp --dport 53 -j RETURN || return 1
        add_udp_local_bypass filter "$UDP_FAIL_FWD_CHAIN" "$_udp_addrs" RETURN || return 1
    else
        iptables -w 5 -t filter -N "$UDP_FAIL_FWD_CHAIN" 2>/dev/null || true
        fill_udp_local_bypass filter "$UDP_FAIL_FWD_CHAIN" "$_udp_addrs" RETURN || return 1
        iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -p udp --dport 53 -j RETURN || return 1
        iptables -w 5 -t filter -A "$UDP_FAIL_FWD_CHAIN" -p udp -j DROP || return 1
    fi
}

# UDP 安装失败时的兜底：IPv4 本机地址/回环/组播/链路本地、root、UDP 53 除外。
install_udp_fail_closed() {
    _udp_addrs="$(udp_local_addrs)" || return 1
    _udp_had_fail_closed=0
    udp_v4_fail_closed_base_ready && _udp_had_fail_closed=1
    if ! install_udp4_fail_closed_chains "$_udp_addrs"; then
        [ "$_udp_had_fail_closed" = "1" ] || remove_udp4_fail_closed_chains
        return 1
    fi

    if ! { iptables -w 5 -t filter -C OUTPUT -p udp -j "$UDP_FAIL_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I OUTPUT 1 -p udp -j "$UDP_FAIL_CHAIN"; }; then
        [ "$_udp_had_fail_closed" = "1" ] || remove_udp4_fail_closed_chains
        return 1
    fi
    if ! { iptables -w 5 -t filter -C FORWARD -p udp -j "$UDP_FAIL_FWD_CHAIN" 2>/dev/null \
        || iptables -w 5 -t filter -I FORWARD 1 -p udp -j "$UDP_FAIL_FWD_CHAIN"; }; then
        [ "$_udp_had_fail_closed" = "1" ] || remove_udp4_fail_closed_chains
        return 1
    fi
    remove_udp443_drop
    write_udp_local_state "$_udp_addrs" || _udp_log "写入 UDP 本地地址状态失败"

    ensure_udp6_protected || _udp_log "IPv6 UDP 443 兜底规则安装失败"
    return 0
}

add_udp6_local_bypass() {
    _udp_table="$1"
    _udp_chain="$2"
    _udp6_addrs="$3"
    for _udp6_addr in $_udp6_addrs; do
        ip6tables -w 5 -t "$_udp_table" -C "$_udp_chain" -d "$_udp6_addr/128" -j RETURN 2>/dev/null \
            || ip6tables -w 5 -t "$_udp_table" -I "$_udp_chain" 1 -d "$_udp6_addr/128" -j RETURN || return 1
    done
}

remove_udp_tproxy_only() {
    iptables -w 5 -t mangle -D OUTPUT -p udp -j "$UDP_NFQ_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -D PREROUTING -p udp -j "$UDP_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -F "$UDP_NFQ_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -X "$UDP_NFQ_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -F "$UDP_CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -X "$UDP_CHAIN" 2>/dev/null
    # 异常退出可能留下不同 priority 的同 table 规则；有界循环删干净。
    _rule_retry=0
    while [ "$_rule_retry" -lt 16 ] \
        && ip rule del fwmark "$UDP_MARK/$UDP_MARK" table "$UDP_TABLE" 2>/dev/null; do
        _rule_retry=$((_rule_retry + 1))
    done
    if ip route show table "$UDP_TABLE" 2>/dev/null \
        | grep -Eq '^local[[:space:]]+(default|0\.0\.0\.0/0)[[:space:]]+dev[[:space:]]+lo'; then
        ip route del local default dev lo table "$UDP_TABLE" 2>/dev/null \
            || ip route del local 0.0.0.0/0 dev lo table "$UDP_TABLE" 2>/dev/null
    fi
}

remove_udp_partial() {
    remove_udp_tproxy_only
}

remove_udp_iptables() {
    remove_udp_fail_closed
    remove_udp_partial
    rm -f "$UDP_LOCAL_HASH_FILE" "$UDP_LOCAL6_HASH_FILE"
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
