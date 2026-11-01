#!/system/bin/sh
# routeproxy-tp 脚本共用函数。
#
# 透明模式要求恰好一个 IPv4 回环监听，因此读取第一个 listen 条目没有歧义。

read_port() {
    # 同时接受单行和多行 TOML listen 数组；遇到第一个右括号即停止，
    # 避免把后面的 `upstream = ...` 行吞进来。
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

# 精确比较 argv。子串 grep 会误匹配 `tail .../bin/routeproxy.log` 或
# `vi .../bin/routeproxy`。可选的第三、四参数还会校验 argv[1] 与
# `--config <path>`，避免把一次性的 `routeproxy doctor` 误认成守护进程。
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
    # 先调用一次 ps 过滤，再对少量候选做精确 argv 校验。逐个扫描
    # /proc/[0-9]* 并 fork tr/sed 在负载高的手机上会拖慢服务启动。
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
    iptables -w -t nat -N "$CHAIN" 2>/dev/null || true
    iptables -w -t nat -F "$CHAIN" || return 1
    iptables -w -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN || return 1
    iptables -w -t nat -A "$CHAIN" -m owner --uid-owner 0 -j RETURN || return 1
    iptables -w -t nat -A "$CHAIN" -p tcp --dport 53 -j RETURN || return 1
    iptables -w -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" || return 1
    iptables -w -t nat -C OUTPUT -p tcp -j "$CHAIN" 2>/dev/null \
        || iptables -w -t nat -A OUTPUT -p tcp -j "$CHAIN" || return 1
}

remove_iptables() {
    iptables -w -t nat -D OUTPUT -p tcp -j "$CHAIN" 2>/dev/null
    iptables -w -t nat -F "$CHAIN" 2>/dev/null
    iptables -w -t nat -X "$CHAIN" 2>/dev/null
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
