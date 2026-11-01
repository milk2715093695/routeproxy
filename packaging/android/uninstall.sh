#!/system/bin/sh
# routeproxy-tp 卸载钩子：停止进程，只删除本模块的 iptables 状态；
# /data/adb/routeproxy 有意保留，供重新安装使用。

MODDIR=${0%/*}
DATA=/data/adb/routeproxy
BIN="$MODDIR/bin/routeproxy"
WATCHDOG_SCRIPT="$MODDIR/scripts/watchdog.sh"
CHAIN=ROUTEPROXY_TP
CONF="$DATA/config.toml"
PIDFILE="$DATA/routeproxy.pid"
WATCHDOG_PID="$DATA/watchdog.pid"

. "$MODDIR/scripts/common.sh"

stop_pid "$WATCHDOG_PID" "/system/bin/sh" "$WATCHDOG_SCRIPT"
rm -rf "$DATA/watchdog.lock"

remove_iptables

stop_pid "$PIDFILE" "$BIN" run "$CONF"
exit 0
