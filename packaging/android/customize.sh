#!/system/bin/sh
# Magisk 解压文件后权限为 0644，这里恢复可执行位并初始化持久化目录，
# 但不覆盖用户已有文件。

MODPATH="${MODPATH:-${0%/*}}"
DATA=/data/adb/routeproxy

mkdir -p "$DATA/logs"

set_perm_recursive "$MODPATH/bin" 0 0 0755 0755 2>/dev/null || chmod -R 755 "$MODPATH/bin"
set_perm_recursive "$MODPATH/scripts" 0 0 0755 0755 2>/dev/null || chmod -R 755 "$MODPATH/scripts"
for script in customize.sh service.sh uninstall.sh; do
    chmod 0755 "$MODPATH/$script" 2>/dev/null
done

if [ ! -f "$DATA/rules.toml" ]; then
    if [ ! -f "$MODPATH/rules.seed.toml" ]; then
        abort "routeproxy-tp: 缺少 rules.seed.toml"
    fi
    cp -f "$MODPATH/rules.seed.toml" "$DATA/rules.toml"
fi

if [ ! -f "$DATA/config.toml" ]; then
    cp -f "$MODPATH/config.toml.example" "$DATA/config.toml"
fi

ui_print "- routeproxy-tp: 数据目录 $DATA"
ui_print "- routeproxy-tp: 编辑 $DATA/config.toml 后重启，或运行 service.sh start"
