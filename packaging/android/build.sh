#!/bin/sh
set -eu

MODDIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$MODDIR/../.." && pwd)"
VERSION="${1:-$(cat "$ROOT/VERSION")}"
VERSION="${VERSION#v}"
VERSION_CODE="$(printf '%s\n' "$VERSION" | awk -F. '
    $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        printf "%d", $1 * 10000 + $2 * 100 + $3
        exit
    }
')"
[ -n "$VERSION_CODE" ] || {
    echo "routeproxy 版本无效: $VERSION" >&2
    exit 1
}
OUTDIR="$MODDIR/dist"
WORK="$OUTDIR/work"
OUT="$OUTDIR/routeproxy-tp-v$VERSION.zip"

ANDROID_BIN="${ROUTEPROXY_ANDROID_BIN:-$ROOT/target/aarch64-linux-android/release/routeproxy}"
RULES_SEED="$ROOT/rules.toml"

if [ ! -f "$ANDROID_BIN" ]; then
    echo "缺少 Android 二进制: $ANDROID_BIN" >&2
    echo "请先构建，或设置 ROUTEPROXY_ANDROID_BIN" >&2
    exit 1
fi
if [ ! -f "$RULES_SEED" ]; then
    echo "缺少规则 seed: $RULES_SEED" >&2
    exit 1
fi
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- \
    rules check --file "$RULES_SEED"

ANDROID_BUILD_ID="$(strings "$ANDROID_BIN" 2>/dev/null \
    | sed -n 's/.*routeproxy-build-id:\([^|]*\)|.*/\1/p' \
    | head -n 1)"
case "$ANDROID_BUILD_ID" in
    "$VERSION"@*) ;;
    *)
        echo "routeproxy 二进制版本不匹配: 期望 $VERSION，实际 ${ANDROID_BUILD_ID:-<未知>}" >&2
        exit 1
        ;;
esac
ANDROID_COMMIT="${ANDROID_BUILD_ID#*@}"
case "$ANDROID_COMMIT" in
    ""|unknown*|*dirty*)
        echo "拒绝打包不可复现的 Android 二进制: build id ${ANDROID_BUILD_ID:-<未知>}" >&2
        exit 1
        ;;
esac
GIT_HEAD="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || true)"
if [ -z "$GIT_HEAD" ]; then
    echo "无法读取 git HEAD，拒绝打包" >&2
    exit 1
fi
if [ "$ANDROID_COMMIT" != "$GIT_HEAD" ]; then
    echo "Android 二进制提交与 HEAD 不一致: $ANDROID_COMMIT != $GIT_HEAD" >&2
    exit 1
fi
if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
    echo "工作区不干净，拒绝打包 Android" >&2
    exit 1
fi
if strings "$ANDROID_BIN" 2>/dev/null | grep -Eq '/Users/|/home/|/data/data/com\.termux/|C:\\Users\\|D:\\a\\'; then
    echo "Android 二进制包含本地路径，请用 RUSTFLAGS=--remap-path-prefix 重新构建" >&2
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/bin" "$WORK/scripts" "$OUTDIR"

cp "$MODDIR/module.prop" "$WORK/module.prop"
sed -i.bak \
    -e "s/^version=.*/version=v$VERSION/" \
    -e "s/^versionCode=.*/versionCode=$VERSION_CODE/" \
    "$WORK/module.prop"
rm -f "$WORK/module.prop.bak"

cp "$MODDIR/customize.sh" "$MODDIR/service.sh" "$MODDIR/uninstall.sh" "$WORK/"
cp "$MODDIR/scripts/common.sh" "$MODDIR/scripts/watchdog.sh" "$WORK/scripts/"
chmod 0755 "$WORK"/*.sh "$WORK/scripts"/*.sh
cp "$MODDIR/config.toml.example" "$WORK/config.toml.example"
cp "$ROOT/LICENSE" "$WORK/LICENSE"
cp "$ROOT/LICENSE-DATA" "$WORK/LICENSE-DATA"
cp "$ROOT/NOTICE" "$WORK/NOTICE"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$WORK/THIRD_PARTY_NOTICES.md"
cp "$ANDROID_BIN" "$WORK/bin/routeproxy"
chmod 0755 "$WORK/bin/routeproxy"
cp "$RULES_SEED" "$WORK/rules.seed.toml"

rm -f "$OUT"
(cd "$WORK" && zip -rq "$OUT" . -x "*._*")
rm -rf "$WORK"

echo "已构建: $OUT"
ls -lh "$OUT"
