#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
DIST="$ROOT/dist"
WORK="$DIST/macos-work"

cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- rules check --file "$ROOT/rules.toml"

export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$ROOT=/routeproxy"

rm -rf "$WORK"
mkdir -p "$WORK" "$DIST"

for target in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --manifest-path "$ROOT/Cargo.toml" --target "$target"
done

lipo -create \
    "$ROOT/target/aarch64-apple-darwin/release/routeproxy" \
    "$ROOT/target/x86_64-apple-darwin/release/routeproxy" \
    -output "$WORK/routeproxy"
chmod 0755 "$WORK/routeproxy"
strip -x "$WORK/routeproxy" 2>/dev/null || true
codesign --force --sign - "$WORK/routeproxy"

cp "$ROOT/rules.toml" "$WORK/rules.toml"
cp "$ROOT/config.toml.example" "$WORK/config.toml.example"
cp "$ROOT/LICENSE" "$WORK/LICENSE"
cp "$ROOT/LICENSE-DATA" "$WORK/LICENSE-DATA"
cp "$ROOT/NOTICE" "$WORK/NOTICE"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$WORK/THIRD_PARTY_NOTICES.md"

version_output="$("$WORK/routeproxy" version)"
binary_version="$(printf '%s\n' "$version_output" | awk '{print $2}')"
build_id="$(printf '%s\n' "$version_output" | sed -n 's/.*routeproxy-build-id:\([^|]*\)|.*/\1/p')"
binary_commit="${build_id#*@}"
if [ "$binary_version" != "$VERSION" ]; then
    echo "routeproxy 二进制版本不匹配: 期望 $VERSION，实际 $binary_version" >&2
    exit 1
fi
case "$binary_commit" in
    ""|unknown*|*dirty*)
        echo "拒绝打包不可复现的 macOS 二进制: build id ${build_id:-<未知>}" >&2
        exit 1
        ;;
esac
GIT_HEAD="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || true)"
if [ -z "$GIT_HEAD" ]; then
    echo "无法读取 git HEAD，拒绝打包" >&2
    exit 1
fi
if [ "$binary_commit" != "$GIT_HEAD" ]; then
    echo "macOS 二进制提交与 HEAD 不一致: $binary_commit != $GIT_HEAD" >&2
    exit 1
fi
if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
    echo "工作区不干净，拒绝打包 macOS" >&2
    exit 1
fi
if strings "$WORK/routeproxy" 2>/dev/null | grep -Eq '/Users/|/home/|/data/data/com\.termux/|C:\\Users\\|D:\\a\\'; then
    echo "macOS 二进制包含本地路径，请检查 RUSTFLAGS remap" >&2
    exit 1
fi

tar -czf "$DIST/routeproxy-$VERSION-macos-universal.tar.gz" -C "$WORK" routeproxy rules.toml config.toml.example LICENSE LICENSE-DATA NOTICE THIRD_PARTY_NOTICES.md
rm -rf "$WORK"
