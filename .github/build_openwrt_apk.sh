#!/usr/bin/env bash

set -e -o pipefail

prepare_apk_root() {
  # apk mkpkg resolves owner/group names through --root/etc/{passwd,group}.
  APK_ROOT_DIR=$(mktemp -d)
  mkdir -p "$APK_ROOT_DIR/etc"
  cat > "$APK_ROOT_DIR/etc/passwd" <<EOF
root:x:$(id -u):$(id -g):root:/root:/sbin/nologin
EOF
  cat > "$APK_ROOT_DIR/etc/group" <<EOF
root:x:$(id -g):root
EOF
}

ARCHITECTURE="$1"
VERSION="$2"
BINARY_PATH="$3"
OUTPUT_PATH="$4"
PACKAGE_NAME="${5:-sing-box-extended}"
PACKAGE_DESCRIPTION="${6:-The universal proxy platform (extended).}"
PACKAGE_ORIGIN="${7:-sing-box-extended}"
PACKAGE_URL="${8:-https://sing-box.sagernet.org/}"
PACKAGE_MAINTAINER="${9:-nekohasekai <contact-git@sekai.icu>}"
REPLACES="${10:-}"
APK_INFO=()

if [ -z "$ARCHITECTURE" ] || [ -z "$VERSION" ] || [ -z "$BINARY_PATH" ] || [ -z "$OUTPUT_PATH" ]; then
  echo "Usage: $0 <architecture> <version> <binary_path> <output_path>"
  exit 1
fi

PROJECT=$(cd "$(dirname "$0")/.."; pwd)

# APK only accepts a fixed set of textual suffixes. The Forkop package name
# already identifies the flavor, so its package version keeps numeric parts.
if [ "$PACKAGE_NAME" = "sing-box-extended" ]; then
  APK_VERSION=$(echo "$VERSION" | sed -E 's/-([a-z]+)\.([0-9]+)/_\1\2/' | sed -E 's/-[a-z]+-/./g')
else
  APK_VERSION=$(echo "$VERSION" | sed -E 's/[^0-9]+/./g; s/^\.+//; s/\.+$//; s/\.+/./g')
fi
APK_VERSION="${APK_VERSION}-r0"

ROOT_DIR=$(mktemp -d)
prepare_apk_root
trap 'rm -rf "$ROOT_DIR" "$APK_ROOT_DIR"' EXIT

# Binary
install -Dm755 "$BINARY_PATH" "$ROOT_DIR/usr/bin/sing-box"
if [ "$PACKAGE_NAME" = "sing-box-forkop" ] || [ "$PACKAGE_NAME" = "sing-box-forkop-compressed" ]; then
  install -Dm644 /dev/null "$ROOT_DIR/usr/share/sing-box-forkop/version"
  printf '%s\n' "$VERSION" > "$ROOT_DIR/usr/share/sing-box-forkop/version"
fi

# Config files
install -Dm644 "$PROJECT/release/config/config.json" "$ROOT_DIR/etc/sing-box/config.json"
install -Dm644 "$PROJECT/release/config/openwrt.conf" "$ROOT_DIR/etc/config/sing-box"
install -Dm755 "$PROJECT/release/config/openwrt.init" "$ROOT_DIR/etc/init.d/sing-box"
install -Dm644 "$PROJECT/release/config/openwrt.keep" "$ROOT_DIR/lib/upgrade/keep.d/sing-box"

# Completions
install -Dm644 "$PROJECT/release/completions/sing-box.bash" "$ROOT_DIR/usr/share/bash-completion/completions/sing-box.bash"
install -Dm644 "$PROJECT/release/completions/sing-box.fish" "$ROOT_DIR/usr/share/fish/vendor_completions.d/sing-box.fish"
install -Dm644 "$PROJECT/release/completions/sing-box.zsh" "$ROOT_DIR/usr/share/zsh/site-functions/_sing-box"

# License
install -Dm644 "$PROJECT/LICENSE" "$ROOT_DIR/usr/share/licenses/sing-box/LICENSE"

# APK metadata
PACKAGES_DIR="$ROOT_DIR/lib/apk/packages"
mkdir -p "$PACKAGES_DIR"

# .conffiles
cat > "$PACKAGES_DIR/.conffiles" <<'EOF'
/etc/config/sing-box
/etc/sing-box/config.json
EOF

# .conffiles_static (sha256 checksums)
while IFS= read -r conffile; do
  sha256=$(sha256sum "$ROOT_DIR$conffile" | cut -d' ' -f1)
  echo "$conffile $sha256"
done < "$PACKAGES_DIR/.conffiles" > "$PACKAGES_DIR/.conffiles_static"

# .list (all files, excluding lib/apk/packages/ metadata)
(cd "$ROOT_DIR" && find . -type f -o -type l) \
  | sed 's|^\./|/|' \
  | grep -v '^/lib/apk/packages/' \
  | sort > "$PACKAGES_DIR/.list"

# Build APK
if [ -n "$REPLACES" ]; then
  APK_INFO=(--info "replaces:${REPLACES}")
fi
apk --root "$APK_ROOT_DIR" mkpkg \
  --info "name:${PACKAGE_NAME}" \
  --info "version:${APK_VERSION}" \
  --info "description:${PACKAGE_DESCRIPTION}" \
  --info "arch:${ARCHITECTURE}" \
  --info "license:GPL-3.0-or-later" \
  --info "origin:${PACKAGE_ORIGIN}" \
  --info "url:${PACKAGE_URL}" \
  --info "maintainer:${PACKAGE_MAINTAINER}" \
  --info "depends:ca-bundle kmod-inet-diag kmod-tun firewall4 kmod-nft-queue" \
  --info "provides:sing-box" \
  "${APK_INFO[@]}" \
  --info "provider-priority:100" \
  --script "pre-deinstall:${PROJECT}/release/config/openwrt.prerm" \
  --files "$ROOT_DIR" \
  --output "$OUTPUT_PATH"
