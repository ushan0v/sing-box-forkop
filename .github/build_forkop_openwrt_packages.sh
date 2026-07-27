#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "Usage: $0 <version> <openwrt-architecture> <binary> <package-name> <replaced-package>" >&2
  exit 2
fi

VERSION="$1"
ARCHITECTURE="$2"
BINARY_PATH="$3"
PACKAGE_NAME="$4"
REPLACED_PACKAGE="$5"

PROJECT=$(cd "$(dirname "$0")/.." && pwd)
DIST="$PROJECT/dist"
PKG_VERSION="$VERSION"
DESCRIPTION="The universal proxy platform for Forkop."

mkdir -p "$DIST"
FPM_DIR=$(mktemp -d)
TMP_DEB=$(mktemp -p "$DIST" _openwrt_XXXXXX.deb)
rm -f "$TMP_DEB"
trap 'rm -rf "$FPM_DIR" "$TMP_DEB"' EXIT

VERSION_FILE="$FPM_DIR/version"
printf '%s\n' "$VERSION" > "$VERSION_FILE"

{
  printf '%s\n' \
    '--conflicts sing-box-extended' \
    "--conflicts ${REPLACED_PACKAGE}" \
    '--replaces sing-box-extended' \
    "--replaces ${REPLACED_PACKAGE}"
  sed \
    -e "s|^--name .*|--name ${PACKAGE_NAME}|" \
    -e "s|^--description .*|--description \"${DESCRIPTION}\"|" \
    -e 's|^--url .*|--url "https://github.com/ushan0v/sing-box-forkop"|' \
    -e 's|^--maintainer .*|--maintainer "ushan0v"|' \
    -e "s|release/|$PROJECT/release/|g" \
    -e "s|^LICENSE|$PROJECT/LICENSE|" \
    "$PROJECT/.fpm_openwrt"
} > "$FPM_DIR/.fpm"

(cd "$FPM_DIR" && fpm -t deb \
  -v "$PKG_VERSION" \
  -p "$TMP_DEB" \
  --architecture all \
  "$BINARY_PATH=/usr/bin/sing-box" \
  "$VERSION_FILE=/usr/share/sing-box-forkop/version")

ASSET_NAME="sing-box-${VERSION}-openwrt-${ARCHITECTURE}"
if [ "$PACKAGE_NAME" = "sing-box-forkop-compressed" ]; then
  ASSET_NAME="${ASSET_NAME}-compressed"
fi
IPK_PATH="$DIST/${ASSET_NAME}.ipk"
APK_PATH="$DIST/${ASSET_NAME}.apk"

bash "$PROJECT/.github/deb2ipk.sh" "$ARCHITECTURE" "$TMP_DEB" "$IPK_PATH"
bash "$PROJECT/.github/build_openwrt_apk.sh" \
  "$ARCHITECTURE" \
  "$VERSION" \
  "$BINARY_PATH" \
  "$APK_PATH" \
  "$PACKAGE_NAME" \
  "$DESCRIPTION" \
  "$PACKAGE_NAME" \
  "https://github.com/ushan0v/sing-box-forkop" \
  "ushan0v" \
  "sing-box sing-box-extended ${REPLACED_PACKAGE}"

echo "Built: $(basename "$IPK_PATH")"
echo "Built: $(basename "$APK_PATH")"
