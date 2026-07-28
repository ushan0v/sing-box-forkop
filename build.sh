#!/usr/bin/env bash
set -euo pipefail

PROJECT=$(cd "$(dirname "$0")" && pwd)
CRONET_GO_PATH="${CRONET_GO_PATH:-$HOME/.cache/sing-box-forkop/cronet-go}"
TARGETS=(amd64 arm64 386 armv7 mipsle)

usage() {
  cat <<'EOF'
Usage: ./build.sh [all|amd64|arm64|386|armv7|mipsle] [version]

Builds normal and UPX-compressed OpenWrt IPK/APK packages. If version is
omitted, it is derived as <sing-box>-extended-<extended>-f<forkop>.
EOF
}

version_from_git() {
  local exact base count version fork_version
  if exact=$(git -C "$PROJECT" describe --tags --exact-match --match 'v*-extended-*-f*' 2>/dev/null); then
    printf '%s\n' "${exact#v}"
    return
  fi
  base=$(git -C "$PROJECT" describe --tags --abbrev=0 --match 'v*')
  count=$(git -C "$PROJECT" rev-list --count "$base..HEAD")
  case "$base" in
    v*-extended-*-f*)
      version=${base#v}
      fork_version=${version##*-f}
      printf '%s-f%s\n' "${version%-f*}" "$((fork_version + count))"
      ;;
    v*-extended-*)
      version=${base#v}
      printf '%s-f%s\n' "$version" "$count"
      ;;
    *)
      echo "Cannot derive Forkop version from tag: $base" >&2
      exit 1
      ;;
  esac
}

require_tools() {
  local tool tools=(go git npm fpm ar tar install sha256sum)
  [ "$PACKAGE_FORMAT" = ipk ] || tools+=(apk)
  [ "$BUILD_COMPRESSED" = 0 ] || tools+=(upx)
  for tool in "${tools[@]}"; do
    command -v "$tool" >/dev/null || {
      echo "Missing required tool: $tool" >&2
      exit 1
    }
  done
}

build_admin_panel() {
  (cd "$PROJECT/service/admin_panel/web" && npm ci --no-audit --no-fund && npm run build)
  (cd "$PROJECT" && go run ./cmd/internal/admin_panel_pack -dir service/admin_panel/dist)
}

ensure_cronet_go() {
  local revision marker keyring
  revision=$(tr -d '[:space:]' < "$PROJECT/.github/CRONET_GO_VERSION")
  if [ ! -d "$CRONET_GO_PATH/.git" ]; then
    mkdir -p "$CRONET_GO_PATH"
    git -C "$CRONET_GO_PATH" init -q
    git -C "$CRONET_GO_PATH" remote add origin https://github.com/sagernet/cronet-go.git
  fi
  if [ "$(git -C "$CRONET_GO_PATH" rev-parse HEAD 2>/dev/null || true)" != "$revision" ]; then
    git -C "$CRONET_GO_PATH" fetch --depth=1 origin "$revision"
    git -C "$CRONET_GO_PATH" checkout -q --detach FETCH_HEAD
  fi
  git -C "$CRONET_GO_PATH" submodule update --init --recursive --depth=1

  marker="$CRONET_GO_PATH/.forkop-keyring-$revision"
  keyring="$CRONET_GO_PATH/naiveproxy/src/build/linux/sysroot_scripts/keyring.gpg"
  if [ ! -e "$marker" ]; then
    rm -f "$keyring"
    (cd "$CRONET_GO_PATH" && GPG_TTY=/dev/null ./naiveproxy/src/build/linux/sysroot_scripts/generate_keyring.sh)
    touch "$marker"
  fi
}

configure_target() {
  case "$1" in
    amd64)
      GOARCH=amd64; GOAMD64=v1; NAIVE_ARCH=amd64
      OPENWRT_ARCHITECTURES="x86_64"
      ;;
    arm64)
      GOARCH=arm64; NAIVE_ARCH=arm64
      OPENWRT_ARCHITECTURES="aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76 aarch64_generic"
      ;;
    386)
      GOARCH=386; GO386=sse2; NAIVE_ARCH=386
      OPENWRT_ARCHITECTURES="i386_pentium4"
      ;;
    armv7)
      GOARCH=arm; GOARM=7; NAIVE_ARCH=arm
      OPENWRT_ARCHITECTURES="arm_cortex-a5_vfpv4 arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a9_neon arm_cortex-a9_vfpv3-d16 arm_cortex-a15_neon-vfpv4"
      ;;
    mipsle)
      GOARCH=mipsle; GOMIPS=softfloat; NAIVE_ARCH=mipsle
      OPENWRT_ARCHITECTURES="mipsel_24kc mipsel_74kc mipsel_mips32"
      ;;
    *)
      echo "Unknown target: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
}

load_naive_environment() {
  local line
  (cd "$CRONET_GO_PATH" && go run ./cmd/build-naive --target="linux/$NAIVE_ARCH" --libc=musl download-toolchain)
  while IFS= read -r line; do
    if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      declare -gx "$line"
    fi
  done < <(cd "$CRONET_GO_PATH" && go run ./cmd/build-naive --target="linux/$NAIVE_ARCH" --libc=musl env)
}

build_target() {
  local target="$1" build_dir binary compressed architecture tags ldflags
  local -a go_env
  unset GOAMD64 GO386 GOARM GOMIPS
  configure_target "$target"
  if [ -n "${FORKOP_OPENWRT_ARCHITECTURE:-}" ]; then
    OPENWRT_ARCHITECTURES="$FORKOP_OPENWRT_ARCHITECTURE"
  fi
  load_naive_environment

  build_dir="$PROJECT/dist/build/$target"
  binary="$build_dir/sing-box"
  compressed="$build_dir/sing-box-compressed"
  mkdir -p "$build_dir"

  if [ "$target" = mipsle ]; then
    # modernc SQLite used by with_manager has no mipsle port.
    tags="$(tr -d '[:space:]' < "$PROJECT/release/DEFAULT_BUILD_TAGS"),with_musl"
  else
    tags="$(tr -d '[:space:]' < "$PROJECT/release/DEFAULT_BUILD_TAGS_DOCKER")"
  fi
  ldflags="-X github.com/sagernet/sing-box/constant.Version=$VERSION $(tr '\n' ' ' < "$PROJECT/release/LDFLAGS") -s -w -buildid="

  echo "Building $target ($VERSION)"
  go_env=(
    CGO_ENABLED=1
    GOOS=linux
    "GOARCH=$GOARCH"
  )
  [ -z "${GOAMD64:-}" ] || go_env+=("GOAMD64=$GOAMD64")
  [ -z "${GO386:-}" ] || go_env+=("GO386=$GO386")
  [ -z "${GOARM:-}" ] || go_env+=("GOARM=$GOARM")
  [ -z "${GOMIPS:-}" ] || go_env+=("GOMIPS=$GOMIPS")
  env "${go_env[@]}" go build -trimpath -tags "$tags" -ldflags "$ldflags" -o "$binary" ./cmd/sing-box

  if [ "$BUILD_COMPRESSED" = 1 ]; then
    cp "$binary" "$compressed"
    upx --best --lzma "$compressed"
  fi
  for architecture in $OPENWRT_ARCHITECTURES; do
    bash "$PROJECT/.github/build_forkop_openwrt_packages.sh" \
      "$VERSION" "$architecture" "$binary" \
      sing-box-forkop sing-box-forkop-compressed
    if [ "$BUILD_COMPRESSED" = 1 ]; then
      bash "$PROJECT/.github/build_forkop_openwrt_packages.sh" \
        "$VERSION" "$architecture" "$compressed" \
        sing-box-forkop-compressed sing-box-forkop
    fi
  done
}

case "${1:-all}" in
  -h|--help)
    usage
    exit 0
    ;;
  --list-targets)
    printf '%s\n' "${TARGETS[@]}"
    exit 0
    ;;
esac

SELECTED_TARGET="${1:-all}"
VERSION="${2:-$(version_from_git)}"
BUILD_COMPRESSED="${FORKOP_BUILD_COMPRESSED:-1}"
PACKAGE_FORMAT="${FORKOP_PACKAGE_FORMAT:-all}"
if [ "$SELECTED_TARGET" != all ]; then
  case " ${TARGETS[*]} " in
    *" $SELECTED_TARGET "*) ;;
    *)
      echo "Unknown target: $SELECTED_TARGET" >&2
      usage >&2
      exit 2
      ;;
  esac
fi
if [[ ! "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+~-]*$ ]]; then
  echo "Invalid version: $VERSION" >&2
  exit 2
fi
if [[ ! "$BUILD_COMPRESSED" =~ ^[01]$ ]]; then
  echo "FORKOP_BUILD_COMPRESSED must be 0 or 1" >&2
  exit 2
fi
if [[ ! "$PACKAGE_FORMAT" =~ ^(all|ipk|apk)$ ]]; then
  echo "FORKOP_PACKAGE_FORMAT must be all, ipk, or apk" >&2
  exit 2
fi

require_tools
build_admin_panel
ensure_cronet_go

if [ "$SELECTED_TARGET" = all ]; then
  for target in "${TARGETS[@]}"; do
    build_target "$target"
  done
else
  build_target "$SELECTED_TARGET"
fi
