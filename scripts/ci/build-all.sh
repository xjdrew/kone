#!/usr/bin/env bash
set -euo pipefail

# The release caller supplies the exact version for the checked-out source.
if [[ -z "${KONE_VERSION:-}" ]]; then
  KONE_VERSION="0.4.0-dev.$(git rev-parse HEAD)"
fi
export KONE_VERSION CGO_ENABLED=0
# The fixed matrix chooses stack capabilities; ignore a native-build override.
unset KONE_BUILD_STACK
# Historical SHA qualification uses its original console-only source contract.
# A partially migrated desktop source still requires both entrypoints to build.
KONE_DESKTOP_ENTRIES=false
if [[ -d pkg/application || -d cmd/kone-cli ]]; then KONE_DESKTOP_ENTRIES=true; fi
export KONE_DESKTOP_ENTRIES
mkdir -p dist
build_target() {
  local target="$1" os="${1%%/*}" arch="${1##*/}" suffix=""
  if [[ "$os" == windows ]]; then suffix=".exe"; fi
  if [[ "$arch" == arm ]]; then
    target="$os-armv7"
    set --
  else
    target="$os-$arch"
    set -- -tags with_gvisor
  fi
  printf 'Compiling %s\n' "$target"
  local ldflags="-X main.VERSION=$KONE_VERSION"
  if [[ "$os" == windows && "$KONE_DESKTOP_ENTRIES" == true ]]; then ldflags="-H=windowsgui $ldflags"; fi
  GOOS="$os" GOARCH="$arch" GOARM=7 go build "$@" -trimpath -ldflags="$ldflags" -o "dist/kone-$target$suffix" ./cmd/kone
  if [[ "$os" != linux && "$KONE_DESKTOP_ENTRIES" == true ]]; then
    GOOS="$os" GOARCH="$arch" GOARM=7 go build "$@" -trimpath -ldflags="-X main.VERSION=$KONE_VERSION" -o "dist/kone-cli-$target$suffix" ./cmd/kone-cli
  fi
}
export -f build_target
printf '%s\n' linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 | xargs -n 1 -P 2 bash -euo pipefail -c 'build_target "$1"' _
cp LICENSE LICENSE-MIT dist/
cp -R licenses dist/
node scripts/release/build-info.mjs
