#!/usr/bin/env bash
set -euo pipefail

# The release caller supplies the exact version for the checked-out source.
if [[ -z "${KONE_VERSION:-}" ]]; then
  KONE_VERSION="0.4.0-dev.$(git rev-parse HEAD)"
fi
export KONE_VERSION CGO_ENABLED=0
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
  GOOS="$os" GOARCH="$arch" GOARM=7 go build "$@" -trimpath -ldflags="-X main.VERSION=$KONE_VERSION" -o "dist/kone-$target$suffix" ./cmd/kone
}
export -f build_target
printf '%s\n' linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 | xargs -n 1 -P 2 bash -euo pipefail -c 'build_target "$1"' _
cp LICENSE LICENSE-MIT dist/
cp -R licenses dist/
node scripts/release/build-info.mjs
