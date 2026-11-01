#!/usr/bin/env bash
set -euo pipefail

stack="${1:?stack is required}"
output="${2:?output is required}"
case "$stack" in
  system) set -- ;;
  mixed) set -- -tags with_gvisor ;;
  *) printf '%s\n' 'Build stack must be system or mixed.' >&2; exit 2 ;;
esac
version="${KONE_VERSION:-0.4.0-dev.$(git rev-parse HEAD)}"
mkdir -p "$(dirname -- "$output")"
os="${GOOS:-$(go env GOOS)}"
ldflags="-X main.VERSION=$version"
desktop_entries=false
if [[ -d pkg/application || -d cmd/kone-cli ]]; then desktop_entries=true; fi
if [[ "$os" == windows && "$desktop_entries" == true ]]; then ldflags="-H=windowsgui $ldflags"; fi
go build "$@" -trimpath -ldflags="$ldflags" -o "$output" ./cmd/kone
if [[ "$os" != linux && "$desktop_entries" == true ]]; then
  cli="$(dirname -- "$output")/kone-cli"
  if [[ "$os" == windows ]]; then cli="$cli.exe"; fi
  go build "$@" -trimpath -ldflags="-X main.VERSION=$version" -o "$cli" ./cmd/kone-cli
fi
