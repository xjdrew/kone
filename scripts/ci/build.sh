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
go build "$@" -trimpath -ldflags="-X main.VERSION=$version" -o "$output" ./cmd/kone
