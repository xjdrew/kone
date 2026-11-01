#!/usr/bin/env bash
set -euo pipefail

# The output is relative to the selected module, just as go test -coverprofile.
cd -- "${1:?source directory is required}"
output="${2:?coverage output is required}"
packages="$(go list ./...)"
packages="${packages//$'\r'/}"
packages="${packages//$'\n'/,}"
if [[ -z "$packages" ]]; then
  printf '%s\n' 'go list returned no packages; refusing an empty coverage baseline' >&2
  exit 1
fi
go test -race -count=1 "-coverpkg=$packages" "-coverprofile=$output" -covermode=atomic ./...
