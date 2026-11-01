#!/usr/bin/env bash
set -euo pipefail

just --fmt --check
unformatted="$(gofmt -l cmd pkg test web/embed.go)"
if [[ -n "$unformatted" ]]; then
  printf 'Run just fmt to format:\n%s\n' "$unformatted" >&2
  exit 1
fi
go mod tidy
git diff --exit-code -- go.mod go.sum
