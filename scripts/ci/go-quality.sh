#!/usr/bin/env bash
set -euo pipefail

just --fmt --check
just --justfile "$KONE_TASK_ROOT/scripts/ci/justfile" --fmt --check
unformatted="$(gofmt -l cmd pkg test web/embed.go)"
if [[ -n "$unformatted" ]]; then
  printf 'Run just quality fmt to format:\n%s\n' "$unformatted" >&2
  exit 1
fi
go mod tidy
git diff --exit-code -- go.mod go.sum
