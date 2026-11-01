#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required for the CI browser fixture}"
: "${GITHUB_ENV:?GITHUB_ENV is required to publish the fixture path}"
entry=./cmd/kone
if [[ -d cmd/kone-cli ]]; then entry=./cmd/kone-cli; fi
go build -o "$RUNNER_TEMP/kone-management-ui" "$entry"
printf 'KONE_MANAGEMENT_TEST_BINARY=%s/kone-management-ui\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
