#!/usr/bin/env bash
set -euo pipefail

source_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kone-source.XXXXXX")"
git archive HEAD | tar -xf - -C "$source_dir"
go mod vendor -o "$source_dir/vendor"
cp dist/build-info.json "$source_dir/BUILD-INFO.json"
tar -czf dist/kone-source.tar.gz -C "$source_dir" .
