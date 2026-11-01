#!/usr/bin/env bash
set -euo pipefail

: "${KONE_TASK_ROOT:?task entrypoint root is required}"
sha="$(git rev-parse HEAD)"
export KONE_VERSION="${KONE_VERSION:-0.4.0-dev.$sha}"
bash "$KONE_TASK_ROOT/scripts/ci/build-all.sh"
export RELEASE_INPUT=dist
export RELEASE_SHA="$sha"
export RELEASE_VERSION="$KONE_VERSION"
# This creates and checks local packages; it never invokes the release publisher.
node scripts/release/package.mjs
