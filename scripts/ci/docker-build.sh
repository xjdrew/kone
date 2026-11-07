#!/usr/bin/env bash
set -euo pipefail

if [[ "${KONE_DOCKER_CACHE:-}" != 1 ]]; then
  exec docker build -f deploy/docker/Dockerfile -t kone:ci .
fi
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux || "${RUNNER_TEMP:-}" != /* || ! -d "$RUNNER_TEMP" ]]; then
  echo 'Container caching requires a disposable Linux GitHub runner and RUNNER_TEMP.' >&2
  exit 2
fi

cache="$RUNNER_TEMP/kone-buildkit-cache"
next="$(mktemp -d "$RUNNER_TEMP/kone-buildkit-export.XXXXXX")"
builder="kone-ci-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
cleanup() {
  docker buildx rm "$builder" >/dev/null 2>&1 || true
  rm -rf -- "$next"
}
trap cleanup EXIT
docker buildx create --name "$builder" --driver docker-container
arguments=()
if [[ -f "$cache/index.json" ]]; then
  arguments+=(--cache-from "type=local,src=$cache")
fi
docker buildx build --builder "$builder" --load --progress plain \
  "${arguments[@]}" --cache-to "type=local,dest=$next,mode=max" \
  -f deploy/docker/Dockerfile -t kone:ci .
# Replace only our disposable cache after a successful build/export, so old
# unreferenced BuildKit blobs do not accumulate in the next Actions cache.
rm -rf -- "$cache"
mv -- "$next" "$cache"
