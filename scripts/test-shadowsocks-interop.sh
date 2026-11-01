#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
  echo 'Official server interoperability runs only in disposable CI containers.' >&2
  exit 2
fi

image='ghcr.io/shadowsocks/ssserver-rust@sha256:22240c07d8ce3a36421ede770bd775dcc5fc56d5d829943196957b05452dc36f'
container="kone-ss-interop-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
directory="${RUNNER_TEMP:?}/kone-shadowsocks-interop"
mkdir -p "$directory"

cleanup() {
  docker logs "$container" > "$directory/server.log" 2>&1 || true
  docker cp "$container:/tmp/shadowsocks-interop.json" "$directory/results.json" 2>/dev/null || true
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull --platform linux/amd64 "$image"
docker image inspect "$image" > "$directory/image.json"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$directory/interop.test" ./test/integration
docker run -d --name "$container" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e TOKIO_WORKER_THREADS=2 \
  --mount "type=bind,source=$PWD/test/fixtures/shadowsocks-rust.json,target=/ci/config.json,readonly" \
  --mount "type=bind,source=$directory/interop.test,target=/ci/interop.test,readonly" \
  --entrypoint /usr/bin/ssserver "$image" -c /ci/config.json --log-without-time

docker exec -e GITHUB_ACTIONS=true -e GOMAXPROCS=2 -e KONE_SS_OFFICIAL_TEST=1 \
  -e "KONE_SS_OFFICIAL_IMAGE=$image" "$container" \
  /ci/interop.test -test.run '^TestOfficialShadowsocksRustInterop$' -test.v -test.timeout 90s \
  | tee "$directory/test.log"
