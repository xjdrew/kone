#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${KONE_MANAGEMENT_TEST_BINARY:-}" ]]; then
  # Node resolves native Windows paths correctly when invoked from Git Bash.
  KONE_MANAGEMENT_TEST_BINARY="$(node -e 'console.log(require("node:path").resolve("dist", "kone-management-ui" + (process.platform === "win32" ? ".exe" : "")))')"
  export KONE_MANAGEMENT_TEST_BINARY
  mkdir -p dist
  entry=./cmd/kone
  if [[ -d cmd/kone-cli ]]; then entry=./cmd/kone-cli; fi
  go build -tags with_gvisor -o "$KONE_MANAGEMENT_TEST_BINARY" "$entry"
fi
cd web
if [[ -f bun.lock ]]; then
  bunx playwright test --project=chromium --grep '@real' --list
  bun run test:e2e
else
  npx playwright test --project=chromium --grep '@real' --list
  npm run test:e2e
fi
node e2e/assert-real-results.mjs test-results/results.json
