#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${KONE_MANAGEMENT_TEST_BINARY:-}" ]]; then
  # Node resolves native Windows paths correctly when invoked from Git Bash.
  KONE_MANAGEMENT_TEST_BINARY="$(node -e 'console.log(require("node:path").resolve("dist", "kone-management-ui" + (process.platform === "win32" ? ".exe" : "")))')"
  export KONE_MANAGEMENT_TEST_BINARY
  mkdir -p dist
  entry=./cmd/kone
  if [[ -d cmd/kone-cli ]]; then entry=./cmd/kone-cli; fi
  go build -o "$KONE_MANAGEMENT_TEST_BINARY" "$entry"
fi
cd web
npx playwright test --project=chromium-1440x900 --grep '@real' --list
npm run test:e2e
node e2e/assert-real-results.mjs test-results/results.json
