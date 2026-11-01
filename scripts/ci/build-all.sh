#!/usr/bin/env bash
set -euo pipefail

# The release caller supplies the exact version for the checked-out source.
if [[ -z "${KONE_VERSION:-}" ]]; then
  if [[ -f scripts/release/version-policy.mjs ]]; then
    KONE_VERSION="$(node scripts/release/version-policy.mjs --format version)"
  else
    KONE_VERSION="0.4.0-dev.$(git rev-parse HEAD)"
  fi
fi
export KONE_VERSION CGO_ENABLED=0
# The fixed matrix chooses stack capabilities; ignore a native-build override.
unset KONE_BUILD_STACK
# Historical SHA qualification uses its original console-only source contract.
# A partially migrated desktop source still requires both entrypoints to build.
KONE_DESKTOP_ENTRIES=false
if [[ -d pkg/application || -d cmd/kone-cli ]]; then KONE_DESKTOP_ENTRIES=true; fi
export KONE_DESKTOP_ENTRIES
KONE_FULL_STACKS=false
if [[ -f pkg/kone/stack_modes.go ]]; then KONE_FULL_STACKS=true; fi
export KONE_FULL_STACKS
KONE_BUILD_TARGETS="$(node --input-type=module -e '
  import { existsSync } from "node:fs";
  import { targets } from "./scripts/release/model.mjs";
  const tools = existsSync("scripts/release/targets.mjs") ? await import("./scripts/release/targets.mjs") : {};
  let selected = process.env.KONE_BUILD_TARGETS ? process.env.KONE_BUILD_TARGETS.split(",") : targets;
  if (typeof tools.selectedTargets === "function") selected = tools.selectedTargets(selected);
  else {
    if (process.env.KONE_FULL_STACKS === "true") throw new Error("Runtime-stack source is missing target selection support");
    if (!Array.isArray(selected) || !selected.length || new Set(selected).size !== selected.length || selected.some(target => !targets.includes(target)))
      throw new Error("Select unique supported historical targets");
  }
  console.log(selected.join(","));
')"
export KONE_BUILD_TARGETS
mkdir -p dist
build_target() {
  local target="$1" os="${1%%-*}" arch="${1#*-}" suffix=""
  if [[ "$os" == windows ]]; then suffix=".exe"; fi
  if [[ "$arch" == armv7 && "$KONE_FULL_STACKS" != true ]]; then
    arch=arm
    set --
  else
    if [[ "$arch" == armv7 ]]; then arch=arm; fi
    set -- -tags with_gvisor
  fi
  printf 'Compiling %s\n' "$target"
  local ldflags="-X main.VERSION=$KONE_VERSION"
  if [[ "$os" == windows && "$KONE_DESKTOP_ENTRIES" == true ]]; then ldflags="-H=windowsgui $ldflags"; fi
  GOOS="$os" GOARCH="$arch" GOARM=7 go build "$@" -trimpath -ldflags="$ldflags" -o "dist/kone-$target$suffix" ./cmd/kone
  if [[ "$os" != linux && "$KONE_DESKTOP_ENTRIES" == true ]]; then
    GOOS="$os" GOARCH="$arch" GOARM=7 go build "$@" -trimpath -ldflags="-X main.VERSION=$KONE_VERSION" -o "dist/kone-cli-$target$suffix" ./cmd/kone-cli
  fi
}
export -f build_target
printf '%s\n' "${KONE_BUILD_TARGETS//,/$'\n'}" | xargs -n 1 -P 2 bash -euo pipefail -c 'build_target "$1"' _
cp LICENSE LICENSE-MIT dist/
cp -R licenses dist/
if grep -q -- '--targets' scripts/release/build-info.mjs; then
  node scripts/release/build-info.mjs --targets "$KONE_BUILD_TARGETS"
else
  # Older metadata writers always describe their complete default matrix.
  expected="$(node --input-type=module -e 'import { targets } from "./scripts/release/model.mjs"; console.log(targets.join(","))')"
  if [[ "$KONE_BUILD_TARGETS" != "$expected" ]]; then
    echo 'Historical build metadata cannot describe a non-default target selection.' >&2
    exit 1
  fi
  node scripts/release/build-info.mjs
fi
