#!/bin/sh
# Portable installer: files only, no services, routes, DNS, firewall or trust changes.
set -eu
KONE_PREFIX=${1:-"$HOME/.local"}
KONE_SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$KONE_PREFIX/bin" "$KONE_PREFIX/share/kone/licenses"
install -m 755 "$KONE_SOURCE/kone" "$KONE_PREFIX/bin/kone"
cp "$KONE_SOURCE/LICENSE" "$KONE_SOURCE/LICENSE-MIT" "$KONE_SOURCE/build-info.json" "$KONE_PREFIX/share/kone/"
cp -R "$KONE_SOURCE/licenses/." "$KONE_PREFIX/share/kone/licenses/"
printf 'Installed KONE in %s/bin. Add it to PATH if needed. Settings were not changed.\n' "$KONE_PREFIX"
