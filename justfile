# Daily development entrypoints. Windows requires Git Bash on PATH.
set minimum-version := '1.59.0'
set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

export KONE_TASK_ROOT := justfile_directory()

# Comprehensive CI, native acceptance and advanced maintenance.
mod ci 'scripts/ci/justfile'

# Show daily tasks without building or changing system networking.
default:
    @just --justfile "$KONE_TASK_ROOT/justfile" --list

# Prepare the local development environment.
init *args:
    node "$KONE_TASK_ROOT/scripts/tasks/init.mjs" "$@"

# Start desktop management by default, or use the frontend development server.
dev *args:
    node "$KONE_TASK_ROOT/scripts/tasks/dev.mjs" "$@"

# Run local quick checks; full, fmt, vet and benchmark are explicit modes.
quality *args:
    node "$KONE_TASK_ROOT/scripts/tasks/quality.mjs" "$@"

# Build all runtime stacks for the current platform.
build *args:
    node "$KONE_TASK_ROOT/scripts/tasks/build.mjs" native "$@"

# Cross-build all supported release targets.
build-all *args:
    node "$KONE_TASK_ROOT/scripts/tasks/build.mjs" all "$@"

# Build an unsigned package for the current platform.
package *args:
    node "$KONE_TASK_ROOT/scripts/tasks/package.mjs" native "$@"

# Build unsigned packages for every supported target.
package-all *args:
    node "$KONE_TASK_ROOT/scripts/tasks/package.mjs" all "$@"
