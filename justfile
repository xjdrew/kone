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
init:
    node "$KONE_TASK_ROOT/scripts/tasks/init.mjs"

# Start desktop management by default, or use the frontend development server.
dev mode='desktop':
    node "$KONE_TASK_ROOT/scripts/tasks/dev.mjs" "$1"

# Run local quick checks; full, fmt, vet and benchmark are explicit modes.
quality mode='quick':
    node "$KONE_TASK_ROOT/scripts/tasks/quality.mjs" "$1"

# Build only the current platform, using system or mixed stack.
build stack='system':
    node "$KONE_TASK_ROOT/scripts/tasks/build.mjs" native "$1"

# Cross-build all supported release targets.
build-all:
    node "$KONE_TASK_ROOT/scripts/tasks/build.mjs" all

# Build an unsigned package for the current platform.
package stack='system':
    node "$KONE_TASK_ROOT/scripts/tasks/package.mjs" native "$1"

# Build unsigned packages for every supported target.
package-all:
    node "$KONE_TASK_ROOT/scripts/tasks/package.mjs" all
