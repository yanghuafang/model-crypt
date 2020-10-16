#!/bin/bash

# install-deps.sh — install build dependencies for whichever OS this is.
#
# A dispatcher, so nothing that calls it has to know which platform it is on.
# Before this existed every CI job carried a pair of steps and an `if` on the
# runner's OS; picking a package manager is build-system logic, not CI logic.
#
# Arguments are passed through to the platform script:
#
#   ./install-deps.sh                    everything
#   ./install-deps.sh --no-style-tools   skip clang-format and clang-tidy
#
# --no-style-tools is for jobs that only compile and test. What it drops differs
# by platform because the packaging does: on Ubuntu clang-format and clang-tidy
# are their own packages, while on macOS both come from Homebrew's llvm, which
# is a multi-gigabyte formula. Neither platform drops anything the build itself
# needs.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

case "$(uname -s)" in
  Linux)  exec "${script_dir}/install-deps-ubuntu.sh" "$@" ;;
  Darwin) exec "${script_dir}/install-deps-macos.sh" "$@" ;;
  *)
    echo "Unsupported OS: $(uname -s). Supported: macOS and Linux." >&2
    exit 1
    ;;
esac
