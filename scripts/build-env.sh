#!/bin/bash

# build-env.sh — toolchain and dependency paths for every other script here.
#
# Sourced, never executed. It locates OpenSSL 3 and exports MODEL_CRYPT_BUILD_DIR,
# then leaves the caller's shell able to run cmake directly.
#
# No `set -euo pipefail` here, unlike every script that runs directly: shell
# options are not scoped to a file, so setting them in something sourced changes
# the caller's shell too. Each caller sets its own, and this file runs under
# whichever one sourced it.
#
# OpenSSL needs finding on macOS only: Apple ships LibreSSL headers under the
# name `openssl`, and a build that finds them fails on a missing symbol that
# reads like an installation problem rather than a "this is not OpenSSL" one.

model_crypt_fail_env() {
  echo "$1" >&2
  return 1
}

case "$(uname -s)" in
  Darwin)
    if ! command -v brew >/dev/null 2>&1; then
      model_crypt_fail_env "Homebrew is required on macOS. See docs/Install.md."
      return 1
    fi

    if [[ -z "${OPENSSL_ROOT_DIR:-}" ]]; then
      OPENSSL_ROOT_DIR="$(brew --prefix openssl@3 2>/dev/null)" || {
        model_crypt_fail_env "Install OpenSSL 3: brew install openssl@3"
        return 1
      }
    fi
    export OPENSSL_ROOT_DIR

    # Homebrew's LLVM supplies clang-format and clang-tidy; Xcode ships no
    # clang-format at all. Unpinned -- format.sh reports the version it used.
    #
    # Named individually, NOT put on PATH. Prepending llvm/bin also shadows
    # `clang` and `clang++`, so CMake's default search or a CI job setting
    # CXX=clang++ would compile with Homebrew LLVM -- whose libc++ disagrees
    # with the macOS SDK's C headers about include order, killing every
    # translation unit on:
    #
    #   <cstddef> tried including <stddef.h> but didn't find libc++'s <stddef.h>
    #
    # An already-set variable wins, so a developer can point these elsewhere.
    brew_llvm="$(brew --prefix llvm 2>/dev/null)" || brew_llvm=""
    if [[ -n "${brew_llvm}" && -x "${brew_llvm}/bin/clang-format" ]]; then
      export MODEL_CRYPT_CLANG_FORMAT="${MODEL_CRYPT_CLANG_FORMAT:-${brew_llvm}/bin/clang-format}"
      export MODEL_CRYPT_CLANG_TIDY="${MODEL_CRYPT_CLANG_TIDY:-${brew_llvm}/bin/clang-tidy}"
    fi
    unset brew_llvm
    ;;
  Linux)
    # Nothing to locate: libssl-dev puts OpenSSL where CMake's FindOpenSSL
    # looks, and clang-format and clang-tidy are on PATH from the distro's LLVM
    # packages. No release is checked here -- install-deps-ubuntu.sh verifies
    # the two versions that actually matter (OpenSSL and CMake) and says so.
    :
    ;;
  *)
    model_crypt_fail_env "Unsupported OS: $(uname -s). Supported: macOS and Linux."
    return 1
    ;;
esac

# Build output goes to a sibling of the repo, so `git status` after a build is
# empty. BASH_SOURCE rather than $0, since this file is sourced.
model_crypt_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_CRYPT_REPO_DIR="$(cd "${model_crypt_env_dir}/.." && pwd)"
export MODEL_CRYPT_REPO_DIR
export MODEL_CRYPT_BUILD_DIR="${MODEL_CRYPT_BUILD_DIR:-$(cd "${model_crypt_env_dir}/../.." && pwd)/model-crypt-build}"

# Where a named preset builds. This mirrors "binaryDir" on the `base` preset in
# CMakePresets.json and has to be changed with it: CMake offers no way to ask
# for a preset's directory without configuring it first.
#
# Every preset gets its own tree, which is why nothing here tracks which flags a
# directory was built with any more -- an ASan build can no longer land on top
# of an uninstrumented one.
model_crypt_preset_dir() {
  echo "${MODEL_CRYPT_REPO_DIR}/../model-crypt-build/$1"
}

# One place to compute the job count, since four scripts want it.
model_crypt_jobs() {
  if [[ -n "${MODEL_CRYPT_BUILD_JOBS:-}" ]]; then
    echo "${MODEL_CRYPT_BUILD_JOBS}"
  elif command -v nproc >/dev/null 2>&1; then
    nproc
  elif [[ "$(uname -s)" == Darwin ]]; then
    sysctl -n hw.logicalcpu
  else
    getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4
  fi
}
