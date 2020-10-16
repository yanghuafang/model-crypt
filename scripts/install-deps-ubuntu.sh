#!/bin/bash

# install-deps-ubuntu.sh — install model-crypt's build dependencies via apt.
#
# No release is named and no version is pinned: the packages below are whatever
# the running Ubuntu currently ships, which is the same thing CI gets from
# `ubuntu-latest`. Nothing comes from a PPA -- an unexpected OpenSSL is exactly
# the thing a cryptographic library should not silently acquire.
#
# The build's own floors are OpenSSL 1.1.1 and CMake 3.16, checked below. Every
# Ubuntu still receiving updates clears both, so those checks are a diagnostic
# for someone on something unusually old rather than a supported-release list.
#
# == clang-format and clang-tidy come from LLVM ==
#
# Both are installed here, from the distro's LLVM packages. They are not pinned
# to a major. That means a clang-format release can decide the tree should look
# slightly different; when that happens the fix is to run ./format.sh and commit
# the result, not to pin the tool.
#
# == sudo ==
#
# Used when present and skipped when already root, so the same script works on a
# developer's machine and in a bare container.

set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "This script installs dependencies on Ubuntu via apt." >&2
  exit 1
fi

# Jobs that only compile and test skip the style tools; see install-deps.sh.
# Unlike macOS, nothing else here depends on them -- llvm stays, because
# coverage.sh needs llvm-profdata and llvm-cov out of it.
style_tools=true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-style-tools) style_tools=false; shift ;;
    -h|--help)
      echo "Usage: $0 [--no-style-tools]" >&2
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

sudo_cmd=()
if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    sudo_cmd=(sudo)
  else
    echo "Not root and sudo is not available; cannot install packages." >&2
    exit 1
  fi
fi

# noninteractive because tzdata prompts for a timezone on a bare image and the
# run then hangs until the job times out.
export DEBIAN_FRONTEND=noninteractive

"${sudo_cmd[@]}" apt-get update

packages=(
  build-essential
  ca-certificates
  clang
  cmake
  git
  libssl-dev
  llvm
  pkg-config
  shellcheck
  valgrind
  zlib1g-dev
)
if [[ "${style_tools}" == true ]]; then
  packages+=(clang-format clang-tidy)
fi

"${sudo_cmd[@]}" apt-get install -y --no-install-recommends "${packages[@]}"

# Verified rather than assumed. 1.1.1 is the floor: it is the first supported
# release with EVP_PBE_scrypt reachable as this library uses it. Failing here
# names the problem; failing in CMake names a version string in a FindOpenSSL
# error.
openssl_version="$(openssl version | awk '{print $2}')"
case "${openssl_version}" in
  1.1.1*|3.*|[4-9].*) ;;
  *)
    echo "model-crypt needs OpenSSL 1.1.1 or newer; found ${openssl_version}." >&2
    exit 1
    ;;
esac

# CMake 3.16 is the floor the build is written against, checked for the same
# reason: a too-old cmake fails on a generator expression deep in the test
# target, which reads like a bug in this project.
cmake_version="$(cmake --version | head -1 | awk '{print $3}')"
cmake_major="${cmake_version%%.*}"
cmake_rest="${cmake_version#*.}"
cmake_minor="${cmake_rest%%.*}"
if [[ "${cmake_major}" -lt 3 ]] || {
     [[ "${cmake_major}" -eq 3 ]] && [[ "${cmake_minor}" -lt 16 ]]
   }; then
  echo "model-crypt needs CMake 3.16 or newer; found ${cmake_version}." >&2
  exit 1
fi

echo "Ubuntu dependencies installed:"
echo "  OpenSSL       ${openssl_version}"
echo "  CMake         ${cmake_version}"
echo "  compiler      $(cc --version | head -1)"
if [[ "${style_tools}" == true ]]; then
  echo "  clang-format  $(clang-format --version)"
fi
echo
echo "Build with: ./build.sh"
