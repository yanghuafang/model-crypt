#!/bin/bash

# install-deps-macos.sh — install model-crypt's build dependencies via Homebrew.
#
# OpenSSL 3, CMake, and LLVM. zlib comes from the macOS SDK and needs nothing
# installed.
#
# LLVM is here for clang-format and clang-tidy, and for those only -- the
# library is compiled with Apple clang, which is what a macOS developer
# actually has. Xcode ships no clang-format at all and its clang-tidy is not
# something you can rely on being present, so the style tools come from
# Homebrew's `llvm`. Unpinned, like everywhere else: build-env.sh points at
# whatever version is installed.
#
# openssl@3 is keg-only, which is why build-env.sh exports OPENSSL_ROOT_DIR
# rather than relying on CMake's default search: without it, FindOpenSSL picks up
# the LibreSSL headers Apple ships under the OpenSSL name, and the build fails
# later on a missing EVP_KDF_fetch.

set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "This script installs dependencies on macOS via Homebrew." >&2
  exit 1
fi

# CI's build jobs never run clang-format or clang-tidy -- linting happens on
# Linux, on one platform, so there is one authority. Homebrew's llvm is a
# multi-gigabyte download, so those jobs skip it. A developer wants it.
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

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew not found; installing it from https://brew.sh ..."
  # NONINTERACTIVE so the installer does not block on a RETURN keypress.
  NONINTERACTIVE=1 /bin/bash -c \
    "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
fi

formulae=(openssl@3 cmake shellcheck)
if [[ "${style_tools}" == true ]]; then
  formulae+=(llvm)
fi
brew install "${formulae[@]}"

echo "macOS dependencies installed:"
echo "  OpenSSL       $(brew --prefix openssl@3)"
if [[ "${style_tools}" == true ]]; then
  echo "  clang-format  $("$(brew --prefix llvm)/bin/clang-format" --version)"
fi
echo "Build with: ./build.sh"
