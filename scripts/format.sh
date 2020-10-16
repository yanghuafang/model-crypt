#!/bin/bash

# format.sh — apply the repo's source formatting rules in place.
#
# Two passes over the same file set:
#   1. clang-format, using the .clang-format at the repo root (Google style,
#      2-space indent, 80 columns, with the include-grouping rules that file
#      documents).
#   2. strip trailing whitespace, which also reaches the files clang-format does
#      not parse — the shell scripts and the CMakeLists.
#
# Modes:
#   (default)   rewrite files in place
#   --check     report what would change and exit 1 without writing; for CI
#
# Usage:
#   ./format.sh
#   ./format.sh --check

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

repo_root="${MODEL_CRYPT_REPO_DIR}"

check_only=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) check_only=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--check]" >&2
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# MODEL_CRYPT_CLANG_FORMAT wins over PATH. That is how macOS reaches Homebrew's
# LLVM without putting its clang on PATH, where it would shadow the compiler;
# build-env.sh sets it.
clang_format="${MODEL_CRYPT_CLANG_FORMAT:-clang-format}"
if ! command -v "${clang_format}" >/dev/null 2>&1; then
  echo "clang-format not found (${clang_format})." >&2
  echo "  macOS:   brew install llvm" >&2
  echo "  Ubuntu:  sudo apt install clang-format" >&2
  exit 1
fi

# == The version is reported, not pinned ==
#
# clang-format is whatever LLVM the platform provides: the distro's
# clang-format package on Linux, Homebrew's `llvm` on macOS (build-env.sh points
# MODEL_CRYPT_CLANG_FORMAT at it, since Xcode ships no clang-format at all).
#
# Nothing enforces a major. That is a deliberate trade and it has a cost worth
# knowing: different clang-format majors disagree about layout in small ways, so
# a tree formatted with one can fail --check under another, and a new release
# can decide the tree should look slightly different from how it looks today.
#
# When that happens the fix is to run ./format.sh and commit the result, not to
# pin the tool. CI runs --check on exactly one platform, so there is one
# authority at any moment rather than a quorum to satisfy.
#
# The version is printed on every run so a surprising diff has an obvious first
# question.
clang_format_version="$("${clang_format}" --version)"
echo "Using $(command -v "${clang_format}") — ${clang_format_version}"

# GNU sed takes -i; BSD sed (macOS) requires an explicit empty suffix.
if sed --version >/dev/null 2>&1; then
  sed_inplace=(sed -i)
else
  sed_inplace=(sed -i '')
fi

list_clang_format_files() {
  find "${repo_root}/src" "${repo_root}/include" "${repo_root}/tests" \
    -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' \) \
    -print
}

# version.h.in is excluded from pass 1 but included in pass 2: it contains
# @CMAKE@ substitution tokens, and clang-format has no reason to be right about a
# file that is not yet valid C++.
list_whitespace_files() {
  find "${repo_root}/src" "${repo_root}/include" "${repo_root}/tests" \
       "${repo_root}/scripts" \
    -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' \
               -o -name '*.in' -o -name '*.sh' \) \
    -print
  echo "${repo_root}/CMakeLists.txt"
}

status=0

if [[ "${check_only}" == true ]]; then
  while IFS= read -r file; do
    if ! "${clang_format}" "${file}" | diff -q - "${file}" >/dev/null 2>&1; then
      echo "needs clang-format: ${file#"${repo_root}"/}"
      status=1
    fi
  done < <(list_clang_format_files | sort)

  while IFS= read -r file; do
    if grep -qE '[[:blank:]]+$' "${file}"; then
      echo "trailing whitespace:  ${file#"${repo_root}"/}"
      status=1
    fi
  done < <(list_whitespace_files | sort)

  if [[ "${status}" -eq 0 ]]; then
    echo "All files are formatted."
  fi
  exit "${status}"
fi

formatted=0
while IFS= read -r file; do
  "${clang_format}" -i "${file}" || exit 1
  formatted=$((formatted + 1))
done < <(list_clang_format_files | sort)

# After clang-format, so this pass has the final say and also reaches the shell
# scripts and CMakeLists.
stripped=0
while IFS= read -r file; do
  if grep -qE '[[:blank:]]+$' "${file}"; then
    "${sed_inplace[@]}" -E 's/[[:blank:]]+$//' "${file}" || exit 1
    stripped=$((stripped + 1))
  fi
done < <(list_whitespace_files | sort)

echo "clang-format applied to ${formatted} file(s); trailing whitespace stripped from ${stripped}."
