#!/bin/bash

# check-valgrind.sh — run the suite under Valgrind's memcheck.
#
# Not redundant with ASan: ASan instruments at compile time and cannot see
# inside OpenSSL or zlib, so a bad length passed *into* them is invisible to it.
# Every buffer handed to EVP_CipherUpdate or inflate() is sized by arithmetic in
# format.cc, and Valgrind checks those calls from the outside.
#
# Valgrind also reports reads of uninitialized memory, which ASan does not
# (MemorySanitizer does, but it needs every dependency rebuilt instrumented,
# including libstdc++ and OpenSSL — a substantial amount of work for a third
# opinion on the same code).
#
# Linux only: Valgrind's macOS support has not kept up with recent releases, and
# on Apple Silicon it does not run at all. So this is a Linux CI job and a Linux
# developer tool, and the ASan job is what covers macOS.
#
# The build must be UNinstrumented. Valgrind and ASan both replace the allocator
# and the combination reports nonsense; ./build.sh --debug is the right input.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

if [[ "$(uname -s)" != Linux ]]; then
  echo "Valgrind is only supported on Linux here; use ./build.sh --asan --ubsan instead." >&2
  exit 0
fi

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind not found. On Ubuntu: sudo apt install valgrind" >&2
  exit 1
fi

# Which tree to check. A leading --preset names one; without it this is the
# default build directory, so an existing ./build.sh --debug still works.
build_dir="${MODEL_CRYPT_BUILD_DIR}"
if [[ "${1:-}" == --preset ]]; then
  if [[ $# -lt 2 ]]; then
    echo "--preset requires a name" >&2
    exit 1
  fi
  build_dir="$(model_crypt_preset_dir "$2")"
  shift 2
fi

binary="${build_dir}/model_crypt_tests"
if [[ ! -x "${binary}" ]]; then
  echo "No test binary at ${binary}." >&2
  echo "Build the uninstrumented tree first: cmake --preset valgrind &&" >&2
  echo "cmake --build --preset valgrind" >&2
  exit 1
fi

# Asked of CMake's own cache rather than a stamp file this project maintains.
# The cache was written by the configure that produced these objects, so it
# cannot disagree with them -- and it answers the same question for a tree built
# any other way.
if grep -qE '^MODEL_CRYPT_(ASAN|TSAN):BOOL=ON' "${build_dir}/CMakeCache.txt" 2>/dev/null; then
  echo "${build_dir} is an instrumented build." >&2
  echo "Valgrind and the sanitizers both replace the allocator and the" >&2
  echo "combination reports nonsense; use the uninstrumented 'valgrind' preset." >&2
  exit 1
fi

# Which suites. Not all of them: Tamper runs thousands of scrypt derivations and
# RoundTrip sweeps 64 cases, and Valgrind's ~30x slowdown turns either into tens
# of minutes. The suites below cover every code path in the library -- Api
# exercises both entry-point families and the file layer, Format the parsers and
# primitives -- at a size Valgrind can chew through.
#
# This is a deliberate cap, so it is stated here and in docs/Testing.md rather
# than being a surprise to whoever wonders why a leak got through.
suites=("$@")
if [[ ${#suites[@]} -eq 0 ]]; then
  suites=(Api Format Compress Kdf Aead SecureBuffer Vector Threading)
fi

status=0
for suite in "${suites[@]}"; do
  echo "=== valgrind: ${suite}"
  # --error-exitcode makes a finding fail the script; without it Valgrind prints
  # its report and exits with the program's own status, which is 0.
  # --errors-for-leak-kinds=definite,possible: an indirect leak is usually a
  # consequence of a definite one and reporting both doubles the noise.
  if ! valgrind \
    --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=definite,possible \
    --errors-for-leak-kinds=definite,possible \
    --track-origins=yes \
    --error-exitcode=42 \
    --gen-suppressions=no \
    "${binary}" "${suite}"; then
    echo "valgrind reported findings in ${suite}" >&2
    status=1
  fi
done

if [[ "${status}" -eq 0 ]]; then
  echo
  echo "Valgrind found nothing."
fi
exit "${status}"
