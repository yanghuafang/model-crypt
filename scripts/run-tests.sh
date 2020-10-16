#!/bin/bash

# run-tests.sh — run the model-crypt test suite through CTest.
#
# Each suite is a separate CTest test (see the foreach in CMakeLists.txt), so a
# failure names the suite. With no argument every suite runs; with one, only the
# matching suites do.
#
# Modes:
#   (default)      run every suite in parallel
#   SUITE...       run only suites matching these names (CTest regex)
#   --serial       one at a time; use when a failure's output is interleaved
#   --verbose      show each test's stdout even when it passes
#
# Usage:
#   ./run-tests.sh
#   ./run-tests.sh Tamper
#   ./run-tests.sh --verbose Vector Format
#
# == Sanitizer options are set here, not in CMake ==
#
# ASAN_OPTIONS and UBSAN_OPTIONS are read by the sanitizer runtime at process
# start, so they belong to whatever *runs* the tests rather than to the build.
# Setting them unconditionally is harmless in an uninstrumented build -- nothing
# reads them -- and means a developer who built with --asan gets leak detection
# without having to know to ask for it.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

if [[ ! -f "${MODEL_CRYPT_BUILD_DIR}/CTestTestfile.cmake" ]]; then
  echo "No test configuration in ${MODEL_CRYPT_BUILD_DIR}." >&2
  echo "Run ./build.sh first (without --no-tests)." >&2
  exit 1
fi

# LeakSanitizer rides along with ASan on Linux only, and asking for it on macOS
# does not degrade gracefully -- the runtime prints "detect_leaks is not
# supported on this platform" and aborts, so every test fails at startup with an
# error that says nothing about the test. Hence the per-platform split rather than
# one string.
#
# It is worth having on where it works: every buffer in this library is owned by a
# SecureBuffer or handed to the caller through mc_free, and a leak means one of
# those two paths was missed -- which for a decrypted model means plaintext left
# in the heap. Linux CI is therefore the only place that is verified, and the only
# place it can be.
if [[ "$(uname -s)" == Linux ]]; then
  export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
else
  export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1}"
fi
# A UBSan report is only actionable with a stack trace, and the runtime has to be
# told to collect one. The build already passes -fno-sanitize-recover, so the
# process aborts on the first finding rather than printing and continuing.
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1}"

ctest_args=(--output-on-failure)
parallel=true
filters=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)  parallel=false; shift ;;
    --verbose) ctest_args+=(--verbose); shift ;;
    -h|--help)
      echo "Usage: $0 [--serial] [--verbose] [SUITE...]" >&2
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      filters+=("$1"); shift ;;
  esac
done

if [[ ${#filters[@]} -gt 0 ]]; then
  # CTest's -R takes one regex, so several names are joined with alternation.
  joined="$(printf '|%s' "${filters[@]}")"
  ctest_args+=(-R "${joined:1}")
fi

# Serial under a sanitizer regardless: ASan reserves a large shadow mapping per
# process, and eight at once on a CI runner is an OOM kill that looks like a
# test failure.
stamp="${MODEL_CRYPT_BUILD_DIR}/.model-crypt-flags"
if [[ -f "${stamp}" ]] && grep -qE 'asan=ON|tsan=ON' "${stamp}"; then
  if [[ "${parallel}" == true ]]; then
    echo "Sanitizer build detected; running suites serially to bound memory use."
    parallel=false
  fi
fi

if [[ "${parallel}" == true ]]; then
  ctest_args+=(--parallel "$(model_crypt_jobs)")
fi

# From inside the build directory: `ctest --test-dir` needs CMake 3.20 and the
# floor here is 3.16. Failing on the cd rather than letting ctest run wherever
# the script started, which reports "no tests were found".
cd "${MODEL_CRYPT_BUILD_DIR}" || {
  echo "No build directory at ${MODEL_CRYPT_BUILD_DIR}. Run ./build.sh first." >&2
  exit 1
}

ctest "${ctest_args[@]}"
