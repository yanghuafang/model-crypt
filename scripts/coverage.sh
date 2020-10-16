#!/bin/bash

# coverage.sh — measure how much of the library the test suite reaches.
#
# Builds instrumented into its own directory
# (../../model-crypt-build-coverage), runs the suite, and renders a per-file
# line-coverage report with llvm-cov.
#
# Its own build directory: the instrumentation changes every object file, so
# sharing would mean a full rebuild each time someone alternates.
#
# Debug, not Release. An optimized build attributes an inlined line to its call
# site, which reports coverage for source that was never separately compiled --
# the number goes up and means less.
#
# Usage:
#   ./coverage.sh
#   ./coverage.sh --html      also write an HTML report and print its path
#   ./coverage.sh --check 85  fail if total line coverage is below 85%

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

html=false
threshold=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --html) html=true; shift ;;
    --check)
      if [[ $# -lt 2 ]]; then
        echo "--check requires a percentage" >&2
        exit 1
      fi
      threshold="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--html] [--check PERCENT]" >&2
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# llvm-profdata and llvm-cov must come from the same LLVM as the compiler that
# wrote the .profraw files: the profile format is versioned, and a mismatch fails
# with "unsupported instrumentation profile format version" rather than anything
# about coverage.
#
# Three places to look, in order.
#
# An unsuffixed pair on PATH is the simple case. Debian and Ubuntu are not that
# case: `apt install llvm` installs /usr/bin/llvm-profdata-18 (or -10, or
# whichever major the release carries) and leaves the unsuffixed name to a
# separate alternatives setup that is often absent. So the compiler is asked
# what major it is and the suffixed pair is tried -- which also gets the
# matching-version requirement right by construction rather than by luck.
#
# On macOS the Apple clang toolchain's copies live under xcrun and have no
# unsuffixed entry on PATH at all.
clang_major=""
if command -v "${CC:-clang}" >/dev/null 2>&1; then
  clang_major="$("${CC:-clang}" --version 2>/dev/null |
    sed -n '1s/.*version \([0-9][0-9]*\).*/\1/p')"
fi

if command -v llvm-profdata >/dev/null 2>&1 &&
   command -v llvm-cov >/dev/null 2>&1; then
  profdata=(llvm-profdata)
  cov=(llvm-cov)
elif [[ -n "${clang_major}" ]] &&
     command -v "llvm-profdata-${clang_major}" >/dev/null 2>&1 &&
     command -v "llvm-cov-${clang_major}" >/dev/null 2>&1; then
  profdata=("llvm-profdata-${clang_major}")
  cov=("llvm-cov-${clang_major}")
elif [[ "$(uname -s)" == Darwin ]] && xcrun --find llvm-profdata >/dev/null 2>&1; then
  profdata=(xcrun llvm-profdata)
  cov=(xcrun llvm-cov)
else
  echo "llvm-profdata / llvm-cov not found." >&2
  echo "  macOS:  brew install llvm   (or use the Xcode toolchain)" >&2
  echo "  Ubuntu: sudo apt install llvm    (scripts/install-deps-ubuntu.sh does this)" >&2
  exit 1
fi

# What a coverage build *is* lives in CMakePresets.json, not here, so CI and a
# developer configure the same one. Preset commands resolve CMakePresets.json
# from the current directory, hence the cd into the repo root.
preset=coverage
build_dir="$(model_crypt_preset_dir "${preset}")"

(cd "${MODEL_CRYPT_REPO_DIR}" \
  && cmake --preset "${preset}" \
  && cmake --build --preset "${preset}" --parallel "$(model_crypt_jobs)")

profile_dir="${build_dir}/profiles"
rm -rf "${profile_dir}"
mkdir -p "${profile_dir}"

# %p in the pattern gives each process its own file. Without it, the eleven CTest
# processes overwrite one another's profile and the report describes whichever
# suite finished last.
export LLVM_PROFILE_FILE="${profile_dir}/model-crypt-%p.profraw"

# LLVM_PROFILE_FILE is exported above and passes through to the test processes:
# the coverage test preset sets no environment of its own.
(cd "${MODEL_CRYPT_REPO_DIR}" && ctest --preset "${preset}")

"${profdata[@]}" merge -sparse "${profile_dir}"/*.profraw \
  -o "${build_dir}/model-crypt.profdata"

# -ignore-filename-regex excludes the tests themselves. Test code that runs is
# not a measure of library coverage, and including it inflates the number by
# thousands of lines that are covered by definition.
report_args=(
  "${build_dir}/model_crypt_tests"
  -instr-profile="${build_dir}/model-crypt.profdata"
  -ignore-filename-regex='(tests/|/usr/|/opt/)'
)

"${cov[@]}" report "${report_args[@]}"

if [[ "${html}" == true ]]; then
  "${cov[@]}" show "${report_args[@]}" -format=html \
    -output-dir="${build_dir}/coverage-html"
  echo
  echo "HTML report: ${build_dir}/coverage-html/index.html"
fi

if [[ -n "${threshold}" ]]; then
  # The TOTAL row's last column is the line-coverage percentage. Parsed rather
  # than read from a JSON export because the report is already being printed and
  # a second llvm-cov invocation would double the slowest step.
  total="$("${cov[@]}" report "${report_args[@]}" \
    | awk '/^TOTAL/ {gsub("%", "", $(NF)); print $(NF)}')"

  if [[ -z "${total}" ]]; then
    echo "Could not parse total coverage from the report." >&2
    exit 1
  fi

  echo
  echo "Total line coverage: ${total}% (threshold ${threshold}%)"
  if awk -v a="${total}" -v b="${threshold}" 'BEGIN { exit !(a < b) }'; then
    echo "Coverage below threshold." >&2
    exit 1
  fi
fi
