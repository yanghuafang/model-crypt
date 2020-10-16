#!/bin/bash

# build.sh — configure and build model-crypt with CMake.
#
# Wraps the right cmake invocation so nobody has to remember OPENSSL_ROOT_DIR or
# the sanitizer option names. Builds into ../../model-crypt-build (a sibling of
# the repo) so the source tree stays clean.
#
# Modes:
#   --debug | --release | --relwithdebinfo   CMAKE_BUILD_TYPE (default Release)
#   --asan                                   AddressSanitizer (+ LeakSanitizer
#                                            on Linux)
#   --ubsan                                  UndefinedBehaviorSanitizer;
#                                            combinable with --asan
#   --tsan                                   ThreadSanitizer; not combinable
#                                            with the other two
#   --coverage                               source-based coverage
#   --werror                                 fail the build on any warning
#   --no-tests                               library and CLI only
#   --clean                                  delete the build directory first
#
# Override the job count with MODEL_CRYPT_BUILD_JOBS=N, and the build directory
# with MODEL_CRYPT_BUILD_DIR=path.
#
# Stop at the first failing step, on an unset variable, and on a failure anywhere
# in a pipe. Without -e a failed configure is followed by a build anyway, and the
# message the user ends on is make's complaint rather than CMake's error.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

usage() {
  cat <<'USAGE'
Usage: build.sh [--debug|--release|--relwithdebinfo] [--asan] [--ubsan]
                [--tsan] [--coverage] [--werror] [--no-tests] [--clean]

Configure and build model-crypt into a sibling of the repo.

Build modes (at most one, default --release):
  --debug           CMAKE_BUILD_TYPE=Debug
  --release         CMAKE_BUILD_TYPE=Release
  --relwithdebinfo  CMAKE_BUILD_TYPE=RelWithDebInfo

Options:
  --asan       AddressSanitizer. Implies Debug unless a mode is given.
  --ubsan      UndefinedBehaviorSanitizer. Combinable with --asan.
  --tsan       ThreadSanitizer. Cannot be combined with --asan or --ubsan.
  --coverage   Source-based coverage. Use scripts/coverage.sh unless you want
               the build alone.
  --werror     Treat compiler warnings as errors.
  --no-tests   Do not build the test suite.
  --clean      Remove the build directory before configuring.
  -h, --help   Show this help.

Environment:
  MODEL_CRYPT_BUILD_DIR   Where to build (default: ../../model-crypt-build).
  MODEL_CRYPT_BUILD_JOBS  Parallel jobs (default: one per logical core).
  OPENSSL_ROOT_DIR        OpenSSL 3 prefix; set automatically on macOS.
USAGE
}

build_type=""
asan=OFF
ubsan=OFF
tsan=OFF
coverage=OFF
werror=OFF
tests=ON
clean=false

set_mode() {
  if [[ -n "${build_type}" ]]; then
    echo "Only one build mode may be specified." >&2
    exit 1
  fi
  build_type="$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)          set_mode Debug; shift ;;
    --release)        set_mode Release; shift ;;
    --relwithdebinfo) set_mode RelWithDebInfo; shift ;;
    --asan)           asan=ON; shift ;;
    --ubsan)          ubsan=ON; shift ;;
    --tsan)           tsan=ON; shift ;;
    --coverage)       coverage=ON; shift ;;
    --werror)         werror=ON; shift ;;
    --no-tests)       tests=OFF; shift ;;
    --clean)          clean=true; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# A sanitizer build defaults to Debug rather than to Release. At -O3 the compiler
# inlines away the frames a sanitizer report is made of, so an ASan trace points
# at the wrong function or at nothing at all -- and the whole reason to run the
# instrumented build is to read that trace. An explicit --release still wins,
# for the rare case of chasing something that only misbehaves optimized.
if [[ -z "${build_type}" ]]; then
  if [[ "${asan}" == ON || "${ubsan}" == ON || "${tsan}" == ON || "${coverage}" == ON ]]; then
    build_type=Debug
    echo "Sanitizer or coverage build: defaulting to Debug for usable stack traces."
  else
    build_type=Release
  fi
fi

if [[ "${clean}" == true ]]; then
  echo "Removing ${MODEL_CRYPT_BUILD_DIR}"
  rm -rf "${MODEL_CRYPT_BUILD_DIR}"
fi

# The sanitizer flags reach every target through add_compile_options, which CMake
# caches. Switching sanitizers in an existing build directory therefore leaves
# stale objects that were compiled without them, and the link fails on missing
# __asan_ symbols. Detecting the switch and reconfiguring from scratch is what
# keeps `./build.sh --asan` after `./build.sh` from being a puzzle.
stamp="${MODEL_CRYPT_BUILD_DIR}/.model-crypt-flags"
want="type=${build_type} asan=${asan} ubsan=${ubsan} tsan=${tsan} coverage=${coverage} werror=${werror} tests=${tests}"
if [[ -f "${stamp}" ]] && [[ "$(cat "${stamp}")" != "${want}" ]]; then
  echo "Build flags changed; reconfiguring from scratch."
  echo "  was: $(cat "${stamp}")"
  echo "  now: ${want}"
  rm -rf "${MODEL_CRYPT_BUILD_DIR}"
fi

cmake -S "${MODEL_CRYPT_REPO_DIR}" -B "${MODEL_CRYPT_BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE="${build_type}" \
  -DMODEL_CRYPT_ASAN="${asan}" \
  -DMODEL_CRYPT_UBSAN="${ubsan}" \
  -DMODEL_CRYPT_TSAN="${tsan}" \
  -DMODEL_CRYPT_COVERAGE="${coverage}" \
  -DMODEL_CRYPT_WERROR="${werror}" \
  -DMODEL_CRYPT_BUILD_TESTS="${tests}"

jobs="$(model_crypt_jobs)"
echo "Building model-crypt with ${jobs} parallel jobs..."
cmake --build "${MODEL_CRYPT_BUILD_DIR}" --parallel "${jobs}"

mkdir -p "${MODEL_CRYPT_BUILD_DIR}"
printf '%s' "${want}" > "${stamp}"

echo
echo "Built into ${MODEL_CRYPT_BUILD_DIR}"
echo "  CLI:   ${MODEL_CRYPT_BUILD_DIR}/model-crypt"
if [[ "${tests}" == ON ]]; then
  echo "  Tests: ./run-tests.sh"
fi
