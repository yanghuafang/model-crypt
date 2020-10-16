#!/bin/bash

# make-vector.sh — regenerate tests/vectors/v2-two-chunks.mcrypt.
#
# Run this ONLY when MC_FORMAT_VERSION is deliberately bumped, and pass --force
# to confirm it. It refuses to overwrite an existing vector otherwise, for the
# reason below.
#
# == Why the output is different every time ==
#
# Encryption draws a fresh random salt and nonce prefix per call, so two runs of
# this script produce two files that differ in 24 bytes of header and in every
# byte of ciphertext -- with an identical format and identical plaintext. The
# output is not reproducible and is not meant to be.
#
# That has a consequence worth stating plainly, because the opposite is the
# natural assumption: **diffing this script's output against the committed
# vector proves nothing.** It always differs. A regression in the byte layout is
# detected by the Vector suite failing to *decrypt* the committed file, not by
# this script disagreeing with it.
#
# == Why overwriting is the thing to avoid ==
#
# The committed vector's whole value is that an *older* build produced it. It is
# the only artifact in the tree that a layout change cannot silently agree with,
# because nothing in this build was involved in making it. Regenerating it with
# the current build replaces that evidence with a file this build wrote, which
# every other test already covers -- and the format regression it would have
# caught then ships.
#
# So: if the Vector suite fails and the version was not bumped, the change that
# broke it is the bug. Do not run this script to make the failure go away.
#
# == When the version IS bumped ==
#
# Keep the old vector beside the new one and add a test asserting the old one is
# now rejected as MC_ERR_UNSUPPORTED, so the rejection path is covered too.
#
# Usage:
#   ./make-vector.sh --force            overwrite the committed vector
#   ./make-vector.sh --out PATH         write elsewhere, leaving the vector alone

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

force=false
target="${MODEL_CRYPT_REPO_DIR}/tests/vectors/v2-two-chunks.mcrypt"
generator_dir="${MODEL_CRYPT_BUILD_DIR}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) force=true; shift ;;
    --preset)
      if [[ $# -lt 2 ]]; then
        echo "--preset requires a name" >&2
        exit 1
      fi
      generator_dir="$(model_crypt_preset_dir "$2")"
      shift 2
      ;;
    --out)
      if [[ $# -lt 2 ]]; then
        echo "--out requires a path" >&2
        exit 1
      fi
      target="$2"
      force=true
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--force] [--out PATH]" >&2
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

generator="${generator_dir}/model_crypt_make_vector"
if [[ ! -x "${generator}" ]]; then
  echo "No generator at ${generator}." >&2
  echo "Run ./build.sh first (without --no-tests)." >&2
  exit 1
fi

if [[ -f "${target}" ]] && [[ "${force}" != true ]]; then
  cat >&2 <<'REFUSE'
Refusing to overwrite the committed vector.

The vector is evidence that a build older than this one produced a file this
one can still read. Regenerating it destroys that -- and because the salt and
nonce are random per encryption, the new file would differ from the old one
even if nothing about the format had changed, so the diff would tell you
nothing either way.

If the Vector suite is failing and MC_FORMAT_VERSION was NOT bumped, the change
that broke it is the bug. Revert that instead.

If the version WAS bumped deliberately:
  ./make-vector.sh --force
and keep the old vector beside the new one with a test asserting it is now
rejected as MC_ERR_UNSUPPORTED.

To generate one somewhere else without touching the committed file:
  ./make-vector.sh --out /tmp/sample.mcrypt
REFUSE
  exit 1
fi

mkdir -p "$(dirname "${target}")"
"${generator}" "${target}"
echo "Wrote ${target} ($(wc -c < "${target}" | tr -d ' ') bytes)"
echo
echo "Reminder: this file is not reproducible -- rerunning produces different"
echo "bytes. Commit it only as part of a deliberate MC_FORMAT_VERSION bump."
