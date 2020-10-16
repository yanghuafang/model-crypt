#!/bin/bash

# check-cli.sh — end-to-end checks of the model-crypt CLI.
#
# Registered with CTest as the "Cli" test, and runnable by hand:
#
#   ./check-cli.sh ../../model-crypt-build/model-crypt
#
# == Why a shell script and not a C++ test ==
#
# What needs checking here is the CLI's *interface*: exit codes, that --key is
# refused rather than accepted, that a key file's trailing newline is stripped,
# that keygen will not clobber an existing key. Driving that from a test binary
# means fork/exec plumbing and pipe reading that would be longer than the thing
# being tested, and would test that plumbing as much as the CLI.
#
# Everything runs in a temporary directory that is removed on exit, including on
# failure, so a failed run leaves nothing behind but its output.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 PATH-TO-model-crypt" >&2
  exit 2
fi

cli="$1"
if [[ ! -x "${cli}" ]]; then
  echo "not executable: ${cli}" >&2
  exit 2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/model-crypt-cli-XXXXXX")"
cleanup() {
  rm -rf "${work}"
}
trap cleanup EXIT

failures=0

# Reports and continues, rather than aborting on the first failure: one run
# should list everything that is broken. `set -e` is still on for the setup
# commands, which is why every checked invocation is wrapped in `|| status=$?`.
fail() {
  echo "  FAIL $1"
  failures=$((failures + 1))
}

pass() {
  echo "  ok   $1"
}

# Runs the CLI and compares its exit status. Output is captured so a passing
# check is quiet and a failing one can show what happened.
expect_status() {
  local want="$1"
  local name="$2"
  shift 2

  local status=0
  local output
  output="$("$@" 2>&1)" || status=$?

  if [[ "${status}" -eq "${want}" ]]; then
    pass "${name}"
  else
    fail "${name}: exit ${status}, want ${want}"
    echo "${output}" | sed 's/^/       /'
  fi
}

echo "Checking $(basename "${cli}") at ${cli}"

# --- Basics ---------------------------------------------------------------

expect_status 0 "--version" "${cli}" --version
expect_status 0 "--help" "${cli}" --help
expect_status 2 "no arguments" "${cli}"
expect_status 2 "unknown command" "${cli}" frobnicate
expect_status 2 "unknown option" "${cli}" encrypt --wat

# --key must be refused outright. This is the one option whose *absence* is a
# security property: a key in argv is visible in `ps` and lands in shell history
# and CI logs, which is how the v1 tool leaked every key it was ever given.
status=0
output="$("${cli}" encrypt --key hunter2hunter2 --in /dev/null --out "${work}/x" 2>&1)" || status=$?
if [[ "${status}" -eq 2 ]] && echo "${output}" | grep -q "not supported"; then
  pass "--key is refused with an explanation"
else
  fail "--key should exit 2 with an explanation; got exit ${status}"
  echo "${output}" | sed 's/^/       /'
fi

# --- keygen ---------------------------------------------------------------

expect_status 2 "keygen without --out" "${cli}" keygen

key="${work}/key.bin"
expect_status 0 "keygen" "${cli}" keygen --out "${key}"

if [[ "$(wc -c < "${key}" | tr -d ' ')" == "32" ]]; then
  pass "keygen writes 32 bytes"
else
  fail "keygen wrote $(wc -c < "${key}") bytes, want 32"
fi

# 0600, not whatever the umask allows. A key file the group can read is a key
# file that has already leaked on a shared machine.
mode="$(ls -l "${key}" | cut -c1-10)"
if [[ "${mode}" == "-rw-------" ]]; then
  pass "keygen writes mode 0600"
else
  fail "keygen wrote mode ${mode}, want -rw-------"
fi

# O_EXCL: overwriting a key makes every model encrypted under it unreadable, and
# that is not a mistake a stray --out should be able to make.
expect_status 1 "keygen refuses to overwrite" "${cli}" keygen --out "${key}"

# --- Round trip through files ---------------------------------------------

# A payload with structure, so a truncated or misordered decryption is visibly
# wrong rather than plausibly empty. /dev/urandom rather than a fixed string
# because an incompressible payload also exercises the raw-store fallback.
plain="${work}/model.bin"
head -c 200000 /dev/urandom > "${plain}"

cipher="${work}/model.mcrypt"
recovered="${work}/model.out"

# The minimum KDF cost, so this script is not eight seconds of scrypt. The
# defaults are exercised by the Kdf suite.
expect_status 0 "encrypt --key-file" \
  "${cli}" encrypt --key-file "${key}" --kdf-log-n 14 \
  --in "${plain}" --out "${cipher}"

expect_status 0 "decrypt --key-file" \
  "${cli}" decrypt --key-file "${key}" --in "${cipher}" --out "${recovered}"

if cmp -s "${plain}" "${recovered}"; then
  pass "round trip is byte-exact"
else
  fail "round trip differs"
fi

mode="$(ls -l "${recovered}" | cut -c1-10)"
if [[ "${mode}" == "-rw-------" ]]; then
  pass "decrypt writes plaintext mode 0600"
else
  fail "decrypt wrote mode ${mode}, want -rw-------"
fi

mode="$(ls -l "${cipher}" | cut -c1-10)"
if [[ "${mode}" == "-rw-r--r--" ]]; then
  pass "encrypt writes ciphertext mode 0644"
else
  fail "encrypt wrote mode ${mode}, want -rw-r--r--"
fi

# --- inspect --------------------------------------------------------------

status=0
output="$("${cli}" inspect --in "${cipher}" 2>&1)" || status=$?
if [[ "${status}" -eq 0 ]] && echo "${output}" | grep -q "plaintext size:  200000"; then
  pass "inspect reports the header"
else
  fail "inspect did not report the expected header; exit ${status}"
  echo "${output}" | sed 's/^/       /'
fi

# inspect must not print anything key-shaped. A tool whose diagnostic output
# includes the salt invites treating that output as the file's identity, and the
# only honest identity check is a successful decryption.
if echo "${output}" | grep -qiE "salt|nonce|tag|key:"; then
  fail "inspect printed salt/nonce/tag material"
else
  pass "inspect prints no key material"
fi

expect_status 1 "inspect rejects a non-model file" "${cli}" inspect --in "${plain}"

# --- Key handling ---------------------------------------------------------

# echo adds a newline and printf does not; both must derive the same key, or a
# key file created the obvious way silently does not work.
printf 'a-passphrase-long-enough' > "${work}/nonl"
printf 'a-passphrase-long-enough\n' > "${work}/withnl"

expect_status 0 "encrypt with a newline-terminated key file" \
  "${cli}" encrypt --key-file "${work}/withnl" --kdf-log-n 14 \
  --in "${plain}" --out "${work}/nl.mcrypt"

expect_status 0 "decrypt it with the un-terminated key file" \
  "${cli}" decrypt --key-file "${work}/nonl" \
  --in "${work}/nl.mcrypt" --out "${work}/nl.out"

if cmp -s "${plain}" "${work}/nl.out"; then
  pass "trailing newline is stripped consistently"
else
  fail "newline handling differs between key files"
fi

# --key-env, which is what CI should use: an environment variable is not in the
# process table the way argv is.
expect_status 0 "encrypt --key-env" \
  env MC_KEY='env-passphrase-long-enough' \
  "${cli}" encrypt --key-env MC_KEY --kdf-log-n 14 \
  --in "${plain}" --out "${work}/env.mcrypt"

expect_status 0 "decrypt --key-env" \
  env MC_KEY='env-passphrase-long-enough' \
  "${cli}" decrypt --key-env MC_KEY \
  --in "${work}/env.mcrypt" --out "${work}/env.out"

expect_status 2 "unset --key-env variable" \
  "${cli}" decrypt --key-env MC_DEFINITELY_NOT_SET \
  --in "${work}/env.mcrypt" --out "${work}/env2.out"

expect_status 2 "both --key-file and --key-env" \
  "${cli}" decrypt --key-file "${key}" --key-env MC_KEY \
  --in "${cipher}" --out "${work}/both.out"

# A key shorter than MC_MIN_KEY_SIZE, reported as a usage error with the
# suggestion to run keygen rather than as a cryptic failure.
printf 'short' > "${work}/short"
expect_status 2 "short key is refused" \
  "${cli}" encrypt --key-file "${work}/short" \
  --in "${plain}" --out "${work}/short.mcrypt"

# No key source and stdin is not a tty: must say so rather than block forever
# waiting on a prompt nobody can answer. This is the shape a CI job that forgot
# --key-env takes, and a hang there is a 6-hour job timeout.
expect_status 2 "no key source without a tty" \
  sh -c "'${cli}' decrypt --in '${cipher}' --out '${work}/notty.out' < /dev/null"

# --- Wrong key and tampering ---------------------------------------------

other="${work}/other.bin"
expect_status 0 "keygen a second key" "${cli}" keygen --out "${other}"

expect_status 1 "wrong key fails" \
  "${cli}" decrypt --key-file "${other}" --in "${cipher}" --out "${work}/wrong.out"

if [[ -e "${work}/wrong.out" ]]; then
  fail "a failed decryption left an output file behind"
else
  pass "a failed decryption leaves no output file"
fi

# One flipped byte in the middle of the payload.
cp "${cipher}" "${work}/bad.mcrypt"
printf '\xff' | dd of="${work}/bad.mcrypt" bs=1 seek=500 count=1 conv=notrunc \
  status=none
expect_status 1 "a modified file fails" \
  "${cli}" decrypt --key-file "${key}" --in "${work}/bad.mcrypt" \
  --out "${work}/bad.out"

# --- Option validation ---------------------------------------------------

expect_status 2 "chunk size below range" \
  "${cli}" encrypt --key-file "${key}" --chunk-size 4095 \
  --in "${plain}" --out "${work}/opt.mcrypt"
expect_status 2 "chunk size above range" \
  "${cli}" encrypt --key-file "${key}" --chunk-size 67108865 \
  --in "${plain}" --out "${work}/opt.mcrypt"
expect_status 2 "non-numeric chunk size" \
  "${cli}" encrypt --key-file "${key}" --chunk-size banana \
  --in "${plain}" --out "${work}/opt.mcrypt"
expect_status 2 "negative chunk size" \
  "${cli}" encrypt --key-file "${key}" --chunk-size -4096 \
  --in "${plain}" --out "${work}/opt.mcrypt"
expect_status 2 "unknown compression" \
  "${cli}" encrypt --key-file "${key}" --compression lzma \
  --in "${plain}" --out "${work}/opt.mcrypt"
expect_status 2 "kdf cost above range" \
  "${cli}" encrypt --key-file "${key}" --kdf-log-n 21 \
  --in "${plain}" --out "${work}/opt.mcrypt"

expect_status 0 "--compression none" \
  "${cli}" encrypt --key-file "${key}" --compression none --kdf-log-n 14 \
  --in "${plain}" --out "${work}/none.mcrypt"
expect_status 0 "decrypt --compression none output" \
  "${cli}" decrypt --key-file "${key}" --in "${work}/none.mcrypt" \
  --out "${work}/none.out"

if cmp -s "${plain}" "${work}/none.out"; then
  pass "--compression none round trips"
else
  fail "--compression none round trip differs"
fi

# --- Missing paths -------------------------------------------------------

expect_status 1 "missing input" \
  "${cli}" encrypt --key-file "${key}" --kdf-log-n 14 \
  --in "${work}/nope" --out "${work}/nope.mcrypt"
expect_status 2 "missing --in" "${cli}" encrypt --key-file "${key}"
expect_status 2 "missing --out" "${cli}" encrypt --key-file "${key}" --in "${plain}"

echo
if [[ "${failures}" -eq 0 ]]; then
  echo "CLI checks passed."
  exit 0
fi

echo "${failures} CLI check(s) failed."
exit 1
