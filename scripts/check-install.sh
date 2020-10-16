#!/bin/bash

# check-install.sh — install into a staging directory and compile a consumer
# against the result.
#
# == What this catches that nothing else does ==
#
# Every other check links the library out of the build tree, where include/ is on
# the include path because CMake put it there. That hides two whole classes of
# mistake:
#
#   * The public header including something under src/. It would compile fine in
#     the build tree and fail for everyone who installed the package.
#   * A symbol the library uses being hidden. -fvisibility=hidden means only the
#     MC_API functions are exported; if one is ever added and the annotation
#     forgotten, the build tree still links (static objects) and the shared
#     library does not.
#
# So this builds both static and shared, installs each into a fresh prefix, and
# compiles a small C program -- C, not C++, because the header claims to be
# usable from C and that claim is worth testing -- against the installed files
# only.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/build-env.sh" || exit 1

work="$(mktemp -d "${TMPDIR:-/tmp}/model-crypt-install-XXXXXX")"
cleanup() {
  rm -rf "${work}"
}
trap cleanup EXIT

# A consumer that exercises the whole documented flow: options, encrypt, inspect,
# decrypt, compare, free. Compiled as C99 with the strict warnings a careful
# consumer would use -- if the header cannot survive those, that is the header's
# problem and not theirs.
cat > "${work}/consumer.c" <<'CONSUMER'
#include <model_crypt/model_crypt.h>

#include <stdio.h>
#include <string.h>

int main(void) {
  const unsigned char key[32] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char plain[10000];
  size_t i;
  for (i = 0; i < sizeof(plain); ++i) {
    plain[i] = (unsigned char)(i * 7u);
  }

  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  /* The cheapest permitted cost: this is a linkage check, not a KDF benchmark. */
  opts.kdf_log_n = 14;

  uint8_t *cipher = NULL;
  size_t cipher_len = 0;
  mc_status rc = mc_encrypt_buffer(key, sizeof(key), &opts, plain,
                                   sizeof(plain), &cipher, &cipher_len);
  if (rc != MC_OK) {
    fprintf(stderr, "encrypt: %s\n", mc_status_string(rc));
    return 1;
  }

  mc_file_info info;
  memset(&info, 0, sizeof(info));
  rc = mc_inspect_buffer(cipher, cipher_len, &info);
  if (rc != MC_OK || info.plaintext_size != sizeof(plain)) {
    fprintf(stderr, "inspect: %s\n", mc_status_string(rc));
    return 1;
  }

  uint8_t *recovered = NULL;
  size_t recovered_len = 0;
  rc = mc_decrypt_buffer(key, sizeof(key), cipher, cipher_len, &recovered,
                         &recovered_len);
  mc_free(cipher, cipher_len);
  if (rc != MC_OK) {
    fprintf(stderr, "decrypt: %s\n", mc_status_string(rc));
    return 1;
  }

  if (recovered_len != sizeof(plain) ||
      memcmp(recovered, plain, sizeof(plain)) != 0) {
    fprintf(stderr, "round trip differs\n");
    mc_free(recovered, recovered_len);
    return 1;
  }

  mc_free(recovered, recovered_len);
  printf("consumer ok (model-crypt %s)\n", mc_version_string());
  return 0;
}
CONSUMER

cc="${CC:-cc}"

# The static case needs three things on the consumer's link line that the shared
# case does not: zlib, libcrypto, and the C++ runtime.
#
# None of that is an oversight in the install rules. A static archive records no
# dependencies, so whoever links it has to name them; a shared library records
# its own, which is exactly why target_link_libraries is PRIVATE in CMakeLists.
#
# The C++ runtime is the one worth calling out, because it surprises people: the
# API is C, but the implementation is C++17, so a C program linking
# libmodel_crypt.a statically must also link libstdc++ (or libc++). Linking with
# the C++ driver instead of `cc` does the same thing. docs/Usage.md says so, and
# this check is what keeps that documentation true.
if [[ "$(uname -s)" == Darwin ]]; then
  cxx_runtime=(-lc++)
else
  cxx_runtime=(-lstdc++)
fi

for kind in static shared; do
  echo "=== ${kind}"
  build="${work}/build-${kind}"
  prefix="${work}/prefix-${kind}"

  shared_flag=OFF
  if [[ "${kind}" == shared ]]; then
    shared_flag=ON
  fi

  cmake -S "${MODEL_CRYPT_REPO_DIR}" -B "${build}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS="${shared_flag}" \
    -DMODEL_CRYPT_BUILD_TESTS=OFF \
    -DCMAKE_INSTALL_PREFIX="${prefix}" >/dev/null

  cmake --build "${build}" --parallel "$(model_crypt_jobs)" >/dev/null
  cmake --install "${build}" >/dev/null

  # The installed tree must contain the public header and nothing from src/.
  if [[ ! -f "${prefix}/include/model_crypt/model_crypt.h" ]]; then
    echo "install did not place the public header" >&2
    exit 1
  fi

  leaked="$(find "${prefix}/include" -name '*.hpp' -print -quit)"
  if [[ -n "${leaked}" ]]; then
    echo "install leaked an internal header: ${leaked}" >&2
    exit 1
  fi

  link_args=(-L"${prefix}/lib" -lmodel_crypt)
  if [[ "${kind}" == static ]]; then
    link_args+=("${cxx_runtime[@]}" -lz)
    if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
      link_args+=(-L"${OPENSSL_ROOT_DIR}/lib")
    fi
    link_args+=(-lcrypto)
  fi

  # -std=c99 -Wall -Wextra -Wpedantic: the header advertises itself as C, and
  # this is what that claim means in practice.
  "${cc}" -std=c99 -Wall -Wextra -Wpedantic -Werror \
    -I"${prefix}/include" \
    "${work}/consumer.c" -o "${work}/consumer-${kind}" \
    "${link_args[@]}"

  # The shared library is not on the default search path in a staging prefix.
  if [[ "${kind}" == shared ]]; then
    if [[ "$(uname -s)" == Darwin ]]; then
      DYLD_LIBRARY_PATH="${prefix}/lib" "${work}/consumer-${kind}"
    else
      LD_LIBRARY_PATH="${prefix}/lib" "${work}/consumer-${kind}"
    fi
  else
    "${work}/consumer-${kind}"
  fi

  # The exported surface must be exactly the documented API. A symbol table with
  # format::ParseFileHeader in it is an ABI nobody meant to promise, and the
  # first release that changes it breaks a consumer who linked against it.
  if [[ "${kind}" == shared ]]; then
    library="${prefix}/lib/libmodel_crypt.so"
    if [[ ! -f "${library}" ]]; then
      library="${prefix}/lib/libmodel_crypt.dylib"
    fi

    if command -v nm >/dev/null 2>&1 && [[ -f "${library}" ]]; then
      # Defined, external, non-weak symbols only. The leading underscore on
      # macOS is stripped so one comparison works on both platforms.
      exported="$(nm -gU "${library}" 2>/dev/null || nm --defined-only -g "${library}")"
      unexpected="$(echo "${exported}" \
        | awk '$2 == "T" || $2 == "D" { print $3 }' \
        | sed 's/^_//' \
        | grep -vE '^mc_[a-z_]+$' \
        | grep -vE '^(_|\.)' || true)"

      if [[ -n "${unexpected}" ]]; then
        echo "the shared library exports symbols outside the mc_ API:" >&2
        echo "${unexpected}" | sed 's/^/  /' >&2
        exit 1
      fi

      echo "exported symbols: $(echo "${exported}" | awk '$2 == "T" { print $3 }' | wc -l | tr -d ' ') (all mc_*)"
    fi
  fi
done

echo
echo "Install checks passed (static and shared)."
