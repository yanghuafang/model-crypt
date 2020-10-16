#include "crypt/kdf.h"

#include <cstddef>
#include <cstdint>
#include <utility>

#include <openssl/evp.h>

#include "crypt/format.h"
#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

// See crypt/kdf.h for why scrypt, and for the split between "validate the
// parameters" (format.cc) and "use them" (here).

namespace kdf {

mc_status DeriveKey(const uint8_t* key, size_t key_size, const uint8_t* salt,
                    size_t salt_size, uint8_t log_n, uint32_t r, uint32_t p,
                    SecureBuffer* out) {
  if (key == nullptr || salt == nullptr || out == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (key_size < MC_MIN_KEY_SIZE || salt_size != format::kSaltSize) {
    return MC_ERR_INVALID_ARG;
  }

  SecureBuffer derived;
  if (!derived.Reset(format::kKeySize)) {
    return MC_ERR_MEMORY;
  }

  // EVP_PBE_scrypt, not EVP_KDF: the latter needs OpenSSL 3.0 and the floor
  // here is 1.1.1. Both compute the same scrypt and produce byte-identical
  // output, which the committed test vector depends on -- it was written
  // through the EVP_KDF path.
  //
  // maxmem must be passed. OpenSSL defaults it to 32 MiB, and the default
  // parameters (N = 2^15, r = 8) need exactly 128 * N * r = 32 MiB plus working
  // buffers, so the derivation fails at the defaults. format::kMaxKdfMemory is
  // already enforced in ParseFileHeader, so passing it widens nothing.
  const uint64_t max_mem = format::kMaxKdfMemory + (1ull << 20);

  // The const char* parameter is a passphrase-shaped API, but it reads exactly
  // key_size bytes and never looks for a terminator, so an embedded NUL is
  // fine.
  if (EVP_PBE_scrypt(reinterpret_cast<const char*>(key), key_size, salt,
                     salt_size, 1ull << log_n, r, p, max_mem, derived.data(),
                     derived.size()) != 1) {
    return MC_ERR_CRYPTO;
  }

  *out = std::move(derived);
  return MC_OK;
}

}  // namespace kdf
