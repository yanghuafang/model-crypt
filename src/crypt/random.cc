#include "crypt/random.h"

#include <cstddef>
#include <cstdint>

#include <openssl/rand.h>

#include "model_crypt/model_crypt.h"

// See crypt/random.h for why a failure here is propagated rather than
// worked around.

namespace random_bytes {

mc_status Fill(uint8_t* out, size_t size) {
  if (out == nullptr || size == 0) {
    return MC_ERR_INVALID_ARG;
  }

  // RAND_bytes takes an int. Truncating a size_t here would be a short draw,
  // leaving the tail of `out` at whatever the caller had there.
  if (size > static_cast<size_t>(INT32_MAX)) {
    return MC_ERR_INVALID_ARG;
  }

  // RAND_bytes, not RAND_priv_bytes: the private DRBG is for key material that
  // must not be inferable from other draws, and salts and nonce prefixes are
  // published in the header.
  if (RAND_bytes(out, static_cast<int>(size)) != 1) {
    return MC_ERR_CRYPTO;
  }

  return MC_OK;
}

}  // namespace random_bytes
