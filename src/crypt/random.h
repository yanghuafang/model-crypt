#ifndef MODEL_CRYPT_SRC_CRYPT_RANDOM_H_
#define MODEL_CRYPT_SRC_CRYPT_RANDOM_H_

#include <cstddef>
#include <cstdint>

#include "model_crypt/model_crypt.h"

/// The one source of randomness in the library: the scrypt salt and the
/// per-file nonce prefix. Neither is secret -- both go in the header in the
/// clear -- but both must be fresh. A repeated salt amortizes one dictionary
/// attack across every file sharing it; a repeated nonce prefix under a
/// repeated key is the nonce reuse that makes AES-GCM forgeable.
///
/// A failure is propagated, never worked around. RAND_bytes fails when the OS
/// entropy source is unavailable, and the alternative -- a time-seeded PRNG --
/// produces salts an attacker can enumerate, which is no salt at all.
namespace random_bytes {

/// Fill \p size bytes at \p out from the system CSPRNG.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, or #MC_ERR_CRYPTO when the system
///         random source failed. \p out is untouched on failure.
mc_status Fill(uint8_t* out, size_t size);

}  // namespace random_bytes

#endif  // MODEL_CRYPT_SRC_CRYPT_RANDOM_H_
