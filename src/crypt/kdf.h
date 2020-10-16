#ifndef MODEL_CRYPT_SRC_CRYPT_KDF_H_
#define MODEL_CRYPT_SRC_CRYPT_KDF_H_

#include <cstddef>
#include <cstdint>

#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

/// Turning a caller-supplied key or passphrase into a 32-byte AES key.
///
/// scrypt, not a plain hash: SHA-256 bridges the length in microseconds for the
/// legitimate caller and for an attacker running a wordlist. At the default
/// parameters one scrypt guess costs ~100 ms and 32 MiB -- unnoticeable once
/// per model load, ruinous across a dictionary. The memory term is what a GPU
/// or ASIC cannot optimize away, which is why scrypt rather than PBKDF2.
///
/// The 16-byte salt is fresh per encryption and stored in the header, so the
/// same model encrypted twice yields unrelated keys and no precomputed table
/// carries from one file to the next.
namespace kdf {

/// Derive a #format::kKeySize AES key from \p key and \p salt.
///
/// \param key       Caller's key or passphrase bytes.
/// \param key_size   Its length; at least #MC_MIN_KEY_SIZE.
/// \param salt      Salt from the file header.
/// \param salt_size  Its length; #format::kSaltSize.
/// \param log_n      scrypt cost as log2(N), already range-checked.
/// \param r         scrypt block size, already range-checked.
/// \param p         scrypt parallelism, already range-checked.
/// \param out       Receives the derived key, sized on success.
///
/// The cost parameters come from a file header on the decrypt path, so an
/// attacker chose them. This function assumes format::ParseFileHeader has
/// already clamped them, individually and against #format::kMaxKdfMemory:
/// validation belongs where the untrusted bytes are parsed.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_MEMORY, or #MC_ERR_CRYPTO.
mc_status DeriveKey(const uint8_t* key, size_t key_size, const uint8_t* salt,
                    size_t salt_size, uint8_t log_n, uint32_t r, uint32_t p,
                    SecureBuffer* out);

}  // namespace kdf

#endif  // MODEL_CRYPT_SRC_CRYPT_KDF_H_
