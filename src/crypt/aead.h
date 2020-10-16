#ifndef MODEL_CRYPT_SRC_CRYPT_AEAD_H_
#define MODEL_CRYPT_SRC_CRYPT_AEAD_H_

#include <cstddef>
#include <cstdint>

#include "model_crypt/model_crypt.h"

/// AES-256-GCM: one call seals a chunk, one opens it.
///
/// An AEAD rather than a bare cipher because a block cipher decrypts
/// attacker-chosen bytes into attacker-influenced plaintext and reports
/// success. GCM's 128-bit tag covers ciphertext and associated data, and Open()
/// returns failure instead of plaintext when it does not match -- which is what
/// #MC_ERR_AUTH means.
///
/// The one rule: a (key, nonce) pair must never seal twice. Nonce reuse does
/// not degrade GCM, it collapses it -- two messages under one nonce leak their
/// XOR and allow the authentication key to be recovered, after which forgeries
/// are free. Nothing here can violate that because nothing here chooses a
/// nonce; format::BuildNonce composes prefix||index, and across files the
/// per-file salt means a different key anyway.
namespace aead {

/// Encrypt \p pt_size bytes at \p pt into \p ct and write the tag to \p tag.
///
/// \p ct may alias \p pt for an in-place seal; GCM is a stream mode, so the
/// two buffers are the same length and OpenSSL handles the overlap.
///
/// \param key   #format::kKeySize bytes.
/// \param nonce #format::kNonceSize bytes, unique for this key.
/// \param aad   Associated data, authenticated but not encrypted.
/// \param tag   Receives #format::kTagSize bytes.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, or #MC_ERR_CRYPTO.
mc_status Seal(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad,
               size_t aad_size, const uint8_t* pt, size_t pt_size, uint8_t* ct,
               uint8_t* tag);

/// Authenticate and decrypt \p ct_size bytes at \p ct into \p pt.
///
/// \p pt may alias \p ct.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_CRYPTO, or #MC_ERR_AUTH if
///         the tag did not verify — in which case \p pt holds no meaningful
///         data and the caller must not use it. Callers in this library wipe
///         it; see crypt/decrypt.cc.
mc_status Open(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad,
               size_t aad_size, const uint8_t* ct, size_t ct_size,
               const uint8_t* tag, uint8_t* pt);

}  // namespace aead

#endif  // MODEL_CRYPT_SRC_CRYPT_AEAD_H_
