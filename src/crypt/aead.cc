#include "crypt/aead.h"

#include <cstddef>
#include <cstdint>
#include <memory>

#include <openssl/evp.h>

#include "crypt/format.h"
#include "model_crypt/model_crypt.h"

// See crypt/aead.h for why this is an AEAD rather than a cipher, and for
// where nonce uniqueness is actually enforced (format::BuildNonce, not here).

namespace aead {

namespace {

struct CipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

// EVP_*Update takes int lengths. A size_t that does not fit would be silently
// truncated, encrypting a prefix and authenticating a different length than the
// caller believes. Unreachable at the format's current limits, but those live
// in another file and could move.
bool FitsInInt(size_t size) { return size <= static_cast<size_t>(INT32_MAX); }

// Identical for seal and open except the direction flag. Split here rather than
// parameterizing the whole operation, so the tag handling -- genuinely
// different in the two directions -- stays explicit at each call site.
mc_status Begin(EVP_CIPHER_CTX* ctx, const uint8_t* key, const uint8_t* nonce,
                const uint8_t* aad, size_t aad_size, int encrypt) {
  if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr,
                        encrypt) != 1) {
    return MC_ERR_CRYPTO;
  }

  // Nonce length before the key and nonce: a nonce installed first would be
  // read at the old default.
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                          static_cast<int>(format::kNonceSize), nullptr) != 1) {
    return MC_ERR_CRYPTO;
  }

  if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key, nonce, encrypt) != 1) {
    return MC_ERR_CRYPTO;
  }

  if (aad != nullptr && aad_size > 0) {
    int written = 0;
    if (EVP_CipherUpdate(ctx, nullptr, &written, aad,
                         static_cast<int>(aad_size)) != 1) {
      return MC_ERR_CRYPTO;
    }
  }

  return MC_OK;
}

}  // namespace

mc_status Seal(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad,
               size_t aad_size, const uint8_t* pt, size_t pt_size, uint8_t* ct,
               uint8_t* tag) {
  if (key == nullptr || nonce == nullptr || tag == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  // A zero-length payload is legitimate -- the empty model's single chunk is
  // exactly that, and its tag authenticates the header. Only a pointer/length
  // disagreement is an error.
  if (pt_size > 0 && (pt == nullptr || ct == nullptr)) {
    return MC_ERR_INVALID_ARG;
  }

  if (!FitsInInt(pt_size) || !FitsInInt(aad_size)) {
    return MC_ERR_INVALID_ARG;
  }

  CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return MC_ERR_CRYPTO;
  }

  const mc_status rc = Begin(ctx.get(), key, nonce, aad, aad_size, 1);
  if (rc != MC_OK) {
    return rc;
  }

  if (pt_size > 0) {
    int written = 0;
    if (EVP_CipherUpdate(ctx.get(), ct, &written, pt,
                         static_cast<int>(pt_size)) != 1) {
      return MC_ERR_CRYPTO;
    }
  }

  // GCM is a stream mode, so Final emits no ciphertext -- but it finishes GHASH
  // and makes the tag readable.
  int final_written = 0;
  if (EVP_CipherFinal_ex(ctx.get(), nullptr, &final_written) != 1) {
    return MC_ERR_CRYPTO;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                          static_cast<int>(format::kTagSize), tag) != 1) {
    return MC_ERR_CRYPTO;
  }

  return MC_OK;
}

mc_status Open(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad,
               size_t aad_size, const uint8_t* ct, size_t ct_size,
               const uint8_t* tag, uint8_t* pt) {
  if (key == nullptr || nonce == nullptr || tag == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (ct_size > 0 && (ct == nullptr || pt == nullptr)) {
    return MC_ERR_INVALID_ARG;
  }

  if (!FitsInInt(ct_size) || !FitsInInt(aad_size)) {
    return MC_ERR_INVALID_ARG;
  }

  CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return MC_ERR_CRYPTO;
  }

  const mc_status rc = Begin(ctx.get(), key, nonce, aad, aad_size, 0);
  if (rc != MC_OK) {
    return rc;
  }

  if (ct_size > 0) {
    int written = 0;
    if (EVP_CipherUpdate(ctx.get(), pt, &written, ct,
                         static_cast<int>(ct_size)) != 1) {
      return MC_ERR_CRYPTO;
    }
  }

  // The expected tag must be installed before Final, where the comparison
  // happens. By then `pt` already holds the unverified decryption --
  // unavoidable in a streaming mode, and why the contract says the caller must
  // not use `pt` on failure. decrypt.cc wipes it.
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                          static_cast<int>(format::kTagSize),
                          const_cast<uint8_t*>(tag)) != 1) {
    return MC_ERR_CRYPTO;
  }

  int final_written = 0;
  if (EVP_CipherFinal_ex(ctx.get(), nullptr, &final_written) != 1) {
    // The only documented reason Final fails in decrypt mode is a tag mismatch,
    // compared in constant time. Reporting MC_ERR_AUTH rather than
    // MC_ERR_CRYPTO lets a caller tell it from "OpenSSL is broken".
    return MC_ERR_AUTH;
  }

  return MC_OK;
}

}  // namespace aead
