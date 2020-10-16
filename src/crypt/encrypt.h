#ifndef MODEL_CRYPT_SRC_CRYPT_ENCRYPT_H_
#define MODEL_CRYPT_SRC_CRYPT_ENCRYPT_H_

#include <cstddef>
#include <cstdint>

#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

/// Assembling a `.mcrypt` file: header, then one sealed chunk per slice of
/// plaintext.
///
/// This layer decides only two things, both per chunk: whether deflate helped,
/// and which nonce the chunk gets. Salt, key and layout are fixed before the
/// first chunk is written.
///
/// The output buffer is allocated at the worst case -- no chunk compresses --
/// because the exact size is not known until every chunk has been compressed,
/// and compressing twice would double the CPU cost on a multi-gigabyte model.
/// The worst case is `plaintext_size + 24 * chunk_count + 64`, about 0.001%
/// over at the default chunk size. For a very compressible model the slack is
/// not noise, so the buffer is copied down when it exceeds #kShrinkThreshold.
namespace encrypt {

/// Slack above which EncryptBuffer copies its output down to the exact size.
///
/// 1 MiB: below this the copy costs more than the memory it returns, and the
/// caller is about to write the buffer to a file or a socket anyway.
inline constexpr size_t kShrinkThreshold = 1u << 20;

/// Encrypt \p in_size bytes at \p in under \p key.
///
/// \param key       Caller's key or passphrase; at least #MC_MIN_KEY_SIZE.
/// \param key_size   Its length.
/// \param opts      Validated options. Never NULL — the C API substitutes the
///                  defaults before calling, so this layer has no "or NULL for
///                  defaults" case to carry.
/// \param in        Plaintext; may be NULL only when \p in_size is 0.
/// \param in_size    Plaintext length.
/// \param out       Receives the finished file.
/// \param out_size   Receives its length, which may be less than out->size().
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_TOO_LARGE, #MC_ERR_MEMORY,
///         #MC_ERR_CRYPTO, or #MC_ERR_COMPRESS.
mc_status EncryptBuffer(const uint8_t* key, size_t key_size,
                        const mc_encrypt_options& opts, const uint8_t* in,
                        size_t in_size, SecureBuffer* out, size_t* out_size);

/// Check \p opts against the ranges documented on #mc_encrypt_options.
///
/// Separate from EncryptBuffer so the CLI can reject a bad `--chunk-size` with
/// a message naming the option, rather than reporting the generic
/// #MC_ERR_INVALID_ARG the C API returns.
///
/// \return #MC_OK or #MC_ERR_INVALID_ARG.
mc_status ValidateOptions(const mc_encrypt_options& opts);

}  // namespace encrypt

#endif  // MODEL_CRYPT_SRC_CRYPT_ENCRYPT_H_
