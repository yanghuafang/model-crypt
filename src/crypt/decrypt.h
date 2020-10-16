#ifndef MODEL_CRYPT_SRC_CRYPT_DECRYPT_H_
#define MODEL_CRYPT_SRC_CRYPT_DECRYPT_H_

#include <cstddef>
#include <cstdint>

#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

/// Reading a `.mcrypt` file back.
///
/// Three phases, in this order so a hostile file cannot provoke a large
/// allocation before it has proven it knows the key:
///
/// 1. Parse. Header ranges, then the chunk table walked record by record; the
///    walk must land exactly on the end of the input. No key is used. The table
///    is itself sized from `chunk_count`, so the walk first requires the input
///    to hold that many records -- otherwise an 88-byte header claiming 64 GiB
///    of plaintext allocates half a gigabyte.
/// 2. Authenticate. Chunk 0 is opened into a buffer of at most `chunk_size`.
///    Its tag covers the whole header, which is what makes `plaintext_size`
///    trustworthy.
/// 3. Allocate the plaintext on that authenticated size, then open the rest
///    into it.
///
/// The invariant to preserve: every allocation before the key is proven is
/// bounded either by the input's own size or by one chunk (4 MiB default,
/// 64 MiB ceiling). It is not visible from any single line, so re-check it when
/// adding an allocation to phase 1 or 2.
///
/// On failure nothing survives: every buffer is a SecureBuffer, so an
/// #MC_ERR_AUTH on chunk 7 of 400 wipes the six already recovered. AES-GCM
/// emits the failing chunk's plaintext before checking the tag, so that is
/// wiped too.
namespace decrypt {

/// Decrypt and authenticate the \p in_size bytes at \p in under \p key.
///
/// \param out      Receives the plaintext, exactly \p *out_size bytes.
/// \param out_size  Receives the length, which equals the authenticated
///                 `plaintext_size` from the header.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_FORMAT, #MC_ERR_UNSUPPORTED,
///         #MC_ERR_AUTH, #MC_ERR_COMPRESS, #MC_ERR_TOO_LARGE, #MC_ERR_MEMORY,
///         or #MC_ERR_CRYPTO. On any failure neither out-parameter is written.
mc_status DecryptBuffer(const uint8_t* key, size_t key_size, const uint8_t* in,
                        size_t in_size, SecureBuffer* out, size_t* out_size);

/// Read the file header of \p in into \p info without using a key.
///
/// Backs mc_inspect_buffer. Nothing it reports is authenticated.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_FORMAT, or
///         #MC_ERR_UNSUPPORTED.
mc_status InspectBuffer(const uint8_t* in, size_t in_size, mc_file_info* info);

}  // namespace decrypt

#endif  // MODEL_CRYPT_SRC_CRYPT_DECRYPT_H_
