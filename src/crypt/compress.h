#ifndef MODEL_CRYPT_SRC_CRYPT_COMPRESS_H_
#define MODEL_CRYPT_SRC_CRYPT_COMPRESS_H_

#include <cstddef>
#include <cstdint>

#include "model_crypt/model_crypt.h"

/// Bounded zlib wrappers, applied per chunk before encryption.
///
/// inflate() is never asked to discover an output size: the caller states the
/// exact number of bytes it expects -- from an *authenticated* header -- and
/// the call fails if the stream produces more or fewer. A decompression bomb
/// cannot expand past the buffer because the buffer is never grown.
///
/// Compression is decided per chunk. Weights compress unevenly: an fp32 tensor
/// may shrink while a quantized one is near-random and inflates. CompressChunk
/// reports when the result is not smaller, and the encryptor then stores the
/// chunk raw, so output never exceeds input plus per-chunk overhead.
// `compression`, not `compress`: zlib.h declares a global function named
// compress(), and a namespace of that name makes every translation unit that
// includes both fail to compile with "redefinition of 'compress' as a different
// kind of symbol". The file keeps its name; only the namespace moves.
namespace compression {

/// Deflate \p in_size bytes at \p in into \p out.
///
/// \param out      Buffer of \p out_capacity bytes. Pass
///                 format::MaxStoredSizeFor() so a chunk that expands still
///                 fits.
/// \param out_size  Receives the compressed length on success.
/// \param smaller  Receives whether compression actually helped. When false,
///                 the caller should store the chunk raw; \p out still holds
///                 a valid deflate stream, it is simply not worth using.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_MEMORY, or #MC_ERR_COMPRESS.
mc_status CompressChunk(const uint8_t* in, size_t in_size, uint8_t* out,
                        size_t out_capacity, size_t* out_size, bool* smaller);

/// Inflate \p in_size bytes at \p in into exactly \p out_size bytes at \p out.
///
/// Exactly: a stream that decompresses to any other length is rejected rather
/// than truncated or zero-padded. See the note on bounding above.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, #MC_ERR_MEMORY, or #MC_ERR_COMPRESS.
mc_status DecompressChunk(const uint8_t* in, size_t in_size, uint8_t* out,
                          size_t out_size);

}  // namespace compression

#endif  // MODEL_CRYPT_SRC_CRYPT_COMPRESS_H_
