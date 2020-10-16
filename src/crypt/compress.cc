#include "crypt/compress.h"

#include <cstddef>
#include <cstdint>

#include <zlib.h>

#include "model_crypt/model_crypt.h"

// See crypt/compress.h for why every call states its output size up front.

namespace compression {

namespace {

// z_stream takes uInt lengths and drives long inputs by refilling avail_in. A
// chunk is at most 64 MiB, so these do a single pass and reject anything that
// would not fit -- rather than carrying a refill loop no input can reach and no
// test can cover.
bool FitsInUInt(size_t size) { return size <= static_cast<size_t>(UINT32_MAX); }

}  // namespace

mc_status CompressChunk(const uint8_t* in, size_t in_size, uint8_t* out,
                        size_t out_capacity, size_t* out_size, bool* smaller) {
  if (in == nullptr || out == nullptr || out_size == nullptr ||
      smaller == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (!FitsInUInt(in_size) || !FitsInUInt(out_capacity)) {
    return MC_ERR_INVALID_ARG;
  }

  z_stream stream = {};
  if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
    return MC_ERR_MEMORY;
  }

  stream.next_in = const_cast<Bytef*>(static_cast<const Bytef*>(in));
  stream.avail_in = static_cast<uInt>(in_size);
  stream.next_out = static_cast<Bytef*>(out);
  stream.avail_out = static_cast<uInt>(out_capacity);

  const int rc = deflate(&stream, Z_FINISH);
  const uLong produced = stream.total_out;
  deflateEnd(&stream);

  // Z_OK after Z_FINISH means it ran out of output room, i.e. the chunk
  // expanded past the worst-case bound. "Not smaller" rather than an error: the
  // caller then stores it raw, which is the right answer for such a chunk.
  if (rc != Z_STREAM_END) {
    if (rc == Z_OK || rc == Z_BUF_ERROR) {
      *out_size = 0;
      *smaller = false;
      return MC_OK;
    }

    return MC_ERR_COMPRESS;
  }

  *out_size = static_cast<size_t>(produced);
  *smaller = static_cast<size_t>(produced) < in_size;
  return MC_OK;
}

mc_status DecompressChunk(const uint8_t* in, size_t in_size, uint8_t* out,
                          size_t out_size) {
  if (in == nullptr || (out_size > 0 && out == nullptr)) {
    return MC_ERR_INVALID_ARG;
  }

  if (!FitsInUInt(in_size) || !FitsInUInt(out_size)) {
    return MC_ERR_INVALID_ARG;
  }

  z_stream stream = {};
  if (inflateInit(&stream) != Z_OK) {
    return MC_ERR_MEMORY;
  }

  stream.next_in = const_cast<Bytef*>(static_cast<const Bytef*>(in));
  stream.avail_in = static_cast<uInt>(in_size);
  stream.next_out = static_cast<Bytef*>(out);
  stream.avail_out = static_cast<uInt>(out_size);

  const int rc = inflate(&stream, Z_FINISH);
  const uLong produced = stream.total_out;
  const uInt remaining_in = stream.avail_in;
  inflateEnd(&stream);

  // All three are required. Z_STREAM_END alone says the stream ended cleanly,
  // not that it produced what was promised -- a short stream also ends cleanly
  // and would leave the tail of `out` holding whatever was there before. A
  // stream that decodes to more than out_size cannot reach Z_STREAM_END at all,
  // because avail_out hits zero and inflate returns Z_BUF_ERROR. The
  // trailing-input check rejects bytes appended after a complete stream, which
  // would otherwise make the format ambiguous.
  if (rc != Z_STREAM_END || static_cast<size_t>(produced) != out_size ||
      remaining_in != 0) {
    return MC_ERR_COMPRESS;
  }

  return MC_OK;
}

}  // namespace compression
