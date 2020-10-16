#include "crypt/format.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model_crypt/model_crypt.h"

// See crypt/format.h for the layout and for why the AAD covers the header
// bytes as written rather than a re-serialization of the parsed struct.

namespace format {

namespace {

// Little-endian by hand, in both directions.
//
// Not a memcpy of a packed struct: that reads and writes host order, so a file
// written on one endianness would be silently unreadable on the other. Explicit
// shifts make byte order a property of the code, and fold to one instruction on
// a little-endian target.
//
// The casts to uint32_t before shifting matter: uint8_t promotes to int, so
// `in[3] << 24` on a byte >= 0x80 shifts into the sign bit, which is undefined.

void WriteU8(uint8_t* out, uint8_t value) { out[0] = value; }

void WriteU16(uint8_t* out, uint16_t value) {
  // Through `unsigned` rather than straight off the uint16_t: integer promotion
  // turns a uint16_t into a signed int before the shift, so the value being
  // shifted is signed even though nothing here can be negative.
  const unsigned widened = value;
  out[0] = static_cast<uint8_t>(widened & 0xFFu);
  out[1] = static_cast<uint8_t>((widened >> 8) & 0xFFu);
}

void WriteU32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value & 0xFFu);
  out[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  out[2] = static_cast<uint8_t>((value >> 16) & 0xFFu);
  out[3] = static_cast<uint8_t>((value >> 24) & 0xFFu);
}

void WriteU64(uint8_t* out, uint64_t value) {
  for (size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFFu);
  }
}

uint8_t ReadU8(const uint8_t* in) { return in[0]; }

uint16_t ReadU16(const uint8_t* in) {
  return static_cast<uint16_t>(static_cast<uint16_t>(in[0]) |
                               static_cast<uint16_t>(in[1] << 8));
}

uint32_t ReadU32(const uint8_t* in) {
  return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
         (static_cast<uint32_t>(in[2]) << 16) |
         (static_cast<uint32_t>(in[3]) << 24);
}

uint64_t ReadU64(const uint8_t* in) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(in[i]) << (8 * i);
  }

  return value;
}

// Field offsets. docs/Format.md holds the same table for anyone implementing
// the format elsewhere.
constexpr size_t kOffMagic = 0;
constexpr size_t kOffVersion = 8;
constexpr size_t kOffKdfId = 10;
constexpr size_t kOffAeadId = 11;
constexpr size_t kOffCompressionId = 12;
constexpr size_t kOffKdfLogN = 13;
constexpr size_t kOffKdfR = 14;
constexpr size_t kOffKdfP = 18;
constexpr size_t kOffSalt = 22;
constexpr size_t kOffNoncePrefix = 38;
constexpr size_t kOffChunkSize = 46;
constexpr size_t kOffPlaintextSize = 50;
constexpr size_t kOffChunkCount = 58;
constexpr size_t kOffHeaderReserved = 62;

constexpr size_t kOffChunkStoredSize = 0;
constexpr size_t kOffChunkFlags = 4;
constexpr size_t kOffChunkReserved = 5;
constexpr size_t kOffChunkTag = 8;

static_assert(kOffHeaderReserved + 2 == kHeaderSize,
              "file header fields must exactly fill kHeaderSize");
static_assert(kOffChunkTag + kTagSize == kChunkHeaderSize,
              "chunk header fields must exactly fill kChunkHeaderSize");

}  // namespace

uint32_t ChunkCountFor(uint64_t plaintext_size, uint32_t chunk_size) {
  // One chunk, not zero: an empty file still needs something whose tag covers
  // the header, or anyone could forge one. See format.h.
  if (plaintext_size == 0) {
    return 1;
  }

  const uint64_t count =
      (plaintext_size + chunk_size - 1) / static_cast<uint64_t>(chunk_size);
  return static_cast<uint32_t>(count);
}

uint32_t MaxStoredSizeFor(uint32_t chunk_size) {
  // zlib's documented worst case is sourceLen + sourceLen/1000 + 12 plus a
  // small header. The encryptor never emits an expanded chunk (it stores raw
  // instead), so this exists only to give the decoder a number to reject above.
  const uint64_t bound =
      static_cast<uint64_t>(chunk_size) + (chunk_size / 1000) + 64;
  return static_cast<uint32_t>(bound);
}

void SerializeFileHeader(const FileHeader& header, uint8_t out[kHeaderSize]) {
  std::memset(out, 0, kHeaderSize);
  std::memcpy(out + kOffMagic, kMagic, kMagicSize);
  WriteU16(out + kOffVersion, header.format_version);
  WriteU8(out + kOffKdfId, header.kdf_id);
  WriteU8(out + kOffAeadId, header.aead_id);
  WriteU8(out + kOffCompressionId, header.compression_id);
  WriteU8(out + kOffKdfLogN, header.kdf_log_n);
  WriteU32(out + kOffKdfR, header.kdf_r);
  WriteU32(out + kOffKdfP, header.kdf_p);
  std::memcpy(out + kOffSalt, header.salt, kSaltSize);
  std::memcpy(out + kOffNoncePrefix, header.nonce_prefix, kNoncePrefixSize);
  WriteU32(out + kOffChunkSize, header.chunk_size);
  WriteU64(out + kOffPlaintextSize, header.plaintext_size);
  WriteU32(out + kOffChunkCount, header.chunk_count);
  WriteU16(out + kOffHeaderReserved, 0);
}

// Order matters: identity first, then capability, then the arithmetic
// preconditions downstream assumes. Validating sizes before the magic would
// report MC_ERR_TOO_LARGE for a JPEG.
mc_status ParseFileHeader(const uint8_t* in, size_t in_size,
                          FileHeader* header) {
  if (in == nullptr || header == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (in_size < kHeaderSize) {
    return MC_ERR_FORMAT;
  }

  if (std::memcmp(in + kOffMagic, kMagic, kMagicSize) != 0) {
    return MC_ERR_FORMAT;
  }

  FileHeader parsed;
  parsed.format_version = ReadU16(in + kOffVersion);
  if (parsed.format_version != MC_FORMAT_VERSION) {
    return MC_ERR_UNSUPPORTED;
  }

  parsed.kdf_id = ReadU8(in + kOffKdfId);
  parsed.aead_id = ReadU8(in + kOffAeadId);
  if (parsed.kdf_id != kKdfScrypt || parsed.aead_id != kAeadAes256Gcm) {
    return MC_ERR_UNSUPPORTED;
  }

  parsed.compression_id = ReadU8(in + kOffCompressionId);
  if (parsed.compression_id != MC_COMPRESS_NONE &&
      parsed.compression_id != MC_COMPRESS_ZLIB) {
    return MC_ERR_UNSUPPORTED;
  }

  // Reserved must be zero so the field stays available: a reader that ignored
  // it would keep accepting files whose meaning it no longer understands.
  if (ReadU16(in + kOffHeaderReserved) != 0) {
    return MC_ERR_FORMAT;
  }

  parsed.kdf_log_n = ReadU8(in + kOffKdfLogN);
  parsed.kdf_r = ReadU32(in + kOffKdfR);
  parsed.kdf_p = ReadU32(in + kOffKdfP);
  if (parsed.kdf_log_n < kMinKdfLogN || parsed.kdf_log_n > kMaxKdfLogN ||
      parsed.kdf_r < kMinKdfR || parsed.kdf_r > kMaxKdfR ||
      parsed.kdf_p < kMinKdfP || parsed.kdf_p > kMaxKdfP) {
    return MC_ERR_UNSUPPORTED;
  }

  // The ranges bound each parameter; this bounds what they cost together.
  // uint64_t because the product overflows 32 bits inside the permitted ranges.
  const uint64_t kdf_memory =
      128ull * (1ull << parsed.kdf_log_n) * parsed.kdf_r;
  if (kdf_memory > kMaxKdfMemory) {
    return MC_ERR_UNSUPPORTED;
  }

  std::memcpy(parsed.salt, in + kOffSalt, kSaltSize);
  std::memcpy(parsed.nonce_prefix, in + kOffNoncePrefix, kNoncePrefixSize);

  parsed.chunk_size = ReadU32(in + kOffChunkSize);
  if (parsed.chunk_size < kMinChunkSize || parsed.chunk_size > kMaxChunkSize) {
    return MC_ERR_FORMAT;
  }

  parsed.plaintext_size = ReadU64(in + kOffPlaintextSize);
  if (parsed.plaintext_size > MC_MAX_PLAINTEXT_SIZE) {
    return MC_ERR_TOO_LARGE;
  }

  // Recomputed and compared rather than trusted, so every later
  // "for i in 0..chunk_count" has a bound known to match the declared size.
  parsed.chunk_count = ReadU32(in + kOffChunkCount);
  if (parsed.chunk_count !=
      ChunkCountFor(parsed.plaintext_size, parsed.chunk_size)) {
    return MC_ERR_FORMAT;
  }

  *header = parsed;
  return MC_OK;
}

void SerializeChunkHeader(const ChunkHeader& chunk, const uint8_t tag[kTagSize],
                          uint8_t out[kChunkHeaderSize]) {
  std::memset(out, 0, kChunkHeaderSize);
  WriteU32(out + kOffChunkStoredSize, chunk.stored_size);
  WriteU8(out + kOffChunkFlags, chunk.flags);
  std::memcpy(out + kOffChunkTag, tag, kTagSize);
}

mc_status ParseChunkHeader(const uint8_t* in, uint32_t max_stored_size,
                           ChunkHeader* chunk, uint8_t tag[kTagSize]) {
  if (in == nullptr || chunk == nullptr || tag == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  ChunkHeader parsed;
  parsed.stored_size = ReadU32(in + kOffChunkStoredSize);
  parsed.flags = ReadU8(in + kOffChunkFlags);

  // `~` promotes the uint8_t mask to int and yields a negative value; the cast
  // brings the complement back into the width the flags actually occupy. Same
  // result for an 8-bit field, without the signed intermediate.
  if ((parsed.flags & static_cast<uint8_t>(~kChunkFlagMask)) != 0) {
    return MC_ERR_FORMAT;
  }

  for (size_t i = 0; i < kOffChunkTag - kOffChunkReserved; ++i) {
    if (in[kOffChunkReserved + i] != 0) {
      return MC_ERR_FORMAT;
    }
  }

  if (parsed.stored_size > max_stored_size) {
    return MC_ERR_FORMAT;
  }

  std::memcpy(tag, in + kOffChunkTag, kTagSize);
  *chunk = parsed;
  return MC_OK;
}

void BuildAad(const uint8_t serialized_header[kHeaderSize],
              uint32_t chunk_index, const ChunkHeader& chunk,
              uint8_t out[kAadSize]) {
  std::memcpy(out, serialized_header, kHeaderSize);
  WriteU32(out + kHeaderSize, chunk_index);
  WriteU32(out + kHeaderSize + 4, chunk.stored_size);
  WriteU8(out + kHeaderSize + 8, chunk.flags);
}

void BuildNonce(const uint8_t nonce_prefix[kNoncePrefixSize],
                uint32_t chunk_index, uint8_t out[kNonceSize]) {
  std::memcpy(out, nonce_prefix, kNoncePrefixSize);

  // Big-endian, matching NIST SP 800-38D's GCM counter block. Any injective
  // encoding would do; matching the spec avoids a byte-order surprise for a
  // reader checking this against it.
  out[kNoncePrefixSize + 0] = static_cast<uint8_t>((chunk_index >> 24) & 0xFFu);
  out[kNoncePrefixSize + 1] = static_cast<uint8_t>((chunk_index >> 16) & 0xFFu);
  out[kNoncePrefixSize + 2] = static_cast<uint8_t>((chunk_index >> 8) & 0xFFu);
  out[kNoncePrefixSize + 3] = static_cast<uint8_t>(chunk_index & 0xFFu);
}

}  // namespace format
