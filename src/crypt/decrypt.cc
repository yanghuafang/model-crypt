#include "crypt/decrypt.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include "crypt/aead.h"
#include "crypt/compress.h"
#include "crypt/format.h"
#include "crypt/kdf.h"
#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

// See crypt/decrypt.h for the three phases and why the plaintext allocation
// happens only after chunk 0 authenticates the header.

namespace decrypt {

namespace {

// One entry per chunk, recorded by the phase-1 walk so the file is traversed
// once and the "table adds up to exactly the input length" check happens before
// any key work.
struct ChunkEntry {
  size_t offset = 0;
  format::ChunkHeader header;
  uint8_t tag[format::kTagSize] = {};
};

size_t ChunkPlainSize(uint64_t plaintext_size, uint32_t chunk_size,
                      uint32_t index) {
  const uint64_t offset = static_cast<uint64_t>(index) * chunk_size;
  if (offset >= plaintext_size) {
    return 0;
  }

  const uint64_t remaining = plaintext_size - offset;
  return remaining < chunk_size ? static_cast<size_t>(remaining) : chunk_size;
}

// Phase 1. Structural validation of the chunk table: no key, no allocation
// beyond the table. Establishes that every record is present, every stored_size
// is backed by bytes that exist, and an uncompressed chunk stores exactly what
// it must decrypt to -- so phase 3 can be a straight loop.
mc_status WalkChunkTable(const uint8_t* in, size_t in_size,
                         const format::FileHeader& header,
                         SecureBuffer* entry_storage,
                         uint32_t* max_compressed) {
  const uint32_t max_stored_size = format::MaxStoredSizeFor(header.chunk_size);
  *max_compressed = 0;

  // The file must contain chunk_count records before a table of that many is
  // allocated. chunk_count comes from plaintext_size, which ParseFileHeader
  // only range-checks: without this, an 88-byte header claiming 64 GiB at the
  // minimum chunk size declares 16.7 M chunks and allocates half a gigabyte
  // before the loop rejects it. With it, the table is bounded by the input.
  const uint64_t minimum_input =
      format::kHeaderSize +
      (static_cast<uint64_t>(header.chunk_count) * format::kChunkHeaderSize);
  if (in_size < minimum_input) {
    return MC_ERR_FORMAT;
  }

  const uint64_t table_bytes =
      static_cast<uint64_t>(header.chunk_count) * sizeof(ChunkEntry);
  if (table_bytes > SIZE_MAX) {
    return MC_ERR_TOO_LARGE;
  }

  if (!entry_storage->Reset(static_cast<size_t>(table_bytes))) {
    return MC_ERR_MEMORY;
  }

  // A SecureBuffer of bytes rather than std::vector<ChunkEntry>: Reset()
  // reports allocation failure as a bool, where a vector would throw
  // std::bad_alloc across the C API boundary. ChunkEntry is trivially copyable
  // and default-constructed by Reset()'s zero fill, so no placement-new.
  auto* entries = reinterpret_cast<ChunkEntry*>(entry_storage->data());

  size_t offset = format::kHeaderSize;
  for (uint32_t index = 0; index < header.chunk_count; ++index) {
    if (in_size - offset < format::kChunkHeaderSize) {
      return MC_ERR_FORMAT;
    }

    ChunkEntry& entry = entries[index];
    const mc_status rc = format::ParseChunkHeader(in + offset, max_stored_size,
                                                  &entry.header, entry.tag);
    if (rc != MC_OK) {
      return rc;
    }

    offset += format::kChunkHeaderSize;

    // Subtraction, not addition: `offset + stored_size` can wrap on a 32-bit
    // host, and a wrapped comparison passes. in_size >= offset holds because
    // the check above only advanced offset after confirming the room for it.
    if (in_size - offset < entry.header.stored_size) {
      return MC_ERR_FORMAT;
    }

    entry.offset = offset;
    offset += entry.header.stored_size;

    const size_t plain_size =
        ChunkPlainSize(header.plaintext_size, header.chunk_size, index);
    const bool compressed =
        (entry.header.flags & format::kChunkFlagCompressed) != 0;
    if (!compressed && entry.header.stored_size != plain_size) {
      return MC_ERR_FORMAT;
    }

    // A compressed chunk that stores nothing cannot inflate to anything, and a
    // zero-length chunk is never marked compressed by this encoder.
    if (compressed && entry.header.stored_size == 0) {
      return MC_ERR_FORMAT;
    }

    // Not redundant with ParseChunkHeader's flag mask, which rejects only
    // *unknown* bits: a header claiming MC_COMPRESS_NONE alongside a compressed
    // chunk would reach phase 3 and use an inflate scratch that was never
    // allocated, since that allocation is conditional on the header.
    if (compressed && header.compression_id != MC_COMPRESS_ZLIB) {
      return MC_ERR_FORMAT;
    }

    // Recorded so the inflate scratch can be sized to the largest chunk this
    // file actually carries, rather than to the largest one its chunk_size
    // would permit. See the allocation in DecryptBuffer.
    if (compressed && entry.header.stored_size > *max_compressed) {
      *max_compressed = entry.header.stored_size;
    }
  }

  // Exactly, not "at least". Bytes after the last chunk are outside every tag,
  // so accepting them would let two different files decrypt to the same
  // plaintext and both report MC_OK.
  if (offset != in_size) {
    return MC_ERR_FORMAT;
  }

  return MC_OK;
}

// Open one chunk into `plain_out`, which must have room for its exact plaintext
// length. `scratch` is used only for a compressed chunk, where the AEAD output
// is a deflate stream that must be inflated elsewhere; a raw chunk decrypts
// straight into plain_out.
mc_status OpenChunk(const uint8_t* derived_key,
                    const uint8_t serialized_header[format::kHeaderSize],
                    const format::FileHeader& header, uint32_t index,
                    const ChunkEntry& entry, const uint8_t* in,
                    uint8_t* plain_out, size_t plain_size,
                    SecureBuffer* scratch) {
  uint8_t aad[format::kAadSize];
  format::BuildAad(serialized_header, index, entry.header, aad);

  uint8_t nonce[format::kNonceSize];
  format::BuildNonce(header.nonce_prefix, index, nonce);

  const bool compressed =
      (entry.header.flags & format::kChunkFlagCompressed) != 0;
  uint8_t* aead_out = compressed ? scratch->data() : plain_out;

  const mc_status rc =
      aead::Open(derived_key, nonce, aad, sizeof(aad), in + entry.offset,
                 entry.header.stored_size, entry.tag, aead_out);
  if (rc != MC_OK) {
    // On MC_ERR_AUTH the AEAD has already written the unverified decryption.
    // Those bytes are attacker-influenced, so wipe rather than leave them in a
    // buffer that outlives this call.
    if (compressed) {
      SecureWipe(scratch->data(), entry.header.stored_size);
    } else {
      SecureWipe(plain_out, plain_size);
    }

    return rc;
  }

  if (!compressed) {
    return MC_OK;
  }

  // plain_size comes from the authenticated header, not from the stream.
  // inflate is told exactly that many bytes and fails on anything else, which
  // is what makes a decompression bomb impossible rather than merely bounded.
  return compression::DecompressChunk(scratch->data(), entry.header.stored_size,
                                      plain_out, plain_size);
}

}  // namespace

mc_status InspectBuffer(const uint8_t* in, size_t in_size, mc_file_info* info) {
  if (in == nullptr || info == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  format::FileHeader header;
  const mc_status rc = format::ParseFileHeader(in, in_size, &header);
  if (rc != MC_OK) {
    return rc;
  }

  info->format_version = header.format_version;
  info->compression = static_cast<mc_compression>(header.compression_id);
  info->plaintext_size = header.plaintext_size;
  info->chunk_size = header.chunk_size;
  info->chunk_count = header.chunk_count;
  info->kdf_log_n = header.kdf_log_n;
  info->kdf_r = header.kdf_r;
  info->kdf_p = header.kdf_p;
  return MC_OK;
}

mc_status DecryptBuffer(const uint8_t* key, size_t key_size, const uint8_t* in,
                        size_t in_size, SecureBuffer* out, size_t* out_size) {
  if (key == nullptr || in == nullptr || out == nullptr ||
      out_size == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (key_size < MC_MIN_KEY_SIZE) {
    return MC_ERR_INVALID_ARG;
  }

  // ---- Phase 1: parse, with no key and no large allocation ----

  format::FileHeader header;
  mc_status rc = format::ParseFileHeader(in, in_size, &header);
  if (rc != MC_OK) {
    return rc;
  }

  SecureBuffer entry_storage;
  uint32_t max_compressed = 0;
  rc = WalkChunkTable(in, in_size, header, &entry_storage, &max_compressed);
  if (rc != MC_OK) {
    return rc;
  }

  const auto* entries =
      reinterpret_cast<const ChunkEntry*>(entry_storage.data());

  // The AAD is the header bytes as they appear in the file, which is why this
  // points into the input rather than re-serializing `header`. See BuildAad.
  const uint8_t* serialized_header = in;

  SecureBuffer derived_key;
  rc = kdf::DeriveKey(key, key_size, header.salt, format::kSaltSize,
                      header.kdf_log_n, header.kdf_r, header.kdf_p,
                      &derived_key);
  if (rc != MC_OK) {
    return rc;
  }

  // Sized from the table, not chunk_size: the largest deflated chunk actually
  // present, which the walk confirmed is backed by real bytes. Sizing from
  // MaxStoredSizeFor(chunk_size) would let a small file with a 64 MiB
  // chunk_size claim 64 MiB it never fills -- before chunk 0 authenticates
  // anything. Zero when nothing is compressed.
  SecureBuffer scratch;
  if (max_compressed > 0 && !scratch.Reset(max_compressed)) {
    return MC_ERR_MEMORY;
  }

  // ---- Phase 2: authenticate the header via chunk 0 ----

  const size_t first_plain_size =
      ChunkPlainSize(header.plaintext_size, header.chunk_size, 0);

  SecureBuffer first_chunk;
  if (!first_chunk.Reset(first_plain_size)) {
    return MC_ERR_MEMORY;
  }

  rc = OpenChunk(derived_key.data(), serialized_header, header, 0, entries[0],
                 in, first_chunk.data(), first_plain_size, &scratch);
  if (rc != MC_OK) {
    return rc;
  }

  // ---- Phase 3: allocate on an authenticated size, then finish ----

  if (header.plaintext_size > SIZE_MAX) {
    return MC_ERR_TOO_LARGE;
  }

  SecureBuffer plaintext;
  if (!plaintext.Reset(static_cast<size_t>(header.plaintext_size))) {
    return MC_ERR_MEMORY;
  }

  // An empty model is legitimate: both buffers are then zero-length with null
  // data(), and memcpy with a null argument is undefined even for zero count.
  if (first_plain_size > 0) {
    std::memcpy(plaintext.data(), first_chunk.data(), first_plain_size);
  }

  for (uint32_t index = 1; index < header.chunk_count; ++index) {
    const size_t plain_size =
        ChunkPlainSize(header.plaintext_size, header.chunk_size, index);
    uint8_t* plain_out =
        plaintext.data() + (static_cast<uint64_t>(index) * header.chunk_size);

    rc = OpenChunk(derived_key.data(), serialized_header, header, index,
                   entries[index], in, plain_out, plain_size, &scratch);
    if (rc != MC_OK) {
      // `plaintext` is a SecureBuffer, so the chunks already recovered are
      // wiped here rather than released to the heap.
      return rc;
    }
  }

  *out = std::move(plaintext);
  *out_size = static_cast<size_t>(header.plaintext_size);
  return MC_OK;
}

}  // namespace decrypt
