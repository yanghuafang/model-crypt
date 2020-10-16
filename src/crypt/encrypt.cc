#include "crypt/encrypt.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include "crypt/aead.h"
#include "crypt/compress.h"
#include "crypt/format.h"
#include "crypt/kdf.h"
#include "crypt/random.h"
#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

// See crypt/encrypt.h for why the output buffer is sized to the worst case
// and conditionally shrunk, rather than computed exactly by a first pass.

namespace encrypt {

namespace {

// Plaintext length of chunk `index`. The last chunk is short, every other one
// full, and an empty file's single chunk is 0.
size_t ChunkPlainSize(uint64_t plaintext_size, uint32_t chunk_size,
                      uint32_t index) {
  const uint64_t offset = static_cast<uint64_t>(index) * chunk_size;
  if (offset >= plaintext_size) {
    return 0;
  }

  const uint64_t remaining = plaintext_size - offset;
  return remaining < chunk_size ? static_cast<size_t>(remaining) : chunk_size;
}

}  // namespace

mc_status ValidateOptions(const mc_encrypt_options& opts) {
  // The compression field is compared as an integer, not as the enum.
  //
  // This function exists to reject values a caller should not have passed, and
  // an out-of-range compression id is one of them -- so the invalid value is
  // not an edge case here, it is the input. Loading an enum lvalue holding
  // something outside the enumeration's range is undefined in C++, which makes
  // the obvious spelling of this check undefined exactly when it matters.
  // Reading the object representation is defined; see mc_status_string in
  // api/c_api.cc, which has the same problem for the same reason.
  static_assert(
      sizeof(mc_compression) == sizeof(int),
      "mc_compression is expected to have int as its underlying type");

  int compression = 0;
  std::memcpy(&compression, &opts.compression, sizeof(compression));
  if (compression != MC_COMPRESS_NONE && compression != MC_COMPRESS_ZLIB) {
    return MC_ERR_INVALID_ARG;
  }

  if (opts.chunk_size < format::kMinChunkSize ||
      opts.chunk_size > format::kMaxChunkSize) {
    return MC_ERR_INVALID_ARG;
  }

  if (opts.kdf_log_n < format::kMinKdfLogN ||
      opts.kdf_log_n > format::kMaxKdfLogN) {
    return MC_ERR_INVALID_ARG;
  }

  if (opts.kdf_r < format::kMinKdfR || opts.kdf_r > format::kMaxKdfR ||
      opts.kdf_p < format::kMinKdfP || opts.kdf_p > format::kMaxKdfP) {
    return MC_ERR_INVALID_ARG;
  }

  // The same product bound ParseFileHeader applies on the way in, so this build
  // cannot write a file it would later refuse to read.
  const uint64_t kdf_memory = 128ull * (1ull << opts.kdf_log_n) * opts.kdf_r;
  if (kdf_memory > format::kMaxKdfMemory) {
    return MC_ERR_INVALID_ARG;
  }

  return MC_OK;
}

mc_status EncryptBuffer(const uint8_t* key, size_t key_size,
                        const mc_encrypt_options& opts, const uint8_t* in,
                        size_t in_size, SecureBuffer* out, size_t* out_size) {
  if (key == nullptr || out == nullptr || out_size == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (key_size < MC_MIN_KEY_SIZE) {
    return MC_ERR_INVALID_ARG;
  }

  if (in_size > 0 && in == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  if (static_cast<uint64_t>(in_size) > MC_MAX_PLAINTEXT_SIZE) {
    return MC_ERR_TOO_LARGE;
  }

  const mc_status opts_rc = ValidateOptions(opts);
  if (opts_rc != MC_OK) {
    return opts_rc;
  }

  format::FileHeader header;
  header.format_version = MC_FORMAT_VERSION;
  header.kdf_id = format::kKdfScrypt;
  header.aead_id = format::kAeadAes256Gcm;
  header.compression_id = static_cast<uint8_t>(opts.compression);
  header.kdf_log_n = opts.kdf_log_n;
  header.kdf_r = opts.kdf_r;
  header.kdf_p = opts.kdf_p;
  header.chunk_size = opts.chunk_size;
  header.plaintext_size = in_size;
  header.chunk_count = format::ChunkCountFor(in_size, opts.chunk_size);

  // Drawn first because every later step depends on them: the salt through the
  // derived key, the prefix through each chunk's nonce.
  mc_status rc = random_bytes::Fill(header.salt, format::kSaltSize);
  if (rc != MC_OK) {
    return rc;
  }

  rc = random_bytes::Fill(header.nonce_prefix, format::kNoncePrefixSize);
  if (rc != MC_OK) {
    return rc;
  }

  // Built once, not re-serialized per chunk: it is the AAD every chunk is
  // sealed over, so producing it twice is two chances to differ.
  uint8_t serialized_header[format::kHeaderSize];
  format::SerializeFileHeader(header, serialized_header);

  SecureBuffer derived_key;
  rc = kdf::DeriveKey(key, key_size, header.salt, format::kSaltSize,
                      header.kdf_log_n, header.kdf_r, header.kdf_p,
                      &derived_key);
  if (rc != MC_OK) {
    return rc;
  }

  // Worst case: every chunk stores raw. uint64_t then range-checked, because
  // in_size is bounded only by MC_MAX_PLAINTEXT_SIZE and the product would be
  // meaningless in a size_t on a 32-bit host.
  const uint64_t worst_case =
      format::kHeaderSize +
      (static_cast<uint64_t>(header.chunk_count) * format::kChunkHeaderSize) +
      in_size;
  if (worst_case > SIZE_MAX) {
    return MC_ERR_TOO_LARGE;
  }

  SecureBuffer file;
  if (!file.Reset(static_cast<size_t>(worst_case))) {
    return MC_ERR_MEMORY;
  }

  std::memcpy(file.data(), serialized_header, format::kHeaderSize);

  // One scratch for the whole loop, sized for the worst deflate output of a
  // full chunk: per-chunk allocation over a 10 GiB model would be 2500 trips
  // through the allocator for a buffer whose size never changes.
  SecureBuffer scratch;
  const bool want_compression = opts.compression == MC_COMPRESS_ZLIB;
  if (want_compression &&
      !scratch.Reset(format::MaxStoredSizeFor(opts.chunk_size))) {
    return MC_ERR_MEMORY;
  }

  size_t write_offset = format::kHeaderSize;
  for (uint32_t index = 0; index < header.chunk_count; ++index) {
    const size_t plain_size =
        ChunkPlainSize(header.plaintext_size, header.chunk_size, index);
    const uint8_t* plain =
        in + (static_cast<uint64_t>(index) * header.chunk_size);

    // Compression is decided first: `flags` and `stored_size` are in the AAD,
    // so the record must be final before the seal.
    format::ChunkHeader chunk;
    const uint8_t* payload = plain;
    if (want_compression && plain_size > 0) {
      size_t compressed_size = 0;
      bool smaller = false;
      rc = compression::CompressChunk(plain, plain_size, scratch.data(),
                                      scratch.size(), &compressed_size,
                                      &smaller);
      if (rc != MC_OK) {
        return rc;
      }

      if (smaller) {
        chunk.flags |= format::kChunkFlagCompressed;
        chunk.stored_size = static_cast<uint32_t>(compressed_size);
        payload = scratch.data();
      } else {
        chunk.stored_size = static_cast<uint32_t>(plain_size);
      }
    } else {
      chunk.stored_size = static_cast<uint32_t>(plain_size);
    }

    // Checked rather than asserted: the one invariant whose failure would be a
    // heap overflow, at a cost of one comparison per chunk.
    if (write_offset + format::kChunkHeaderSize + chunk.stored_size >
        file.size()) {
      return MC_ERR_MEMORY;
    }

    uint8_t aad[format::kAadSize];
    format::BuildAad(serialized_header, index, chunk, aad);

    uint8_t nonce[format::kNonceSize];
    format::BuildNonce(header.nonce_prefix, index, nonce);

    uint8_t* chunk_out = file.data() + write_offset;
    uint8_t* ciphertext = chunk_out + format::kChunkHeaderSize;

    uint8_t tag[format::kTagSize];
    rc = aead::Seal(derived_key.data(), nonce, aad, sizeof(aad), payload,
                    chunk.stored_size, ciphertext, tag);
    if (rc != MC_OK) {
      return rc;
    }

    // After the seal, because the tag is only available then. `chunk` has not
    // been touched since BuildAad read it, so record and AAD agree.
    format::SerializeChunkHeader(chunk, tag, chunk_out);
    write_offset += format::kChunkHeaderSize + chunk.stored_size;
  }

  if (file.size() - write_offset > kShrinkThreshold) {
    SecureBuffer exact;
    if (!exact.Reset(write_offset)) {
      return MC_ERR_MEMORY;
    }

    std::memcpy(exact.data(), file.data(), write_offset);
    file = std::move(exact);
  }

  *out = std::move(file);
  *out_size = write_offset;
  return MC_OK;
}

}  // namespace encrypt
