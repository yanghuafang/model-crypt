#ifndef MODEL_CRYPT_SRC_CRYPT_FORMAT_H_
#define MODEL_CRYPT_SRC_CRYPT_FORMAT_H_

#include <cstddef>
#include <cstdint>

#include "model_crypt/model_crypt.h"

/// The `.mcrypt` container: byte layout, limits, and the rules a parser
/// enforces before any key is used. docs/Format.md is normative.
///
///   [ 64-byte file header ][ chunk 0 ][ chunk 1 ] ... [ chunk N-1 ]
///
/// Each chunk is a 24-byte record plus ciphertext, sealed independently with
/// AES-256-GCM. Chunking bounds how much must be held in memory before any byte
/// can be trusted, and gives compression a unit small enough that an
/// incompressible region can be stored raw.
///
/// Per-chunk seals alone would allow reordering, truncation, and splicing
/// between files under the same key -- every individual tag would still verify.
/// The associated data closes that:
///
///   AAD = file header (all 64 bytes) || chunk index || stored size || flags
///
/// so a chunk carries its position and the shape of the file it belongs to.
/// Splicing fails twice over: a different file has a different salt, hence a
/// different derived key.
///
/// An empty model still gets one chunk -- with zero chunks nothing would cover
/// the header and anyone could forge a valid empty file. See ChunkCountFor().
namespace format {

/// File magic. Version-tagged, so a v1 "MLM" file and a future v3 are both
/// rejected at the first comparison.
inline constexpr char kMagic[] = {'M', 'C', 'R', 'Y', 'P', 'T', '0', '2'};

/// Length of #kMagic.
inline constexpr size_t kMagicSize = sizeof(kMagic);

/// Fixed size of the file header, matching #MC_HEADER_SIZE.
inline constexpr size_t kHeaderSize = MC_HEADER_SIZE;

/// Fixed size of a chunk record, excluding its ciphertext.
inline constexpr size_t kChunkHeaderSize = 24;

/// scrypt salt length. Fresh per file, so two encryptions of the same model
/// under the same passphrase use unrelated keys.
inline constexpr size_t kSaltSize = 16;

/// Random per-file part of every chunk nonce.
inline constexpr size_t kNoncePrefixSize = 8;

/// AES-GCM nonce: #kNoncePrefixSize random bytes plus a 32-bit chunk counter.
///
/// 96 bits is GCM's native size. prefix||counter makes uniqueness structural
/// rather than probabilistic; nonce reuse destroys GCM outright.
inline constexpr size_t kNonceSize = 12;

/// GCM tag length. Full 128 bits; truncation is permitted and not taken.
inline constexpr size_t kTagSize = 16;

/// AES-256 key length.
inline constexpr size_t kKeySize = 32;

/// Associated data length: header || chunk index || stored size || flags.
inline constexpr size_t kAadSize = kHeaderSize + 4 + 4 + 1;

/// Key derivation function id stored in the header. Only scrypt exists.
inline constexpr uint8_t kKdfScrypt = 1;

/// AEAD id stored in the header. Only AES-256-GCM exists.
inline constexpr uint8_t kAeadAes256Gcm = 1;

/// Chunk flag: the ciphertext decrypts to a zlib stream, not to raw bytes.
inline constexpr uint8_t kChunkFlagCompressed = 0x01;

/// Every flag bit this build understands; anything else is rejected, so a
/// future flag cannot be silently ignored by an old reader.
inline constexpr uint8_t kChunkFlagMask = kChunkFlagCompressed;

/// Default and permitted range for mc_encrypt_options::chunk_size.
inline constexpr uint32_t kDefaultChunkSize = 4u << 20;
inline constexpr uint32_t kMinChunkSize = 4u << 10;
inline constexpr uint32_t kMaxChunkSize = 64u << 20;

/// Default and permitted range for the scrypt parameters.
inline constexpr uint8_t kDefaultKdfLogN = 15;
inline constexpr uint8_t kMinKdfLogN = 14;
inline constexpr uint8_t kMaxKdfLogN = 20;
inline constexpr uint32_t kDefaultKdfR = 8;
inline constexpr uint32_t kMinKdfR = 1;
inline constexpr uint32_t kMaxKdfR = 32;
inline constexpr uint32_t kDefaultKdfP = 1;
inline constexpr uint32_t kMinKdfP = 1;
inline constexpr uint32_t kMaxKdfP = 16;

/// Largest `.mcrypt` file this build will read.
///
/// #MC_MAX_PLAINTEXT_SIZE bounds the plaintext; a file is that plus framing.
/// Bounding a ciphertext by the plaintext limit would refuse the largest file
/// this build is willing to write. Framing is the worst case: every chunk at
/// #kMinChunkSize.
inline constexpr uint64_t kMaxFileSize =
    MC_MAX_PLAINTEXT_SIZE +
    ((MC_MAX_PLAINTEXT_SIZE / kMinChunkSize) * kChunkHeaderSize) + kHeaderSize;

/// Ceiling on scrypt's working set (1 GiB).
///
/// The cost parameters come from the file, so an attacker picks them. log_n and
/// r are range-checked individually, but their *product* is what allocates:
/// 2^20 with r = 32 asks for 4 GiB from a 64-byte header.
inline constexpr uint64_t kMaxKdfMemory = 1ull << 30;

/// Parsed file header. Field order matches the on-disk layout.
struct FileHeader {
  uint16_t format_version = MC_FORMAT_VERSION;
  uint8_t kdf_id = kKdfScrypt;
  uint8_t aead_id = kAeadAes256Gcm;
  uint8_t compression_id = static_cast<uint8_t>(MC_COMPRESS_ZLIB);
  uint8_t kdf_log_n = kDefaultKdfLogN;
  uint32_t kdf_r = kDefaultKdfR;
  uint32_t kdf_p = kDefaultKdfP;
  uint8_t salt[kSaltSize] = {};
  uint8_t nonce_prefix[kNoncePrefixSize] = {};
  uint32_t chunk_size = kDefaultChunkSize;
  uint64_t plaintext_size = 0;
  uint32_t chunk_count = 0;
};

/// Parsed chunk record, minus the tag (which callers keep separately because
/// the AEAD wants it as its own buffer).
struct ChunkHeader {
  uint32_t stored_size = 0;
  uint8_t flags = 0;
};

/// Number of chunks a plaintext of \p plaintext_size bytes occupies.
///
/// Never zero; see the note on the empty model above. Callers must already
/// have bounded \p plaintext_size by #MC_MAX_PLAINTEXT_SIZE and \p chunk_size
/// by #kMinChunkSize, which together keep this below 2^32.
uint32_t ChunkCountFor(uint64_t plaintext_size, uint32_t chunk_size);

/// Largest legitimate `stored_size` for a chunk of \p chunk_size plaintext.
///
/// The deflate worst case, not \p chunk_size, because zlib can expand
/// incompressible input. Rejects an absurd size field before it allocates.
uint32_t MaxStoredSizeFor(uint32_t chunk_size);

/// Write \p header into \p out.
void SerializeFileHeader(const FileHeader& header, uint8_t out[kHeaderSize]);

/// Read and validate a file header from \p in.
///
/// Structural only: no key, nothing authenticated. Rejects a wrong magic,
/// unknown version or algorithm id, out-of-range parameter, a chunk count that
/// contradicts the declared plaintext size, and a nonzero reserved field. What
/// it establishes is that the numbers are self-consistent and bounded, so the
/// rest of the pipeline can do arithmetic on them without overflowing.
///
/// \return #MC_OK, #MC_ERR_FORMAT, #MC_ERR_UNSUPPORTED, or #MC_ERR_TOO_LARGE.
mc_status ParseFileHeader(const uint8_t* in, size_t in_size,
                          FileHeader* header);

/// Write \p chunk and \p tag into \p out.
void SerializeChunkHeader(const ChunkHeader& chunk, const uint8_t tag[kTagSize],
                          uint8_t out[kChunkHeaderSize]);

/// Read a chunk record from \p in, which must hold #kChunkHeaderSize bytes.
///
/// Rejects an unknown flag bit, a nonzero reserved field, and a stored size
/// above \p max_stored_size. The caller must still confirm the bytes are
/// present.
///
/// \return #MC_OK or #MC_ERR_FORMAT.
mc_status ParseChunkHeader(const uint8_t* in, uint32_t max_stored_size,
                           ChunkHeader* chunk, uint8_t tag[kTagSize]);

/// Build the associated data for chunk \p chunk_index.
///
/// \p serialized_header must be the exact 64 bytes on disk. Re-serializing the
/// parsed struct would launder any byte the parser ignored -- a reserved field
/// an attacker set would vanish from the AAD and the tag would verify.
void BuildAad(const uint8_t serialized_header[kHeaderSize],
              uint32_t chunk_index, const ChunkHeader& chunk,
              uint8_t out[kAadSize]);

/// Build the nonce for chunk \p chunk_index: \p nonce_prefix then a big-endian
/// counter.
void BuildNonce(const uint8_t nonce_prefix[kNoncePrefixSize],
                uint32_t chunk_index, uint8_t out[kNonceSize]);

}  // namespace format

#endif  // MODEL_CRYPT_SRC_CRYPT_FORMAT_H_
