/// \file model_crypt.h
/// The complete public interface of model-crypt.
///
/// This is the only header the library installs. It is C, not C++, so the
/// library can be linked from C, Objective-C, Rust, Go, or a Python `ctypes`
/// binding without a wrapper; the implementation behind it is C++17.
///
/// == The two things this API guarantees ==
///
/// 1. **Confidentiality.** Model bytes are encrypted with AES-256-GCM under a
///    key derived from your passphrase with scrypt. Nothing in the file
///    reveals the plaintext, and no part of the payload is left unencrypted.
///
/// 2. **Authenticity.** Decryption *fails* — it does not return garbage — if
///    the file was truncated, extended, reordered, byte-flipped, or produced
///    under a different key. There is no mode in which mc_decrypt_* returns
///    #MC_OK with plaintext the encryptor did not write.
///
/// The second guarantee is the reason this API has no "just decrypt it
/// anyway" escape hatch. A model file that fails authentication is not a
/// degraded model, it is an attacker-chosen one, and handing it to an
/// inference runtime is the outcome the library exists to prevent.
///
/// == What it does not guarantee ==
///
/// Nothing here defends the plaintext after mc_decrypt_* returns it, and
/// nothing defends a key that ships inside the binary that uses it. See
/// docs/ThreatModel.md before deploying this on a client device.
///
/// == Minimal use ==
///
/// \code
/// uint8_t *plain = NULL;
/// size_t plain_len = 0;
/// mc_status rc = mc_decrypt_file_to_buffer(key, key_len, "model.mcrypt",
///                                          &plain, &plain_len);
/// if (rc != MC_OK) {
///   fprintf(stderr, "decrypt failed: %s\n", mc_status_string(rc));
///   return 1;
/// }
/// use_model(plain, plain_len);
/// mc_free(plain, plain_len);  // wipes before freeing
/// \endcode

#ifndef MODEL_CRYPT_MODEL_CRYPT_H_
#define MODEL_CRYPT_MODEL_CRYPT_H_

#include <stddef.h>
#include <stdint.h>

/// Marks a return value that must not be dropped.
///
/// Every function below reports failure through its return value and through
/// nothing else — there is no errno, and no out-parameter is written on the
/// failure path. Ignoring the status is therefore the one mistake that turns
/// a caught attack back into a silent one, so the compiler is asked to object.
#if defined(__cplusplus) && __cplusplus >= 201703L
#define MC_NODISCARD [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define MC_NODISCARD __attribute__((warn_unused_result))
#else
#define MC_NODISCARD
#endif

/// Marks the symbols that make up the shared-library ABI.
///
/// The build compiles with -fvisibility=hidden, so a symbol is exported only
/// if it says so here. That is what keeps the internal C++ layer — Format,
/// Aead, SecureBuffer and friends — out of the .so's dynamic symbol table,
/// where it would otherwise become an accidental ABI that cannot be changed.
#if defined(_WIN32)
#define MC_API
#elif defined(__GNUC__) || defined(__clang__)
#define MC_API __attribute__((visibility("default")))
#else
#define MC_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// The container format version this build reads and writes.
///
/// Bumped only for an incompatible change. mc_decrypt_* rejects any other
/// value rather than guessing; see docs/Format.md.
#define MC_FORMAT_VERSION 2u

/// Bytes of file header preceding the first chunk.
///
/// Fixed, not a field to be trusted from the file: a parser that seeks by a
/// length it read out of the input is the parser that can be told to seek past
/// the end. Exposed because mc_inspect_buffer needs at least this many bytes.
#define MC_HEADER_SIZE 64u

/// Shortest key mc_encrypt_* will accept, in bytes.
///
/// A floor on a human-chosen passphrase, not a claim that 12 bytes is enough.
/// scrypt is what makes a passphrase of this length survivable at all; a key
/// that is not memorized by a human should be 32 random bytes from
/// mc_generate_key.
#define MC_MIN_KEY_SIZE 12u

/// How a call ended.
///
/// Ordered so that MC_OK is zero and everything else is a distinct failure.
/// Distinguishing #MC_ERR_AUTH from #MC_ERR_FORMAT is deliberate and is safe
/// to report to the caller: both mean "this file will not be decrypted", and
/// which one fired reveals nothing an attacker holding the file does not
/// already know.
typedef enum mc_status {
  /// The call succeeded and any out-parameters were written.
  MC_OK = 0,

  /// A NULL pointer, a zero length, or an out-of-range option value.
  MC_ERR_INVALID_ARG,

  /// The input was not a model-crypt file: wrong magic, unreadable header, a
  /// length field that contradicts the file size, or a self-inconsistent
  /// chunk table. Nothing was decrypted, because nothing could be parsed.
  MC_ERR_FORMAT,

  /// A well-formed model-crypt file this build cannot process: a newer
  /// #MC_FORMAT_VERSION, or a KDF, cipher, or compressor id it does not know.
  MC_ERR_UNSUPPORTED,

  /// **Authentication failed.** The key is wrong, or the file was modified
  /// after it was written. These are the same answer on purpose — GCM cannot
  /// tell them apart, and neither can anything built on it.
  ///
  /// Treat the output as nonexistent. It is: no out-parameter is written.
  MC_ERR_AUTH,

  /// The payload authenticated but did not decompress to the size the
  /// (authenticated) header promised. Reachable only through a bug in this
  /// library or a mismatched zlib, never through a hostile file.
  MC_ERR_COMPRESS,

  /// An OpenSSL primitive failed. Consult ERR_get_error() for detail; the
  /// library does not surface OpenSSL's error queue through this enum.
  MC_ERR_CRYPTO,

  /// An allocation failed.
  MC_ERR_MEMORY,

  /// Reading or writing a file failed.
  MC_ERR_IO,

  /// The input, or a size declared inside it, exceeds what this build will
  /// process. See #MC_MAX_PLAINTEXT_SIZE.
  MC_ERR_TOO_LARGE
} mc_status;

/// Largest plaintext this build will encrypt or produce, in bytes (64 GiB).
///
/// A ceiling, not a target — it exists so a corrupt or hostile size field
/// turns into #MC_ERR_TOO_LARGE instead of an allocation the machine cannot
/// serve. Decryption additionally never allocates on a declared size before
/// authenticating the chunk that size describes.
// UINT64_C rather than a (uint64_t) cast: this header is C, but it is expanded
// in C++ translation units compiled with -Wold-style-cast, and a public macro
// should not make a consumer's warning configuration a problem for them.
#define MC_MAX_PLAINTEXT_SIZE (UINT64_C(64) << 30)

/// Compression applied before encryption.
///
/// Before, not after: ciphertext is indistinguishable from random and does not
/// compress, so the order is forced. It is also why compression is a
/// per-chunk decision the encryptor records — see docs/Format.md § Chunks.
typedef enum mc_compression {
  /// Store the model bytes as they are.
  MC_COMPRESS_NONE = 0,

  /// Deflate each chunk with zlib, keeping whichever of the two is smaller.
  MC_COMPRESS_ZLIB = 1
} mc_compression;

/// Encryption parameters. Fill with mc_encrypt_options_init, then adjust.
///
/// Decryption takes no options: everything needed to reverse an encryption is
/// recorded in the (authenticated) file header, so a file never depends on the
/// reader being configured the same way the writer was.
typedef struct mc_encrypt_options {
  /// Compressor for the payload. Default #MC_COMPRESS_ZLIB.
  mc_compression compression;

  /// Plaintext bytes per chunk. Default 4 MiB; range 4 KiB to 64 MiB.
  ///
  /// Each chunk is sealed independently, so this trades per-chunk overhead
  /// (24 bytes) against how much must be held in memory at once and how
  /// finely a truncation can be localized. The default is far above the point
  /// where the overhead matters and far below the point where a chunk is an
  /// awkward allocation.
  uint32_t chunk_size;

  /// scrypt cost, as log2(N). Default 15 (N = 32768). Range 14 to 20.
  ///
  /// Memory use is 128 * N * r bytes: the default is 32 MiB and roughly 100 ms
  /// on a current laptop core. Raise it if your threat model includes offline
  /// guessing of a human-chosen passphrase; every increment doubles both the
  /// time and the memory, for you and for the attacker equally.
  uint8_t kdf_log_n;

  /// scrypt block size r. Default 8. Range 1 to 32.
  uint32_t kdf_r;

  /// scrypt parallelism p. Default 1. Range 1 to 16.
  uint32_t kdf_p;
} mc_encrypt_options;

/// Header fields of a model-crypt file, as reported by mc_inspect_buffer.
///
/// \warning Every field here is read **before** anything is authenticated,
/// because reading the header is what tells you which key to try. An attacker
/// who hands you a file chooses these numbers. They are safe to print and
/// safe to size a progress bar with; they are not safe to allocate on, and the
/// library itself never does.
typedef struct mc_file_info {
  /// Container version from the file. Not necessarily #MC_FORMAT_VERSION.
  uint16_t format_version;

  /// Compressor recorded by the encryptor.
  mc_compression compression;

  /// Size the plaintext claims to be.
  uint64_t plaintext_size;

  /// Plaintext bytes per chunk.
  uint32_t chunk_size;

  /// Number of chunks that should follow the header.
  uint32_t chunk_count;

  /// scrypt cost as log2(N).
  uint8_t kdf_log_n;

  /// scrypt block size.
  uint32_t kdf_r;

  /// scrypt parallelism.
  uint32_t kdf_p;
} mc_file_info;

/// Fill \p opts with the defaults documented on #mc_encrypt_options.
///
/// Always call this before setting individual fields. It is what lets a later
/// release add an option without every existing caller passing an
/// uninitialized value for it.
MC_API void mc_encrypt_options_init(mc_encrypt_options* opts);

/// Human-readable name of \p status, for diagnostics.
///
/// Never NULL, including for a value outside the enum. The returned string is
/// static and must not be freed.
MC_API const char* mc_status_string(mc_status status);

/// This build's version, as "MAJOR.MINOR.PATCH". Static; do not free.
MC_API const char* mc_version_string(void);

/// Write \p size cryptographically random bytes to \p out.
///
/// The intended way to produce a key: `mc_generate_key(k, 32)` yields 256 bits
/// from the OS CSPRNG, which is stronger than any passphrase a person will
/// choose and costs nothing to store in a file.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, or #MC_ERR_CRYPTO if the system
///         random source failed — which is a condition to abort on, never to
///         retry or work around.
MC_NODISCARD MC_API mc_status mc_generate_key(uint8_t* out, size_t size);

/// Encrypt \p in_size bytes at \p in into a freshly allocated buffer.
///
/// A random salt and nonce are drawn per call, so encrypting identical input
/// twice under the same key yields unrelated ciphertext.
///
/// \param key       Key or passphrase bytes. At least #MC_MIN_KEY_SIZE.
/// \param key_size  Length of \p key in bytes.
/// \param opts      Options, or NULL for the defaults.
/// \param in        Plaintext. May be NULL only if \p in_size is 0.
/// \param in_size   Plaintext length; at most #MC_MAX_PLAINTEXT_SIZE.
/// \param out       Receives the ciphertext buffer. Release with mc_free.
/// \param out_size  Receives its length.
///
/// \return #MC_OK, or #MC_ERR_INVALID_ARG, #MC_ERR_TOO_LARGE, #MC_ERR_MEMORY,
///         #MC_ERR_CRYPTO. On failure neither out-parameter is written.
MC_NODISCARD MC_API mc_status mc_encrypt_buffer(
    const uint8_t* key, size_t key_size, const mc_encrypt_options* opts,
    const uint8_t* in, size_t in_size, uint8_t** out, size_t* out_size);

/// Decrypt and authenticate \p in_size bytes at \p in.
///
/// Returns #MC_OK only if every chunk authenticated under \p key and the
/// recovered plaintext matched the authenticated header in size. Any other
/// outcome writes no out-parameter and yields no plaintext.
///
/// \param out       Receives the plaintext buffer. Release with mc_free — it
///                  wipes, which plain free() does not.
/// \param out_size  Receives its length.
///
/// \return #MC_OK, #MC_ERR_AUTH, #MC_ERR_FORMAT, #MC_ERR_UNSUPPORTED,
///         #MC_ERR_TOO_LARGE, #MC_ERR_MEMORY, #MC_ERR_CRYPTO, or
///         #MC_ERR_COMPRESS.
MC_NODISCARD MC_API mc_status mc_decrypt_buffer(const uint8_t* key,
                                                size_t key_size,
                                                const uint8_t* in,
                                                size_t in_size, uint8_t** out,
                                                size_t* out_size);

/// Encrypt \p in_path to \p out_path.
///
/// \p out_path is written through a temporary file in the same directory and
/// renamed into place, so a crash or a full disk leaves the previous file
/// intact rather than a half-written one that looks like a corrupt model.
///
/// \return #MC_OK, #MC_ERR_IO, or any status of mc_encrypt_buffer.
MC_NODISCARD MC_API mc_status mc_encrypt_file(const uint8_t* key,
                                              size_t key_size,
                                              const mc_encrypt_options* opts,
                                              const char* in_path,
                                              const char* out_path);

/// Decrypt \p in_path to \p out_path, replacing it atomically.
///
/// \p out_path is created with mode 0600 and is written only after the whole
/// input authenticates, so a failed decryption never leaves attacker-chosen
/// bytes on disk under the name of a model.
///
/// \return #MC_OK, #MC_ERR_IO, or any status of mc_decrypt_buffer.
MC_NODISCARD MC_API mc_status mc_decrypt_file(const uint8_t* key,
                                              size_t key_size,
                                              const char* in_path,
                                              const char* out_path);

/// Decrypt \p in_path straight into memory.
///
/// The form to prefer on a client device: it never writes plaintext to disk,
/// which is the single largest hole in a naive deployment. Release with
/// mc_free as soon as the model is loaded.
///
/// \return #MC_OK, #MC_ERR_IO, or any status of mc_decrypt_buffer.
MC_NODISCARD MC_API mc_status mc_decrypt_file_to_buffer(const uint8_t* key,
                                                        size_t key_size,
                                                        const char* in_path,
                                                        uint8_t** out,
                                                        size_t* out_size);

/// Read the unauthenticated header of \p in into \p info.
///
/// For `model-crypt inspect` and for deciding which key to try. No key is
/// needed and none is checked, so a #MC_OK here says only that the bytes are
/// shaped like a model-crypt header.
///
/// \warning See the warning on #mc_file_info. Do not size an allocation on
/// anything this returns.
///
/// \return #MC_OK, #MC_ERR_INVALID_ARG, or #MC_ERR_FORMAT.
MC_NODISCARD MC_API mc_status mc_inspect_buffer(const uint8_t* in,
                                                size_t in_size,
                                                mc_file_info* info);

/// Wipe \p size bytes at \p ptr, then free it.
///
/// The release call for every buffer this API hands back. Passing the size is
/// what lets it wipe: a plain free() leaves a decrypted model sitting in the
/// heap for whatever allocates that memory next, or for a core dump.
///
/// The wipe uses OPENSSL_cleanse, which the optimizer is not permitted to
/// elide the way it may elide a memset to a buffer that is about to be freed.
/// \p ptr may be NULL, in which case nothing happens.
MC_API void mc_free(void* ptr, size_t size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // MODEL_CRYPT_MODEL_CRYPT_H_
