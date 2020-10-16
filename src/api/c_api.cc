/// \file c_api.cc
/// The C entry points declared in include/model_crypt/model_crypt.h.
///
/// A boundary layer: argument checking, defaulting, ownership transfer. The
/// cryptography is in crypt/, the file handling in util/. Two rules hold
/// throughout.
///
/// Out-parameters are written only on success, so a caller that ignores the
/// status reads whatever it initialized rather than a half-built buffer. The
/// internal layers fill a local SecureBuffer and Release() it into the caller's
/// pointer as the last statement.
///
/// Nothing throws. An exception crossing an `extern "C"` frame is undefined
/// behaviour. The internal layers report allocation failure by return value
/// (SecureBuffer::Reset), so the only source left is std::string in the file
/// paths, each wrapped in a try/catch that becomes #MC_ERR_MEMORY.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>

#include "crypt/decrypt.h"
#include "crypt/encrypt.h"
#include "crypt/format.h"
#include "crypt/random.h"
#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"
#include "util/file_io.h"
#include "util/version.h"

namespace {

// A function rather than a constant so mc_encrypt_options_init and the internal
// NULL-opts default share one definition.
mc_encrypt_options DefaultOptions() {
  mc_encrypt_options opts;
  opts.compression = MC_COMPRESS_ZLIB;
  opts.chunk_size = format::kDefaultChunkSize;
  opts.kdf_log_n = format::kDefaultKdfLogN;
  opts.kdf_r = format::kDefaultKdfR;
  opts.kdf_p = format::kDefaultKdfP;
  return opts;
}

// Hand a finished SecureBuffer to a C caller. Release() stops the destructor
// running, after which mc_free is the only correct way back -- it pairs the
// same delete[] with the wipe.
void HandOff(SecureBuffer* buffer, size_t size, uint8_t** out,
             size_t* out_size) {
  *out = buffer->Release();
  *out_size = size;
}

// Returns false when `path` is NULL, the only failure before allocation.
bool ToPath(const char* path, std::string* out) {
  if (path == nullptr) {
    return false;
  }

  *out = path;
  return true;
}

}  // namespace

extern "C" {

void mc_encrypt_options_init(mc_encrypt_options* opts) {
  if (opts == nullptr) {
    return;
  }

  *opts = DefaultOptions();
}

const char* mc_status_string(mc_status status) {
  // Switched on the object representation, not the enum value.
  //
  // This must work for any value, including one outside the enumeration: a C
  // caller can pass an uninitialized variable or a status from a newer build.
  // Loading an enum lvalue holding something outside its range is undefined in
  // C++ (UBSan's -fsanitize=enum reports it), whereas reading an object's
  // representation is always allowed. The switch then runs on a plain int.
  static_assert(sizeof(mc_status) == sizeof(int),
                "mc_status is expected to have int as its underlying type");

  int value = 0;
  std::memcpy(&value, &status, sizeof(value));

  switch (value) {
    case MC_OK:
      return "ok";
    case MC_ERR_INVALID_ARG:
      return "invalid argument";
    case MC_ERR_FORMAT:
      return "not a model-crypt file, or its header is inconsistent";
    case MC_ERR_UNSUPPORTED:
      return "unsupported format version or algorithm";
    case MC_ERR_AUTH:
      return "authentication failed: wrong key, or the file was modified";
    case MC_ERR_COMPRESS:
      return "decompression failed";
    case MC_ERR_CRYPTO:
      return "cryptographic operation failed";
    case MC_ERR_MEMORY:
      return "out of memory";
    case MC_ERR_IO:
      return "I/O error";
    case MC_ERR_TOO_LARGE:
      return "input too large";

    // Not a status. A string rather than NULL keeps this usable in a printf
    // that is already reporting an error. Explicit, because switching on an int
    // gives the compiler no way to know the cases are exhaustive.
    default:
      return "unknown status";
  }
}

const char* mc_version_string(void) { return MODEL_CRYPT_VERSION_STRING; }

mc_status mc_generate_key(uint8_t* out, size_t size) {
  return random_bytes::Fill(out, size);
}

mc_status mc_encrypt_buffer(const uint8_t* key, size_t key_size,
                            const mc_encrypt_options* opts, const uint8_t* in,
                            size_t in_size, uint8_t** out, size_t* out_size) {
  if (out == nullptr || out_size == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  const mc_encrypt_options effective =
      opts != nullptr ? *opts : DefaultOptions();

  SecureBuffer buffer;
  size_t size = 0;
  const mc_status rc = encrypt::EncryptBuffer(key, key_size, effective, in,
                                              in_size, &buffer, &size);
  if (rc != MC_OK) {
    return rc;
  }

  HandOff(&buffer, size, out, out_size);
  return MC_OK;
}

mc_status mc_decrypt_buffer(const uint8_t* key, size_t key_size,
                            const uint8_t* in, size_t in_size, uint8_t** out,
                            size_t* out_size) {
  if (out == nullptr || out_size == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  SecureBuffer buffer;
  size_t size = 0;
  const mc_status rc =
      decrypt::DecryptBuffer(key, key_size, in, in_size, &buffer, &size);
  if (rc != MC_OK) {
    return rc;
  }

  HandOff(&buffer, size, out, out_size);
  return MC_OK;
}

mc_status mc_encrypt_file(const uint8_t* key, size_t key_size,
                          const mc_encrypt_options* opts, const char* in_path,
                          const char* out_path) {
  std::string input_path;
  std::string output_path;
  try {
    if (!ToPath(in_path, &input_path) || !ToPath(out_path, &output_path)) {
      return MC_ERR_INVALID_ARG;
    }
  } catch (const std::bad_alloc&) {
    return MC_ERR_MEMORY;
  }

  SecureBuffer plaintext;
  size_t plaintext_size = 0;
  mc_status rc = fileio::ReadFile(input_path, MC_MAX_PLAINTEXT_SIZE, &plaintext,
                                  &plaintext_size);
  if (rc != MC_OK) {
    return rc;
  }

  const mc_encrypt_options effective =
      opts != nullptr ? *opts : DefaultOptions();

  SecureBuffer ciphertext;
  size_t ciphertext_size = 0;
  rc = encrypt::EncryptBuffer(key, key_size, effective, plaintext.data(),
                              plaintext_size, &ciphertext, &ciphertext_size);
  if (rc != MC_OK) {
    return rc;
  }

  // 0644: the ciphertext is meant to be shipped and read. Its confidentiality
  // is the AEAD's job, not the filesystem's.
  return fileio::WriteFileAtomically(output_path, ciphertext.data(),
                                     ciphertext_size, 0644);
}

mc_status mc_decrypt_file(const uint8_t* key, size_t key_size,
                          const char* in_path, const char* out_path) {
  std::string input_path;
  std::string output_path;
  try {
    if (!ToPath(in_path, &input_path) || !ToPath(out_path, &output_path)) {
      return MC_ERR_INVALID_ARG;
    }
  } catch (const std::bad_alloc&) {
    return MC_ERR_MEMORY;
  }

  // format::kMaxFileSize, not MC_MAX_PLAINTEXT_SIZE: the input here is a
  // ciphertext, which is its plaintext plus framing. Bounding it by the
  // plaintext limit would reject the largest file mc_encrypt_file is willing to
  // produce.
  SecureBuffer ciphertext;
  size_t ciphertext_size = 0;
  mc_status rc = fileio::ReadFile(input_path, format::kMaxFileSize, &ciphertext,
                                  &ciphertext_size);
  if (rc != MC_OK) {
    return rc;
  }

  SecureBuffer plaintext;
  size_t plaintext_size = 0;
  rc = decrypt::DecryptBuffer(key, key_size, ciphertext.data(), ciphertext_size,
                              &plaintext, &plaintext_size);
  if (rc != MC_OK) {
    return rc;
  }

  // Reached only once the whole input has authenticated, so a failed decryption
  // never creates the output file at all. 0600: this is the plaintext model.
  return fileio::WriteFileAtomically(output_path, plaintext.data(),
                                     plaintext_size, 0600);
}

mc_status mc_decrypt_file_to_buffer(const uint8_t* key, size_t key_size,
                                    const char* in_path, uint8_t** out,
                                    size_t* out_size) {
  if (out == nullptr || out_size == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  std::string input_path;
  try {
    if (!ToPath(in_path, &input_path)) {
      return MC_ERR_INVALID_ARG;
    }
  } catch (const std::bad_alloc&) {
    return MC_ERR_MEMORY;
  }

  // See mc_decrypt_file: the bound is the ciphertext limit, not the plaintext
  // one.
  SecureBuffer ciphertext;
  size_t ciphertext_size = 0;
  mc_status rc = fileio::ReadFile(input_path, format::kMaxFileSize, &ciphertext,
                                  &ciphertext_size);
  if (rc != MC_OK) {
    return rc;
  }

  SecureBuffer plaintext;
  size_t plaintext_size = 0;
  rc = decrypt::DecryptBuffer(key, key_size, ciphertext.data(), ciphertext_size,
                              &plaintext, &plaintext_size);
  if (rc != MC_OK) {
    return rc;
  }

  HandOff(&plaintext, plaintext_size, out, out_size);
  return MC_OK;
}

mc_status mc_inspect_buffer(const uint8_t* in, size_t in_size,
                            mc_file_info* info) {
  return decrypt::InspectBuffer(in, in_size, info);
}

void mc_free(void* ptr, size_t size) {
  if (ptr == nullptr) {
    return;
  }

  // Every pointer this API hands out came from SecureBuffer::Release(), i.e.
  // new uint8_t[]. std::free here would be undefined even though it "works".
  SecureWipe(ptr, size);
  delete[] static_cast<uint8_t*>(ptr);
}

}  // extern "C"
