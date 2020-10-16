#ifndef MODEL_CRYPT_SRC_UTIL_FILE_IO_H_
#define MODEL_CRYPT_SRC_UTIL_FILE_IO_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

/// Reading and writing whole files.
///
/// WriteFileAtomically writes a temporary in the destination's own directory,
/// fsyncs it, then rename()s it over the target -- so an interrupted write
/// leaves the old contents rather than a partial file. A truncated model has no
/// marker saying so: a short `.onnx` is an `.onnx` that fails to parse, and a
/// short `.mcrypt` fails to authenticate, which reads as "wrong key".
///
/// The temporary must share the destination's directory: rename() across
/// filesystems fails with EXDEV, and the copy-then-delete fallback is the
/// non-atomic write this exists to avoid.
///
/// Callers pass 0600 for plaintext regardless of umask. This cannot stop a
/// caller choosing a bad path, but it will not make the file world-readable on
/// the way.
namespace fileio {

/// Read all of \p path into \p out.
///
/// \param max_size  Reject anything larger, before allocating.
///
/// \return #MC_OK, #MC_ERR_IO, #MC_ERR_TOO_LARGE, or #MC_ERR_MEMORY.
mc_status ReadFile(const std::string& path, uint64_t max_size,
                   SecureBuffer* out, size_t* out_size);

/// Write \p size bytes at \p data to \p path, replacing it atomically.
///
/// \param mode  Permission bits for the created file, e.g. 0600 for plaintext
///              and 0644 for ciphertext.
///
/// \return #MC_OK or #MC_ERR_IO.
mc_status WriteFileAtomically(const std::string& path, const uint8_t* data,
                              size_t size, unsigned int mode);

}  // namespace fileio

#endif  // MODEL_CRYPT_SRC_UTIL_FILE_IO_H_
