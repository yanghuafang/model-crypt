#include "util/file_io.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>

#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

// See util/file_io.h for why the write goes through a rename and why plaintext
// is created 0600.

namespace fileio {

namespace {

// read() and write() may return short without it being an error. Looping until
// the count is satisfied is not optional: a single unchecked call is how a
// large file is silently truncated on a loaded machine.

bool ReadFully(int fd, uint8_t* out, size_t size) {
  size_t done = 0;
  while (done < size) {
    const ssize_t n = ::read(fd, out + done, size - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }

      return false;
    }

    // The caller sized this read from fstat, so EOF here means the file shrank
    // underneath us.
    if (n == 0) {
      return false;
    }

    done += static_cast<size_t>(n);
  }

  return true;
}

bool WriteFully(int fd, const uint8_t* in, size_t size) {
  size_t done = 0;
  while (done < size) {
    const ssize_t n = ::write(fd, in + done, size - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }

      return false;
    }

    done += static_cast<size_t>(n);
  }

  return true;
}

// The directory component of `path`, or "." when there is none. The temporary
// must land here -- see the header.
std::string DirectoryOf(const std::string& path) {
  const auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return ".";
  }

  if (slash == 0) {
    return "/";
  }

  return path.substr(0, slash);
}

}  // namespace

mc_status ReadFile(const std::string& path, uint64_t max_size,
                   SecureBuffer* out, size_t* out_size) {
  if (out == nullptr || out_size == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    return MC_ERR_IO;
  }

  struct stat st = {};
  if (::fstat(fd, &st) != 0) {
    ::close(fd);
    return MC_ERR_IO;
  }

  // S_ISREG, not `st.st_mode & S_IFREG`: S_IFMT is a multi-bit field, not a set
  // of flags, so a socket (0140000) shares a bit with S_IFREG (0100000) and
  // passes the bitwise form. Sizing a read from fstat only makes sense for
  // something that has a size; a fifo reports 0 and then blocks forever.
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    return MC_ERR_IO;
  }

  // st_size is a signed off_t, compared before any conversion.
  if (st.st_size < 0) {
    ::close(fd);
    return MC_ERR_IO;
  }

  const auto size = static_cast<uint64_t>(st.st_size);
  if (size > max_size || size > SIZE_MAX) {
    ::close(fd);
    return MC_ERR_TOO_LARGE;
  }

  SecureBuffer buffer;
  if (!buffer.Reset(static_cast<size_t>(size))) {
    ::close(fd);
    return MC_ERR_MEMORY;
  }

  if (size > 0 && !ReadFully(fd, buffer.data(), static_cast<size_t>(size))) {
    ::close(fd);
    return MC_ERR_IO;
  }

  ::close(fd);
  *out = std::move(buffer);
  *out_size = static_cast<size_t>(size);
  return MC_OK;
}

mc_status WriteFileAtomically(const std::string& path, const uint8_t* data,
                              size_t size, unsigned int mode) {
  if (size > 0 && data == nullptr) {
    return MC_ERR_INVALID_ARG;
  }

  std::string temporary = DirectoryOf(path);
  if (temporary.back() != '/') {
    temporary += '/';
  }
  temporary += ".model-crypt-XXXXXX";

  // mkstemp creates the file 0600 and returns a descriptor, so there is no
  // window in which the name exists without the file for a symlink to occupy.
  std::string mutable_path = temporary;
  const int fd = ::mkstemp(mutable_path.data());
  if (fd < 0) {
    return MC_ERR_IO;
  }

  // fchmod rather than mkstemp's 0600: the caller may want 0644, and umask does
  // not apply to fchmod, so the mode is the one asked for.
  if (::fchmod(fd, static_cast<mode_t>(mode)) != 0) {
    ::close(fd);
    ::unlink(mutable_path.c_str());
    return MC_ERR_IO;
  }

  if (size > 0 && !WriteFully(fd, data, size)) {
    ::close(fd);
    ::unlink(mutable_path.c_str());
    return MC_ERR_IO;
  }

  // fsync before rename, not after: rename() is atomic for the directory entry
  // but says nothing about the contents reaching disk, so a power loss could
  // otherwise leave the new name pointing at zeroes.
  //
  // The directory is deliberately not fsynced. That would also make the rename
  // survive a power loss, at a second open() and fsync() per write; the failure
  // it closes leaves the *old* file intact, which is the outcome this function
  // exists to preserve anyway.
  if (::fsync(fd) != 0) {
    ::close(fd);
    ::unlink(mutable_path.c_str());
    return MC_ERR_IO;
  }

  if (::close(fd) != 0) {
    ::unlink(mutable_path.c_str());
    return MC_ERR_IO;
  }

  if (::rename(mutable_path.c_str(), path.c_str()) != 0) {
    ::unlink(mutable_path.c_str());
    return MC_ERR_IO;
  }

  return MC_OK;
}

}  // namespace fileio
