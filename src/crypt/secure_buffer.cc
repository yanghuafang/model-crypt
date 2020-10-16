#include "crypt/secure_buffer.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <utility>

#include <openssl/crypto.h>

// See crypt/secure_buffer.h for why this exists rather than a
// std::vector<uint8_t> with a wiping allocator.

void SecureWipe(void* ptr, size_t size) {
  if (ptr == nullptr || size == 0) {
    return;
  }

  OPENSSL_cleanse(ptr, size);
}

SecureBuffer::SecureBuffer(size_t size) { Reset(size); }

SecureBuffer::~SecureBuffer() { WipeAndFree(); }

// Leaves `other` empty, not merely unspecified: a moved-from buffer still
// aliasing the new owner's block would wipe it from under them.
SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    WipeAndFree();
    data_ = other.data_;
    size_ = other.size_;
    other.data_ = nullptr;
    other.size_ = 0;
  }

  return *this;
}

bool SecureBuffer::Reset(size_t size) {
  WipeAndFree();

  if (size == 0) {
    return true;
  }

  // nothrow, because a std::bad_alloc escaping the C API boundary above is
  // undefined. The "()" value-initializes, so the block never starts out
  // holding whatever the allocator last had there.
  data_ = new (std::nothrow) uint8_t[size]();
  if (data_ == nullptr) {
    return false;
  }

  size_ = size;
  return true;
}

uint8_t* SecureBuffer::Release() {
  uint8_t* released = data_;
  data_ = nullptr;
  size_ = 0;
  return released;
}

void SecureBuffer::WipeAndFree() {
  if (data_ == nullptr) {
    return;
  }

  SecureWipe(data_, size_);
  delete[] data_;
  data_ = nullptr;
  size_ = 0;
}
