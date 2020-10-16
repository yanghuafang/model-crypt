#ifndef MODEL_CRYPT_SRC_CRYPT_SECURE_BUFFER_H_
#define MODEL_CRYPT_SRC_CRYPT_SECURE_BUFFER_H_

#include <cstddef>
#include <cstdint>

/// A heap buffer that wipes itself on destruction.
///
/// Holds the derived AES key and the plaintext assembled during decryption.
///
/// Not a std::vector, for two reasons. Growth reallocates: the old block is
/// copied and freed *unwiped*, above the allocator, so no custom allocator can
/// fix it -- this class cannot grow. And the wipe is OPENSSL_cleanse, not
/// std::memset, which the as-if rule lets a compiler delete when the storage is
/// dead immediately afterwards.
///
/// Does not mlock, so contents can reach swap. See docs/ThreatModel.md.
class SecureBuffer {
 public:
  SecureBuffer() = default;

  /// Allocate \p size zeroed bytes. Zero size allocates nothing.
  explicit SecureBuffer(size_t size);

  ~SecureBuffer();

  /// Non-copyable: a copy is a second plaintext with a second lifetime.
  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  /// Wipe the current contents, then allocate \p size zeroed bytes.
  ///
  /// \return false if the allocation failed; the buffer is then empty.
  bool Reset(size_t size);

  /// Release ownership to the caller, who becomes responsible for wiping it.
  ///
  /// Exists for the one boundary where that is the right thing: handing a
  /// finished plaintext out through the C API, where mc_free takes over the
  /// wipe. Everywhere else, let the destructor do it.
  uint8_t* Release();

  [[nodiscard]] uint8_t* data() { return data_; }
  [[nodiscard]] const uint8_t* data() const { return data_; }
  [[nodiscard]] size_t size() const { return size_; }
  [[nodiscard]] bool empty() const { return size_ == 0; }

 private:
  void WipeAndFree();

  uint8_t* data_ = nullptr;
  size_t size_ = 0;
};

/// Wipe \p size bytes at \p ptr in a way the optimizer may not remove.
///
/// Free function because the C API's mc_free needs it on memory that was never
/// in a SecureBuffer.
void SecureWipe(void* ptr, size_t size);

#endif  // MODEL_CRYPT_SRC_CRYPT_SECURE_BUFFER_H_
