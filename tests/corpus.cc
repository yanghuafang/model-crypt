#include "corpus.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// See corpus.h for why the payloads are generated rather than committed, and
// for what each profile is meant to exercise.

namespace corpus {

namespace {

// splitmix64. Chosen because it is eight lines, has no state beyond a uint64_t,
// and is specified precisely enough that the sequence is identical on every
// platform and compiler — which is the whole requirement here. It is not a
// cryptographic generator and nothing in the library uses it; the real salts
// and nonces come from crypt/random.cc.
class Rng {
 public:
  explicit Rng(uint64_t seed) : state_(seed) {}

  uint64_t Next() {
    state_ += 0x9E3779B97F4A7C15ull;
    uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }

  uint32_t Next32() { return static_cast<uint32_t>(Next() >> 32); }

  uint8_t NextByte() { return static_cast<uint8_t>(Next() >> 56); }

 private:
  uint64_t state_;
};

void FillRandom(std::vector<uint8_t>& out, Rng& rng) {
  for (uint8_t& byte : out) {
    byte = rng.NextByte();
  }
}

// fp32 values in [-0.5, 0.5), written little-endian by hand.
//
// By hand rather than memcpy of a float, for the same reason format.cc writes
// its integers by hand: a test fixture whose bytes depend on the host's float
// endianness would make the committed golden vector unreproducible on the other
// kind of machine.
void FillFloatWeights(std::vector<uint8_t>& out, Rng& rng) {
  for (size_t i = 0; i + 4 <= out.size(); i += 4) {
    // A small-magnitude float has a narrow exponent range, so byte 3 (sign +
    // high exponent bits) and byte 2 take few distinct values while bytes 0-1
    // are effectively random. That asymmetry is what makes the result partially
    // compressible, which is the point of this profile.
    const uint32_t mantissa = rng.Next32() & 0x007FFFFFu;
    const uint32_t exponent = 0x3E000000u + ((rng.Next32() % 3u) << 23);
    const uint32_t sign = (rng.Next32() & 1u) << 31;
    const uint32_t bits = sign | exponent | mantissa;

    out[i + 0] = static_cast<uint8_t>(bits & 0xFFu);
    out[i + 1] = static_cast<uint8_t>((bits >> 8) & 0xFFu);
    out[i + 2] = static_cast<uint8_t>((bits >> 16) & 0xFFu);
    out[i + 3] = static_cast<uint8_t>((bits >> 24) & 0xFFu);
  }

  // A size that is not a multiple of four still has to be filled, and the tail
  // is exactly where an off-by-one in the chunk walk would hide.
  for (size_t i = out.size() & ~static_cast<size_t>(3); i < out.size(); ++i) {
    out[i] = rng.NextByte();
  }
}

// Alternating runs of the other three profiles, so one payload contains both
// regions deflate helps on and regions it does not.
//
// The run length is 1 KiB rather than something chunk-sized on purpose. The
// round-trip sweep runs at a 4 KiB chunk to keep multi-chunk files small, and a
// run longer than a chunk would make every chunk of a small payload a single
// phase -- for a payload under one run, the whole thing would be zeros and the
// profile would silently be Zeros under another name. At 1 KiB, every chunk at
// every size the tests use is a genuine mixture.
void FillMixed(std::vector<uint8_t>& out, Rng& rng) {
  constexpr size_t kRun = 1u << 10;
  size_t offset = 0;
  int phase = 0;

  while (offset < out.size()) {
    const size_t length = std::min(kRun, out.size() - offset);
    std::vector<uint8_t> run(length);

    switch (phase % 3) {
      case 0:
        // Left zeroed.
        break;
      case 1:
        FillRandom(run, rng);
        break;
      default:
        FillFloatWeights(run, rng);
        break;
    }

    std::memcpy(out.data() + offset, run.data(), length);
    offset += length;
    ++phase;
  }
}

}  // namespace

const char* ProfileName(Profile profile) {
  switch (profile) {
    case Profile::kZeros:
      return "zeros";
    case Profile::kRandom:
      return "random";
    case Profile::kFloatWeights:
      return "float-weights";
    case Profile::kMixed:
      return "mixed";
  }

  return "unknown";
}

std::vector<uint8_t> Generate(Profile profile, size_t size, uint64_t seed) {
  std::vector<uint8_t> out(size, 0);
  if (size == 0) {
    return out;
  }

  Rng rng(seed);
  switch (profile) {
    case Profile::kZeros:
      break;
    case Profile::kRandom:
      FillRandom(out, rng);
      break;
    case Profile::kFloatWeights:
      FillFloatWeights(out, rng);
      break;
    case Profile::kMixed:
      FillMixed(out, rng);
      break;
  }

  return out;
}

std::vector<size_t> BoundarySizes(size_t chunk_size) {
  // Every entry is a boundary something in the pipeline reasons about. The
  // interesting ones are chunk_size - 1 / chunk_size / chunk_size + 1, which is
  // where ChunkCountFor rolls over, and 2 * chunk_size + 7, which produces a
  // three-chunk file whose last chunk is 7 bytes -- the shape that catches a
  // final-chunk length computed as "chunk_size" rather than "what is left".
  return {
      0,
      1,
      7,
      chunk_size - 1,
      chunk_size,
      chunk_size + 1,
      2 * chunk_size,
      (2 * chunk_size) + 7,
  };
}

std::vector<uint8_t> TestKey(uint64_t seed) {
  std::vector<uint8_t> key(32);
  Rng rng(seed);
  FillRandom(key, rng);
  return key;
}

std::vector<uint8_t> ReadWholeFile(const std::string& path) {
  std::vector<uint8_t> out;

  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    return out;
  }

  struct stat info = {};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0) {
    ::close(fd);
    return out;
  }

  out.resize(static_cast<size_t>(info.st_size));

  size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::read(fd, out.data() + done, out.size() - done);
    if (n <= 0) {
      // A short read means the file changed under us, which for a test fixture
      // is a failure rather than a partial success to work with.
      ::close(fd);
      out.clear();
      return out;
    }

    done += static_cast<size_t>(n);
  }

  ::close(fd);
  return out;
}

bool WriteWholeFile(const std::string& path, const std::vector<uint8_t>& data) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    return false;
  }

  size_t done = 0;
  while (done < data.size()) {
    const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
    if (n < 0) {
      ::close(fd);
      return false;
    }

    done += static_cast<size_t>(n);
  }

  return ::close(fd) == 0;
}

std::string TempPath(const std::string& tag) {
  const char* base = std::getenv("TMPDIR");
  std::string directory = base != nullptr ? base : "/tmp";
  if (!directory.empty() && directory.back() == '/') {
    directory.pop_back();
  }

  return directory + "/model-crypt-test-" + std::to_string(::getpid()) + "-" +
         tag;
}

}  // namespace corpus
