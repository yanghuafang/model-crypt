#ifndef MODEL_CRYPT_TESTS_CORPUS_H_
#define MODEL_CRYPT_TESTS_CORPUS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/// Synthetic test payloads -- the reason this suite needs no model file.
///
/// The library is byte-oriented; only two input properties change its
/// behaviour, so those are what the corpus spans:
///
///   * length, against the chunk boundaries;
///   * compressibility, which decides whether a chunk stores deflated or raw.
///
/// Generation is deterministic from a fixed seed, so a failure is reproducible
/// from the test name alone.
///
/// The profiles: kZeros is deflate's best case; kRandom makes deflate expand
/// and exercises the raw-store fallback; kFloatWeights is the realistic case,
/// with repeating exponent bytes and random-looking mantissas that deflate
/// shrinks by 10-20%; kMixed puts both chunk flags in one file.
namespace corpus {

/// The byte-pattern families described in the table above.
enum class Profile {
  kZeros,
  kRandom,
  kFloatWeights,
  kMixed,
};

/// Human-readable name of \p profile, for test output.
const char* ProfileName(Profile profile);

/// Generate \p size bytes of \p profile, deterministically from \p seed.
///
/// Byte-identical on every platform. Written longhand rather than with
/// <random>, whose distributions are not specified to produce the same sequence
/// across standard library implementations -- and the committed format vector
/// depends on this being reproducible.
std::vector<uint8_t> Generate(Profile profile, size_t size, uint64_t seed);

/// The lengths every round-trip test sweeps, for a given chunk size: empty, one
/// byte, just under, exactly, and just over one chunk, several full chunks, and
/// a multi-chunk file with a short tail. Built from \p chunk_size so the sweep
/// still lands on the boundaries at a non-default chunk size.
std::vector<size_t> BoundarySizes(size_t chunk_size);

/// A deterministic 32-byte key, for tests that do not care which key they use.
std::vector<uint8_t> TestKey(uint64_t seed);

/// Read all of \p path, or an empty vector if it cannot be read.
///
/// Sized from fstat and read in one call. The fread-until-zero loop is the
/// idiom, but clang-analyzer-unix.Stream reports its final no-op read as a read
/// on an exhausted stream.
std::vector<uint8_t> ReadWholeFile(const std::string& path);

/// Write \p data to \p path, replacing it. Returns false on any failure.
bool WriteWholeFile(const std::string& path, const std::vector<uint8_t>& data);

/// A path under the build tree's temporary directory, for the file-API tests.
///
/// Includes the process id, so two concurrent `ctest -j` runs cannot collide.
std::string TempPath(const std::string& tag);

}  // namespace corpus

#endif  // MODEL_CRYPT_TESTS_CORPUS_H_
