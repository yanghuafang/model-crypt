/// \file vector_test.cc
/// A committed `.mcrypt` file, and the requirement that this build still reads
/// it.
///
/// Every other suite encrypts and decrypts with the same binary, so it agrees
/// with itself by construction: change an offset in format.cc or flip the nonce
/// counter's byte order and the round trip still passes while every file the
/// previous release wrote becomes undecryptable. This suite is what catches
/// that.
///
/// The vector is two 4 KiB chunks -- a zeroed run that deflates and a random
/// run stored raw -- so both chunk flags are covered in 4 KiB of repository.
/// Its plaintext is regenerated from corpus::Generate rather than committed,
/// which is why that generator is specified to be byte-identical everywhere.
///
/// Regenerate only when #MC_FORMAT_VERSION is deliberately bumped, with
/// `scripts/make-vector.sh --force`, and keep the old vector with a test
/// asserting it is now #MC_ERR_UNSUPPORTED. A regression looks like this suite
/// failing, not like a diff: the salt and nonce are random per call, so a
/// regenerated vector differs every time whether or not the layout moved.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "check.h"
#include "corpus.h"
#include "model_crypt/model_crypt.h"

namespace {

// The parameters scripts/make-vector.sh used. Duplicated here rather than
// derived from the file, because reading them out of the header under test
// would make the test agree with whatever the header happens to say.
constexpr size_t kVectorChunkSize = 4u << 10;
constexpr size_t kVectorPlainSize = 2 * kVectorChunkSize;
constexpr uint64_t kVectorSeed = 20240824;
constexpr uint64_t kVectorKeySeed = 99;

std::string VectorPath() {
  // MODEL_CRYPT_TEST_DATA_DIR is set by CMake, so the test finds its data
  // whether it is run from the build directory, from ctest, or from a
  // debugger's working directory. A relative path would work in exactly one of
  // those.
  const char* dir = std::getenv("MODEL_CRYPT_TEST_DATA_DIR");
  if (dir == nullptr) {
    dir = MODEL_CRYPT_TEST_DATA_DIR;
  }

  return std::string(dir) + "/v2-two-chunks.mcrypt";
}

std::vector<uint8_t> ReadVector() {
  return corpus::ReadWholeFile(VectorPath());
}

}  // namespace

TEST(Vector, CommittedFileStillDecrypts) {
  const std::vector<uint8_t> cipher = ReadVector();
  if (cipher.empty()) {
    // Restore, not regenerate. A fresh vector would be a file this build
    // wrote, which proves nothing the other suites do not already prove; the
    // committed one is the copy an older build produced.
    testing::ReportFailure(
        ctx, __FILE__, __LINE__, "read test vector",
        "cannot read " + VectorPath() +
            " — restore it with: git checkout -- tests/vectors/");
    return;
  }

  const std::vector<uint8_t> key = corpus::TestKey(kVectorKeySeed);
  // The same two halves make_vector.cc writes, spelled out again rather than
  // shared through a header: a helper both sides called would let one change
  // redefine the expectation and the data together, which is exactly what a
  // golden vector exists to prevent.
  std::vector<uint8_t> expected =
      corpus::Generate(corpus::Profile::kZeros, kVectorChunkSize, kVectorSeed);
  const std::vector<uint8_t> tail = corpus::Generate(
      corpus::Profile::kRandom, kVectorChunkSize, kVectorSeed + 1);
  expected.insert(expected.end(), tail.begin(), tail.end());

  uint8_t* recovered = nullptr;
  size_t recovered_size = 0;
  const mc_status rc =
      mc_decrypt_buffer(key.data(), key.size(), cipher.data(), cipher.size(),
                        &recovered, &recovered_size);
  if (rc != MC_OK) {
    testing::ReportFailure(
        ctx, __FILE__, __LINE__, "mc_decrypt_buffer",
        std::string("committed vector no longer decrypts: ") +
            mc_status_string(rc) +
            " — a format change would break every file already written");
    return;
  }

  CHECK_EQ(recovered_size, expected.size());
  if (recovered_size == expected.size()) {
    CHECK(std::memcmp(recovered, expected.data(), expected.size()) == 0);
  }

  mc_free(recovered, recovered_size);
}

TEST(Vector, CommittedFileHasTheExpectedShape) {
  const std::vector<uint8_t> cipher = ReadVector();
  REQUIRE(!cipher.empty());

  mc_file_info info = {};
  REQUIRE_EQ(mc_inspect_buffer(cipher.data(), cipher.size(), &info), MC_OK);

  CHECK_EQ(info.format_version, MC_FORMAT_VERSION);
  CHECK_EQ(info.chunk_size, kVectorChunkSize);
  CHECK_EQ(info.chunk_count, 2u);
  CHECK_EQ(info.plaintext_size, kVectorPlainSize);
  CHECK_EQ(info.compression, MC_COMPRESS_ZLIB);

  // Both chunk flags appear: chunk 0 is the zeroed run of the Mixed profile and
  // deflates well, chunk 1 is its random run and is stored raw. If a future
  // change made the encoder stop falling back to raw storage, the round trip
  // would still pass and this would not.
  const size_t chunk0_flags = MC_HEADER_SIZE + 4;
  uint32_t chunk0_stored = 0;
  for (size_t i = 0; i < 4; ++i) {
    chunk0_stored |= static_cast<uint32_t>(cipher[MC_HEADER_SIZE + i])
                     << (8 * i);
  }

  CHECK_EQ(cipher[chunk0_flags] & 0x01, 0x01);
  CHECK(chunk0_stored < kVectorChunkSize);

  const size_t chunk1_base = MC_HEADER_SIZE + 24 + chunk0_stored;
  REQUIRE(chunk1_base + 24 <= cipher.size());
  CHECK_EQ(cipher[chunk1_base + 4] & 0x01, 0x00);
}

TEST(Vector, WrongKeyOnCommittedFileFails) {
  const std::vector<uint8_t> cipher = ReadVector();
  REQUIRE(!cipher.empty());

  const std::vector<uint8_t> wrong = corpus::TestKey(kVectorKeySeed + 1);
  uint8_t* recovered = nullptr;
  size_t recovered_size = 0;
  CHECK_EQ(mc_decrypt_buffer(wrong.data(), wrong.size(), cipher.data(),
                             cipher.size(), &recovered, &recovered_size),
           MC_ERR_AUTH);
}
