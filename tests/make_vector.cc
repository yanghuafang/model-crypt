/// \file make_vector.cc
/// Writes tests/vectors/v2-two-chunks.mcrypt, the committed golden vector.
///
/// A separate binary rather than a mode of the test suite, because generating
/// the file and asserting against it are opposite jobs: a test that can rewrite
/// its own expected data cannot fail. Run through scripts/make-vector.sh, and
/// only when #MC_FORMAT_VERSION is deliberately bumped — see vector_test.cc.

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

#include "corpus.h"
#include "model_crypt/model_crypt.h"

namespace {

// Split from main so an allocation failure in the corpus vectors becomes an
// exit code rather than an exception escaping main. See the same split in
// src/cli/main.cc.
int Run(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s OUTPUT.mcrypt\n", argv[0]);
    return 2;
  }

  // These four constants are mirrored in vector_test.cc. Kept as literals in
  // both places on purpose: a shared header would let a change to the generator
  // silently redefine what the test expects, which is the one thing this vector
  // exists to prevent.
  constexpr uint32_t kChunkSize = 4u << 10;
  constexpr uint64_t kSeed = 20240824;
  constexpr uint64_t kKeySeed = 99;

  // Two halves, one per chunk: a compressible one and an incompressible one, so
  // the vector pins down both chunk flags. A single profile could not guarantee
  // that -- whether a given chunk deflates is a property of its contents, and a
  // uniform payload gives every chunk the same answer.
  std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kZeros, kChunkSize, kSeed);
  const std::vector<uint8_t> tail =
      corpus::Generate(corpus::Profile::kRandom, kChunkSize, kSeed + 1);
  plain.insert(plain.end(), tail.begin(), tail.end());

  const std::vector<uint8_t> key = corpus::TestKey(kKeySeed);

  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  opts.chunk_size = kChunkSize;
  opts.compression = MC_COMPRESS_ZLIB;
  // The minimum cost, so the vector test stays fast; the vector is about
  // layout, not about how expensive the KDF is.
  opts.kdf_log_n = 14;

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  const mc_status rc =
      mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                        plain.size(), &cipher, &cipher_size);
  if (rc != MC_OK) {
    std::fprintf(stderr, "make-vector: encrypt failed: %s\n",
                 mc_status_string(rc));
    return 1;
  }

  std::FILE* file = std::fopen(argv[1], "wb");
  if (file == nullptr) {
    std::fprintf(stderr, "make-vector: cannot write %s\n", argv[1]);
    mc_free(cipher, cipher_size);
    return 1;
  }

  const size_t written = std::fwrite(cipher, 1, cipher_size, file);
  std::fclose(file);
  mc_free(cipher, cipher_size);

  if (written != cipher_size) {
    std::fprintf(stderr, "make-vector: short write to %s\n", argv[1]);
    return 1;
  }

  std::printf("wrote %zu bytes to %s\n", cipher_size, argv[1]);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return Run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "make-vector: %s\n", error.what());
    return 1;
  }
}
