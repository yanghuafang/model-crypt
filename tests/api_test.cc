/// \file api_test.cc
/// The C API's own contract: argument validation, defaults, the file-based
/// entry points, and inspect.
///
/// Separate from RoundTripTests because the subject is different. There, the
/// question is whether the bytes survive; here it is whether a caller who does
/// the wrong thing gets a defined answer — a NULL pointer, a short key, a
/// nonexistent path, an out-of-range option. Those are the paths a library
/// linked into someone else's inference runtime will actually be driven down.

#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "check.h"
#include "corpus.h"
#include "model_crypt/model_crypt.h"

namespace {

// size_t, not uint32_t. Every use is `N * kSmallChunk` as a byte count, and in
// uint32_t that product is computed narrow and then widened -- which is correct
// here but is the shape of a real overflow bug, so clang-tidy flags it. Making
// the constant size_t means the arithmetic happens in the type the result is
// used as, and the one place a uint32_t is required says so with a cast.
constexpr size_t kSmallChunk = 4u << 10;

mc_encrypt_options FastOptions() {
  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  opts.chunk_size = static_cast<uint32_t>(kSmallChunk);
  opts.kdf_log_n = 14;
  return opts;
}

}  // namespace

TEST(Api, VersionAndStatusStringsAreUsable) {
  CHECK(mc_version_string() != nullptr);
  CHECK(std::strlen(mc_version_string()) > 0);

  // Every enumerator has its own message, and none is null.
  const mc_status all[] = {
      MC_OK,       MC_ERR_INVALID_ARG, MC_ERR_FORMAT, MC_ERR_UNSUPPORTED,
      MC_ERR_AUTH, MC_ERR_COMPRESS,    MC_ERR_CRYPTO, MC_ERR_MEMORY,
      MC_ERR_IO,   MC_ERR_TOO_LARGE};
  for (mc_status status : all) {
    CHECK(mc_status_string(status) != nullptr);
    CHECK(std::strlen(mc_status_string(status)) > 0);
  }

  // And a value outside the enum, which a C caller can produce, still returns a
  // printable string rather than falling off the end of the switch.
  CHECK(mc_status_string(static_cast<mc_status>(9999)) != nullptr);
}

TEST(Api, OptionsInitIsTolerantOfNull) {
  // Documented to do nothing rather than crash, because a caller checking its
  // own allocation after the fact is a normal shape.
  mc_encrypt_options_init(nullptr);

  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  CHECK_EQ(opts.compression, MC_COMPRESS_ZLIB);
  CHECK_EQ(opts.chunk_size, 4u << 20);
  CHECK_EQ(opts.kdf_log_n, 15);
  CHECK_EQ(opts.kdf_r, 8u);
  CHECK_EQ(opts.kdf_p, 1u);
}

TEST(Api, NullArgumentsAreRejected) {
  const std::vector<uint8_t> key = corpus::TestKey(31);
  const std::vector<uint8_t> plain = {1, 2, 3, 4};
  uint8_t* out = nullptr;
  size_t out_size = 0;

  CHECK_EQ(mc_encrypt_buffer(nullptr, key.size(), nullptr, plain.data(),
                             plain.size(), &out, &out_size),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(mc_encrypt_buffer(key.data(), key.size(), nullptr, plain.data(),
                             plain.size(), nullptr, &out_size),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(mc_encrypt_buffer(key.data(), key.size(), nullptr, plain.data(),
                             plain.size(), &out, nullptr),
           MC_ERR_INVALID_ARG);

  // A non-zero length with a NULL buffer is the mismatch that would otherwise
  // become a read of 4 bytes from address zero.
  CHECK_EQ(mc_encrypt_buffer(key.data(), key.size(), nullptr, nullptr, 4, &out,
                             &out_size),
           MC_ERR_INVALID_ARG);

  CHECK_EQ(mc_decrypt_buffer(nullptr, key.size(), plain.data(), plain.size(),
                             &out, &out_size),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(
      mc_decrypt_buffer(key.data(), key.size(), nullptr, 4, &out, &out_size),
      MC_ERR_INVALID_ARG);

  CHECK_EQ(mc_inspect_buffer(nullptr, 64, nullptr), MC_ERR_INVALID_ARG);
  CHECK_EQ(mc_generate_key(nullptr, 32), MC_ERR_INVALID_ARG);
  CHECK_EQ(mc_generate_key(out, 0), MC_ERR_INVALID_ARG);

  // mc_free on NULL is a no-op, so a caller's cleanup path needs no guard.
  mc_free(nullptr, 0);
  mc_free(nullptr, 1234);
}

TEST(Api, ShortKeyIsRejected) {
  const std::vector<uint8_t> plain = {1, 2, 3, 4};
  std::vector<uint8_t> short_key(MC_MIN_KEY_SIZE - 1, 0xAB);
  uint8_t* out = nullptr;
  size_t out_size = 0;

  CHECK_EQ(mc_encrypt_buffer(short_key.data(), short_key.size(), nullptr,
                             plain.data(), plain.size(), &out, &out_size),
           MC_ERR_INVALID_ARG);

  // Exactly at the minimum, it must work -- otherwise the constant documents a
  // boundary the code does not have.
  std::vector<uint8_t> minimal_key(MC_MIN_KEY_SIZE, 0xAB);
  mc_encrypt_options opts = FastOptions();
  REQUIRE_EQ(mc_encrypt_buffer(minimal_key.data(), minimal_key.size(), &opts,
                               plain.data(), plain.size(), &out, &out_size),
             MC_OK);
  mc_free(out, out_size);
}

TEST(Api, OutOfRangeOptionsAreRejected) {
  const std::vector<uint8_t> key = corpus::TestKey(33);
  const std::vector<uint8_t> plain = {1, 2, 3, 4};
  uint8_t* out = nullptr;
  size_t out_size = 0;

  struct Case {
    const char* what;
    mc_encrypt_options opts;
  };

  auto with_chunk = [](uint32_t size) {
    mc_encrypt_options o;
    mc_encrypt_options_init(&o);
    o.kdf_log_n = 14;
    o.chunk_size = size;
    return o;
  };

  auto with_log_n = [](uint8_t log_n) {
    mc_encrypt_options o;
    mc_encrypt_options_init(&o);
    o.kdf_log_n = log_n;
    return o;
  };

  const Case cases[] = {
      {"chunk too small", with_chunk((4u << 10) - 1)},
      {"chunk too large", with_chunk((64u << 20) + 1)},
      {"chunk zero", with_chunk(0)},
      {"log_n too small", with_log_n(13)},
      {"log_n too large", with_log_n(21)},
  };

  for (const Case& test_case : cases) {
    const mc_status rc =
        mc_encrypt_buffer(key.data(), key.size(), &test_case.opts, plain.data(),
                          plain.size(), &out, &out_size);
    if (rc != MC_ERR_INVALID_ARG) {
      testing::ReportFailure(
          ctx, __FILE__, __LINE__, "expected INVALID_ARG",
          std::string(test_case.what) + " gave " + mc_status_string(rc));
      if (rc == MC_OK) {
        mc_free(out, out_size);
      }
    }
  }

  // An unknown compression id, which a caller can produce by casting.
  mc_encrypt_options bad = FastOptions();
  bad.compression = static_cast<mc_compression>(7);
  CHECK_EQ(mc_encrypt_buffer(key.data(), key.size(), &bad, plain.data(),
                             plain.size(), &out, &out_size),
           MC_ERR_INVALID_ARG);

  // The scrypt memory product bound: log_n 20 with r 32 is inside both
  // individual ranges and asks for 4 GiB together. It must be refused on the
  // way *out* as well as on the way in, so this build cannot write a file it
  // would refuse to read.
  mc_encrypt_options greedy = FastOptions();
  greedy.kdf_log_n = 20;
  greedy.kdf_r = 32;
  CHECK_EQ(mc_encrypt_buffer(key.data(), key.size(), &greedy, plain.data(),
                             plain.size(), &out, &out_size),
           MC_ERR_INVALID_ARG);
}

TEST(Api, GenerateKeyProducesDistinctBytes) {
  uint8_t first[32] = {};
  uint8_t second[32] = {};
  REQUIRE_EQ(mc_generate_key(first, sizeof(first)), MC_OK);
  REQUIRE_EQ(mc_generate_key(second, sizeof(second)), MC_OK);

  // Two draws differing is a weak property, but its failure mode is the one
  // that matters: a stub or a misconfigured RNG that returns a constant.
  CHECK(std::memcmp(first, second, sizeof(first)) != 0);

  bool all_zero = true;
  for (uint8_t byte : first) {
    if (byte != 0) {
      all_zero = false;
      break;
    }
  }
  CHECK(!all_zero);
}

TEST(Api, InspectReportsHeaderFields) {
  const std::vector<uint8_t> key = corpus::TestKey(35);
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kRandom, (3 * kSmallChunk) + 11, 37);

  mc_encrypt_options opts = FastOptions();
  opts.compression = MC_COMPRESS_NONE;
  opts.kdf_r = 4;
  opts.kdf_p = 2;

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  mc_file_info info = {};
  CHECK_EQ(mc_inspect_buffer(cipher, cipher_size, &info), MC_OK);
  CHECK_EQ(info.format_version, MC_FORMAT_VERSION);
  CHECK_EQ(info.compression, MC_COMPRESS_NONE);
  CHECK_EQ(info.plaintext_size, plain.size());
  CHECK_EQ(info.chunk_size, kSmallChunk);
  CHECK_EQ(info.chunk_count, 4u);
  CHECK_EQ(info.kdf_log_n, 14);
  CHECK_EQ(info.kdf_r, 4u);
  CHECK_EQ(info.kdf_p, 2u);

  // The header alone is enough, which is what lets the CLI's `inspect` read 64
  // bytes instead of a multi-gigabyte file.
  mc_file_info header_only = {};
  CHECK_EQ(mc_inspect_buffer(cipher, MC_HEADER_SIZE, &header_only), MC_OK);
  CHECK_EQ(header_only.chunk_count, 4u);

  // One byte short of the header is not.
  CHECK_EQ(mc_inspect_buffer(cipher, MC_HEADER_SIZE - 1, &header_only),
           MC_ERR_FORMAT);

  mc_free(cipher, cipher_size);
}

TEST(Api, FileRoundTripAndPermissions) {
  const std::vector<uint8_t> key = corpus::TestKey(39);
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kMixed, (5 * kSmallChunk) + 3, 41);

  const std::string plain_path = corpus::TempPath("api-plain");
  const std::string cipher_path = corpus::TempPath("api-cipher");
  const std::string out_path = corpus::TempPath("api-out");

  REQUIRE(corpus::WriteWholeFile(plain_path, plain));

  const mc_encrypt_options opts = FastOptions();
  REQUIRE_EQ(mc_encrypt_file(key.data(), key.size(), &opts, plain_path.c_str(),
                             cipher_path.c_str()),
             MC_OK);
  REQUIRE_EQ(mc_decrypt_file(key.data(), key.size(), cipher_path.c_str(),
                             out_path.c_str()),
             MC_OK);

  const std::vector<uint8_t> recovered = corpus::ReadWholeFile(out_path);
  CHECK_EQ(recovered.size(), plain.size());
  CHECK(recovered == plain);

  // The decrypted model is 0600 and the ciphertext is 0644, regardless of the
  // process umask. The v1 demos wrote plaintext to world-readable locations,
  // which made their encryption irrelevant; this is the assertion that keeps
  // that from coming back.
  struct stat plain_stat = {};
  struct stat cipher_stat = {};
  REQUIRE_EQ(::stat(out_path.c_str(), &plain_stat), 0);
  REQUIRE_EQ(::stat(cipher_path.c_str(), &cipher_stat), 0);
  CHECK_EQ(plain_stat.st_mode & 0777, 0600);
  CHECK_EQ(cipher_stat.st_mode & 0777, 0644);

  // decrypt-to-buffer must agree with decrypt-to-file, and is the form a client
  // device should use.
  uint8_t* buffered = nullptr;
  size_t buffered_size = 0;
  REQUIRE_EQ(
      mc_decrypt_file_to_buffer(key.data(), key.size(), cipher_path.c_str(),
                                &buffered, &buffered_size),
      MC_OK);
  CHECK_EQ(buffered_size, plain.size());
  CHECK(std::memcmp(buffered, plain.data(), plain.size()) == 0);
  mc_free(buffered, buffered_size);

  ::unlink(plain_path.c_str());
  ::unlink(cipher_path.c_str());
  ::unlink(out_path.c_str());
}

TEST(Api, FailedDecryptionLeavesNoOutputFile) {
  const std::vector<uint8_t> key = corpus::TestKey(43);
  const std::vector<uint8_t> wrong_key = corpus::TestKey(44);
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kZeros, 2 * kSmallChunk, 45);

  const std::string plain_path = corpus::TempPath("noleak-plain");
  const std::string cipher_path = corpus::TempPath("noleak-cipher");
  const std::string out_path = corpus::TempPath("noleak-out");

  REQUIRE(corpus::WriteWholeFile(plain_path, plain));
  const mc_encrypt_options opts = FastOptions();
  REQUIRE_EQ(mc_encrypt_file(key.data(), key.size(), &opts, plain_path.c_str(),
                             cipher_path.c_str()),
             MC_OK);

  CHECK_EQ(mc_decrypt_file(wrong_key.data(), wrong_key.size(),
                           cipher_path.c_str(), out_path.c_str()),
           MC_ERR_AUTH);

  // Not created at all -- not empty, not partial. A failed decryption that left
  // a file behind would put attacker-chosen bytes under the name of a model.
  struct stat out_stat = {};
  CHECK(::stat(out_path.c_str(), &out_stat) != 0);

  ::unlink(plain_path.c_str());
  ::unlink(cipher_path.c_str());
  ::unlink(out_path.c_str());
}

TEST(Api, MissingAndNonRegularPathsReportIo) {
  const std::vector<uint8_t> key = corpus::TestKey(47);
  const mc_encrypt_options opts = FastOptions();

  const std::string missing = corpus::TempPath("does-not-exist");
  CHECK_EQ(mc_encrypt_file(key.data(), key.size(), &opts, missing.c_str(),
                           corpus::TempPath("ignored").c_str()),
           MC_ERR_IO);
  CHECK_EQ(mc_decrypt_file(key.data(), key.size(), missing.c_str(),
                           corpus::TempPath("ignored").c_str()),
           MC_ERR_IO);

  uint8_t* out = nullptr;
  size_t out_size = 0;
  CHECK_EQ(mc_decrypt_file_to_buffer(key.data(), key.size(), missing.c_str(),
                                     &out, &out_size),
           MC_ERR_IO);

  // A directory is not a regular file. The naive `st_mode & S_IFREG` test used
  // by the v1 code accepted several of these; S_ISREG does not.
  CHECK_EQ(mc_encrypt_file(key.data(), key.size(), &opts, "/",
                           corpus::TempPath("ignored").c_str()),
           MC_ERR_IO);

  CHECK_EQ(mc_encrypt_file(key.data(), key.size(), &opts, nullptr, "x"),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(mc_decrypt_file(key.data(), key.size(), "x", nullptr),
           MC_ERR_INVALID_ARG);
}

TEST(Api, EmptyInputRoundTrips) {
  const std::vector<uint8_t> key = corpus::TestKey(49);
  const mc_encrypt_options opts = FastOptions();

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, nullptr, 0,
                               &cipher, &cipher_size),
             MC_OK);

  // One chunk, not zero: something has to authenticate the header, or an empty
  // file would be forgeable without the key. See format.h.
  mc_file_info info = {};
  CHECK_EQ(mc_inspect_buffer(cipher, cipher_size, &info), MC_OK);
  CHECK_EQ(info.chunk_count, 1u);
  CHECK_EQ(info.plaintext_size, 0u);
  CHECK_EQ(cipher_size, MC_HEADER_SIZE + 24);

  uint8_t* plain = nullptr;
  size_t plain_size = 1;
  REQUIRE_EQ(mc_decrypt_buffer(key.data(), key.size(), cipher, cipher_size,
                               &plain, &plain_size),
             MC_OK);
  CHECK_EQ(plain_size, 0u);
  mc_free(plain, plain_size);

  // And an empty file must still reject a wrong key, which is only true because
  // that single chunk's tag covers the header.
  const std::vector<uint8_t> wrong_key = corpus::TestKey(50);
  uint8_t* rejected = nullptr;
  size_t rejected_size = 0;
  CHECK_EQ(mc_decrypt_buffer(wrong_key.data(), wrong_key.size(), cipher,
                             cipher_size, &rejected, &rejected_size),
           MC_ERR_AUTH);

  mc_free(cipher, cipher_size);
}
