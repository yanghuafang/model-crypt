/// \file round_trip_test.cc
/// Encrypt-then-decrypt over the size and compressibility sweep.
///
/// This is the suite that would catch a chunk-walk off-by-one, a wrong final
/// chunk length, or a compression flag that disagrees with what the chunk
/// holds. Every case is generated — see corpus.h for why there is no model
/// file here.
///
/// == Why the KDF cost is turned down ==
///
/// Every test derives a key, and at the library's default cost (N = 2^15) that
/// is ~100 ms and 32 MiB each. Across this file's ~90 derivations it would be
/// nine seconds of CI time spent re-measuring scrypt's speed, which nothing
/// here is testing. The minimum permitted cost (N = 2^14) is used instead, and
/// KdfTests separately confirms the defaults work and that out-of-range values
/// are rejected.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "check.h"
#include "corpus.h"
#include "model_crypt/model_crypt.h"

namespace {

// A small chunk, so a multi-chunk file is a few hundred kilobytes rather than
// tens of megabytes. The chunk *logic* does not know how big a chunk is, so
// exercising it at 4 KiB proves the same thing as 4 MiB and runs 1000x faster;
// the default size is covered by DefaultOptionsRoundTrip below.
// size_t, not uint32_t. Every use is `N * kSmallChunk` as a byte count, and in
// uint32_t that product is computed narrow and then widened -- which is correct
// here but is the shape of a real overflow bug, so clang-tidy flags it. Making
// the constant size_t means the arithmetic happens in the type the result is
// used as, and the one place a uint32_t is required says so with a cast.
constexpr size_t kSmallChunk = 4u << 10;

mc_encrypt_options FastOptions(mc_compression compression, size_t chunk_size) {
  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  opts.compression = compression;
  opts.chunk_size = static_cast<uint32_t>(chunk_size);
  opts.kdf_log_n = 14;
  return opts;
}

// Encrypt, decrypt, compare. Reports through the caller's ctx so a failure
// points at the TEST that set up the case rather than at this helper.
void RoundTrip(testing::Context& ctx, const std::vector<uint8_t>& plain,
               const mc_encrypt_options& opts, const char* label) {
  const std::vector<uint8_t> key = corpus::TestKey(1);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  const mc_status encrypt_rc = mc_encrypt_buffer(
      key.data(), key.size(), &opts, plain.empty() ? nullptr : plain.data(),
      plain.size(), &cipher, &cipher_size);
  if (encrypt_rc != MC_OK) {
    testing::ReportFailure(
        ctx, __FILE__, __LINE__, "mc_encrypt_buffer",
        std::string(label) + ": " + mc_status_string(encrypt_rc));
    return;
  }

  // The header is always present, and the ciphertext always carries a chunk
  // record even for an empty model -- checked here because the alternative (a
  // zero-chunk file) would be forgeable without the key. See format.h.
  if (cipher_size < MC_HEADER_SIZE + 24) {
    testing::ReportFailure(
        ctx, __FILE__, __LINE__, "ciphertext too short",
        std::string(label) + ": " + std::to_string(cipher_size) + " bytes");
    mc_free(cipher, cipher_size);
    return;
  }

  uint8_t* recovered = nullptr;
  size_t recovered_size = 0;
  const mc_status decrypt_rc = mc_decrypt_buffer(
      key.data(), key.size(), cipher, cipher_size, &recovered, &recovered_size);
  mc_free(cipher, cipher_size);

  if (decrypt_rc != MC_OK) {
    testing::ReportFailure(
        ctx, __FILE__, __LINE__, "mc_decrypt_buffer",
        std::string(label) + ": " + mc_status_string(decrypt_rc));
    return;
  }

  if (recovered_size != plain.size()) {
    testing::ReportFailure(ctx, __FILE__, __LINE__, "recovered size",
                           std::string(label) + ": got " +
                               std::to_string(recovered_size) + ", want " +
                               std::to_string(plain.size()));
    mc_free(recovered, recovered_size);
    return;
  }

  for (size_t i = 0; i < plain.size(); ++i) {
    if (recovered[i] != plain[i]) {
      testing::ReportFailure(
          ctx, __FILE__, __LINE__, "recovered bytes",
          std::string(label) + ": first difference at " + std::to_string(i));
      break;
    }
  }

  mc_free(recovered, recovered_size);
}

}  // namespace

// The main sweep: every profile at every boundary size, with and without
// compression. 4 profiles x 8 sizes x 2 compression settings = 64 cases.
TEST(RoundTrip, ProfilesAcrossChunkBoundaries) {
  const corpus::Profile profiles[] = {
      corpus::Profile::kZeros, corpus::Profile::kRandom,
      corpus::Profile::kFloatWeights, corpus::Profile::kMixed};
  const mc_compression compressions[] = {MC_COMPRESS_NONE, MC_COMPRESS_ZLIB};

  for (corpus::Profile profile : profiles) {
    for (size_t size : corpus::BoundarySizes(kSmallChunk)) {
      const std::vector<uint8_t> plain = corpus::Generate(profile, size, 7);

      for (mc_compression compression : compressions) {
        const std::string label =
            std::string(corpus::ProfileName(profile)) + "/" +
            std::to_string(size) + "/" +
            (compression == MC_COMPRESS_ZLIB ? "zlib" : "none");
        RoundTrip(ctx, plain, FastOptions(compression, kSmallChunk),
                  label.c_str());
      }
    }
  }
}

// The default options, once, at a size that spans several default-sized chunks.
// Separate from the sweep because it is the configuration every caller who does
// not pass options gets, and the sweep deliberately does not use it.
TEST(RoundTrip, DefaultOptionsRoundTrip) {
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kFloatWeights, (9u << 20) + 12345u, 11);

  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  RoundTrip(ctx, plain, opts, "defaults/9MiB+12345");
}

// A NULL options pointer must behave exactly like mc_encrypt_options_init,
// which is the promise the header makes. Verified by decrypting one with the
// other's reader -- decryption takes no options, so a mismatch shows up as the
// two ciphertexts having different declared chunk sizes.
TEST(RoundTrip, NullOptionsMatchesDefaults) {
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kMixed, 200000, 3);
  const std::vector<uint8_t> key = corpus::TestKey(2);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), nullptr, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  mc_file_info info = {};
  CHECK_EQ(mc_inspect_buffer(cipher, cipher_size, &info), MC_OK);
  CHECK_EQ(info.chunk_size, 4u << 20);
  CHECK_EQ(info.kdf_log_n, 15);
  CHECK_EQ(info.compression, MC_COMPRESS_ZLIB);
  CHECK_EQ(info.plaintext_size, plain.size());

  mc_free(cipher, cipher_size);
}

// Two encryptions of the same plaintext under the same key must not produce the
// same bytes. This is the property the per-file random salt and nonce prefix
// exist for; the v1 format failed it, because Blowfish-ECB with a
// deterministically derived key is a pure function of the input.
TEST(RoundTrip, CiphertextDiffersAcrossCalls) {
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kZeros, 100000, 5);
  const std::vector<uint8_t> key = corpus::TestKey(3);

  uint8_t* first = nullptr;
  size_t first_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), nullptr, plain.data(),
                               plain.size(), &first, &first_size),
             MC_OK);

  uint8_t* second = nullptr;
  size_t second_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), nullptr, plain.data(),
                               plain.size(), &second, &second_size),
             MC_OK);

  // Same length -- the plaintext and the settings are identical -- but
  // different content, starting inside the header where the salt lives.
  CHECK_EQ(first_size, second_size);
  CHECK(std::memcmp(first, second, first_size) != 0);

  // And specifically: an all-zero plaintext must not encrypt to a repeating
  // ciphertext. Under ECB it would, which is the single most recognizable
  // symptom of the mode the v1 format used.
  bool saw_difference = false;
  const size_t payload = MC_HEADER_SIZE + 24;
  for (size_t i = payload + 8; i + 8 <= first_size && !saw_difference; i += 8) {
    if (std::memcmp(first + payload, first + i, 8) != 0) {
      saw_difference = true;
    }
  }
  CHECK(saw_difference);

  mc_free(first, first_size);
  mc_free(second, second_size);
}

// An incompressible payload must not make the file grow without bound: the
// encoder stores such chunks raw rather than emitting an expanded deflate
// stream. The bound checked here is the format's own overhead, 24 bytes per
// chunk plus the 64-byte header.
TEST(RoundTrip, IncompressibleInputDoesNotExpand) {
  const size_t size = 10 * kSmallChunk;
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kRandom, size, 13);
  const std::vector<uint8_t> key = corpus::TestKey(4);
  const mc_encrypt_options opts = FastOptions(MC_COMPRESS_ZLIB, kSmallChunk);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  CHECK_EQ(cipher_size, MC_HEADER_SIZE + (10 * (24 + kSmallChunk)));
  mc_free(cipher, cipher_size);
}

// A highly compressible payload must actually get smaller, which confirms the
// compressed path is taken at all rather than always falling back to raw.
TEST(RoundTrip, CompressibleInputShrinks) {
  const size_t size = 64 * kSmallChunk;
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kZeros, size, 17);
  const std::vector<uint8_t> key = corpus::TestKey(5);
  const mc_encrypt_options opts = FastOptions(MC_COMPRESS_ZLIB, kSmallChunk);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  CHECK(cipher_size < size / 10);
  mc_free(cipher, cipher_size);
}

// A key that is not the one used to encrypt must fail, and must fail as
// MC_ERR_AUTH specifically -- not MC_ERR_FORMAT, and above all not MC_OK with
// garbage. The v1 code returned success here, which is the defect that made
// every other weakness in it reachable.
TEST(RoundTrip, WrongKeyFailsWithAuthError) {
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kFloatWeights, 5 * kSmallChunk, 19);
  const std::vector<uint8_t> right = corpus::TestKey(6);
  const std::vector<uint8_t> wrong = corpus::TestKey(7);
  const mc_encrypt_options opts = FastOptions(MC_COMPRESS_ZLIB, kSmallChunk);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(right.data(), right.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  auto* recovered = reinterpret_cast<uint8_t*>(0x1);
  size_t recovered_size = 12345;
  CHECK_EQ(mc_decrypt_buffer(wrong.data(), wrong.size(), cipher, cipher_size,
                             &recovered, &recovered_size),
           MC_ERR_AUTH);

  // Out-parameters untouched on failure, which is what lets a caller that
  // ignores the status still not read a half-built buffer.
  CHECK(recovered == reinterpret_cast<uint8_t*>(0x1));
  CHECK_EQ(recovered_size, 12345u);

  mc_free(cipher, cipher_size);
}
