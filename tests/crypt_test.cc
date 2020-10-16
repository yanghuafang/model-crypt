/// \file crypt_test.cc
/// Unit tests for the internal layers, below the C API.
///
/// These reach into `src/` — crypt/format.h, crypt/compress.h,
/// crypt/secure_buffer.h, crypt/kdf.h — which the installed library does not
/// export. That is deliberate: the properties tested here are not observable
/// through the public API without constructing a whole file to provoke them,
/// and a test that has to go the long way round is a test that stops being
/// written.
///
/// The division of labour with the other suites: TamperTests asserts that a
/// hostile *file* is rejected, and this asserts that each layer rejects a
/// hostile *argument* — including combinations the format's own encoder can
/// never produce, which is where a future encoder's bug would land.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "check.h"
#include "corpus.h"
#include "crypt/aead.h"
#include "crypt/compress.h"
#include "crypt/format.h"
#include "crypt/kdf.h"
#include "crypt/secure_buffer.h"
#include "model_crypt/model_crypt.h"

namespace {

// A header with every field set to something distinguishable, so a
// serialize/parse round trip that swapped two fields would show up rather than
// cancelling out.
format::FileHeader DistinctiveHeader() {
  format::FileHeader header;
  header.format_version = MC_FORMAT_VERSION;
  header.kdf_id = format::kKdfScrypt;
  header.aead_id = format::kAeadAes256Gcm;
  header.compression_id = static_cast<uint8_t>(MC_COMPRESS_ZLIB);
  header.kdf_log_n = 16;
  header.kdf_r = 7;
  header.kdf_p = 3;
  header.chunk_size = 8u << 10;
  header.plaintext_size = (3 * (8u << 10)) + 5;
  header.chunk_count = 4;

  for (size_t i = 0; i < format::kSaltSize; ++i) {
    header.salt[i] = static_cast<uint8_t>(0xA0 + i);
  }
  for (size_t i = 0; i < format::kNoncePrefixSize; ++i) {
    header.nonce_prefix[i] = static_cast<uint8_t>(0xF0 + i);
  }

  return header;
}

}  // namespace

TEST(Format, ConstantsAreSelfConsistent) {
  // The public MC_HEADER_SIZE and the internal kHeaderSize must agree; a caller
  // sizes its inspect buffer on the former and the parser reads the latter.
  CHECK_EQ(format::kHeaderSize, MC_HEADER_SIZE);
  CHECK_EQ(format::kMagicSize, 8u);
  CHECK_EQ(format::kNonceSize, format::kNoncePrefixSize + 4);
  CHECK_EQ(format::kAadSize, format::kHeaderSize + 9);
  CHECK_EQ(format::kKeySize, 32u);
  CHECK_EQ(format::kTagSize, 16u);
  CHECK_EQ(format::kChunkHeaderSize, 24u);

  // The magic carries the version, so a v1 or a v3 file is rejected at the
  // first memcmp rather than after a partial parse.
  CHECK(std::memcmp(format::kMagic, "MCRYPT02", 8) == 0);
}

TEST(Format, HeaderRoundTrips) {
  const format::FileHeader original = DistinctiveHeader();
  uint8_t bytes[format::kHeaderSize];
  format::SerializeFileHeader(original, bytes);

  format::FileHeader parsed;
  REQUIRE_EQ(format::ParseFileHeader(bytes, sizeof(bytes), &parsed), MC_OK);

  CHECK_EQ(parsed.format_version, original.format_version);
  CHECK_EQ(parsed.kdf_id, original.kdf_id);
  CHECK_EQ(parsed.aead_id, original.aead_id);
  CHECK_EQ(parsed.compression_id, original.compression_id);
  CHECK_EQ(parsed.kdf_log_n, original.kdf_log_n);
  CHECK_EQ(parsed.kdf_r, original.kdf_r);
  CHECK_EQ(parsed.kdf_p, original.kdf_p);
  CHECK_EQ(parsed.chunk_size, original.chunk_size);
  CHECK_EQ(parsed.plaintext_size, original.plaintext_size);
  CHECK_EQ(parsed.chunk_count, original.chunk_count);
  CHECK(std::memcmp(parsed.salt, original.salt, format::kSaltSize) == 0);
  CHECK(std::memcmp(parsed.nonce_prefix, original.nonce_prefix,
                    format::kNoncePrefixSize) == 0);
}

TEST(Format, HeaderIsLittleEndianRegardlessOfHost) {
  // The whole point of writing the integers by hand in format.cc: the bytes on
  // disk must not depend on the machine that wrote them. Asserting the exact
  // positions is what makes this a portability test rather than a tautology --
  // a memcpy of a packed struct would pass a round trip and fail this.
  format::FileHeader header;
  header.chunk_size = 0x01020304u;
  header.plaintext_size = 0x0102030405060708ull;
  header.chunk_count =
      format::ChunkCountFor(header.plaintext_size, 0x01020304u);

  uint8_t bytes[format::kHeaderSize];
  format::SerializeFileHeader(header, bytes);

  CHECK_EQ(bytes[46], 0x04);
  CHECK_EQ(bytes[47], 0x03);
  CHECK_EQ(bytes[48], 0x02);
  CHECK_EQ(bytes[49], 0x01);

  CHECK_EQ(bytes[50], 0x08);
  CHECK_EQ(bytes[57], 0x01);
}

TEST(Format, ChunkCountIsNeverZero) {
  // An empty model still gets a chunk, because a zero-chunk file would have
  // nothing authenticating its header and could be forged without the key.
  CHECK_EQ(format::ChunkCountFor(0, 4096), 1u);
  CHECK_EQ(format::ChunkCountFor(1, 4096), 1u);
  CHECK_EQ(format::ChunkCountFor(4096, 4096), 1u);
  CHECK_EQ(format::ChunkCountFor(4097, 4096), 2u);
  CHECK_EQ(format::ChunkCountFor(8192, 4096), 2u);
  CHECK_EQ(format::ChunkCountFor(8193, 4096), 3u);
}

TEST(Format, ParserRejectsBadHeaders) {
  const format::FileHeader good = DistinctiveHeader();
  uint8_t bytes[format::kHeaderSize];
  format::FileHeader parsed;

  // Short input, at every length up to the header size.
  format::SerializeFileHeader(good, bytes);
  for (size_t length = 0; length < format::kHeaderSize; ++length) {
    CHECK_EQ(format::ParseFileHeader(bytes, length, &parsed), MC_ERR_FORMAT);
  }

  // Null arguments.
  CHECK_EQ(format::ParseFileHeader(nullptr, sizeof(bytes), &parsed),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(format::ParseFileHeader(bytes, sizeof(bytes), nullptr),
           MC_ERR_INVALID_ARG);

  struct Case {
    const char* what;
    size_t offset;
    uint8_t value;
    mc_status expected;
  };

  // Each case names the field and the status it must produce. The statuses are
  // asserted individually because the distinction is part of the contract: a
  // caller shows a different message for "not our file" than for "our file,
  // from a newer version".
  const Case cases[] = {
      {"magic", 0, 'X', MC_ERR_FORMAT},
      {"version", 8, 0x63, MC_ERR_UNSUPPORTED},
      {"kdf id", 10, 9, MC_ERR_UNSUPPORTED},
      {"aead id", 11, 9, MC_ERR_UNSUPPORTED},
      {"compression id", 12, 9, MC_ERR_UNSUPPORTED},
      {"log_n below range", 13, 13, MC_ERR_UNSUPPORTED},
      {"log_n above range", 13, 21, MC_ERR_UNSUPPORTED},
      {"reserved nonzero", 62, 1, MC_ERR_FORMAT},
  };

  for (const Case& test_case : cases) {
    format::SerializeFileHeader(good, bytes);
    bytes[test_case.offset] = test_case.value;
    const mc_status rc = format::ParseFileHeader(bytes, sizeof(bytes), &parsed);
    if (rc != test_case.expected) {
      testing::ReportFailure(ctx, __FILE__, __LINE__, "ParseFileHeader",
                             std::string(test_case.what) + ": got " +
                                 mc_status_string(rc) + ", want " +
                                 mc_status_string(test_case.expected));
    }
  }

  // An out-of-range chunk size, written through the struct so both bounds are
  // covered rather than one byte of one of them.
  for (uint32_t chunk_size : {0u, format::kMinChunkSize - 1,
                              format::kMaxChunkSize + 1, 0xFFFFFFFFu}) {
    format::FileHeader bad = good;
    bad.chunk_size = chunk_size;
    bad.chunk_count = 1;
    format::SerializeFileHeader(bad, bytes);
    CHECK_EQ(format::ParseFileHeader(bytes, sizeof(bytes), &parsed),
             MC_ERR_FORMAT);
  }

  // A chunk count that disagrees with the declared plaintext size. The parser
  // recomputes it rather than trusting it, which removes a whole class of
  // mismatch from every loop downstream.
  format::FileHeader inconsistent = good;
  inconsistent.chunk_count = good.chunk_count + 1;
  format::SerializeFileHeader(inconsistent, bytes);
  CHECK_EQ(format::ParseFileHeader(bytes, sizeof(bytes), &parsed),
           MC_ERR_FORMAT);

  // A plaintext size above the build's ceiling.
  format::FileHeader huge = good;
  huge.plaintext_size = MC_MAX_PLAINTEXT_SIZE + 1;
  huge.chunk_count =
      format::ChunkCountFor(huge.plaintext_size, huge.chunk_size);
  format::SerializeFileHeader(huge, bytes);
  CHECK_EQ(format::ParseFileHeader(bytes, sizeof(bytes), &parsed),
           MC_ERR_TOO_LARGE);

  // The scrypt memory product: log_n and r each in range, 4 GiB together.
  format::FileHeader greedy = good;
  greedy.kdf_log_n = 20;
  greedy.kdf_r = 32;
  format::SerializeFileHeader(greedy, bytes);
  CHECK_EQ(format::ParseFileHeader(bytes, sizeof(bytes), &parsed),
           MC_ERR_UNSUPPORTED);
}

TEST(Format, ChunkHeaderRoundTripsAndValidates) {
  format::ChunkHeader chunk;
  chunk.stored_size = 1234;
  chunk.flags = format::kChunkFlagCompressed;

  uint8_t tag[format::kTagSize];
  for (size_t i = 0; i < sizeof(tag); ++i) {
    tag[i] = static_cast<uint8_t>(0x10 + i);
  }

  uint8_t bytes[format::kChunkHeaderSize];
  format::SerializeChunkHeader(chunk, tag, bytes);

  format::ChunkHeader parsed;
  uint8_t parsed_tag[format::kTagSize];
  REQUIRE_EQ(format::ParseChunkHeader(bytes, 4096, &parsed, parsed_tag), MC_OK);
  CHECK_EQ(parsed.stored_size, chunk.stored_size);
  CHECK_EQ(parsed.flags, chunk.flags);
  CHECK(std::memcmp(parsed_tag, tag, sizeof(tag)) == 0);

  // Above the caller's bound.
  CHECK_EQ(format::ParseChunkHeader(bytes, 1233, &parsed, parsed_tag),
           MC_ERR_FORMAT);

  // An unknown flag bit, rejected rather than masked -- so a future flag cannot
  // be silently ignored by this reader.
  uint8_t modified[format::kChunkHeaderSize];
  std::memcpy(modified, bytes, sizeof(bytes));
  modified[4] |= 0x02;
  CHECK_EQ(format::ParseChunkHeader(modified, 4096, &parsed, parsed_tag),
           MC_ERR_FORMAT);

  // Nonzero reserved bytes.
  for (size_t i = 5; i < 8; ++i) {
    std::memcpy(modified, bytes, sizeof(bytes));
    modified[i] = 0x01;
    CHECK_EQ(format::ParseChunkHeader(modified, 4096, &parsed, parsed_tag),
             MC_ERR_FORMAT);
  }
}

TEST(Format, NonceIsUniquePerChunk) {
  uint8_t prefix[format::kNoncePrefixSize];
  for (size_t i = 0; i < sizeof(prefix); ++i) {
    prefix[i] = static_cast<uint8_t>(i);
  }

  // The property AES-GCM's security rests on entirely: within one file, no two
  // chunks share a nonce. Checked by construction rather than statistically --
  // the counter suffix is injective, so a collision would be a coding error,
  // and this is the test that would catch one.
  uint8_t a[format::kNonceSize];
  uint8_t b[format::kNonceSize];
  format::BuildNonce(prefix, 0, a);
  format::BuildNonce(prefix, 1, b);
  CHECK(std::memcmp(a, b, sizeof(a)) != 0);

  // Big-endian counter, matching NIST SP 800-38D's convention.
  format::BuildNonce(prefix, 0x01020304u, a);
  CHECK_EQ(a[8], 0x01);
  CHECK_EQ(a[9], 0x02);
  CHECK_EQ(a[10], 0x03);
  CHECK_EQ(a[11], 0x04);

  // The prefix is carried through unchanged, so two files with different
  // prefixes never share a nonce even at the same chunk index.
  CHECK(std::memcmp(a, prefix, sizeof(prefix)) == 0);
}

TEST(Format, AadCoversHeaderBytesAsWritten) {
  uint8_t header[format::kHeaderSize];
  for (size_t i = 0; i < sizeof(header); ++i) {
    header[i] = static_cast<uint8_t>(i);
  }

  format::ChunkHeader chunk;
  chunk.stored_size = 0x01020304u;
  chunk.flags = 0x01;

  uint8_t aad[format::kAadSize];
  format::BuildAad(header, 0x0A0B0C0Du, chunk, aad);

  // The header prefix must be byte-identical, including any byte the parser
  // does not interpret. Re-serializing a parsed struct instead would launder a
  // reserved byte an attacker set, and the tag would then verify.
  CHECK(std::memcmp(aad, header, sizeof(header)) == 0);

  CHECK_EQ(aad[64], 0x0D);
  CHECK_EQ(aad[67], 0x0A);
  CHECK_EQ(aad[68], 0x04);
  CHECK_EQ(aad[71], 0x01);
  CHECK_EQ(aad[72], 0x01);
}

TEST(Compress, RoundTripsAndRefusesToOverrun) {
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kFloatWeights, 40000, 61);

  std::vector<uint8_t> deflated(format::MaxStoredSizeFor(40000));
  size_t deflated_size = 0;
  bool smaller = false;
  REQUIRE_EQ(
      compression::CompressChunk(plain.data(), plain.size(), deflated.data(),
                                 deflated.size(), &deflated_size, &smaller),
      MC_OK);
  CHECK(smaller);

  std::vector<uint8_t> inflated(plain.size());
  REQUIRE_EQ(compression::DecompressChunk(deflated.data(), deflated_size,
                                          inflated.data(), inflated.size()),
             MC_OK);
  CHECK(inflated == plain);

  // Told to produce one byte fewer than the stream holds: rejected, not
  // truncated. This is the bound that makes a decompression bomb impossible
  // rather than merely large.
  CHECK_EQ(compression::DecompressChunk(deflated.data(), deflated_size,
                                        inflated.data(), inflated.size() - 1),
           MC_ERR_COMPRESS);

  // And one byte more: rejected too, because the tail would otherwise be left
  // holding whatever was there before.
  std::vector<uint8_t> bigger(plain.size() + 1);
  CHECK_EQ(compression::DecompressChunk(deflated.data(), deflated_size,
                                        bigger.data(), bigger.size()),
           MC_ERR_COMPRESS);

  // Garbage in is an error, never a crash or a partial output.
  const std::vector<uint8_t> garbage =
      corpus::Generate(corpus::Profile::kRandom, 500, 63);
  CHECK_EQ(compression::DecompressChunk(garbage.data(), garbage.size(),
                                        inflated.data(), inflated.size()),
           MC_ERR_COMPRESS);

  // Truncating a valid stream is the most likely real corruption, and must not
  // produce a short read that looks like success.
  CHECK_EQ(compression::DecompressChunk(deflated.data(), deflated_size / 2,
                                        inflated.data(), inflated.size()),
           MC_ERR_COMPRESS);
}

TEST(Compress, ExpansionIsReportedNotHidden) {
  // Incompressible input: deflate makes it bigger, and the caller has to be
  // told so it can store the chunk raw. Silently emitting the expanded stream
  // is what would make an encrypted model larger than the model.
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kRandom, 20000, 65);

  std::vector<uint8_t> deflated(format::MaxStoredSizeFor(20000));
  size_t deflated_size = 0;
  bool smaller = true;
  REQUIRE_EQ(
      compression::CompressChunk(plain.data(), plain.size(), deflated.data(),
                                 deflated.size(), &deflated_size, &smaller),
      MC_OK);
  CHECK(!smaller);

  // A deliberately tiny output buffer: reported as "not smaller" rather than as
  // an error, because the caller's fallback is the right answer either way.
  std::vector<uint8_t> tiny(16);
  bool tiny_smaller = true;
  REQUIRE_EQ(
      compression::CompressChunk(plain.data(), plain.size(), tiny.data(),
                                 tiny.size(), &deflated_size, &tiny_smaller),
      MC_OK);
  CHECK(!tiny_smaller);
}

TEST(Kdf, IsDeterministicAndSaltDependent) {
  const std::vector<uint8_t> key = corpus::TestKey(67);
  uint8_t salt_a[format::kSaltSize] = {};
  uint8_t salt_b[format::kSaltSize] = {};
  std::memset(salt_a, 0x11, sizeof(salt_a));
  std::memset(salt_b, 0x22, sizeof(salt_b));

  SecureBuffer first;
  SecureBuffer again;
  SecureBuffer other;
  REQUIRE_EQ(kdf::DeriveKey(key.data(), key.size(), salt_a, sizeof(salt_a), 14,
                            8, 1, &first),
             MC_OK);
  REQUIRE_EQ(kdf::DeriveKey(key.data(), key.size(), salt_a, sizeof(salt_a), 14,
                            8, 1, &again),
             MC_OK);
  REQUIRE_EQ(kdf::DeriveKey(key.data(), key.size(), salt_b, sizeof(salt_b), 14,
                            8, 1, &other),
             MC_OK);

  REQUIRE_EQ(first.size(), format::kKeySize);
  CHECK(std::memcmp(first.data(), again.data(), format::kKeySize) == 0);

  // A different salt yields an unrelated key, which is what makes two
  // encryptions of the same model under the same passphrase incomparable and a
  // precomputed table worthless.
  CHECK(std::memcmp(first.data(), other.data(), format::kKeySize) != 0);

  // A different cost yields a different key too, which is why rewriting the
  // cost in a header cannot make an attacker's life easier -- it just breaks
  // the file.
  SecureBuffer cheaper;
  REQUIRE_EQ(kdf::DeriveKey(key.data(), key.size(), salt_a, sizeof(salt_a), 15,
                            8, 1, &cheaper),
             MC_OK);
  CHECK(std::memcmp(first.data(), cheaper.data(), format::kKeySize) != 0);
}

TEST(Kdf, DefaultCostWorks) {
  // The library's default is N = 2^15, r = 8, which needs exactly 32 MiB --
  // precisely OpenSSL's own default scrypt memory limit, so the derivation
  // fails unless OSSL_KDF_PARAM_SCRYPT_MAXMEM is raised. Every other test in
  // the tree runs at the cheaper minimum cost, which means this is the only
  // place that failure would be caught.
  const std::vector<uint8_t> key = corpus::TestKey(69);
  uint8_t salt[format::kSaltSize] = {};
  std::memset(salt, 0x33, sizeof(salt));

  SecureBuffer derived;
  CHECK_EQ(kdf::DeriveKey(key.data(), key.size(), salt, sizeof(salt),
                          format::kDefaultKdfLogN, format::kDefaultKdfR,
                          format::kDefaultKdfP, &derived),
           MC_OK);
  CHECK_EQ(derived.size(), format::kKeySize);
}

TEST(Kdf, RejectsBadArguments) {
  const std::vector<uint8_t> key = corpus::TestKey(71);
  uint8_t salt[format::kSaltSize] = {};
  SecureBuffer derived;

  CHECK_EQ(kdf::DeriveKey(nullptr, key.size(), salt, sizeof(salt), 14, 8, 1,
                          &derived),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(kdf::DeriveKey(key.data(), key.size(), nullptr, sizeof(salt), 14, 8,
                          1, &derived),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(kdf::DeriveKey(key.data(), key.size(), salt, sizeof(salt), 14, 8, 1,
                          nullptr),
           MC_ERR_INVALID_ARG);
  CHECK_EQ(kdf::DeriveKey(key.data(), MC_MIN_KEY_SIZE - 1, salt, sizeof(salt),
                          14, 8, 1, &derived),
           MC_ERR_INVALID_ARG);

  // A salt of the wrong length. The format fixes it at 16 bytes, and accepting
  // another length would mean two files could disagree about what their salt
  // was.
  CHECK_EQ(kdf::DeriveKey(key.data(), key.size(), salt, sizeof(salt) - 1, 14, 8,
                          1, &derived),
           MC_ERR_INVALID_ARG);
}

TEST(Aead, DetectsEveryModificationItCovers) {
  uint8_t key[format::kKeySize];
  uint8_t nonce[format::kNonceSize];
  std::memset(key, 0x5A, sizeof(key));
  std::memset(nonce, 0xA5, sizeof(nonce));

  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kMixed, 5000, 73);
  const std::vector<uint8_t> aad = {1, 2, 3, 4, 5};

  std::vector<uint8_t> cipher(plain.size());
  uint8_t tag[format::kTagSize];
  REQUIRE_EQ(aead::Seal(key, nonce, aad.data(), aad.size(), plain.data(),
                        plain.size(), cipher.data(), tag),
             MC_OK);

  // The ciphertext must not be the plaintext, which is the one way a
  // catastrophically broken cipher configuration would still pass a round trip.
  CHECK(std::memcmp(cipher.data(), plain.data(), plain.size()) != 0);

  std::vector<uint8_t> recovered(plain.size());
  REQUIRE_EQ(aead::Open(key, nonce, aad.data(), aad.size(), cipher.data(),
                        cipher.size(), tag, recovered.data()),
             MC_OK);
  CHECK(recovered == plain);

  // Each of the four inputs, modified in turn. All four are covered by the tag,
  // and all four must produce MC_ERR_AUTH -- not MC_ERR_CRYPTO, which would
  // mean "OpenSSL is broken" to a caller.
  std::vector<uint8_t> modified_cipher = cipher;
  modified_cipher[100] ^= 0x01;
  CHECK_EQ(
      aead::Open(key, nonce, aad.data(), aad.size(), modified_cipher.data(),
                 modified_cipher.size(), tag, recovered.data()),
      MC_ERR_AUTH);

  std::vector<uint8_t> modified_aad = aad;
  modified_aad[2] ^= 0x01;
  CHECK_EQ(aead::Open(key, nonce, modified_aad.data(), modified_aad.size(),
                      cipher.data(), cipher.size(), tag, recovered.data()),
           MC_ERR_AUTH);

  uint8_t modified_tag[format::kTagSize];
  std::memcpy(modified_tag, tag, sizeof(tag));
  modified_tag[0] ^= 0x01;
  CHECK_EQ(aead::Open(key, nonce, aad.data(), aad.size(), cipher.data(),
                      cipher.size(), modified_tag, recovered.data()),
           MC_ERR_AUTH);

  uint8_t modified_nonce[format::kNonceSize];
  std::memcpy(modified_nonce, nonce, sizeof(nonce));
  modified_nonce[0] ^= 0x01;
  CHECK_EQ(aead::Open(key, modified_nonce, aad.data(), aad.size(),
                      cipher.data(), cipher.size(), tag, recovered.data()),
           MC_ERR_AUTH);

  // A zero-length payload is legitimate -- it is the empty model's single
  // chunk, and its tag is what authenticates the header.
  uint8_t empty_tag[format::kTagSize];
  REQUIRE_EQ(aead::Seal(key, nonce, aad.data(), aad.size(), nullptr, 0, nullptr,
                        empty_tag),
             MC_OK);
  CHECK_EQ(aead::Open(key, nonce, aad.data(), aad.size(), nullptr, 0, empty_tag,
                      nullptr),
           MC_OK);
}

TEST(SecureBuffer, AllocatesZeroedAndMovesCleanly) {
  SecureBuffer buffer(64);
  REQUIRE_EQ(buffer.size(), 64u);
  REQUIRE(buffer.data() != nullptr);

  // Value-initialized, so a buffer never starts out holding whatever the
  // allocator last had there -- which for a key buffer would be a previous key.
  for (size_t i = 0; i < buffer.size(); ++i) {
    CHECK_EQ(buffer.data()[i], 0);
  }

  std::memset(buffer.data(), 0xAB, buffer.size());

  SecureBuffer moved(std::move(buffer));
  CHECK_EQ(moved.size(), 64u);

  // Inspecting the moved-from object is the point of these two lines, so
  // bugprone-use-after-move is suppressed rather than obeyed. SecureBuffer
  // promises a moved-from buffer is *empty*, not merely unspecified -- if its
  // pointer still aliased the new owner's block it would wipe it from under
  // them on destruction -- and that promise is only testable by looking.
  // NOLINTNEXTLINE(bugprone-use-after-move)
  CHECK_EQ(buffer.size(), 0u);
  // NOLINTNEXTLINE(bugprone-use-after-move)
  CHECK(buffer.data() == nullptr);
  CHECK_EQ(moved.data()[0], 0xAB);

  // Self-move-assignment must not wipe and free the buffer it is about to keep.
  SecureBuffer& alias = moved;
  moved = std::move(alias);
  CHECK_EQ(moved.size(), 64u);
  CHECK_EQ(moved.data()[0], 0xAB);

  // A zero-size buffer is empty rather than a one-byte allocation, and is safe
  // to construct, move, and destroy.
  SecureBuffer empty(0);
  CHECK(empty.empty());
  CHECK(empty.data() == nullptr);

  // Reset() wipes before reallocating, so calling it on a buffer holding a key
  // is safe. Only the post-state is observable from here; ASan and Valgrind
  // cover the rest.
  CHECK(moved.Reset(16));
  CHECK_EQ(moved.size(), 16u);
  CHECK_EQ(moved.data()[0], 0);

  // Release() hands ownership out; the buffer must then be empty so its
  // destructor does not free memory the caller now owns.
  SecureBuffer donor(8);
  uint8_t* raw = donor.Release();
  CHECK(raw != nullptr);
  CHECK(donor.empty());
  CHECK(donor.data() == nullptr);
  delete[] raw;
}
