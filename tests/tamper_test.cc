/// \file tamper_test.cc
/// Every way a `.mcrypt` file can be modified, and the requirement that each is
/// rejected.
///
/// Written against the attacks rather than the code: chunked AEAD without the
/// right associated data passes a naive round-trip test while still allowing
/// reordering, truncation and splicing, because each individual tag verifies.
/// So each test names what an attacker does and asserts the status it gets.
///
/// BitFlipAnywhereFails is the exception -- it flips one bit per byte across
/// the file rather than testing a named attack, which is the only way to catch
/// a field the AAD forgot to cover without thinking of that field first.

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

// size_t, not uint32_t: `N * kSmallChunk` in uint32_t computes narrow then
// widens, which is correct here but is the shape of an overflow bug and
// clang-tidy flags it.
constexpr size_t kSmallChunk = 4u << 10;
constexpr size_t kChunkRecordSize = 24;

mc_encrypt_options TamperOptions(size_t chunk_size) {
  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);
  opts.chunk_size = static_cast<uint32_t>(chunk_size);
  opts.kdf_log_n = 14;
  // No compression, so a chunk's ciphertext length equals its plaintext length
  // and the offset arithmetic in these tests is readable. The compressed path
  // shares every tag check; RoundTripTests covers it.
  opts.compression = MC_COMPRESS_NONE;
  return opts;
}

// A ready-made ciphertext plus the key that made it, so each test starts from a
// valid file and states only the modification it makes.
struct Sample {
  std::vector<uint8_t> key;
  std::vector<uint8_t> plain;
  std::vector<uint8_t> cipher;
};

bool MakeSample(testing::Context& ctx, size_t plain_size, size_t chunk_size,
                Sample* out) {
  out->key = corpus::TestKey(21);
  out->plain = corpus::Generate(corpus::Profile::kFloatWeights, plain_size, 23);

  const mc_encrypt_options opts = TamperOptions(chunk_size);
  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  const mc_status rc =
      mc_encrypt_buffer(out->key.data(), out->key.size(), &opts,
                        out->plain.empty() ? nullptr : out->plain.data(),
                        out->plain.size(), &cipher, &cipher_size);
  if (rc != MC_OK) {
    testing::ReportFailure(ctx, __FILE__, __LINE__, "MakeSample",
                           mc_status_string(rc));
    return false;
  }

  out->cipher.assign(cipher, cipher + cipher_size);
  mc_free(cipher, cipher_size);
  return true;
}

// Attempt a decryption and return the status, freeing anything produced. Used
// by the tests that only care that the attempt failed.
mc_status TryDecrypt(const Sample& sample, const std::vector<uint8_t>& cipher) {
  uint8_t* out = nullptr;
  size_t out_size = 0;
  const mc_status rc =
      mc_decrypt_buffer(sample.key.data(), sample.key.size(), cipher.data(),
                        cipher.size(), &out, &out_size);
  if (rc == MC_OK) {
    mc_free(out, out_size);
  }

  return rc;
}

}  // namespace

// The baseline. Without this, every other test in the file could pass because
// decryption never succeeds at all.
TEST(Tamper, UnmodifiedFileDecrypts) {
  Sample sample;
  REQUIRE(MakeSample(ctx, 3 * kSmallChunk, kSmallChunk, &sample));
  CHECK_EQ(TryDecrypt(sample, sample.cipher), MC_OK);
}

// One bit at a time: exhaustive over metadata, sampled over the payload.
//
// Each attempt past the structural checks costs an scrypt derivation (~20 ms at
// the minimum cost), so exhaustive coverage is spent where it earns it -- the
// 64-byte header and each 24-byte chunk record, the bytes a field might be
// missing from the AAD. GCM authenticates ciphertext uniformly, so sampling the
// payload every kPayloadStride bytes establishes the same thing. The split is
// printed rather than applied quietly.
TEST(Tamper, BitFlipAnywhereFails) {
  constexpr size_t kPayloadStride = 64;

  Sample sample;
  REQUIRE(MakeSample(ctx, 2 * kSmallChunk, kSmallChunk, &sample));

  // Computed from the layout rather than hardcoded, so it stays right if the
  // sample's chunk count changes.
  std::vector<bool> is_metadata(sample.cipher.size(), false);
  for (size_t i = 0; i < MC_HEADER_SIZE; ++i) {
    is_metadata[i] = true;
  }

  const size_t stride = kChunkRecordSize + kSmallChunk;
  for (size_t base = MC_HEADER_SIZE; base < sample.cipher.size();
       base += stride) {
    for (size_t i = 0; i < kChunkRecordSize && base + i < is_metadata.size();
         ++i) {
      is_metadata[base + i] = true;
    }
  }

  size_t attempted = 0;
  size_t accepted = 0;
  size_t first_accepted = 0;
  for (size_t byte = 0; byte < sample.cipher.size(); ++byte) {
    if (!is_metadata[byte] && byte % kPayloadStride != 0) {
      continue;
    }

    // One bit per byte: all eight is eight times the runtime for the same
    // question, which is whether this byte is authenticated at all.
    std::vector<uint8_t> modified = sample.cipher;
    modified[byte] ^= 0x01;
    ++attempted;

    if (TryDecrypt(sample, modified) == MC_OK) {
      if (accepted == 0) {
        first_accepted = byte;
      }
      ++accepted;
    }
  }

  std::printf(
      "       (%zu of %zu byte positions tried: all metadata, payload every "
      "%zu)\n",
      attempted, sample.cipher.size(), kPayloadStride);

  if (accepted != 0) {
    testing::ReportFailure(ctx, __FILE__, __LINE__, "bit flip accepted",
                           std::to_string(accepted) +
                               " modified file(s) decrypted; first at byte " +
                               std::to_string(first_accepted));
  }
}

// Swapping two chunks. Each chunk's own tag still verifies -- the ciphertext
// and the tag moved together -- so only the chunk index in the associated data
// catches this.
TEST(Tamper, SwappedChunksFail) {
  Sample sample;
  REQUIRE(MakeSample(ctx, 3 * kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  const size_t stride = kChunkRecordSize + kSmallChunk;
  uint8_t* first = modified.data() + MC_HEADER_SIZE;
  uint8_t* second = first + stride;

  std::vector<uint8_t> scratch(stride);
  std::memcpy(scratch.data(), first, stride);
  std::memcpy(first, second, stride);
  std::memcpy(second, scratch.data(), stride);

  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_AUTH);
}

// Dropping the last chunk. Every remaining tag verifies, so this is caught by
// chunk_count and plaintext_size being inside the associated data -- the file's
// declared shape no longer matches the bytes present.
TEST(Tamper, TruncatedTailFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, 3 * kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  modified.resize(modified.size() - (kChunkRecordSize + kSmallChunk));

  // MC_ERR_FORMAT, not MC_ERR_AUTH: the chunk-table walk in phase 1 notices the
  // shortfall before any key work happens, which is the cheaper and more
  // specific answer. Asserting the exact status is deliberate -- it pins the
  // phase ordering the header documents.
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);
}

// Appending bytes after the last chunk. Nothing in the file covers them, so a
// reader that stopped at chunk_count would accept two different files as the
// same model.
TEST(Tamper, AppendedBytesFail) {
  Sample sample;
  REQUIRE(MakeSample(ctx, 2 * kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  modified.push_back(0x00);
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);

  // Also with a plausible-looking extra chunk record, in case the check were
  // "is there a whole record left" rather than "does the walk land exactly on
  // the end".
  modified = sample.cipher;
  modified.resize(modified.size() + kChunkRecordSize, 0x00);
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);
}

// Duplicating a chunk. Its tag verifies in its original position, so this tests
// that the index in the associated data is the chunk's *position*, not a value
// stored in the record where it could be copied along with it.
TEST(Tamper, DuplicatedChunkFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, 3 * kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  const size_t stride = kChunkRecordSize + kSmallChunk;
  std::memcpy(modified.data() + MC_HEADER_SIZE + stride,
              modified.data() + MC_HEADER_SIZE, stride);

  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_AUTH);
}

// Splicing a chunk out of a *different* file encrypted under the *same* key.
// This is the attack a per-chunk seal with no file binding is most exposed to,
// and the one a round-trip test can never see. It fails twice over here: the
// other file has a different salt, so its chunks were sealed under a different
// derived key, and its header is different, so the associated data does not
// match either.
TEST(Tamper, SplicedChunkFromAnotherFileFails) {
  const std::vector<uint8_t> key = corpus::TestKey(21);
  const mc_encrypt_options opts = TamperOptions(kSmallChunk);

  std::vector<std::vector<uint8_t>> files;
  for (int i = 0; i < 2; ++i) {
    const std::vector<uint8_t> plain =
        corpus::Generate(corpus::Profile::kRandom, 3 * kSmallChunk,
                         100 + static_cast<uint64_t>(i));

    uint8_t* cipher = nullptr;
    size_t cipher_size = 0;
    REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                                 plain.size(), &cipher, &cipher_size),
               MC_OK);
    files.emplace_back(cipher, cipher + cipher_size);
    mc_free(cipher, cipher_size);
  }

  // Same key, same options, same plaintext length -- so the two files have the
  // same layout and a chunk from one lands exactly where a chunk of the other
  // sits.
  REQUIRE_EQ(files[0].size(), files[1].size());

  const size_t stride = kChunkRecordSize + kSmallChunk;
  std::vector<uint8_t> modified = files[0];
  std::memcpy(modified.data() + MC_HEADER_SIZE + stride,
              files[1].data() + MC_HEADER_SIZE + stride, stride);

  uint8_t* out = nullptr;
  size_t out_size = 0;
  const mc_status rc =
      mc_decrypt_buffer(key.data(), key.size(), modified.data(),
                        modified.size(), &out, &out_size);
  if (rc == MC_OK) {
    mc_free(out, out_size);
  }
  CHECK_EQ(rc, MC_ERR_AUTH);
}

// Rewriting the header's declared plaintext size.
//
// Worth noticing what this test found: there is no header field whose *only*
// protection is the associated data. Every one of them also feeds the key
// derivation, the nonce, or the file's declared layout, so a change to any of
// them is usually caught by something cheaper than the tag. That is defence in
// depth rather than redundancy, and both halves are asserted below because a
// future field might have only one of them.
TEST(Tamper, ModifiedHeaderSizeFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, 3 * kSmallChunk, kSmallChunk, &sample));

  // plaintext_size sits at offset 50; see the offset table in format.cc.
  constexpr size_t kOffPlaintextSize = 50;

  // A size that contradicts chunk_count: caught by ParseFileHeader, which
  // recomputes the count rather than trusting it.
  std::vector<uint8_t> modified = sample.cipher;
  modified[kOffPlaintextSize] ^= 0x40;
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);

  // One byte shorter, which still maps to the same chunk count. In an
  // uncompressed file this is caught structurally too: the walk requires an
  // uncompressed chunk to store exactly as many bytes as it must decrypt to,
  // and the last chunk now claims one byte too many.
  modified = sample.cipher;
  const uint64_t shorter = (3 * static_cast<uint64_t>(kSmallChunk)) - 1;
  for (size_t i = 0; i < 8; ++i) {
    modified[kOffPlaintextSize + i] =
        static_cast<uint8_t>((shorter >> (8 * i)) & 0xFFu);
  }
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);
}

// The same one-byte-shorter edit, on a *compressed* file, where the associated
// data is the only thing that can catch it.
//
// A compressed chunk's stored size is whatever deflate produced, so the walk
// has no length to compare it against -- the structural check that fires above
// cannot apply. This edit therefore reaches the AEAD, and is caught only
// because the whole 64-byte header is inside every chunk's associated data.
// Remove the header from BuildAad and this is the test that fails.
TEST(Tamper, ModifiedHeaderSizeOnCompressedFileIsCaughtByTheTag) {
  const std::vector<uint8_t> key = corpus::TestKey(21);
  mc_encrypt_options opts = TamperOptions(kSmallChunk);
  opts.compression = MC_COMPRESS_ZLIB;

  // Zeros, so every chunk certainly deflates and none falls back to raw storage
  // -- a raw chunk would be caught structurally and the test would pass for the
  // wrong reason.
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kZeros, 3 * kSmallChunk, 31);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  std::vector<uint8_t> modified(cipher, cipher + cipher_size);
  mc_free(cipher, cipher_size);

  // Confirm the premise: chunk 0 really is stored compressed.
  REQUIRE_EQ(modified[MC_HEADER_SIZE + 4] & 0x01, 0x01);

  const uint64_t shorter = (3 * static_cast<uint64_t>(kSmallChunk)) - 1;
  for (size_t i = 0; i < 8; ++i) {
    modified[50 + i] = static_cast<uint8_t>((shorter >> (8 * i)) & 0xFFu);
  }

  uint8_t* out = nullptr;
  size_t out_size = 0;
  const mc_status rc =
      mc_decrypt_buffer(key.data(), key.size(), modified.data(),
                        modified.size(), &out, &out_size);
  if (rc == MC_OK) {
    mc_free(out, out_size);
  }
  CHECK_EQ(rc, MC_ERR_AUTH);
}

// Rewriting the KDF cost downward. If it were not authenticated, an attacker
// could rewrite every file to N = 2^14 and make an offline dictionary attack
// 64x cheaper without the owner ever noticing.
TEST(Tamper, ModifiedKdfCostFails) {
  const std::vector<uint8_t> key = corpus::TestKey(21);
  mc_encrypt_options opts = TamperOptions(kSmallChunk);
  opts.kdf_log_n = 15;

  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kZeros, kSmallChunk, 29);

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  std::vector<uint8_t> modified(cipher, cipher + cipher_size);
  mc_free(cipher, cipher_size);

  // kdf_log_n is at offset 13.
  modified[13] = 14;

  uint8_t* out = nullptr;
  size_t out_size = 0;
  const mc_status rc =
      mc_decrypt_buffer(key.data(), key.size(), modified.data(),
                        modified.size(), &out, &out_size);
  if (rc == MC_OK) {
    mc_free(out, out_size);
  }

  // MC_ERR_AUTH: the value is in range, so nothing structural objects. It
  // changes the derived key, so every chunk's tag fails -- and it is also in
  // the associated data, so it would fail even if it did not.
  CHECK_EQ(rc, MC_ERR_AUTH);
}

// The reserved header field must be zero. A reader that ignored it would keep
// accepting files after a future version gave the field a meaning, and would
// then be silently misinterpreting them.
TEST(Tamper, NonZeroReservedFieldFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  modified[62] = 0x01;  // kOffHeaderReserved
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);

  // Same for the three reserved bytes in the chunk record, at record offset 5.
  modified = sample.cipher;
  modified[MC_HEADER_SIZE + 5] = 0x01;
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);
}

// An unknown chunk flag bit. Rejected rather than masked off, for the same
// reason as the reserved fields.
TEST(Tamper, UnknownChunkFlagFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  modified[MC_HEADER_SIZE + 4] |= 0x80;  // kOffChunkFlags
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);
}

// A chunk record claiming more bytes than the file contains. The v1 format's
// equivalent field was used directly as a malloc size; here it is checked
// against what remains, before anything is allocated.
TEST(Tamper, OversizedStoredSizeFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  const uint32_t huge = 0xF0000000u;
  for (size_t i = 0; i < 4; ++i) {
    modified[MC_HEADER_SIZE + i] =
        static_cast<uint8_t>((huge >> (8 * i)) & 0xFFu);
  }

  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);
}

// A header declaring a 64 GiB plaintext in a 200-byte file. This is the exact
// shape of the v1 denial of service: a size field read from an unauthenticated
// header and handed to malloc. It must be rejected without a large allocation,
// which is what running this suite under ASan confirms.
TEST(Tamper, HugeDeclaredPlaintextInTinyFileFails) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  const uint64_t huge = (1ull << 36);  // 64 GiB, the format's ceiling
  for (size_t i = 0; i < 8; ++i) {
    modified[50 + i] = static_cast<uint8_t>((huge >> (8 * i)) & 0xFFu);
  }

  // MC_ERR_FORMAT because chunk_count no longer matches the declared size. The
  // status matters less than the fact that nothing was allocated to find out.
  const mc_status rc = TryDecrypt(sample, modified);
  CHECK(rc == MC_ERR_FORMAT || rc == MC_ERR_TOO_LARGE);
}

// A *consistent* huge declaration, so unlike the test above it gets past
// ParseFileHeader and reaches the chunk-table walk.
//
// The status is the usual MC_ERR_FORMAT; the point is that rejecting it must
// cost nothing. chunk_count is 16.7 M here, and a table allocated from that
// before the records were shown to exist is half a gigabyte bought with an
// 88-byte input. The bound in WalkChunkTable is what keeps it cheap.
TEST(Tamper, HeaderOnlyFileDeclaringMaximumChunkCountIsCheap) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  // Header only: the declared chunks are not there at all.
  std::vector<uint8_t> modified(sample.cipher.begin(),
                                sample.cipher.begin() + MC_HEADER_SIZE);

  const uint32_t min_chunk = 4u << 10;
  const uint64_t huge = 1ull << 36;
  const uint64_t chunks = huge / min_chunk;

  for (size_t i = 0; i < 4; ++i) {
    modified[46 + i] = static_cast<uint8_t>((min_chunk >> (8 * i)) & 0xFFu);
    modified[58 + i] = static_cast<uint8_t>((chunks >> (8 * i)) & 0xFFu);
  }
  for (size_t i = 0; i < 8; ++i) {
    modified[50 + i] = static_cast<uint8_t>((huge >> (8 * i)) & 0xFFu);
  }

  CHECK(TryDecrypt(sample, modified) == MC_ERR_FORMAT);
}

// Truncating inside the header, and just short of it. Both must be a clean
// MC_ERR_FORMAT rather than a read past the end -- which is what ASan would
// report if the length checks were missing.
TEST(Tamper, ShortInputsAreRejected) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  for (size_t length = 0; length <= MC_HEADER_SIZE + kChunkRecordSize;
       ++length) {
    std::vector<uint8_t> modified(
        sample.cipher.begin(),
        sample.cipher.begin() + static_cast<std::ptrdiff_t>(length));
    if (TryDecrypt(sample, modified) == MC_OK) {
      testing::ReportFailure(ctx, __FILE__, __LINE__, "short input accepted",
                             "length = " + std::to_string(length));
      break;
    }
  }
}

// Wrong magic and wrong version, which must be distinguishable: a v1 "MLM" file
// or a future v3 both need an answer better than "corrupt".
TEST(Tamper, WrongMagicAndVersionAreDistinguished) {
  Sample sample;
  REQUIRE(MakeSample(ctx, kSmallChunk, kSmallChunk, &sample));

  std::vector<uint8_t> modified = sample.cipher;
  modified[0] = 'X';
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_FORMAT);

  modified = sample.cipher;
  modified[8] = 0x63;  // version 99, low byte
  modified[9] = 0x00;
  CHECK_EQ(TryDecrypt(sample, modified), MC_ERR_UNSUPPORTED);
}
