/// \file threading_test.cc
/// The concurrency promise, and the only claim the library makes about it.
///
/// == What is promised ==
///
/// The API is reentrant, not synchronized. Any number of threads may call
/// mc_encrypt_* and mc_decrypt_* at the same time, provided no two of them
/// share a buffer. Nothing here holds a lock, and nothing here holds mutable
/// state that outlives a call — no cached context, no static salt, no lazily
/// initialized singleton.
///
/// That property is worth a test because it is easy to lose. A future change
/// that memoized a derived key across calls, or reused one scratch buffer to
/// avoid an allocation, would pass every other suite in this tree and corrupt
/// output the moment two threads ran at once. The failure would be
/// nondeterministic and would look like a corrupt model file.
///
/// == Why this needs ThreadSanitizer to be worth much ==
///
/// Run without instrumentation, this suite mostly proves the results are
/// correct — which a data race often still is, by luck, on a given run. Under
/// TSan
/// (`./scripts/build.sh --tsan && ctest -R Threading`) the same code reports
/// the race itself. So this file is written to be *driven* by TSan rather than
/// to catch races on its own, and CI runs it both ways.
///
/// OpenSSL's thread safety is a precondition, not under test. 1.1.0 made the
/// library lock internally, so both 1.1.1 and 3.x are safe for the EVP
/// interfaces used here -- and no EVP object is held across a call boundary.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
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
  // The minimum cost. Eight threads at the default N = 2^15 would ask for
  // 256 MiB of scrypt working set at once, which on a two-core CI runner is
  // enough to matter; the KDF's cost is not what this suite is measuring.
  opts.kdf_log_n = 14;
  return opts;
}

}  // namespace

// Eight threads, each round-tripping its own payload under its own key. If
// anything in the library were shared across calls, the odds of eight
// simultaneous encryptions all producing correct output are poor.
TEST(Threading, ConcurrentRoundTripsAreIndependent) {
  constexpr int kThreads = 8;
  constexpr int kIterations = 4;

  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);

  for (int t = 0; t < kThreads; ++t) {
    workers.emplace_back([t, &failures]() {
      // Per-thread key and payload, and a different size per thread so the
      // threads do not march in lockstep through the same code path.
      const auto seed = static_cast<uint64_t>(t);
      const std::vector<uint8_t> key = corpus::TestKey(200 + seed);
      const std::vector<uint8_t> plain = corpus::Generate(
          corpus::Profile::kMixed,
          (kSmallChunk * (static_cast<size_t>(t) + 1)) + 17, 300 + seed);
      const mc_encrypt_options opts = FastOptions();

      for (int i = 0; i < kIterations; ++i) {
        uint8_t* cipher = nullptr;
        size_t cipher_size = 0;
        if (mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                              plain.size(), &cipher, &cipher_size) != MC_OK) {
          ++failures;
          return;
        }

        uint8_t* recovered = nullptr;
        size_t recovered_size = 0;
        const mc_status rc =
            mc_decrypt_buffer(key.data(), key.size(), cipher, cipher_size,
                              &recovered, &recovered_size);
        mc_free(cipher, cipher_size);

        if (rc != MC_OK) {
          ++failures;
          return;
        }

        if (recovered_size != plain.size() ||
            std::memcmp(recovered, plain.data(), plain.size()) != 0) {
          ++failures;
        }

        mc_free(recovered, recovered_size);
      }
    });
  }

  for (std::thread& worker : workers) {
    worker.join();
  }

  CHECK_EQ(failures.load(), 0);
}

// Many threads decrypting the *same* ciphertext buffer at once. Reading one
// buffer concurrently is allowed and is the realistic shape for a server that
// loads one model into several workers, so it is worth stating as a test rather
// than leaving to inference from "reentrant".
TEST(Threading, ConcurrentReadersOfOneCiphertext) {
  const std::vector<uint8_t> key = corpus::TestKey(211);
  const std::vector<uint8_t> plain =
      corpus::Generate(corpus::Profile::kFloatWeights, 6 * kSmallChunk, 213);
  const mc_encrypt_options opts = FastOptions();

  uint8_t* cipher = nullptr;
  size_t cipher_size = 0;
  REQUIRE_EQ(mc_encrypt_buffer(key.data(), key.size(), &opts, plain.data(),
                               plain.size(), &cipher, &cipher_size),
             MC_OK);

  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(6);

  for (int t = 0; t < 6; ++t) {
    workers.emplace_back([&]() {
      uint8_t* recovered = nullptr;
      size_t recovered_size = 0;
      if (mc_decrypt_buffer(key.data(), key.size(), cipher, cipher_size,
                            &recovered, &recovered_size) != MC_OK) {
        ++failures;
        return;
      }

      if (recovered_size != plain.size() ||
          std::memcmp(recovered, plain.data(), plain.size()) != 0) {
        ++failures;
      }

      mc_free(recovered, recovered_size);
    });
  }

  for (std::thread& worker : workers) {
    worker.join();
  }

  CHECK_EQ(failures.load(), 0);
  mc_free(cipher, cipher_size);
}

// Concurrent key generation, which is the one place the library reaches into
// OpenSSL's global DRBG state. A lock missing there would show up as duplicate
// keys, which is the worst possible failure mode and the reason this is checked
// rather than assumed.
TEST(Threading, ConcurrentKeyGenerationProducesDistinctKeys) {
  constexpr int kThreads = 8;
  constexpr int kPerThread = 16;

  std::vector<std::vector<uint8_t>> keys(static_cast<size_t>(kThreads) *
                                         static_cast<size_t>(kPerThread));
  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);

  for (int t = 0; t < kThreads; ++t) {
    workers.emplace_back([t, &keys, &failures]() {
      for (int i = 0; i < kPerThread; ++i) {
        std::vector<uint8_t> key(32);
        if (mc_generate_key(key.data(), key.size()) != MC_OK) {
          ++failures;
          return;
        }
        // Each thread writes only its own slice, so this needs no
        // synchronization -- and TSan verifies that claim rather than trusting
        // the comment.
        keys[(static_cast<size_t>(t) * kPerThread) + static_cast<size_t>(i)] =
            std::move(key);
      }
    });
  }

  for (std::thread& worker : workers) {
    worker.join();
  }

  REQUIRE_EQ(failures.load(), 0);

  // Every key distinct. O(n^2) over 128 keys is 8128 comparisons, which is
  // nothing, and a set would need a hash function whose collisions would then
  // be the thing under test.
  size_t duplicates = 0;
  for (size_t i = 0; i < keys.size(); ++i) {
    for (size_t j = i + 1; j < keys.size(); ++j) {
      if (keys[i] == keys[j]) {
        ++duplicates;
      }
    }
  }

  CHECK_EQ(duplicates, 0u);
}
