# Testing

56 tests in ten C++ suites, plus a shell suite over the CLI. They run against
synthetic data, so the repository carries no model file and CI downloads
nothing.

```bash
cd scripts
./build.sh --debug
./run-tests.sh                 # everything, in parallel
./run-tests.sh Tamper          # one suite (CTest regex)
./run-tests.sh --serial        # when interleaved output is hiding the failure
```

## Testing an encryptor with no models

This is the question the design starts from, so it is worth answering directly:
**the library does not care that its input is a model.** The pipeline is
byte-oriented. Only two properties of the input change its behaviour:

- **Length**, relative to the chunk boundaries.
- **Compressibility**, because that decides whether a chunk is stored deflated
  or raw, and therefore which of two decrypt paths runs.

Committing a real `.onnx` or `.safetensors` would add tens to thousands of
megabytes to the repository, bring its own license, and test neither property
any better than a generated buffer does. Downloading one in CI is worse: the
suite then fails whenever a model host is slow, moved, or blocked, which is a
red build that says nothing about the code.

So [`tests/corpus.cc`](../tests/corpus.cc) generates byte patterns that span
both axes, deterministically from a fixed seed.

### The four profiles

| Profile | Stands in for | Exercises |
|---|---|---|
| `Zeros` | zero-initialized tensor padding | deflate's best case |
| `Random` | quantized or already-compressed weights | deflate *expanding*; the raw-store fallback |
| `FloatWeights` | fp32 weights, small and clustered near zero | partial compression — the realistic case |
| `Mixed` | alternating runs of the above | both chunk flags in one file |

`FloatWeights` is the one worth explaining. Real fp32 weights are mostly small
values near zero, so their exponent bytes repeat while their mantissa bytes
look random, and deflate finds perhaps 10–20%. Generating that shape rather
than uniform random is what keeps the "did compression help" branch from being
decided the same way in every test.

### The size sweep

`corpus::BoundarySizes(chunk_size)` builds the lengths from the chunk size
rather than hardcoding them, so the sweep still lands on the boundaries when a
test uses a non-default chunk: empty, one byte, just under one chunk, exactly
one chunk, just over, two full chunks, and a multi-chunk file with a short
tail.

Four profiles × those lengths is what `RoundTrip,
ProfilesAcrossChunkBoundaries` covers.

### Why the generator is written longhand

`corpus::Generate` does not use `<random>`. The C++ standard does not specify
that its distributions produce identical sequences across implementations, and
`std::uniform_int_distribution` genuinely differs between libstdc++ and
libc++. A test that passes on Ubuntu and fails on macOS for that reason is a
bug hunt with no bug in it — and the committed vector below depends on the
generator being byte-identical everywhere.

## The suites

| Suite | Tests | What it establishes |
|---|---:|---|
| `Api` | 11 | Every public function's contract: NULL handling, short keys, out-of-range options, file permissions, that a failed decryption leaves no output file |
| `Format` | 8 | Header and chunk serialization, little-endianness regardless of host, the parser's rejection rules, nonce uniqueness, that the AAD covers the header bytes *as written* |
| `Compress` | 2 | Round trip, refusal to overrun the output bound, expansion reported rather than hidden |
| `Kdf` | 3 | Determinism, salt dependence, argument validation |
| `Aead` | 1 | That GCM detects every modification it covers |
| `SecureBuffer` | 1 | Zeroed allocation, clean moves |
| `RoundTrip` | 7 | The size × profile sweep, ciphertext differing across calls, compression helping and not expanding, wrong key → `MC_ERR_AUTH` |
| `Tamper` | 17 | **See below** |
| `Threading` | 3 | Concurrent encrypt/decrypt independence, many readers of one ciphertext, concurrent key generation |
| `Vector` | 3 | That this build still reads a committed `.mcrypt` |
| `Cli` | 30-odd | Exit codes, that `--key` stays refused, tty-only prompting, keygen not overwriting |

Each suite is a separate CTest entry, so a failure names the suite and
`ctest -j` runs them in parallel. The suites are safe under that because
`corpus::TempPath` includes the process id — two concurrent runs cannot collide
on a filename.

Adding a suite means adding it to the source list *and* to the `foreach` in
CMakeLists. That is a real footgun, so `testing::Run()` treats "no test
matched" as a failure: a suite renamed in one place and not the other fails
loudly instead of quietly running nothing.

## The Tamper suite

This is the suite that justifies the format's design, and it is written
against the *attacks* rather than against the code. Chunked AEAD without the
right associated data passes a naive round-trip test while still allowing
reordering, truncation, and splicing — each individual GCM tag verifies. So
each test names what an attacker would do and asserts the status it gets.

`Tamper, BitFlipAnywhereFails` is the one that earns its runtime. It walks the
file and flips one bit at a time:

- **Exhaustively** over the 64-byte file header and each 24-byte chunk record.
  Those are the bytes a field might be missing from the AAD, and this is the
  only test that can find such a field without someone thinking of it first.
- **Sampled**, every `kPayloadStride` bytes, over the payload. Nothing is lost:
  GCM authenticates its ciphertext uniformly, so byte 4001 is covered by
  exactly the same tag computation as byte 4000.

The split is a runtime decision — each attempt that gets past the structural
checks costs an scrypt derivation — and the test prints it rather than applying
it quietly.

## The committed vector

[`tests/vectors/v2-two-chunks.mcrypt`](../tests/vectors/v2-two-chunks.mcrypt)
is 4 KiB and is the only thing in the tree that can tell a format change from a
refactor.

Every other suite encrypts and decrypts with the same binary, so it agrees with
itself by construction. Change an offset in `format.cc`, swap two AAD
components, flip the nonce counter to little-endian — the round trip still
passes, and every file the previous release wrote silently becomes
undecryptable. `Vector, CommittedFileStillDecrypts` is what stands between that
change and a release.

The vector is two 4 KiB chunks: a zeroed run that deflates to almost nothing
and a random run that is stored raw, so both chunk flags are exercised in 4 KiB
of repository. Its plaintext is regenerated from `corpus::Generate` rather than
committed beside it, which is why the generator is specified to be
byte-identical across platforms.

**Regenerate it only when `MC_FORMAT_VERSION` is deliberately bumped**, with
`scripts/make-vector.sh --force`, and then keep the old vector beside the new
one with a test asserting the old one is now rejected as `MC_ERR_UNSUPPORTED`.
Without `--force` the script refuses, which is the behaviour you want the 99%
of the time you ran it out of curiosity.

One property to be clear about: **the vector is not reproducible.** Encryption
draws a fresh salt and nonce prefix per call, so regenerating it always yields
different bytes even when the format has not changed by a hair. Diffing a fresh
generation against the committed file therefore proves nothing in either
direction — the signal is the `Vector` suite failing to *decrypt* the committed
file. If that happens and the version was not bumped, the change that broke it
is the bug; regenerating the vector would only hide it, because the new file
would be one this build wrote, which every other suite already covers.

## Sanitizers

```bash
./build.sh --asan --ubsan && ./run-tests.sh
./build.sh --tsan          && ./run-tests.sh
```

Switching sanitizers reconfigures from scratch; `build.sh` detects it and says
so, because reusing the directory would leave objects compiled without the
flags and a link failure on missing `__asan_` symbols.

The instrumentation flags are applied with `add_compile_options`, which is
directory-scoped and reaches only targets created **after** it — so that block
sits above every `add_library` and `add_executable` in `CMakeLists.txt`. This
is worth knowing because getting it wrong is invisible: the build succeeds, the
suites pass, and the sanitizer instruments the test harness while leaving the
library alone, finding nothing forever. The symptom that gives it away is a
coverage report listing a single file.

**ASan + UBSan** run together — they compose into one build. This is where a
buffer overflow in the chunk walk, a use-after-free on a key, or a shift past
the width of a type in `format.cc` would appear, and the Tamper suite feeding
several thousand deliberately malformed files is what provokes it. UBSan is
built with `-fno-sanitize-recover`, so the process aborts on the first finding
rather than printing and carrying on.

**LeakSanitizer** rides along with ASan on Linux only, which makes the Ubuntu
jobs the only place a leak is ever caught — a developer build on macOS cannot
check it. Every buffer here is either owned by a `SecureBuffer` or handed to
the caller through `mc_free`, and a leak means one of those two paths was
missed. For a decrypted model that means plaintext left in the heap.

**TSan** gets its own job, because it cannot be combined with ASan — the two
use incompatible shadow-memory layouts, and CMakeLists rejects the pair with a
`FATAL_ERROR` rather than letting the linker deliver the news. What it verifies
is a documented promise rather than internal state: the API is reentrant, and
nothing in the library holds a lock or mutable global state. This is what keeps
a future change that memoizes a derived key from silently breaking that.

Sanitizer builds default to Debug. At `-O3` the compiler inlines away the
frames a report is made of, and the trace is the only reason to run the
instrumented build.

## Valgrind

```bash
./build.sh --debug        # uninstrumented; the script refuses otherwise
./check-valgrind.sh
```

Not redundant with ASan, for a specific reason: ASan instruments at compile
time and sees only what it was compiled into. OpenSSL and zlib are ordinary
system libraries here, so a bad length passed *into* `EVP_CipherUpdate` or
`inflate()` is invisible to it — and every buffer this library hands them is
sized by arithmetic in `format.cc`. Valgrind works on the binary, so it checks
those calls too, and it reports reads of uninitialized memory, which ASan does
not.

It runs a **subset** of suites — `Api Format Compress Kdf Aead SecureBuffer
Vector Threading` — because Valgrind's ~30× slowdown turns `Tamper`'s thousands
of scrypt derivations into tens of minutes. Those suites still cover every code
path in the library. The cap is stated here and in the script rather than being
a surprise to whoever wonders why a leak got through.

`check-valgrind.sh` refuses to run against an instrumented build: Valgrind and
the sanitizers both replace the allocator, and the combination reports
nonsense.

## Coverage

```bash
./coverage.sh
```

Builds instrumented into its own directory (`../../model-crypt-build-coverage`,
so alternating with a normal build does not force a full rebuild each way),
runs the suite, and prints a per-file line-coverage table from `llvm-cov`. Test
code is excluded — test code that runs is not a measure of library coverage,
and including it inflates the number by thousands of lines that are covered by
definition.

CI reports the number and **does not gate on it**. A threshold gets gamed the
moment it fails, and the useful question is not "is it above 85%" but "is
anything important at zero" — an untested error path in the chunk walk, a
status code nothing returns. The per-file table answers that; a single
percentage does not.

## CLI tests

`scripts/check-cli.sh` is registered with CTest as the `Cli` test and is also
runnable by hand:

```bash
./check-cli.sh ../../model-crypt-build/model-crypt
```

A shell script rather than a C++ test because what needs checking is the
*interface*: exit codes, that `--key` is refused rather than accepted, that a
key file's trailing newline is stripped, that no key source without a tty is an
error instead of a read from a pipe, that `keygen` will not overwrite. Driving
that through `fork`/`exec` in a test binary would be more code than the thing
it tests.

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml). Eight jobs; the
matrix reports every platform's result even when one fails, because a macOS
failure hiding whether Linux was also broken is the first thing anyone
wants to know.

| Job | Platform | What it adds |
|---|---|---|
| build-and-test | ubuntu-latest, clang, `-Werror` | Linux. Release *and* Debug, both under `-Werror`, then install-and-consume |
| build-and-test | macos-latest, clang, `-Werror` | macOS, with Apple clang and Homebrew OpenSSL 3 |
| build-and-test | ubuntu-latest, gcc, no `-Werror` | That it compiles and passes with the other major toolchain — the one a distro package build uses |
| lint | ubuntu-latest | `format.sh --check`, then `tidy.sh` |
| sanitizers | ubuntu-latest | ASan + UBSan |
| thread-sanitizer | ubuntu-latest | TSan |
| valgrind | ubuntu-latest | memcheck, uninstrumented build |
| coverage | ubuntu-latest | The per-file table |

### No pinned versions

Every job uses `ubuntu-latest` or `macos-latest`. No distro release is named,
nothing runs in a container, and no tool is pinned to a major.

A pin is a promise to keep re-pinning. GitHub retires runner images, so a pinned
label eventually either fails to schedule or freezes the toolchain under test
years behind what anyone uses. Tracking `latest` means a new compiler's
diagnostics arrive when that compiler ships.

What it costs is worth stating plainly. The build declares floors — CMake 3.16
and OpenSSL 1.1.1 — and **nothing in CI proves they still hold**, because the
runners are well above both. Those floors exist for people building on older
distributions, and they are now maintained by reading rather than by testing.
The two constructs they force (an `OBJECT` library, and `ctest` run from inside
the build directory) both work on every newer CMake, so nothing breaks — it just
stops being checked.

`clang-format` and `clang-tidy` are likewise unpinned, and come from LLVM: the
distro package on Linux, Homebrew's `llvm` on macOS, where Xcode ships no
`clang-format` at all. A clang-format release can therefore decide the tree
should look slightly different. When that happens the fix is to run
`./format.sh` and commit the result. Because `--check` runs on exactly one
platform, there is one authority at any moment rather than a quorum to satisfy.

### `-Werror`

The warning set — `-Wall -Wextra -Wconversion -Wshadow -Wold-style-cast
-Wpedantic` — is always on, for every target: the library objects, the library,
the CLI, the test binary, and the vector generator. Turning those warnings into
errors is separate, `MODEL_CRYPT_WERROR`, and off by default; `./build.sh
--werror` is what enables it.

In CI it is on for both **clang** jobs and covers **both configurations** they
build, Release and Debug. That pairing matters: the two warn about different
things — `NDEBUG` decides whether a variable used only inside an `assert()` is
used at all, and the optimizer's flow-sensitive diagnostics need `-O2` to fire
— so holding one to `-Werror` and not the other leaves the looser one
accumulating warnings nobody sees.

GCC runs without `-Werror` on purpose. Its `-Wconversion` and
`-Wold-style-cast` fire on different things than clang's, and a GCC release
adding a diagnostic should not turn every branch red before anyone has looked
at it. The warnings are still printed and still worth reading. What `-Werror`
means here is therefore precisely "clang's warning set", which is the one the
flag list was calibrated against.

clang-format comes from LLVM and is not pinned — see [No pinned
versions](#no-pinned-versions) for what that trades away.

The formatting check runs *before* the build — a formatting slip should fail in
seconds, not after a full compile.

## Adding a test

1. Put it in the suite it belongs to, or add a file and list it in
   `CMakeLists.txt` **twice**: the `add_executable` source list and the
   `foreach(suite ...)`.
2. Name it after the property, not the function: `WrongKeyFailsWithAuthError`,
   not `TestDecrypt3`.
3. If it is a tamper test, say in a comment what an attacker is doing and which
   part of the format catches it. That comment is the reason the test exists,
   and it is the part that survives a refactor.
4. Do not add a fixture file. If the input needs a shape, add a
   `corpus::Profile` for it — that keeps the repository free of binary blobs
   and keeps the input reproducible from the test name alone.
