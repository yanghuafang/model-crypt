# Contributing to `model-crypt`

Thanks for your interest. model-crypt is a small library with a large blast
radius: a mistake here does not produce a wrong answer, it produces a model
file someone believed was protected. So changes are reviewed for what they make
*impossible*, not just for what they make work.

Small, reviewable changes with a stated reason are worth more than large ones.

## Ways to contribute

- **Fix a bug.** [docs/Architecture.md](docs/Architecture.md) maps `src/` to
  responsibilities.
- **Add a test**, especially a tamper case nobody thought of — see
  [Adding a test](#adding-a-test).
- **Improve the docs**, or add comments that explain *why*. Comment density is
  deliberately high here and that is the house style.
- **Port it.** Windows and Android/iOS toolchains are not currently built or
  tested; adding one means adding it to CI too.

## Prerequisites

macOS or Linux. OpenSSL 1.1.1+, zlib, CMake 3.16+, a C++17 compiler.

Those last two are floors the build is written against rather than merely
tolerated: `$<TARGET_OBJECTS:>` on a non-`OBJECT` library and `ctest
--test-dir` both need a newer CMake, and `EVP_KDF` needs a newer OpenSSL. CI
runs current toolchains and will **not** catch you reaching for one of those —
the floors are maintained by reading, so keep them in mind when editing
`CMakeLists.txt` or `crypt/kdf.cc`.

```bash
cd scripts
./install-deps-macos.sh     # macOS
./install-deps-ubuntu.sh    # Ubuntu / Debian
```

See [docs/Install.md](docs/Install.md) for the manual CMake route and for the
macOS OpenSSL/LibreSSL trap.

## Build and test

```bash
cd scripts
./build.sh --debug
./run-tests.sh
```

Output goes to `../../model-crypt-build` — a sibling of the repo, so
`git status` after a build is empty.

## What a change has to pass

Everything CI runs, and it is all runnable locally. Do that before opening a
pull request; the sanitizer jobs are slow and finding out from a red badge
wastes a round trip.

```bash
cd scripts

./format.sh --check              # clang-format 20 + trailing whitespace
./build.sh --debug && ./tidy.sh  # clang-tidy, needs the compile database

./build.sh --release --werror && ./run-tests.sh
./build.sh --debug --werror   && ./run-tests.sh

./build.sh --asan --ubsan      && ./run-tests.sh
./build.sh --tsan              && ./run-tests.sh

./build.sh --debug && ./check-valgrind.sh    # Linux; uninstrumented build
./check-install.sh                           # installs and compiles a consumer
./coverage.sh                                # reported, not gated
```

`./format.sh` without `--check` fixes formatting in place.

Both configurations under `-Werror`, not just Release: `NDEBUG` changes which
code the compiler can see as reachable, so the two do not warn about the same
things.

CI additionally builds with GCC on Linux without `-Werror`. See
[docs/Testing.md § `-Werror`](docs/Testing.md#-werror).

## Style

The [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
applies, and most of it is checked rather than remembered: `.clang-format` and
`.clang-tidy` at the repo root are normative, and `./format.sh` and `./tidy.sh`
apply them.

**Naming**, since it is the part a tool cannot fully police:

| | |
|---|---|
| Files | `lower_case.cc`, `lower_case.h` — `secure_buffer.h`, `file_io.cc` |
| Types | `PascalCase` — `SecureBuffer`, `FileHeader` |
| Tests | `<unit>_test.cc` — `tamper_test.cc`, `round_trip_test.cc` |
| Functions | `PascalCase` — `ParseFileHeader`, `DeriveKey` |
| Variables, parameters | `snake_case` — `chunk_count`, `plain_size` |
| Class data members | `snake_case_` — `data_`, `size_` |
| Struct data members | `snake_case` — `stored_size` |
| Constants, enumerators | `kPascalCase` — `kHeaderSize`, `Profile::kZeros` |
| Namespaces | `lower_case` — `format`, `random_bytes` |
| Macros | `UPPER_SNAKE` |

Two deliberate exceptions:

- **Accessors may be named like variables.** `SecureBuffer::data()`, `size()`
  and `empty()` are lowercase, which the guide explicitly permits and which
  keeps the type reading like the container it stands in for.
  `readability-identifier-naming` is configured without `FunctionCase` for
  exactly this reason — it cannot tell an accessor from a function, and the
  alternative was renaming those three or scattering `NOLINT`s.
- **The public C API is `mc_snake_case`.** It is C, it should look like C, and
  renaming `mc_status` would break every consumer. `include/` is outside
  `HeaderFilterRegex` so the naming check does not report it.

**Header guards, not `#pragma once`.** `MODEL_CRYPT_<PATH>_<FILE>_H_`, matching
the file's path under the repo root.

**Include order** is the guide's: related header, C system, C++ standard
library, other libraries, this project. `.clang-format` encodes it, so
`./format.sh` will fix a wrong one for you.

**Comments explain why, never what.** `// increment i` is noise; `// The casts
through uint32_t before shifting matter: uint8_t promotes to int, so in[3] << 24
on a byte >= 0x80 shifts into the sign bit` is the house style. If a line looks
odd and is correct, say why it is correct — that comment is what stops the next
person from "fixing" it.

**Every header carries a `///` block** stating what the unit is for and what
decision shaped it. The ones in `src/crypt/` are the model: they explain the
alternative that was rejected and why, which is the part a reader cannot
reconstruct from the code.

**Doxygen `\param` / `\return` on every public and internal API function**,
including which statuses it can return. `include/model_crypt/model_crypt.h` is
the reference.

**No new dependency** without discussing it first. OpenSSL and zlib come from
the platform so a CVE in either is the platform's to fix; a vendored library
would make it ours.

## Rules specific to this codebase

These are not style preferences. A change that breaks one will be sent back.

1. **Nothing is allocated on an unauthenticated size.** If you find yourself
   sizing a buffer from a header field before a tag has verified, the design is
   wrong, not the bound.
2. **Untrusted bytes reach a decoder only after authentication.** zlib, and
   anything added later, sits behind the GCM check.
3. **Validation lives where the untrusted bytes are parsed** — in
   `format::ParseFileHeader` and `ParseChunkHeader` — not scattered across
   consumers. Lower layers are entitled to assume their inputs are in range,
   and each says so in its doc comment.
4. **Keys and plaintext live in `SecureBuffer`**, never in `std::vector`. A
   vector that grows has already scattered its old contents across the heap
   before any destructor runs.
5. **A new format field goes into the AAD**, or there is a written reason why
   it does not need to be.
6. **No new exported symbol** without `MC_API` and a decision that it is
   permanently part of the ABI. Eleven functions is the entire surface, and
   `-fvisibility=hidden` is what keeps it that way.
7. **No exception crosses the C boundary.** `src/api/c_api.cc` catches
   everything; it is undefined behaviour otherwise.
8. **Do not add an anti-debugging or obfuscation feature.**
   [docs/ThreatModel.md](docs/ThreatModel.md#anti-debugging) explains why: it
   is a speed bump that reads as a security control, which is worse than none
   at all because it gets counted in the budget.

## Changing the format

A change to the on-disk layout is a **version bump**, not an edit.

1. Bump `MC_FORMAT_VERSION` and the magic (`MCRYPT02` → `MCRYPT03`).
2. Update [docs/Format.md](docs/Format.md) — it is normative, so a layout
   change that does not touch it is incomplete.
3. Run `scripts/make-vector.sh --force` for the new vector, and **keep the old
   one**, with a test asserting it is now rejected as `MC_ERR_UNSUPPORTED`.
4. Say in the pull request what an existing file does when the new build reads
   it.

**Do not regenerate `tests/vectors/` for any other reason.** That file is the
only thing in the tree that can distinguish a format change from a refactor —
every other test encrypts and decrypts with the same binary and agrees with
itself no matter what the layout is — and its value comes entirely from having
been produced by an older build. Replacing it with one this build wrote throws
that away and lets the regression it would have caught ship.

Note that regenerating is not a comparison you can reason from: the salt and
nonce are random per encryption, so a fresh vector differs from the committed
one every time, format change or not. The signal is the `Vector` suite failing
to decrypt the committed file. `make-vector.sh` refuses to overwrite without
`--force` for exactly this reason.

## Adding a test

1. Put it in the suite it belongs to, or add a file and list it in
   `CMakeLists.txt` **twice**: the `add_executable` source list and the
   `foreach(suite ...)`. Missing the second is why `testing::Run()` treats "no
   test matched" as a failure.
2. Name it after the property, not the function:
   `WrongKeyFailsWithAuthError`, not `TestDecrypt3`.
3. For a tamper test, write what the attacker is doing and which part of the
   format catches it. That comment is the reason the test exists and the part
   that survives a refactor.
4. **Do not add a fixture file.** If the input needs a shape, add a
   `corpus::Profile`. The repository carries no model and no binary blob
   besides the format vector, and CI downloads nothing — see
   [docs/Testing.md](docs/Testing.md#testing-an-encryptor-with-no-models).

## Reporting a vulnerability

Do not open a public issue. Email the maintainer with the file or input that
reproduces it and, if you have one, the status the library returned instead of
the one it should have.

Findings in scope, roughly in order of interest: anything that recovers
plaintext without the key; anything that makes `mc_decrypt_*` return `MC_OK` on
bytes the encryptor did not write; a memory-safety bug reachable from a crafted
file; an allocation a small hostile file can provoke.

Out of scope, because they are documented limits rather than bugs: extracting a
key from a binary that contains one, and recovering plaintext from the process
that legitimately decrypted it. See [docs/ThreatModel.md](docs/ThreatModel.md).

## Pull requests

- One concern per pull request.
- Say what the change makes impossible, not only what it makes work.
- If a behaviour changed, name the test that would have caught the old
  behaviour.
- Keep `docs/` true. A format or API change with stale docs is not done.
