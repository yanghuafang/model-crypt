# Installing and building

model-crypt is supported on **macOS** and **Linux**. CI builds and tests both
on every push, on whatever the platforms currently ship — `macos-latest` and
`ubuntu-latest`, no pinned release.

The dependency floors below are floors for people building on older systems,
not statements about what is tested. Nothing in CI runs a toolchain that old,
so they are maintained by reading rather than by testing.

## Requirements

| | Version | Why |
|---|---|---|
| C++ compiler | C++17 | `std::optional`, structured bindings, `[[nodiscard]]`. GCC 9 and clang 10 are both new enough |
| CMake | ≥ 3.16 | A floor for older systems; any current CMake works |
| OpenSSL | ≥ 1.1.1, **libcrypto only** | AES-256-GCM and `EVP_PBE_scrypt`, both present since 1.1.0 |
| zlib | any | Optional compression |
| pthreads | — | The API is reentrant; the tests exercise that |

Two of those floors shape the build in ways worth knowing about:

- **CMake 3.16** is why the sources are compiled into an `OBJECT` library that
  the real library and the tests both consume. `$<TARGET_OBJECTS:>` did not
  accept a non-`OBJECT` target until 3.21, and the tests must link the objects
  to reach the internal layers that `-fvisibility=hidden` keeps out of the
  library. It is also why the scripts run `ctest` from inside the build
  directory rather than passing `--test-dir`, which arrived in 3.20. Both
  spellings work on every newer CMake, so keeping the floor costs nothing.
- **OpenSSL 1.1.1** is why the KDF calls `EVP_PBE_scrypt` rather than the
  `EVP_KDF`/`OSSL_PARAM` interface. The two compute byte-identical scrypt, and
  only the former exists before 3.0. `EVP_PBE_scrypt` is not deprecated in 3.x,
  so one call spans the whole supported range without a `#if`.

There are no vendored dependencies and no submodules. The library links
`libcrypto` and `libz` and nothing else.

`clang-format` and `clang-tidy` are needed only to run the style checks, and
`valgrind` only for `check-valgrind.sh`.

## macOS

```bash
git clone git@github.com:yanghuafang/model-crypt.git
cd model-crypt/scripts
./install-deps-macos.sh
./build.sh
./run-tests.sh
```

`install-deps-macos.sh` installs Homebrew if it is missing, then
`openssl@3`, `cmake`, and `llvm`. zlib comes from the macOS SDK and needs
nothing.

Two things about macOS are worth knowing, because both produce confusing
failures if you build by hand instead of through the scripts:

- **Apple ships LibreSSL under the name `openssl`.** A `cmake` that finds it
  fails on a missing symbol, which reads like an OpenSSL installation problem
  rather than a "this is not OpenSSL" problem. `scripts/build-env.sh` exports
  `OPENSSL_ROOT_DIR` from `brew --prefix openssl@3` to avoid it entirely.
- **Homebrew's LLVM is keg-only, and stays off `PATH`.** `build-env.sh` points
  `MODEL_CRYPT_CLANG_FORMAT` and `MODEL_CRYPT_CLANG_TIDY` at the binaries by
  name instead. LLVM is wanted for those two tools only — Xcode ships no
  `clang-format` at all — and the library itself is compiled with Apple clang.

  Naming them rather than prepending the directory is deliberate.
  Homebrew's `llvm/bin` also contains `clang` and `clang++`, so putting it on
  `PATH` silently captures the compiler — and Homebrew's clang pairs its own
  libc++ with the macOS SDK's C headers, which on a recent SDK fails every
  translation unit with `<cstddef> tried including <stddef.h> but didn't find
  libc++'s <stddef.h>`. The library is meant to build with Apple clang; only
  the two style tools come from Homebrew.

## Linux

```bash
git clone git@github.com:yanghuafang/model-crypt.git
cd model-crypt/scripts
./install-deps-ubuntu.sh
./build.sh
./run-tests.sh
```

`install-deps-ubuntu.sh` installs `build-essential`, `cmake`, `clang`,
`clang-format`, `clang-tidy`, `llvm`, `libssl-dev`, `zlib1g-dev`, and
`valgrind`, then **verifies** the OpenSSL and CMake versions rather than
assuming them. Failing in the dependency script names the problem; failing in
CMake names a version string in a `FindOpenSSL` error.

No release is named and nothing is pinned — the packages are whatever the
running Ubuntu ships. Everything comes from the distro archive: no PPA, because
an unexpected OpenSSL is the thing a cryptographic library should not silently
acquire.

The script works as root without `sudo`, so it also runs unchanged in a bare
container.

`clang-format` and `clang-tidy` come from LLVM, unpinned. Different
clang-format majors can disagree about layout in small ways, so a release may
one day decide the tree should look slightly different; the fix then is to run
`./format.sh` and commit the result, not to pin the tool. `./format.sh` prints
which binary and version it used.

## Where the build goes

Out of tree, into a **sibling of the repository**:

```
~/study-projects/
├── model-crypt/                  the repo; `git status` stays clean
├── model-crypt-build/            default build directory
└── model-crypt-build-coverage/   coverage.sh's separate instrumented build
```

Override with `MODEL_CRYPT_BUILD_DIR`; the default is a choice about someone
else's filesystem, so it is a choice you can take back.

```bash
MODEL_CRYPT_BUILD_DIR=/tmp/mc ./build.sh
MODEL_CRYPT_BUILD_JOBS=4 ./build.sh     # default: one job per logical core
```

## Build modes

Every option is a flag on `scripts/build.sh`, which is a wrapper over one
`cmake` invocation so nobody has to remember the CMake variable names.

```bash
./build.sh                       # Release, tests on
./build.sh --debug               # Debug
./build.sh --relwithdebinfo
./build.sh --werror              # warnings are errors
./build.sh --no-tests            # library and CLI only
./build.sh --clean               # wipe the build directory first

./build.sh --asan --ubsan        # Address + UndefinedBehavior sanitizers
./build.sh --tsan                # ThreadSanitizer (not combinable with the above)
./build.sh --coverage            # source-based coverage
```

Two behaviours are worth knowing:

- A sanitizer or coverage build **defaults to Debug**. At `-O3` the compiler
  inlines away the frames a sanitizer report is made of, and the trace is the
  only reason to run the instrumented build. An explicit `--release` still
  wins.
- Changing sanitizer flags **reconfigures from scratch.** The flags reach every
  target through `add_compile_options`, which CMake caches, so reusing the
  directory would leave objects compiled without them and a link failure on
  missing `__asan_` symbols. The script detects the switch and says so.

`MODEL_CRYPT_TSAN` combined with `MODEL_CRYPT_ASAN` or `MODEL_CRYPT_UBSAN` is a
`FATAL_ERROR` in CMakeLists rather than a linker error later: the two use
incompatible shadow-memory layouts and clang rejects the pair.

## Building without the scripts

Nothing requires them. They exist to encode the two platform quirks above.

```bash
cmake -S . -B ../model-crypt-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"     # macOS only
cmake --build ../model-crypt-build --parallel
(cd ../model-crypt-build && ctest --output-on-failure)
```

CMake options, all `OFF` unless noted:

| Option | Default | Effect |
|---|---|---|
| `MODEL_CRYPT_BUILD_TESTS` | `ON` | Build the test suite |
| `MODEL_CRYPT_WERROR` | `OFF` | `-Werror` |
| `MODEL_CRYPT_ASAN` | `OFF` | AddressSanitizer (+ LeakSanitizer on Linux) |
| `MODEL_CRYPT_UBSAN` | `OFF` | UndefinedBehaviorSanitizer, `-fno-sanitize-recover` |
| `MODEL_CRYPT_TSAN` | `OFF` | ThreadSanitizer |
| `MODEL_CRYPT_COVERAGE` | `OFF` | `-fprofile-instr-generate -fcoverage-mapping` |

## Installing

```bash
cmake --install ../model-crypt-build --prefix /usr/local
```

Installs, under `GNUInstallDirs`:

```
bin/model-crypt                        the CLI
lib/libmodel_crypt.a                   static by default
include/model_crypt/model_crypt.h      the one public header
```

The library follows `BUILD_SHARED_LIBS`, which CMake defaults to `OFF`, so a
plain build produces `libmodel_crypt.a`. Configure with
`-DBUILD_SHARED_LIBS=ON` for `libmodel_crypt.so` / `.dylib`; the target already
carries `VERSION 2.0.0`, `SOVERSION 2`, and position-independent code, so
nothing else changes.

`src/` is deliberately not installed. That is the same boundary
`-fvisibility=hidden` enforces at link time: a consumer that cannot include
`crypt/format.h` cannot come to depend on it.

`scripts/check-install.sh` does this into a staging directory and then compiles
a small consumer against the result. It runs in CI on every platform, and it is
the only check that the *installed* interface works — everything else links out
of the build tree, where `include/` happens to be on the include path anyway.

## Consuming the library

There is no CMake package config yet. Link it as a plain library:

```bash
cc consumer.c -lmodel_crypt -o consumer
```

or from CMake:

```cmake
find_library(MODEL_CRYPT_LIB model_crypt REQUIRED)
find_path(MODEL_CRYPT_INCLUDE model_crypt/model_crypt.h REQUIRED)
target_link_libraries(app PRIVATE ${MODEL_CRYPT_LIB})
target_include_directories(app PRIVATE ${MODEL_CRYPT_INCLUDE})
```

The header is C, so C, Objective-C, Rust, Go, and Python `ctypes` consume it
without a wrapper. Link with the **C++** driver (`c++`/`clang++`) or add
`-lstdc++`/`-lc++` if your final link is done by `cc`: the implementation
behind the C interface is C++17 and needs the C++ runtime.

## Troubleshooting

**`Could NOT find OpenSSL (Required is at least version "1.1.1")`** — on
macOS, `brew install openssl@3` and build through `scripts/build.sh`, or pass
`-DOPENSSL_ROOT_DIR` yourself. On Ubuntu, `apt install libssl-dev`.

**`error: use of undeclared identifier 'EVP_PBE_scrypt'`** — you are building
against LibreSSL, which Apple ships under the `openssl` name. Same fix: point
`OPENSSL_ROOT_DIR` at a real OpenSSL.

**`CMake 3.x or higher is required. You are running version 3.16.3`** — from a
dependency, not from this project; model-crypt's own floor is 3.16. Check what
else is in your configure line.

**`undefined symbol: __asan_...` when linking** — a build directory with mixed
flags. `./build.sh --clean` with the flags you want; the script normally
catches this itself.

**`Unsupported OS`** from a script — `build-env.sh` supports Darwin and Linux
only. Configure CMake by hand elsewhere.

**Tests pass but `Cli` fails** — `check-cli.sh` needs a POSIX shell,
`mktemp`, and a writable `TMPDIR`. It is skipped nowhere, so a failure here is
real.
