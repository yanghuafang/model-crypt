# `model-crypt`: deep learning model encryption

[![CI](https://github.com/yanghuafang/model-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/yanghuafang/model-crypt/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Authenticated encryption for model files, as a **C API**, a **CLI**, and a
documented **container format**. AES-256-GCM under an scrypt-derived key, with
optional per-chunk zlib.

Runs on **macOS** and **Linux**. Dependencies are OpenSSL (1.1.1 or newer) and
zlib, both from the platform.

## Why this project

A model shipped to a device is an asset sitting in a file someone else
controls. The obvious fix — encrypt it — is easy to do in a way that looks
right and is not, and the previous version of this repository is a worked
example of that: half of every file was recoverable **without the key**, a
wrong key returned success and garbage, and a malformed file segfaulted the
decoder. Those are all in
[docs/ThreatModel.md § What v1 got wrong](docs/ThreatModel.md#what-v1-got-wrong),
because they are the failure modes to check for in any homegrown model
encryptor.

This version is built around four properties:

- **Authenticated, not just encrypted.** A wrong key or a modified file gives
  you `MC_ERR_AUTH` and *no output*. There is no "decrypt it anyway" escape
  hatch, because a model that fails authentication is not a degraded model, it
  is an attacker-chosen one — and the whole point is that it does not reach the
  inference runtime.
- **Nothing is trusted before it is authenticated.** No allocation is sized on
  a number read from an unverified header, and zlib is never handed bytes that
  have not already passed a GCM tag check.
- **One primitive, applied to everything.** No section of the file gets a
  different or weaker treatment. Standard constructions from OpenSSL, no
  hand-rolled ciphers.
- **The whole thing is checked.** 56 tests plus a CLI suite, run under
  ASan+UBSan, TSan, and Valgrind on every push, on the oldest supported
  toolchain and on a current one — with no model file in the repository and no
  download in CI.

## How it works

```
model.onnx
  │  scrypt(passphrase, random 16-byte salt)      →  256-bit key
  ▼
split into chunks (4 MiB default)
  │  per chunk:  deflate if it helps  →  AES-256-GCM seal
  │              nonce  = per-file random prefix ‖ chunk index
  │              AAD    = the 64 header bytes ‖ index ‖ stored size ‖ flags
  ▼
model.mcrypt
  [ 64-byte header ][ 24-byte record ][ ciphertext ] × N
```

The associated data is what makes the file a whole rather than a bag of
independently valid chunks. Each chunk carries its own position and the shape
of the file it belongs to, so reordering, truncating, duplicating, or splicing
chunks between two files fails — even though every individual GCM tag would
still verify. [docs/Format.md](docs/Format.md) has the byte layout and a table
of which AAD component defeats which attack;
[docs/Architecture.md](docs/Architecture.md) walks the code.

## Quick start

```bash
git clone git@github.com:yanghuafang/model-crypt.git
cd model-crypt/scripts

# macOS:                    ./install-deps-macos.sh
# Ubuntu / Debian:          ./install-deps-ubuntu.sh

./build.sh
./run-tests.sh
```

Then:

```bash
cd ../../model-crypt-build

./model-crypt keygen  --out model.key
./model-crypt encrypt --key-file model.key --in model.onnx --out model.mcrypt
./model-crypt inspect --in model.mcrypt
./model-crypt decrypt --key-file model.key --in model.mcrypt --out recovered.onnx
```

There is deliberately **no `--key` option**: a key on the command line is
visible in `ps`, in shell history, and in CI logs. Use `--key-file`,
`--key-env`, or the terminal prompt.

## From C

```c
#include <model_crypt/model_crypt.h>

uint8_t *plain = NULL;
size_t plain_len = 0;

mc_status rc = mc_decrypt_file_to_buffer(key, key_len, "model.mcrypt",
                                         &plain, &plain_len);
if (rc != MC_OK) {
  fprintf(stderr, "decrypt failed: %s\n", mc_status_string(rc));
  return -1;
}

runtime_load_weights(plain, plain_len);
mc_free(plain, plain_len);   /* wipes with OPENSSL_cleanse, then frees */
```

Eleven functions, one header, no init or teardown, no global state — so any
number of threads may encrypt and decrypt concurrently. The header is C, so
Objective-C, Rust, Go, and Python `ctypes` consume it without a wrapper; the
implementation behind it is C++17.

`mc_decrypt_file_to_buffer` rather than `mc_decrypt_file` is the form to prefer
on a client device: it never writes plaintext to disk, which is the single
largest hole in a naive deployment. See [docs/Usage.md](docs/Usage.md).

## What it does not do

**model-crypt protects a model file at rest and in transit. It cannot protect a
model from the person running the process that decrypts it.**

If your app decrypts on a device the user controls, the key must be available
to the app on that device, and a determined person with a debugger recovers it
however you hide it. The library makes sure the file format is not the weak
link; it cannot make the key one you control.
[docs/ThreatModel.md](docs/ThreatModel.md) lays out the four real options and
is honest about what each one buys.

Also absent, on purpose: page locking, anti-debugging (v1 had it; on Android it
was dead code that never ran), and any defence of the plaintext after
`mc_decrypt_*` hands it back.

## Format at a glance

| | |
|---|---|
| Magic | `MCRYPT02` |
| KDF | scrypt, N = 2¹⁵, r = 8, p = 1 by default; 16-byte per-file salt |
| Cipher | AES-256-GCM, 96-bit nonce, 128-bit tag |
| Nonce | per-file random 8-byte prefix ‖ 32-bit chunk index — unique by construction |
| Chunking | 4 MiB default, 4 KiB – 64 MiB |
| Compression | zlib per chunk, kept only when it helps |
| Overhead | 64 + 24 per chunk ≈ 6 parts per million at the default |
| Byte order | little-endian everywhere, by explicit shifts |
| Max plaintext | 64 GiB |

## Documentation

| | |
|---|---|
| [docs/Install.md](docs/Install.md) | Requirements, setup, build modes, troubleshooting |
| [docs/Usage.md](docs/Usage.md) | The CLI and the C API |
| [docs/Format.md](docs/Format.md) | The container format, normatively |
| [docs/Architecture.md](docs/Architecture.md) | Layers, and the decryption ordering |
| [docs/ThreatModel.md](docs/ThreatModel.md) | Scope, limits, and the deployment checklist |
| [docs/Testing.md](docs/Testing.md) | Suites, sanitizers, CI |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Style, and what a change has to pass |

## Repository layout

```
include/model_crypt/     the one installed header
src/api/                 the C ABI seam
src/crypt/               format, AEAD, KDF, compression, secure buffers
src/cli/                 the model-crypt executable — a plain API consumer
src/util/                file I/O
tests/                   ten C++ suites + a committed format vector
scripts/                 build, test, format, tidy, coverage, valgrind, install checks
docs/                    the above
```

## Testing, without a model file

The library is byte-oriented; the only input properties that change its
behaviour are **length** relative to the chunk boundaries and
**compressibility**. So the suite generates both, deterministically, from four
profiles that stand in for zeroed padding, quantized weights, fp32 weights, and
a mix — no fixture to fetch, nothing to keep in sync, and a failure reproducible
from the test name alone.

The exception is one committed 4 KiB `.mcrypt` vector, which is the only thing
in the tree that can tell a format change from a refactor: every other test
encrypts and decrypts with the same binary and so agrees with itself no matter
what the layout is.

`Tamper` is the suite that justifies the format. It is written against the
attacks — reorder, truncate, duplicate, splice, flip one bit anywhere — and
`BitFlipAnywhereFails` walks every metadata byte exhaustively, which is the only
way to catch a field the AAD forgot to cover without someone thinking of that
field first.

See [docs/Testing.md](docs/Testing.md).

## Status

Format version 2. The container is stable and the committed vector guards it —
if the `Vector` suite stops decrypting that file and `MC_FORMAT_VERSION` was not
bumped, the change that broke it is the bug.

v1 files (`MLM` magic) are **not** readable and will not be. They had no
integrity protection, so "reading" one would mean trusting bytes that nothing
ever authenticated. Decrypt with the old tool, re-encrypt with this one.

## License

MIT. See [LICENSE](LICENSE).

Note that model-crypt links OpenSSL (Apache-2.0) and zlib, both from the
platform. Neither is vendored, so this repository carries no code under another
license — unlike the v1 engine, which statically linked GPL-3.0 sources into
BSD-licensed demo apps.
