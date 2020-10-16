# Threat model

What this library defends against, what it does not, and which of those gaps
you have to close yourself. Read this before shipping model-crypt in anything.

The short version: **model-crypt protects a model file at rest and in
transit. It cannot protect a model from the person running the process that
decrypts it.** Everything below is a consequence of that sentence.

## What is in scope

### The attacker who has the file

Someone who obtains `model.mcrypt` — from an app bundle, an OTA payload, an S3
bucket, a stolen laptop, a CDN cache — and does not have the key.

They learn, from the unauthenticated header: that it is a model-crypt v2 file,
its plaintext length to the byte, the chunk size, whether the encryptor
intended to compress, and the scrypt cost parameters. They learn the
compressibility of each chunk, because `stored_size` is in the clear. Nothing
else.

They cannot recover any plaintext. AES-256-GCM under a key derived by scrypt
from a 16-byte per-file salt has no known shortcut, and there is no part of
the payload — no header, no first block, no tail — that is stored unencrypted
or under a weaker transform. This is the specific property the v1 format did
not have.

### The attacker who can modify the file

Someone who can rewrite bytes: a MITM on an unauthenticated download, a
process with write access to the app's data directory, a malicious OTA.

Every modification is detected, and detection means `MC_ERR_AUTH` with **no
output**, not degraded output. See
[Format.md § What the AAD buys](Format.md#what-the-aad-buys) for the
per-attack mapping and [`tests/tamper_test.cc`](../tests/tamper_test.cc) for
the tests. The attacks that a naive chunked-AEAD design would let through —
reordering, truncation, duplication, cross-file splicing — are each covered by
a named component of the associated data.

This is the guarantee that actually matters operationally. A wrong model that
loads is worse than a model that fails to load, because the failure gets
noticed and the wrong weights do not.

### The attacker who supplies the file

Someone who hands your process a file they wrote, hoping the parser does
something for them. This is the memory-safety surface, and it is why the
library is shaped the way it is:

- The header is fixed at 64 bytes. Nothing seeks by a length read out of the
  input.
- Every allocation made before a key is proven is bounded by the size of the
  input, not by what the input claims. `plaintext_size` and `stored_size` are
  range-checked and then checked against the bytes actually present; the chunk
  table is allocated only once the file is known to contain that many records;
  and the plaintext buffer is allocated only after chunk 0's tag has
  authenticated the header that declares its size. The worst a hostile file can
  provoke is one chunk's worth of memory — 4 MiB at the default, 64 MiB at the
  format's ceiling — plus a table proportional to the file it actually sent.
- The scrypt parameters are bounded by their product, not just individually,
  so a 64-byte file cannot request a 4 GiB working set.
- zlib is only ever handed bytes that already authenticated, with an output
  bound taken from the authenticated header. A decompression bomb is not
  bounded, it is impossible.
- Every reserved field must be zero and every unknown flag bit is rejected, so
  nothing is silently ignored.

CI runs the whole suite under ASan+UBSan on two Ubuntu releases, under TSan,
and under Valgrind — the last because ASan cannot see inside OpenSSL and zlib,
and every buffer handed to `EVP_CipherUpdate` or `inflate()` is sized by
arithmetic in `format.cc`. See [Testing.md](Testing.md).

### Offline guessing of a passphrase

In scope, partially. scrypt at the default cost (N = 2^15, r = 8, p = 1) costs
about 100 ms and 32 MiB per guess, and the memory term is what a GPU or ASIC
cannot optimize away. A 16-byte salt per file makes precomputation useless and
makes two files under the same passphrase independent targets.

That buys a great deal against a weak passphrase and it does not make one
strong. If the key is not memorized by a human, use
`mc_generate_key(k, 32)` — 256 bits from the OS CSPRNG — and the question
stops being interesting. Raise `--kdf-log-n` if a human-chosen passphrase is
unavoidable; every increment doubles cost and memory for both sides equally.

## What is out of scope

These are not oversights. Each one is a thing this library structurally cannot
do, listed so you can decide what to do about it.

### Plaintext after `mc_decrypt_*` returns

The library hands you a buffer. From that moment the model is in your process's
memory and its safety is your process's problem.

What is provided: `mc_free(ptr, size)` wipes with `OPENSSL_cleanse` before
freeing, so a decrypted model does not linger for the next allocation or a
core dump. Internally the derived key and the plaintext under construction
live in `SecureBuffer`, which cannot grow — a `std::vector` that reallocates
has already scattered its old contents across the heap before any destructor
runs, and no custom allocator fixes that.

What is not provided:

- **No page locking.** Nothing calls `mlock`, so plaintext and keys can reach
  swap or a hibernation image. Locking pages needs a privilege the target
  platforms do not grant by default, and a silently failing `mlock` is worse
  than an honest absence of one.
- **No control over what you do next.** If you `write()` the buffer to a file,
  it is a plaintext model on disk. `mc_decrypt_file_to_buffer` exists to make
  the in-memory path the easy one; prefer it on any client device.
- **No protection from your own crash handler.** A core dump or a crash
  reporter that captures the heap captures the model.

### A key shipped inside the binary that uses it

**This is the one that matters, and this library cannot help with it.**

If your app decrypts a model on a device the user controls, the key has to be
available to the app on that device. However you hide it — a string literal,
scattered bytes, an XOR ladder, a whitebox, code in the NDK — a determined
person with a debugger recovers it, because the process must have it in
registers at the moment it calls into scrypt. The old iOS and Android demos
had `const char *key = "!@#$%^&*()";` compiled in, recoverable with `strings`
in seconds; obfuscating that literal would have raised the cost from seconds
to an afternoon.

What actually changes the picture, in rough order of strength:

1. **Do not put the model on the device.** Run inference server-side. Then
   nothing about this problem exists.
2. **Fetch the key at runtime over an authenticated channel**, bound to an
   attested device and a per-install identity, and hold it only in memory. The
   attacker now needs a live device rather than a copy of your app, and you
   can revoke.
3. **Keep the key in hardware.** Secure Enclave or the Android Keystore with
   `StrongBox` and user or attestation gating. The key is not extractable; the
   attacker's target becomes the decrypted output rather than the key.
4. **Accept that a local key is anti-casual-copying, not security.** Which is
   a legitimate choice — it stops a model being lifted out of an APK by
   someone with `unzip`, and that is most of the real-world copying. Just do
   not budget for it as if it were more.

model-crypt's job is to make sure that once you have solved this, the file
format is not the weak link. It cannot solve it for you.

### Extraction of the model through the model

Nothing here addresses model stealing via query access, distillation, or
membership inference. A deployed model that answers questions leaks
information about itself by design, and that is a different field.

### Side channels

Not analyzed. The AES-GCM implementation is OpenSSL's, which uses AES-NI where
available and is written to be constant-time; scrypt is OpenSSL's
`EVP_PBE_scrypt`. Beyond relying on those, nothing in this library is hardened
against timing, cache, or power analysis, and the chunk walk is not written to
be data-independent (it does not need to be — every branch is on authenticated
metadata, not on key material).

### The age of the platform's OpenSSL

The build's floor is OpenSSL **1.1.1**, and 1.1.1 reached end of life in
September 2023 — it receives no upstream fixes. Distributions that still ship it
patch it under their own extended-maintenance terms, which on some is a paid
subscription.

None of this library's guarantees depend on which version is underneath it: the
primitives are the same, `EVP_PBE_scrypt` derives byte-identical keys on both,
and the committed format vector decrypts under either. What differs is **who is
fixing the next vulnerability in the code doing the AES.**

So: the floor exists so the library still builds on an older system, not as a
recommendation. Build against **OpenSSL 3** wherever you have the choice, which
is what CI does on both platforms. If you must ship against 1.1.1, know that its
maintenance is your distribution's problem rather than upstream's, and check
what that costs you.

### Anti-debugging

Deliberately absent, and this is a change from v1.

v1 shipped `disable_debugger_attach()`, `is_being_traced()`, and an
IDA-detector, with the strings XOR-obfuscated. They cost real complexity and
delivered nothing: `ptrace(PT_DENY_ATTACH)` is bypassed by a debugger that
attaches before `main`, `/proc/self/status` is a file an attacker can make say
anything, and the Android path was in fact **dead code** — it gated on an API
level that no app ever set, so every `ptrace` call was a no-op in the shipped
library and nobody noticed for years.

The judgment here is that anti-debugging is a speed bump that reads as a
security control, which is worse than no control at all, because it gets
counted in the budget. If you need it, add it in your app where you can
measure whether it runs, not in a library where it silently cannot.

### Denial of service against your own process

Bounded, not eliminated. A hostile file cannot make the library allocate
unboundedly, but a legitimately huge one takes a long time, and the scrypt
cost recorded in a file is an attacker-chosen amount of work up to the 1 GiB /
`log_n = 20` ceiling. If you decrypt files from untrusted sources on a shared
service, inspect the header first (`mc_inspect_buffer` needs no key) and
reject costs you are not willing to pay.

## What v1 got wrong

Recorded because the current design is a direct response to it, and because
these are the failure modes to check for in any homegrown model encryptor.

| v1 behaviour | Consequence | How v2 answers it |
|---|---|---|
| Alternating 64 KiB sections: Blowfish, then a rotate+XOR keyed only by a bit-count of the key | **Half of every file recoverable with no key.** The bit-count had ~36 distinct values over random keys; 67 trial decryptions recovered plaintext | One primitive, AES-256-GCM, over every byte. No section is treated differently |
| No MAC, magic-only validation | Wrong key returned `MC_OK` and garbage, which then reached the inference runtime | AEAD per chunk; `MC_ERR_AUTH` and no output |
| Huffman decoder given unauthenticated input | Segfault on a corrupted or wrong-keyed file (ASan-confirmed) | Decompression happens only after the tag verifies, with an authenticated output bound |
| Payload transformed through `unsigned int*` casts at unaligned offsets | Undefined behaviour, and a file format that silently depended on host endianness | Explicit little-endian shifts; byte-oriented throughout |
| ECB, no IV, deterministic | Same model twice produced identical ciphertext; identical blocks visible | Random salt and nonce prefix per file |
| Attacker-controlled `decompressed_file_size` sized a `malloc` | Trivial memory pressure from a 64-byte file | Nothing is allocated on an unauthenticated size |
| Keys as `-k` on the command line, echoed to stdout | Key in `ps`, shell history, CI logs | `--key-file` / `--key-env` / tty prompt only; there is no `--key` |
| `unsigned int` sizes | 4 GiB ceiling, silent truncation above it | `uint64_t` sizes, explicit 64 GiB limit, `MC_ERR_TOO_LARGE` |
| Anti-debug that did not run | Complexity counted as defence | Removed; see above |

## Deployment checklist

If you are putting this on a device:

- [ ] The key is not a literal in the binary. If it has to be, you have
      documented internally that this is anti-copying, not security.
- [ ] You use `mc_decrypt_file_to_buffer`, not `mc_decrypt_file`, so plaintext
      never lands on disk.
- [ ] You call `mc_free` as soon as the runtime has taken the weights.
- [ ] Your ciphertext download is authenticated in transit as well —
      model-crypt detects tampering, but only when the file reaches it.
- [ ] You are not writing decrypted output anywhere world-readable.
      (`/sdcard`, an iOS `Documents` directory with `UIFileSharingEnabled`,
      a temp file in `/tmp`.)
- [ ] Crash reporting does not upload heap contents.
- [ ] You check the return status. It is `MC_NODISCARD` for a reason: ignoring
      it is the one mistake that turns a caught attack back into a silent one.
