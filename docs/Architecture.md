# Architecture

How the source is laid out, what each layer may depend on, and the handful of
decisions that shaped it.

If you are implementing a reader elsewhere, [Format.md](Format.md) is what you
want. This file is about the code.

## Layers

```
include/model_crypt/model_crypt.h   the only public header — C, eleven functions
        │
src/api/c_api.cc                    C ABI: validate, default, translate exceptions
        │
        ├── src/crypt/encrypt.cc    assemble a file: header + sealed chunks
        └── src/crypt/decrypt.cc    parse → authenticate → allocate → finish
                    │
                    ├── src/crypt/format.cc         byte layout, parsing, AAD, nonces
                    ├── src/crypt/aead.cc           AES-256-GCM (OpenSSL EVP)
                    ├── src/crypt/kdf.cc            scrypt (EVP_PBE_scrypt)
                    ├── src/crypt/compress.cc       zlib deflate/inflate, bounded
                    ├── src/crypt/random.cc         RAND_bytes
                    └── src/crypt/secure_buffer.cc  a heap buffer that wipes itself
        │
src/util/file_io.cc                 read whole, write atomically, mode control

src/cli/main.cc                     the `model-crypt` executable — public API only
```

Dependencies point downward and the graph is acyclic. `format` knows nothing
about `aead`; `aead` knows nothing about the file layout. The CLI is an ordinary
consumer of the public header — it links no internal symbol, which is what
keeps it honest as a demonstration that the public API is sufficient.

## The public/internal boundary, enforced twice

`include/` is `PUBLIC` on the library target and `src/` is `PRIVATE`, so
nothing outside this build can include `crypt/format.h`. That is the
compile-time half.

The link-time half is `-fvisibility=hidden` plus `MC_API` on exactly eleven
functions. Without it, every symbol in the internal namespaces —
`format::ParseFileHeader`, `aead::open` — would land in the shared library's
dynamic symbol table, become something a consumer can link against, and thereby
become an ABI that cannot be changed. With it, those eleven functions are the
entire surface, and `install()` ships the public header only.

`scripts/check-install.sh` is what keeps both halves true: it installs into a
staging prefix and compiles a consumer against the result, which is the only
check that does not accidentally have `include/` on its path already.

The tests deliberately breach this, and have to: `crypt_test.cc` calls
`format::ParseFileHeader` and `kdf::DeriveKey` directly. They link the
library's **object files** (`$<TARGET_OBJECTS:model_crypt>`) rather than the
library, so the internal layers can be tested without punching a hole in the
export list — which would mean the thing being tested is not the thing being
shipped.

## Why the API is C

The header is C so that C, Objective-C, Rust, Go, and a Python `ctypes` binding
consume it without a wrapper. The implementation behind it is C++17, because
RAII is what makes "this buffer is wiped on every path out of this function"
true without a `goto cleanup` ladder in every function.

`src/api/c_api.cc` is the seam. It does four things and nothing else:

1. Validates arguments, so no lower layer carries a "or NULL for defaults"
   case.
2. Substitutes option defaults.
3. Converts a `SecureBuffer` into the `malloc`-compatible buffer the caller
   will pass to `mc_free`.
4. Catches every exception. A C++ exception crossing a C ABI boundary is
   undefined behaviour, so `std::bad_alloc` becomes `MC_ERR_MEMORY` here and
   nothing propagates past it.

## Decryption, in three phases

The ordering in `decrypt.cc` is the single most security-relevant thing in the
codebase, and it is a direct response to how the v1 format failed.

1. **Parse.** Check the magic, version, algorithm ids, and every parameter
   range. Walk the chunk table record by record, checking each `stored_size`
   against the bytes that actually remain, and require the walk to land exactly
   on the end of the input. No key is used, and nothing larger than a 24-byte
   chunk record is read.

   The table of parsed records is itself an allocation sized from
   `chunk_count`, which the file chose — so the walk first requires the input to
   be big enough to hold that many records. Without that, an 88-byte header
   declaring 64 GiB of plaintext at the 4 KiB minimum chunk size asks for 16.7 M
   entries, and the rejection costs half a gigabyte of resident memory before it
   happens.

2. **Authenticate the header.** Open chunk 0 into a scratch buffer of at most
   `chunk_size` bytes. Its tag covers the entire file header, so success here
   is what makes `plaintext_size` trustworthy.

3. **Allocate and finish.** *Now* allocate the full plaintext buffer, on a size
   that has been authenticated, and open chunks 1..N-1 straight into it.

A parser that allocated `plaintext_size` in phase 1 would let a 200-byte file
demand 64 GiB — which is exactly what v1 did, with a `malloc` on a
`decompressed_file_size` read out of an unauthenticated header.

The property to preserve is that **every allocation before the key is proven is
bounded either by the input's own size or by one chunk** — 4 MiB at the
default, 64 MiB at the format's ceiling. It is worth re-deriving whenever an
allocation is added to phase 1 or 2, because it is not visible from any single
line: the inflate scratch, for instance, is sized from the largest deflated
chunk the table actually contains rather than from the largest one `chunk_size`
would permit, and the difference only matters for a file that lies.

Decompression sits inside phase 3, after the tag check, never before. zlib is
handed only bytes that were sealed by someone holding the key, with an output
bound taken from the authenticated header.

### What a failure leaves behind

Nothing. Every buffer in the decrypt path is a `SecureBuffer`, so an
`MC_ERR_AUTH` on chunk 7 of 400 wipes the six chunks of real plaintext already
recovered rather than releasing them to the heap. The unverified output of the
failing chunk is wiped for the same reason — AES-GCM produces those bytes
before it checks the tag, and they are attacker-influenced by construction.

## Encryption

Shorter, because it decides less. The salt, the derived key, and the whole
layout are fixed before the first chunk is written; the loop decides only
whether deflate helped and which nonce the chunk gets.

The one wrinkle is the output allocation. The exact file size is not known
until every chunk has been compressed, and compressing twice to find out would
double the CPU cost on a multi-gigabyte model. So the buffer is allocated at the
worst case — no chunk compresses — which is `plaintext_size + 24 * chunk_count
+ 64` bytes, about 0.001% over at the default chunk size. For an incompressible
model that slack is noise. For a very compressible one it is not, so the buffer
is copied down when the slack exceeds `kShrinkThreshold` (1 MiB): the common
case pays no copy, and the pathological case does not hand back a buffer many
times larger than the file it holds.

Note that encryption is therefore **not** a streaming operation over an
unknown-length input. `plaintext_size` and `chunk_count` are in the AAD of the
very first chunk, which is precisely what makes truncation detectable. Making
it streamable means giving that up, and it is not a trade worth reversing.

## `SecureBuffer`

Used for the two things whose lifetime matters more than their contents: the
derived AES key, and the plaintext being assembled during decryption.

It is not a `std::vector<uint8_t>`, for two reasons, and only the second is
about wiping.

**A vector's growth reallocates.** It copies the old contents to a new block
and frees the old one *without clearing it*. A key held in a vector that was
ever resized has already been scattered across the heap before any destructor
runs, and no custom allocator fixes that, because the copy happens above the
allocator. `SecureBuffer` cannot grow, which is what makes its wipe complete
rather than best-effort.

**The wipe is `OPENSSL_cleanse`, not `std::memset`.** A memset to storage that
is dead immediately afterwards is a no-op under the as-if rule, and compilers
do delete it. Every "secure zero" that is a plain memset is a comment about
intent rather than a wipe.

It is also non-copyable: a copy is a second plaintext with a second lifetime,
and every use here wants exactly one.

What it does *not* do is `mlock`. See
[ThreatModel.md § Plaintext after `mc_decrypt_*` returns](ThreatModel.md#plaintext-after-mc_decrypt_-returns).

## Byte order

Every integer in the format is little-endian, written and read with explicit
shifts. Not a `memcpy` of a packed struct, and not `htole32`.

A packed struct reads and writes host order, so a file written on one
endianness is silently unreadable on the other. That is exactly the bug v1
had — its payload was transformed through `unsigned int*` casts, which made the
file format depend on the machine that produced it and, at unaligned offsets,
was undefined behaviour besides.

Doing the shifts by hand makes byte order a property of the code rather than of
the host, and costs nothing a compiler does not fold into a single instruction
on a little-endian target. The casts through `uint32_t` before shifting matter
too: `uint8_t` promotes to `int`, so `in[3] << 24` on a byte ≥ 0x80 shifts into
the sign bit of a signed int. UBSan in CI is what keeps that honest.

## Error handling

One `mc_status` enum, returned by value, from every function. No errno, no
out-parameter written on a failure path, no exception crossing the C boundary.

The return type is `MC_NODISCARD`. Ignoring the status is the one mistake that
turns a caught attack back into a silent one, so the compiler is asked to
object.

Internally the split is: **validation belongs where the untrusted bytes are
parsed**, not scattered across every consumer. `kdf::DeriveKey` asserts nothing
about its cost parameters because `format::ParseFileHeader` has already
clamped them, individually and against the memory bound. Every layer below the
parser is entitled to assume its inputs are in range, and that assumption is
documented on each function that makes it.

## Warnings

`-Wall -Wextra -Wpedantic` plus three that are here for specific classes of bug
this code could have:

- **`-Wconversion`** — a `size_t` narrowed into the `uInt` zlib wants, or the
  `int` OpenSSL wants, is how a large chunk becomes a short one. Every such
  conversion in the tree is an explicit cast with a range check in front of it;
  this is what stops a new one from being implicit.
- **`-Wshadow`** — a `size` shadowing an outer `size` in the chunk walk would
  compile and be wrong in the quietest possible way.
- **`-Wold-style-cast`** — the C API boundary is where a `(uint8_t*)` cast is
  tempting, and naming the cast says whether `const` is being dropped.

`-Werror` is on for clang in CI and off for GCC; see
[Testing.md § CI](Testing.md#ci) for why.

## What is deliberately absent

- **No anti-debugging.** v1 had it, it was bypassable, and on Android it was
  dead code that never ran. See
  [ThreatModel.md § Anti-debugging](ThreatModel.md#anti-debugging).
- **No algorithm agility beyond the id fields.** `kdf_id` and `aead_id` exist so
  a future version can add one, but only scrypt and AES-256-GCM are defined and
  anything else is `MC_ERR_UNSUPPORTED`. A negotiable cipher suite is an attack
  surface, and there is no second algorithm anyone needs today.
- **No streaming API.** See above; it would cost truncation detection.
- **No vendored dependencies.** OpenSSL and zlib come from the platform, so a
  CVE in either is fixed by the platform's updater rather than by a release
  here.
- **No globbed sources.** `CMakeLists.txt` names all eleven files. A glob is
  evaluated at configure time, so a new source is silently left out until
  something reconfigures — and with eleven files, naming them makes an
  accidental addition visible in review.
