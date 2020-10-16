# The `.mcrypt` container format

This is the normative description of the file format, version **2**. It is
enough to write an independent reader or writer. The same layout expressed as
code lives in [`src/crypt/format.h`](../src/crypt/format.h) and
[`src/crypt/format.cc`](../src/crypt/format.cc); if the two ever disagree,
the code is what ships and this file is the bug.

## Shape

```
+--------------------------------+
| file header            64 B    |   magic, algorithm ids, KDF params,
|                                |   salt, nonce prefix, sizes
+--------------------------------+
| chunk 0 record         24 B    |   stored_size, flags, GCM tag
| chunk 0 ciphertext     N₀ B    |
+--------------------------------+
| chunk 1 record         24 B    |
| chunk 1 ciphertext     N₁ B    |
+--------------------------------+
| ...                            |
+--------------------------------+
| chunk C-1 record       24 B    |
| chunk C-1 ciphertext   N B     |
+--------------------------------+
```

There is no trailer and no index. `chunk_count` in the header says how many
chunk records follow, and each record's `stored_size` says how far to the next
one. Both are authenticated, so neither can be used to steer a reader.

Every integer is **little-endian**, unconditionally, on every host. The
serializer writes the bytes with explicit shifts rather than memcpy-ing a
packed struct, so the format's byte order is a property of the code and not of
the machine that ran it. `Format, HeaderIsLittleEndianRegardlessOfHost` is the
test that holds this.

## File header, 64 bytes

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0  | 8  | `magic` | ASCII `MCRYPT02`, no terminator |
| 8  | 2  | `format_version` | 2. Any other value is `MC_ERR_UNSUPPORTED` |
| 10 | 1  | `kdf_id` | 1 = scrypt. Only value defined |
| 11 | 1  | `aead_id` | 1 = AES-256-GCM. Only value defined |
| 12 | 1  | `compression_id` | 0 = none, 1 = zlib. The encryptor's *intent*; each chunk records what it actually did |
| 13 | 1  | `kdf_log_n` | scrypt cost, log2(N). 14–20 |
| 14 | 4  | `kdf_r` | scrypt block size. 1–32 |
| 18 | 4  | `kdf_p` | scrypt parallelism. 1–16 |
| 22 | 16 | `salt` | Random per file. scrypt salt |
| 38 | 8  | `nonce_prefix` | Random per file. High 8 bytes of every chunk nonce |
| 46 | 4  | `chunk_size` | Plaintext bytes per chunk. 4096 – 67108864 |
| 50 | 8  | `plaintext_size` | Total plaintext length. ≤ 64 GiB |
| 58 | 4  | `chunk_count` | Number of chunk records following |
| 62 | 2  | `reserved` | Must be zero |

The magic is version-tagged (`02`, not a bare `MCRYPT`) so that a v1 file and a
future v3 are both rejected at the first eight-byte comparison, before any
field is interpreted.

`reserved` must be zero and is *checked*. A reader that ignored it would let a
future version smuggle meaning past it — and since the whole header is
authenticated, a writer cannot set it without invalidating every tag anyway.

### What the header parser enforces

Structural validation only. No key is involved and nothing is authenticated
yet, because reading the header is what tells you which key to try.

- `magic` matches exactly → else `MC_ERR_FORMAT`
- `format_version` == 2 → else `MC_ERR_UNSUPPORTED`
- `kdf_id`, `aead_id`, `compression_id` are known → else `MC_ERR_UNSUPPORTED`
- every KDF parameter is inside its range → else `MC_ERR_UNSUPPORTED`
- `128 * 2^kdf_log_n * kdf_r ≤ 1 GiB` → else `MC_ERR_UNSUPPORTED`
- `chunk_size` is inside its range → else `MC_ERR_FORMAT`
- `plaintext_size ≤ MC_MAX_PLAINTEXT_SIZE` → else `MC_ERR_TOO_LARGE`
- `chunk_count == ceil(plaintext_size / chunk_size)`, or 1 when
  `plaintext_size` is 0 → else `MC_ERR_FORMAT`
- `reserved == 0` → else `MC_ERR_FORMAT`

The scrypt memory bound deserves the separate line it gets. `kdf_log_n` and
`kdf_r` are each range-checked, but it is their *product* that allocates:
`log_n = 20` with `r = 32` asks for 4 GiB from a header that costs nothing to
write. Without this check, a 64-byte file would be an out-of-memory kill.

Passing all of the above establishes only that the numbers are self-consistent
and bounded, so the rest of the pipeline can do arithmetic on them without
overflowing. It says nothing about the file being genuine.

## Chunk record, 24 bytes

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0  | 4  | `stored_size` | Ciphertext bytes following this record |
| 4  | 1  | `flags` | Bit 0: payload is a zlib stream. No other bit may be set |
| 5  | 3  | `reserved` | Must be zero |
| 8  | 16 | `tag` | AES-256-GCM tag over the ciphertext and the AAD below |

`stored_size` is rejected above `chunk_size + chunk_size/1000 + 64` — deflate's
documented worst case plus headroom. The encryptor never actually emits an
expanded chunk (it stores raw instead when deflate does not help), so this
bound exists purely to give the decoder a number to reject above.

A chunk holds `chunk_size` plaintext bytes, except the last, which holds the
remainder. An empty plaintext still gets **one** empty chunk — see
[Why one chunk minimum](#why-one-chunk-minimum).

## Keys, nonces, and associated data

### Key derivation

```
key = scrypt(passphrase, salt, N = 2^kdf_log_n, r = kdf_r, p = kdf_p, dkLen = 32)
```

One 256-bit AES key per file. The salt is 16 fresh random bytes per
encryption, so the same passphrase over the same model twice produces two
unrelated keys, and a table precomputed against one file is worthless against
the next.

### Nonce

```
nonce[0..8)  = nonce_prefix          (random, per file)
nonce[8..12) = chunk_index           (big-endian uint32)
```

96 bits, GCM's native size — the only length that skips GCM's internal GHASH
derivation step. Composing it as prefix‖counter makes uniqueness within a file
structural rather than probabilistic: nothing has to hope that 96 random bits
never collide. Across files the per-file salt means two chunks with the same
nonce are not even under the same key.

This matters more than any other rule in the format. GCM does not degrade
under nonce reuse, it collapses: two messages under one nonce leak their XOR
and allow the authentication key itself to be recovered, after which forgeries
are free.

### Associated data

Each chunk is sealed over 73 bytes of AAD:

```
AAD = header[0..64)          the 64 header bytes exactly as they appear on disk
    ‖ chunk_index            little-endian uint32
    ‖ stored_size            little-endian uint32
    ‖ flags                  uint8
```

Little-endian here, like every other integer in the format. The nonce counter
above is the one big-endian value in the file, and only because NIST SP 800-38D
writes a GCM counter block that way — matching the spec's convention means a
reader checking this against the standard is not also decoding a byte-order
surprise.

The header bytes are the **bytes as written**, not a re-serialization of the
parsed struct. Re-serializing would launder anything the parser did not look
at: a reserved byte an attacker set would vanish from the AAD, and the tag
would verify over a header that is not the one on disk.
`Format, AadCoversHeaderBytesAsWritten` pins this.

### Seal and open

```
seal:  ct, tag = AES-256-GCM-Encrypt(key, nonce, aad, pt)
open:  pt      = AES-256-GCM-Decrypt(key, nonce, aad, ct, tag)   or failure
```

`open` returning failure is reported as `MC_ERR_AUTH` and produces no output.
There is no path through the library that returns plaintext from a chunk whose
tag did not verify.

## What the AAD buys

A per-chunk seal on its own is not enough. Each of these attacks leaves every
individual GCM tag verifying, and each is defeated by a specific AAD
component:

| Attack | Caught by |
|--------|-----------|
| Reorder two chunks | `chunk_index` — the tag is bound to the position |
| Duplicate a chunk | `chunk_index`, for the same reason. The index is the chunk's *position*, never a value stored in the record where a copy would carry it along |
| Truncate the tail | `chunk_count` and `plaintext_size`, both inside the header the AAD covers |
| Append extra bytes | `chunk_count`: the reader stops where the header says, and any trailing byte is a mismatch against the file size |
| Splice a chunk in from another file under the same passphrase | Twice over: the other file has a different `salt` in its header *and* therefore a different derived key |
| Edit any header field — including `plaintext_size`, `chunk_size`, the KDF cost | The header is the first 64 bytes of every chunk's AAD |
| Flip one bit anywhere | The tag over that chunk |

Each row is a test in [`tests/tamper_test.cc`](../tests/tamper_test.cc), and
`Tamper, BitFlipAnywhereFails` covers the whole class exhaustively over the
metadata bytes without anyone having to think of the case first.

## Why one chunk minimum

`ChunkCountFor(0, chunk_size)` returns 1, not 0. A zero-chunk file has no tags
in it, so nothing authenticates the header — and anyone could write a valid
"empty model" under any key. One empty chunk gives the header a tag that
covers it. `Format, ChunkCountIsNeverZero` holds the line.

## Compression

Compression happens **before** encryption, and it has to: ciphertext is
indistinguishable from random and does not compress, so the reverse order
would accomplish nothing.

It is decided per chunk. The encryptor deflates the chunk, compares, and keeps
whichever of the two is smaller — setting the `flags` bit when it kept the
deflated form. That is why `compression_id` in the header is the encryptor's
intent rather than a fact about the payload: a model with a compressible
header and incompressible quantized tensors produces a file with both kinds of
chunk in it, and `RoundTrip, IncompressibleInputDoesNotExpand` asserts the
fallback works.

The decompressed size is not stored per chunk. It does not need to be: it is
`chunk_size` for every chunk but the last, and `plaintext_size % chunk_size`
for the last — both authenticated. Decompression is given that exact bound and
refuses to overrun it, so a zlib stream that inflates to more than its chunk
should hold is `MC_ERR_COMPRESS` rather than a heap overflow.

## Reading a file, in order

The order below is the security-relevant part of the design, not just an
implementation note.

1. Read 64 bytes. Parse and range-check the header. Walk the chunk table,
   confirming each record and its ciphertext are present and that the walk ends
   exactly at the end of the input. **Nothing here is allocated on a size the
   header claims** — a table of `chunk_count` records is allocated only after
   the input has been shown to be large enough to hold that many, so its size
   is bounded by the file rather than by the file's assertions.
2. Derive the key with the header's scrypt parameters (already bounded in
   step 1).
3. For each chunk index `0 .. chunk_count-1`:
   1. Read 24 bytes. Range-check `stored_size` and `flags`.
   2. Confirm `stored_size` bytes are actually present in the file.
   3. Build the AAD and the nonce for this index.
   4. **Open the chunk.** On failure, stop and report `MC_ERR_AUTH`.
   5. Only now, with authenticated bytes in hand, inflate if the flag is set.
4. Confirm the total recovered length equals `plaintext_size`.

Step 3.5 coming after 3.4 is the whole point. zlib is being handed
attacker-supplied bytes in every naive design; here it is only ever handed
bytes that were sealed by someone holding the key. The v1 format got this
backwards, and a malformed file reached the Huffman decoder and segfaulted.

## Writing a file

1. Draw a 16-byte salt and an 8-byte nonce prefix from the CSPRNG.
2. Derive the key.
3. Fill and serialize the header, including the final `plaintext_size` and
   `chunk_count`. Both must be known up front, because both are in the AAD of
   the very first chunk.
4. For each chunk: compress if it helps, build AAD and nonce, seal, write the
   record and the ciphertext.

Step 3 is why encryption is not a streaming operation over an unknown-length
input. It could be made one by moving the sizes out of the AAD, but they are
in the AAD precisely so that truncation is detectable, and that trade is not
worth reversing.

## Overhead

`64 + 24 * ceil(plaintext_size / chunk_size)` bytes, before compression.

At the default 4 MiB chunk that is 64 bytes plus 24 per 4 MiB — about six
parts per million. A 1 GiB model gains roughly 6 KB of framing, and normally
loses considerably more than that to deflate.

## Version history

| Version | Magic | Status |
|---------|-------|--------|
| 1 | `MLM` (3 bytes) | The Blowfish/`private_encrypt` format. Not readable by this library and not supported; see [ThreatModel.md § What v1 got wrong](ThreatModel.md#what-v1-got-wrong) |
| 2 | `MCRYPT02` | Current |

A version bump is a deliberate act with a checklist attached: see
[`scripts/make-vector.sh`](../scripts/make-vector.sh) and
[Testing.md § The committed vector](Testing.md#the-committed-vector).
