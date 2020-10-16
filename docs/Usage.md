# Using model-crypt

Two interfaces over the same library: a CLI for build pipelines and one-off
work, and a C API for whatever loads the model.

Read [ThreatModel.md](ThreatModel.md) before deploying either. The most
important thing on this page is the part about where keys come from, and it is
not a code sample.

## The CLI

```
model-crypt keygen  --out PATH
model-crypt encrypt --in PATH --out PATH [key source] [options]
model-crypt decrypt --in PATH --out PATH [key source]
model-crypt inspect --in PATH
```

Exit codes: `0` success, `1` the operation failed (wrong key, tampered file,
I/O), `2` usage error (bad arguments, missing key source). The split matters in
a pipeline — `2` means you invoked it wrong, `1` means it worked and the answer
was no.

### A full round trip

```bash
model-crypt keygen --out model.key                       # 32 random bytes, mode 0600
model-crypt encrypt --key-file model.key --in model.onnx --out model.mcrypt
model-crypt inspect --in model.mcrypt
model-crypt decrypt --key-file model.key --in model.mcrypt --out recovered.onnx
cmp model.onnx recovered.onnx
```

`keygen` refuses to overwrite an existing file (exit `1`). Silently replacing a
key means silently orphaning every file encrypted under it.

### Key sources

```bash
--key-file PATH    read the key from a file
--key-env VAR      read the key from an environment variable
(neither)          prompt on the terminal, with echo off
```

**There is deliberately no `--key` option.** A key on the command line is
visible in `ps` output to every user on the box, and it lands in shell history,
in CI logs, and in any process-accounting audit trail. The old v1 tool took
`-k` and then printed the key to stdout for good measure. `check-cli.sh`
asserts that `--key` is still rejected.

If no key source is given and stdin is not a terminal, the CLI exits `2` rather
than reading a key from a pipe by accident.

`--key-file` strips exactly one trailing newline, so `echo secret > key` and
`printf secret > key` produce the same key. Anything else — a `\r\n`, two
newlines — is part of the key, because guessing further would mean a file that
means different things on different platforms.

### Encrypt options

| Option | Default | Range |
|---|---|---|
| `--compression none\|zlib` | `zlib` | — |
| `--chunk-size BYTES` | `4194304` (4 MiB) | 4096 – 67108864 |
| `--kdf-log-n N` | `15` | 14 – 20 |
| `--kdf-r N` | `8` | 1 – 32 |
| `--kdf-p N` | `1` | 1 – 16 |

Out-of-range or non-numeric values are usage errors (`2`), not clamped.

`decrypt` takes **no** options beyond the key. Everything needed to reverse an
encryption is recorded in the authenticated header, so a file never depends on
the reader being configured the way the writer was.

### `inspect`

Reads the header only. No key, nothing authenticated:

```
$ model-crypt inspect --in model.mcrypt
format version:  2
compression:     zlib
plaintext size:  104857600 bytes (declared, not authenticated)
chunk size:      4194304 bytes
chunk count:     25
kdf:             scrypt N=2^15 r=8 p=1
```

Useful for deciding which key to try and for sizing a progress bar. **Do not
allocate on these numbers** — an attacker who hands you a file chooses all of
them. Exit `1` if the input is not a model-crypt file.

### In a build pipeline

```bash
set -euo pipefail

: "${MODEL_KEY:?MODEL_KEY must be set}"
for model in build/models/*.onnx; do
  model-crypt encrypt --key-env MODEL_KEY \
    --in "${model}" --out "dist/$(basename "${model}" .onnx).mcrypt"
done
```

`--key-env` rather than `--key-file` here because CI secret stores hand you an
environment variable and writing it to disk first only adds a file to forget
about.

## The C API

Eleven functions, one header, no init or teardown. Nothing holds global state
or a lock, so any number of threads may encrypt and decrypt concurrently —
`threading_test.cc` and the TSan job in CI are what keep that true.

### Decrypt into memory

This is the form to use on a client device. It is the only one that never
writes plaintext to disk, which is the largest hole in a naive deployment.

```c
#include <model_crypt/model_crypt.h>
#include <stdio.h>

int load_model(const uint8_t *key, size_t key_len, const char *path) {
  uint8_t *plain = NULL;
  size_t plain_len = 0;

  mc_status rc = mc_decrypt_file_to_buffer(key, key_len, path,
                                           &plain, &plain_len);
  if (rc != MC_OK) {
    fprintf(stderr, "decrypt failed: %s\n", mc_status_string(rc));
    return -1;
  }

  int ok = runtime_load_weights(plain, plain_len);
  mc_free(plain, plain_len);   /* wipes, then frees */
  return ok;
}
```

`mc_free` rather than `free`. Passing the size is what lets it wipe with
`OPENSSL_cleanse`; a plain `free()` leaves the model readable by whatever
allocates that memory next, and captured by any core dump for the life of the
process.

### Encrypt a buffer

```c
uint8_t key[32];
if (mc_generate_key(key, sizeof(key)) != MC_OK) {
  abort();   /* the system CSPRNG failed. Do not retry, do not work around. */
}

mc_encrypt_options opts;
mc_encrypt_options_init(&opts);       /* always; then adjust */
opts.compression = MC_COMPRESS_NONE;  /* already-compressed weights */

uint8_t *ct = NULL;
size_t ct_len = 0;
mc_status rc = mc_encrypt_buffer(key, sizeof(key), &opts,
                                 model, model_len, &ct, &ct_len);
```

Call `mc_encrypt_options_init` before setting fields, every time. It is what
lets a later release add an option without every existing caller passing an
uninitialized value for it. Passing `NULL` for `opts` means "all defaults".

A fresh salt and nonce prefix are drawn per call, so encrypting the same model
twice under the same key yields unrelated ciphertext. That is a property worth
knowing about if you were planning to deduplicate by hash.

### Handling the status

```c
switch (rc) {
  case MC_OK:              break;
  case MC_ERR_AUTH:        /* wrong key, or the file was modified. */
                           /* No output was produced. Do not retry. */
  case MC_ERR_FORMAT:      /* not a model-crypt file at all */
  case MC_ERR_UNSUPPORTED: /* newer format version, or an unknown algorithm id */
  case MC_ERR_TOO_LARGE:   /* over 64 GiB, or a size field that claims to be */
  case MC_ERR_IO:          /* the file could not be read or written */
  case MC_ERR_MEMORY:
  case MC_ERR_CRYPTO:      /* an OpenSSL primitive failed; see ERR_get_error() */
  case MC_ERR_COMPRESS:    /* a bug here or a mismatched zlib; not reachable */
                           /* from a hostile file */
  case MC_ERR_INVALID_ARG: /* a NULL, a zero length, an out-of-range option */
}
```

Every function reports failure through its return value and through nothing
else — there is no errno and **no out-parameter is written on the failure
path**. The return type is `MC_NODISCARD`, because ignoring it is the one
mistake that turns a caught attack back into a silent one.

`MC_ERR_AUTH` means the file will not be decrypted. There is no
"decrypt it anyway" escape hatch, and adding one would defeat the point: a
model file that fails authentication is not a degraded model, it is an
attacker-chosen one, and handing it to an inference runtime is the outcome this
library exists to prevent.

`MC_ERR_AUTH` and `MC_ERR_FORMAT` being distinguishable is deliberate and
safe. Both mean "this will not decrypt", and which one fired reveals nothing an
attacker holding the file does not already know.

### The file forms

| Function | Plaintext touches disk? | Use for |
|---|---|---|
| `mc_encrypt_file` | input only | build pipelines |
| `mc_decrypt_file` | yes, output | server-side staging |
| `mc_decrypt_file_to_buffer` | **no** | client devices |
| `mc_encrypt_buffer` / `mc_decrypt_buffer` | no | you already hold the bytes |

`mc_encrypt_file` and `mc_decrypt_file` write through a temporary file in the
destination directory and rename it into place, so a crash or a full disk
leaves the previous file intact rather than a half-written one that looks like
a corrupt model. `mc_decrypt_file` creates its output mode `0600`, and writes
it only after the whole input authenticates — a failed decryption never leaves
attacker-chosen bytes on disk under the name of a model.

## Linking

The header is C, so C, Objective-C, Rust, Go, and Python `ctypes` all consume
it without a wrapper. The implementation behind it is C++17, which has one
consequence for the **static** case:

```bash
# shared: the library records its own dependencies
cc consumer.c -lmodel_crypt -o consumer

# static: you name them, including the C++ runtime
cc consumer.c -lmodel_crypt -lz -lcrypto -lstdc++ -o consumer   # Linux
cc consumer.c -lmodel_crypt -lz -lcrypto -lc++    -o consumer   # macOS
```

Linking with the C++ driver (`c++`, `clang++`) instead of `cc` does the same
thing. This is not an oversight in the install rules — a static archive records
no dependencies, so whoever links it has to name them.
`scripts/check-install.sh` builds both cases in CI, which is what keeps this
paragraph true.

## Choosing parameters

The defaults are right for the common case: a model of tens to thousands of
megabytes, decrypted once at startup, with a key that came from
`mc_generate_key`.

**`--chunk-size`** trades 24 bytes of framing per chunk against how much has to
be held in memory at once. At the 4 MiB default the overhead is about six parts
per million. Lower it if the process is memory-constrained; there is no reason
to raise it.

**`--compression none`** if the weights are already compressed — quantized
`int8`, or anything that has been through a container that deflates. deflate on
incompressible data costs CPU on both ends and the encryptor will fall back to
storing raw anyway, so `none` just skips the attempt. `RoundTrip,
IncompressibleInputDoesNotExpand` is the test that the fallback works.

**`--kdf-log-n`** is the only knob with a security meaning. Raise it if the key
is a human-chosen passphrase and your threat model includes offline guessing;
every increment doubles both time and memory, for you and for the attacker
equally. Leave it alone if the key is 32 random bytes, because at that point
guessing is not the attack anyone would attempt.

## Where keys come from

The library cannot answer this and it is the question that decides whether any
of the above matters.

- **Build pipeline / server-side.** A secret manager, injected as an
  environment variable. `--key-env`. Solved.
- **Client device.** Not solved by anything on this page. See
  [ThreatModel.md § A key shipped inside the binary that uses it](ThreatModel.md#a-key-shipped-inside-the-binary-that-uses-it),
  which lays out the four options and is honest about what each one buys.

The one thing not to do is what the v1 demos did:

```c
const char *key = "!@#$%^&*()";   /* recoverable with `strings` in seconds */
```
