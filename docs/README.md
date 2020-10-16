# model-crypt documentation

Five documents. Read them in whatever order your question lands in.

| | |
|---|---|
| [Install.md](Install.md) | Requirements, macOS and Linux setup, build modes, installing, troubleshooting |
| [Usage.md](Usage.md) | The CLI and the C API, with the parameter choices explained |
| [Format.md](Format.md) | The `.mcrypt` container, normatively — enough to write an independent reader |
| [Architecture.md](Architecture.md) | How `src/` is laid out and why decryption is ordered the way it is |
| [ThreatModel.md](ThreatModel.md) | What is defended, what is not, and what you have to solve yourself |
| [Testing.md](Testing.md) | The suites, the sanitizers, CI, and why there is no model file in the repo |

## If you only read one thing

[ThreatModel.md](ThreatModel.md). model-crypt protects a model file at rest and
in transit; it cannot protect a model from the person running the process that
decrypts it. Every deployment decision follows from that sentence, and the
document is specific about the four options for the hard case.

## Common questions

**Where does the key come from?**
[Usage.md § Where keys come from](Usage.md#where-keys-come-from), then
[ThreatModel.md § A key shipped inside the binary that uses it](ThreatModel.md#a-key-shipped-inside-the-binary-that-uses-it).

**Decryption returned `MC_ERR_AUTH`. Can I get the data anyway?**
No, and that is the design. See
[Usage.md § Handling the status](Usage.md#handling-the-status).

**Can I read a `.mcrypt` file from Python / Rust / Go?**
Yes — the header is C. See [Usage.md § Linking](Usage.md#linking), or
implement the format from [Format.md](Format.md).

**How is this tested without a model file?**
[Testing.md § Testing an encryptor with no models](Testing.md#testing-an-encryptor-with-no-models).

**What was wrong with the old version?**
[ThreatModel.md § What v1 got wrong](ThreatModel.md#what-v1-got-wrong).

**Does the OpenSSL version matter?**
Not for what this library guarantees — 1.1.1 and 3.x derive identical keys —
but the support status of the one you ship does:
[ThreatModel.md § The age of the platform's OpenSSL](ThreatModel.md#the-age-of-the-platforms-openssl).
