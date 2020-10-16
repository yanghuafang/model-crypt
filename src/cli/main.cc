/// \file main.cc
/// The `model-crypt` command-line tool.
///
/// Four subcommands: `keygen`, `encrypt`, `decrypt`, `inspect`. The library
/// does the work; this file is argument parsing, key sourcing, and diagnostics.
///
/// There is no `--key SECRET` option: a command line is visible to every user
/// through `ps` and is recorded in shell history and CI logs. A key comes from
/// exactly one of:
///
///   --key-file PATH   the file's bytes, with one trailing newline stripped
///   --key-env VAR     the value of an environment variable
///   (neither)         a prompt on the terminal, with echo disabled
///
/// The newline strip is not cosmetic: `printf 'hunter2' > key` and
/// `echo hunter2 > key` otherwise derive different AES keys.
///
/// Nothing printed here includes the key, the derived key, a salt, or any
/// plaintext; `inspect` shows only header fields the format publishes anyway.

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "model_crypt/model_crypt.h"
#include "util/version.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 2;
constexpr int kExitFailure = 1;

// Largest key file the tool will read. A key is at most a passphrase or 32
// random bytes; anything in the megabytes is a mistake -- most likely the model
// passed to --key-file -- and saying so beats deriving a key from it.
constexpr size_t kMaxKeyFileSize = 4096;

void PrintUsage(std::FILE* stream) {
  std::fprintf(
      stream,
      "model-crypt %s — encrypt and decrypt deep learning model files\n"
      "\n"
      "Usage:\n"
      "  model-crypt keygen  --out PATH\n"
      "  model-crypt encrypt --in PATH --out PATH [key source] [options]\n"
      "  model-crypt decrypt --in PATH --out PATH [key source]\n"
      "  model-crypt inspect --in PATH\n"
      "\n"
      "Key source (encrypt and decrypt; prompts on the terminal if omitted):\n"
      "  --key-file PATH    Read the key from a file. One trailing newline is\n"
      "                     stripped, so `echo secret > key` and\n"
      "                     `printf secret > key` are equivalent.\n"
      "  --key-env VAR      Read the key from an environment variable.\n"
      "\n"
      "  There is deliberately no --key option: a key on the command line is\n"
      "  visible in `ps` output and recorded in shell history and CI logs.\n"
      "\n"
      "Encrypt options:\n"
      "  --compression none|zlib   Default zlib.\n"
      "  --chunk-size BYTES        Default %u; range %u to %u.\n"
      "  --kdf-log-n N             scrypt cost log2(N). Default %u; range %u"
      " to %u.\n"
      "  --kdf-r N                 scrypt block size. Default %u.\n"
      "  --kdf-p N                 scrypt parallelism. Default %u.\n"
      "\n"
      "Other:\n"
      "  -h, --help                Show this help.\n"
      "  --version                 Print the version and exit.\n",
      mc_version_string(), 4u << 20, 4u << 10, 64u << 20, 15u, 14u, 20u, 8u,
      1u);
}

// Wipe `n` bytes at `p`.
//
// A volatile-pointer loop rather than a call into OpenSSL: the CLI links the
// library, not OpenSSL directly, so OPENSSL_cleanse is not on its link line.
// The volatile qualifier is what keeps the compiler from eliding a write to
// storage that is dead immediately afterwards -- which it is entitled to do,
// and does.
//
// A free function rather than a member of KeyBytes because the stack buffers
// that key material passes through on its way *into* a KeyBytes need it too,
// and those live in the reader functions below.
void SecureZero(unsigned char* p, size_t n) {
  volatile unsigned char* v = p;
  while (n-- > 0) {
    *v++ = 0;
  }
}

// A key held for as long as the process needs it, wiped when it goes.
//
// std::vector deliberately, not the library's SecureBuffer: SecureBuffer is an
// internal header the installed library does not export, and the CLI is
// compiled against the same tree only as a convenience. The wipe is explicit in
// the destructor, and the vector is reserved once so no growth reallocation
// scatters a copy -- the same reason SecureBuffer exists, applied by hand.
class KeyBytes {
 public:
  KeyBytes() { bytes_.reserve(kMaxKeyFileSize); }

  ~KeyBytes() {
    if (!bytes_.empty()) {
      SecureZero(bytes_.data(), bytes_.size());
    }
  }

  KeyBytes(const KeyBytes&) = delete;
  KeyBytes& operator=(const KeyBytes&) = delete;

  std::vector<unsigned char>& Bytes() { return bytes_; }
  [[nodiscard]] const unsigned char* data() const { return bytes_.data(); }
  [[nodiscard]] size_t size() const { return bytes_.size(); }

 private:
  std::vector<unsigned char> bytes_;
};

// Strip one trailing newline, and a "\r" before it. Exactly one: a key that
// genuinely ends in two newlines is possible, and eating all of them would make
// the tool unable to express it. See the file comment.
void StripOneTrailingNewline(std::vector<unsigned char>* bytes) {
  if (!bytes->empty() && bytes->back() == '\n') {
    bytes->pop_back();
    if (!bytes->empty() && bytes->back() == '\r') {
      bytes->pop_back();
    }
  }
}

bool ReadKeyFile(const std::string& path, KeyBytes* key) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    std::fprintf(stderr, "model-crypt: cannot open key file %s: %s\n",
                 path.c_str(), std::strerror(errno));
    return false;
  }

  unsigned char buffer[kMaxKeyFileSize + 1];
  const size_t read = std::fread(buffer, 1, sizeof(buffer), file);
  const bool too_large = read > kMaxKeyFileSize;
  std::fclose(file);

  if (too_large) {
    std::fprintf(stderr,
                 "model-crypt: key file %s is larger than %zu bytes; is that "
                 "the model rather than the key?\n",
                 path.c_str(), kMaxKeyFileSize);
    return false;
  }

  key->Bytes().assign(buffer, buffer + read);
  SecureZero(buffer, sizeof(buffer));
  StripOneTrailingNewline(&key->Bytes());
  return true;
}

bool ReadKeyEnv(const std::string& name, KeyBytes* key) {
  const char* value = std::getenv(name.c_str());
  if (value == nullptr) {
    std::fprintf(stderr, "model-crypt: environment variable %s is not set\n",
                 name.c_str());
    return false;
  }

  const size_t length = std::strlen(value);
  if (length > kMaxKeyFileSize) {
    std::fprintf(stderr, "model-crypt: %s holds more than %zu bytes\n",
                 name.c_str(), kMaxKeyFileSize);
    return false;
  }

  key->Bytes().assign(value, value + length);
  return true;
}

// Prompt with echo off, restoring the terminal on every path out -- including
// the error paths, which is why the original termios is captured before
// anything is changed. A tool that leaves a terminal with echo disabled after
// a failed run is a tool nobody uses twice.
bool ReadKeyPrompt(KeyBytes* key) {
  if (::isatty(STDIN_FILENO) == 0) {
    std::fprintf(stderr,
                 "model-crypt: no key source given and stdin is not a "
                 "terminal; use --key-file or --key-env\n");
    return false;
  }

  termios original = {};
  if (::tcgetattr(STDIN_FILENO, &original) != 0) {
    std::fprintf(stderr, "model-crypt: cannot read terminal settings\n");
    return false;
  }

  termios quiet = original;
  quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
  if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) != 0) {
    std::fprintf(stderr, "model-crypt: cannot disable terminal echo\n");
    return false;
  }

  std::fprintf(stderr, "Key: ");
  std::fflush(stderr);

  unsigned char buffer[kMaxKeyFileSize + 1];
  char* line =
      std::fgets(reinterpret_cast<char*>(buffer), sizeof(buffer), stdin);

  ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
  std::fprintf(stderr, "\n");

  if (line == nullptr) {
    std::fprintf(stderr, "model-crypt: no key read\n");
    return false;
  }

  const size_t length = std::strlen(reinterpret_cast<char*>(buffer));

  // fgets stops at a newline or at size-1 bytes, whichever comes first, and
  // does not say which happened. A full buffer with no newline therefore means
  // the line was longer than the buffer -- and accepting it would silently
  // derive a key from a prefix of what was typed, with no indication that
  // anything was dropped. That is the same failure the trailing-newline strip
  // exists to prevent, in a form the user cannot see at all.
  if (length == sizeof(buffer) - 1 && buffer[length - 1] != '\n') {
    SecureZero(buffer, sizeof(buffer));
    std::fprintf(stderr, "model-crypt: key is longer than %zu bytes\n",
                 kMaxKeyFileSize);
    return false;
  }

  key->Bytes().assign(buffer, buffer + length);
  SecureZero(buffer, sizeof(buffer));
  StripOneTrailingNewline(&key->Bytes());
  return true;
}

// Parsed command line. Everything is a string until the subcommand that needs
// it converts it, so an unknown option is reported before any conversion can
// fail confusingly.
struct Args {
  std::string command;
  std::string in;
  std::string out;
  std::string key_file;
  std::string key_env;
  std::string compression;
  std::string chunk_size;
  std::string kdf_log_n;
  std::string kdf_r;
  std::string kdf_p;
  bool help = false;
  bool version = false;
};

bool TakeValue(int argc, char** argv, int* i, const char* name,
               std::string* out) {
  if (*i + 1 >= argc) {
    std::fprintf(stderr, "model-crypt: %s requires a value\n", name);
    return false;
  }

  *out = argv[++(*i)];
  return true;
}

bool ParseArgs(int argc, char** argv, Args* args) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];

    if (arg == "-h" || arg == "--help") {
      args->help = true;
    } else if (arg == "--version") {
      args->version = true;
    } else if (arg == "--in") {
      if (!TakeValue(argc, argv, &i, "--in", &args->in)) return false;
    } else if (arg == "--out") {
      if (!TakeValue(argc, argv, &i, "--out", &args->out)) return false;
    } else if (arg == "--key-file") {
      if (!TakeValue(argc, argv, &i, "--key-file", &args->key_file))
        return false;
    } else if (arg == "--key-env") {
      if (!TakeValue(argc, argv, &i, "--key-env", &args->key_env)) return false;
    } else if (arg == "--compression") {
      if (!TakeValue(argc, argv, &i, "--compression", &args->compression))
        return false;
    } else if (arg == "--chunk-size") {
      if (!TakeValue(argc, argv, &i, "--chunk-size", &args->chunk_size))
        return false;
    } else if (arg == "--kdf-log-n") {
      if (!TakeValue(argc, argv, &i, "--kdf-log-n", &args->kdf_log_n))
        return false;
    } else if (arg == "--kdf-r") {
      if (!TakeValue(argc, argv, &i, "--kdf-r", &args->kdf_r)) return false;
    } else if (arg == "--kdf-p") {
      if (!TakeValue(argc, argv, &i, "--kdf-p", &args->kdf_p)) return false;
    } else if (arg == "--key") {
      // Named explicitly so the answer is the reason rather than "unknown
      // option", which reads like an oversight to fix in the next release.
      std::fprintf(stderr,
                   "model-crypt: --key is not supported. A key on the command "
                   "line is visible in `ps` and in shell history; use "
                   "--key-file or --key-env.\n");
      return false;
    } else if (!arg.empty() && arg[0] == '-') {
      std::fprintf(stderr, "model-crypt: unknown option %s\n", arg.c_str());
      return false;
    } else if (args->command.empty()) {
      args->command = arg;
    } else {
      std::fprintf(stderr, "model-crypt: unexpected argument %s\n",
                   arg.c_str());
      return false;
    }
  }

  return true;
}

// strtoull with the checks that make it usable: a value that consumed the whole
// string, is in range, and did not come from an empty or sign-prefixed input.
// The bare call returns 0 for "abc" and for "0" alike.
bool ParseU32(const std::string& text, const char* name, uint32_t min,
              uint32_t max, uint32_t* out) {
  if (text.empty() || text[0] == '-' || text[0] == '+') {
    std::fprintf(stderr, "model-crypt: %s: expected a number, got '%s'\n", name,
                 text.c_str());
    return false;
  }

  errno = 0;
  char* end = nullptr;
  const auto value = std::strtoull(text.c_str(), &end, 10);
  if (errno != 0 || end == nullptr || *end != '\0') {
    std::fprintf(stderr, "model-crypt: %s: expected a number, got '%s'\n", name,
                 text.c_str());
    return false;
  }

  if (value < min || value > max) {
    std::fprintf(stderr,
                 "model-crypt: %s must be between %u and %u, got %llu\n", name,
                 min, max, value);
    return false;
  }

  *out = static_cast<uint32_t>(value);
  return true;
}

bool LoadKey(const Args& args, KeyBytes* key) {
  if (!args.key_file.empty() && !args.key_env.empty()) {
    std::fprintf(stderr,
                 "model-crypt: give at most one of --key-file and --key-env\n");
    return false;
  }

  if (!args.key_file.empty()) {
    if (!ReadKeyFile(args.key_file, key)) {
      return false;
    }
  } else if (!args.key_env.empty()) {
    if (!ReadKeyEnv(args.key_env, key)) {
      return false;
    }
  } else if (!ReadKeyPrompt(key)) {
    return false;
  }

  if (key->size() < MC_MIN_KEY_SIZE) {
    std::fprintf(stderr,
                 "model-crypt: key is %zu bytes; at least %u are required. "
                 "Generate one with `model-crypt keygen --out key.bin`.\n",
                 key->size(), MC_MIN_KEY_SIZE);
    return false;
  }

  return true;
}

bool RequirePaths(const Args& args, bool need_out) {
  if (args.in.empty()) {
    std::fprintf(stderr, "model-crypt: --in is required\n");
    return false;
  }

  if (need_out && args.out.empty()) {
    std::fprintf(stderr, "model-crypt: --out is required\n");
    return false;
  }

  return true;
}

int RunKeygen(const Args& args) {
  if (args.out.empty()) {
    std::fprintf(stderr, "model-crypt: --out is required\n");
    return kExitUsage;
  }

  // 32 bytes: a full AES-256 key's worth of entropy, so scrypt has nothing to
  // stretch and an offline guessing attack has nothing to guess.
  unsigned char raw[32];
  const mc_status rc = mc_generate_key(raw, sizeof(raw));
  if (rc != MC_OK) {
    std::fprintf(stderr, "model-crypt: keygen failed: %s\n",
                 mc_status_string(rc));
    return kExitFailure;
  }

  // Written through the C library rather than the library's atomic writer,
  // which is internal. O_EXCL so an existing key is never silently replaced:
  // overwriting a key file makes every model encrypted under it unreadable, and
  // that is not a mistake a tool should let a stray `--out` make.
  const int fd = ::open(args.out.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    std::fprintf(stderr, "model-crypt: cannot create %s: %s\n",
                 args.out.c_str(), std::strerror(errno));
    return kExitFailure;
  }

  const ssize_t written = ::write(fd, raw, sizeof(raw));
  const bool ok = written == static_cast<ssize_t>(sizeof(raw));
  ::close(fd);

  volatile unsigned char* wipe = raw;
  for (size_t i = 0; i < sizeof(raw); ++i) {
    wipe[i] = 0;
  }

  if (!ok) {
    std::fprintf(stderr, "model-crypt: failed to write %s\n", args.out.c_str());
    return kExitFailure;
  }

  std::printf("wrote a 32-byte key to %s (mode 0600)\n", args.out.c_str());
  return kExitOk;
}

int RunEncrypt(const Args& args) {
  if (!RequirePaths(args, true)) {
    return kExitUsage;
  }

  mc_encrypt_options opts;
  mc_encrypt_options_init(&opts);

  if (!args.compression.empty()) {
    if (args.compression == "none") {
      opts.compression = MC_COMPRESS_NONE;
    } else if (args.compression == "zlib") {
      opts.compression = MC_COMPRESS_ZLIB;
    } else {
      std::fprintf(stderr,
                   "model-crypt: --compression must be 'none' or 'zlib'\n");
      return kExitUsage;
    }
  }

  if (!args.chunk_size.empty() &&
      !ParseU32(args.chunk_size, "--chunk-size", 4u << 10, 64u << 20,
                &opts.chunk_size)) {
    return kExitUsage;
  }

  if (!args.kdf_log_n.empty()) {
    uint32_t log_n = 0;
    if (!ParseU32(args.kdf_log_n, "--kdf-log-n", 14, 20, &log_n)) {
      return kExitUsage;
    }
    opts.kdf_log_n = static_cast<uint8_t>(log_n);
  }

  if (!args.kdf_r.empty() &&
      !ParseU32(args.kdf_r, "--kdf-r", 1, 32, &opts.kdf_r)) {
    return kExitUsage;
  }

  if (!args.kdf_p.empty() &&
      !ParseU32(args.kdf_p, "--kdf-p", 1, 16, &opts.kdf_p)) {
    return kExitUsage;
  }

  KeyBytes key;
  if (!LoadKey(args, &key)) {
    return kExitUsage;
  }

  const mc_status rc = mc_encrypt_file(key.data(), key.size(), &opts,
                                       args.in.c_str(), args.out.c_str());
  if (rc != MC_OK) {
    std::fprintf(stderr, "model-crypt: encrypt failed: %s\n",
                 mc_status_string(rc));
    return kExitFailure;
  }

  std::printf("encrypted %s -> %s\n", args.in.c_str(), args.out.c_str());
  return kExitOk;
}

int RunDecrypt(const Args& args) {
  if (!RequirePaths(args, true)) {
    return kExitUsage;
  }

  KeyBytes key;
  if (!LoadKey(args, &key)) {
    return kExitUsage;
  }

  const mc_status rc = mc_decrypt_file(key.data(), key.size(), args.in.c_str(),
                                       args.out.c_str());
  if (rc != MC_OK) {
    std::fprintf(stderr, "model-crypt: decrypt failed: %s\n",
                 mc_status_string(rc));
    return kExitFailure;
  }

  std::printf("decrypted %s -> %s (mode 0600)\n", args.in.c_str(),
              args.out.c_str());
  return kExitOk;
}

int RunInspect(const Args& args) {
  if (!RequirePaths(args, false)) {
    return kExitUsage;
  }

  // Only the header is read, so this stops at MC_HEADER_SIZE rather than
  // pulling a multi-gigabyte file into memory to print nine numbers.
  std::FILE* file = std::fopen(args.in.c_str(), "rb");
  if (file == nullptr) {
    std::fprintf(stderr, "model-crypt: cannot open %s: %s\n", args.in.c_str(),
                 std::strerror(errno));
    return kExitFailure;
  }

  unsigned char header[MC_HEADER_SIZE];
  const size_t read = std::fread(header, 1, sizeof(header), file);
  std::fclose(file);

  mc_file_info info = {};
  const mc_status rc = mc_inspect_buffer(header, read, &info);
  if (rc != MC_OK) {
    std::fprintf(stderr, "model-crypt: inspect failed: %s\n",
                 mc_status_string(rc));
    return kExitFailure;
  }

  // No salt, no nonce prefix, no tag. They are not secret, but printing them
  // invites a reader to treat this output as the file's identity, and the only
  // honest identity check is a successful decryption.
  std::printf("format version:  %u\n", info.format_version);
  std::printf("compression:     %s\n",
              info.compression == MC_COMPRESS_ZLIB ? "zlib" : "none");
  std::printf("plaintext size:  %llu bytes (declared, not authenticated)\n",
              static_cast<unsigned long long>(info.plaintext_size));
  std::printf("chunk size:      %u bytes\n", info.chunk_size);
  std::printf("chunk count:     %u\n", info.chunk_count);
  std::printf("kdf:             scrypt N=2^%u r=%u p=%u\n", info.kdf_log_n,
              info.kdf_r, info.kdf_p);
  return kExitOk;
}

// The body of main, wrapped below.
//
// Split out so main itself is noexcept in practice: std::string is used
// throughout for paths and option values, so an allocation failure here would
// otherwise propagate out of main, where the standard says the stack is not
// unwound and the result is a std::terminate with no message. A CLI that dies
// silently on a full memory is a CLI whose exit code means nothing.
int Run(int argc, char** argv) {
  Args args;
  if (!ParseArgs(argc, argv, &args)) {
    return kExitUsage;
  }

  if (args.version) {
    std::printf("model-crypt %s\n", mc_version_string());
    return kExitOk;
  }

  if (args.help || args.command.empty()) {
    PrintUsage(args.help ? stdout : stderr);
    return args.help ? kExitOk : kExitUsage;
  }

  if (args.command == "keygen") {
    return RunKeygen(args);
  }

  if (args.command == "encrypt") {
    return RunEncrypt(args);
  }

  if (args.command == "decrypt") {
    return RunDecrypt(args);
  }

  if (args.command == "inspect") {
    return RunInspect(args);
  }

  std::fprintf(stderr, "model-crypt: unknown command '%s'\n",
               args.command.c_str());
  PrintUsage(stderr);
  return kExitUsage;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return Run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "model-crypt: %s\n", error.what());
    return kExitFailure;
  } catch (...) {
    std::fprintf(stderr, "model-crypt: unknown error\n");
    return kExitFailure;
  }
}
