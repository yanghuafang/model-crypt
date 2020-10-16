#ifndef MODEL_CRYPT_TESTS_CHECK_H_
#define MODEL_CRYPT_TESTS_CHECK_H_

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

/// A test harness in one header, with no third-party dependency.
///
/// Not GoogleTest: the library depends only on OpenSSL and zlib, both of which
/// every target platform ships, and a test framework would add either a system
/// package or a FetchContent download to the test build. What is needed here is
/// "assert this, name the test, report which failed".
///
/// == What it does provide ==
///
/// Registration by static initializer, so a new test is a TEST() block and
/// nothing else; per-suite selection, so CTest can register each suite as its
/// own test and report them separately; and a failure message that names the
/// file, the line, and the expression. CHECK_* keeps going after a failure so
/// one run reports every problem; REQUIRE_* stops the test, for the cases where
/// continuing would just crash on a null.

namespace testing {

/// One registered test: its suite, its name, and the function to run.
struct TestCase {
  const char* suite = nullptr;
  const char* name = nullptr;
  void (*fn)(struct Context&) = nullptr;
};

/// Per-test state. `failed` is what CHECK_* sets and the runner reads.
struct Context {
  const char* suite = "";
  const char* name = "";
  int failures = 0;
};

/// The registry: fixed storage, filled by static initializers.
///
/// == Why not std::vector ==
///
/// A vector would allocate during static initialization, where a throw is
/// std::terminate with no diagnostic and no indication of which test was being
/// registered. clang-tidy's bugprone-throwing-static-initialization flags it.
///
/// Fixed storage cannot throw and cannot reallocate. It also needs no
/// function-local-static dance to dodge the static initialization order problem
/// that a namespace-scope vector would have: zero-initialized storage is ready
/// before any dynamic initializer runs, by definition.
///
/// The cost is a capacity to maintain. Exceeding it is reported by run() rather
/// than silently dropping tests, because a suite that quietly stopped running
/// some of its cases is worse than one that fails.
inline constexpr size_t kMaxTests = 256;

inline TestCase g_tests[kMaxTests];
inline size_t g_test_count = 0;
inline size_t g_overflow_count = 0;

/// Registers one test at static initialization time.
///
/// noexcept is load-bearing: bugprone-throwing-static-initialization reasons
/// from the declared exception specification, not the body, so a constructor
/// that merely happens not to throw still reports on every TEST().
struct Registrar {
  Registrar(const char* suite, const char* name,
            void (*fn)(Context&)) noexcept {
    if (g_test_count >= kMaxTests) {
      ++g_overflow_count;
      return;
    }

    g_tests[g_test_count++] = TestCase{suite, name, fn};
  }
};

inline void ReportFailure(Context& ctx, const char* file, int line,
                          const char* expression, const std::string& detail) {
  ++ctx.failures;
  std::fprintf(stderr, "  FAIL %s.%s\n    %s:%d: %s\n", ctx.suite, ctx.name,
               file, line, expression);
  if (!detail.empty()) {
    std::fprintf(stderr, "    %s\n", detail.c_str());
  }
}

/// Runs every test whose suite matches \p suite_filter, or all of them when it
/// is null. Returns the number of failed tests.
inline int Run(const char* suite_filter) {
  int failed_tests = 0;
  int ran_tests = 0;

  // Reported before anything runs: a dropped test is not a failing test, so
  // nothing below would notice it.
  if (g_overflow_count > 0) {
    std::fprintf(stderr,
                 "%zu test(s) could not be registered: raise "
                 "testing::kMaxTests above %zu\n",
                 g_overflow_count, kMaxTests);
    return 1;
  }

  for (size_t i = 0; i < g_test_count; ++i) {
    const TestCase& test = g_tests[i];
    if (suite_filter != nullptr && std::strcmp(suite_filter, test.suite) != 0) {
      continue;
    }

    Context ctx;
    ctx.suite = test.suite;
    ctx.name = test.name;
    test.fn(ctx);
    ++ran_tests;

    if (ctx.failures > 0) {
      ++failed_tests;
    } else {
      std::printf("  ok   %s.%s\n", test.suite, test.name);
    }
  }

  // A filter that matched nothing is a failure, not a pass. This is the state
  // the tree is in when a suite is renamed but CMakeLists still registers the
  // old name, and a silent zero-test success there is the most misleading
  // result the suite can produce.
  if (ran_tests == 0) {
    std::fprintf(stderr, "no tests matched %s\n",
                 suite_filter != nullptr ? suite_filter : "(all)");
    return 1;
  }

  std::printf("%d test(s) run, %d failed\n", ran_tests, failed_tests);
  return failed_tests;
}

}  // namespace testing

/// Defines and registers a test. The body receives `ctx`, which the CHECK
/// macros use; it is named rather than hidden so a helper can take it and
/// report failures at the caller's expense.
#define TEST(suite_name, test_name)                               \
  static void suite_name##_##test_name(testing::Context& ctx);    \
  static testing::Registrar registrar_##suite_name##_##test_name( \
      #suite_name, #test_name, &suite_name##_##test_name);        \
  static void suite_name##_##test_name(testing::Context& ctx)

/// Records a failure and continues.
#define CHECK(expr)                                                       \
  do {                                                                    \
    if (!(expr)) {                                                        \
      testing::ReportFailure(ctx, __FILE__, __LINE__, "CHECK(" #expr ")", \
                             std::string());                              \
    }                                                                     \
  } while (false)

/// Records a failure with both values printed, and continues.
#define CHECK_EQ(a, b)                                                     \
  do {                                                                     \
    const auto check_left = (a);                                           \
    const auto check_right = (b);                                          \
    if (!(check_left == check_right)) {                                    \
      testing::ReportFailure(                                              \
          ctx, __FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ")",             \
          "left = " + std::to_string(static_cast<long long>(check_left)) + \
              ", right = " +                                               \
              std::to_string(static_cast<long long>(check_right)));        \
    }                                                                      \
  } while (false)

/// Records a failure and returns from the test.
#define REQUIRE(expr)                                                       \
  do {                                                                      \
    if (!(expr)) {                                                          \
      testing::ReportFailure(ctx, __FILE__, __LINE__, "REQUIRE(" #expr ")", \
                             std::string());                                \
      return;                                                               \
    }                                                                       \
  } while (false)

/// Records a failure with both values printed, and returns from the test.
#define REQUIRE_EQ(a, b)                                                   \
  do {                                                                     \
    const auto check_left = (a);                                           \
    const auto check_right = (b);                                          \
    if (!(check_left == check_right)) {                                    \
      testing::ReportFailure(                                              \
          ctx, __FILE__, __LINE__, "REQUIRE_EQ(" #a ", " #b ")",           \
          "left = " + std::to_string(static_cast<long long>(check_left)) + \
              ", right = " +                                               \
              std::to_string(static_cast<long long>(check_right)));        \
      return;                                                              \
    }                                                                      \
  } while (false)

#endif  // MODEL_CRYPT_TESTS_CHECK_H_
