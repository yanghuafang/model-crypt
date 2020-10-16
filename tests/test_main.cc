/// \file test_main.cc
/// Entry point for the model-crypt test binary.
///
/// Takes an optional suite name and runs only that suite, which is how
/// CMakeLists registers each one as its own CTest test: a failure then names
/// the suite in `ctest` output instead of being one line inside a single
/// monolithic pass/fail. Run with no argument to execute everything.

#include <cstdio>
#include <cstring>

#include "check.h"

int main(int argc, char** argv) {
  const char* suite = nullptr;
  if (argc > 2) {
    std::fprintf(stderr, "usage: %s [suite]\n", argv[0]);
    return 2;
  }

  if (argc == 2) {
    suite = argv[1];
    std::printf("running suite %s\n", suite);
  } else {
    std::printf("running all suites\n");
  }

  // Nonzero when any test failed, which is what CTest reads. The count itself
  // is not meaningful to CTest, only its being nonzero, but returning it makes
  // a direct run of the binary say how much is broken.
  return testing::Run(suite) == 0 ? 0 : 1;
}
