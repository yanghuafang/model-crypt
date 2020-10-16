# CMakeLists.txt — the whole build for model-crypt.
#
# One file rather than a tree of them: there are three targets (a library, a CLI,
# a test binary) and two dependencies, which is not enough to justify the
# indirection of per-directory lists. Everything a reader needs to know about how
# this is compiled is here.
#
# Targets:
#   model_crypt_objects  the compiled sources, shared by the library and the
#                        tests (see the note on CMake 3.16 below)
#   model_crypt        the library — static by default, shared with
#                      -DBUILD_SHARED_LIBS=ON
#   model-crypt        the CLI
#   model_crypt_tests  the test binary, registered with CTest per suite
#   model_crypt_make_vector
#                      writes the committed golden vector (scripts/make-vector.sh)

# 3.16. Low on purpose: it is a floor for people building on older
# distributions, not a statement about what CI runs, which is current. Two
# things in this file are written the way they are because of it, and both would
# otherwise be tidier:
# model_crypt_objects exists because $<TARGET_OBJECTS:> did not accept a
# non-OBJECT library until 3.21, and the scripts run ctest from inside the build
# directory because `ctest --test-dir` arrived in 3.20.
cmake_minimum_required(VERSION 3.16)

# The version reaches C++ through src/util/version.h.in, so this is the single
# place it is written. mc_version_string() reports it.
project(model_crypt
  VERSION 2.0.0
  DESCRIPTION "Authenticated encryption for deep learning model files"
  LANGUAGES CXX)

# All three, because the first alone promises less than it looks. Without
# REQUIRED, CMAKE_CXX_STANDARD is a preference and a compiler that cannot do
# C++17 silently gets an older one, surfacing as an unrelated syntax error.
# Without EXTENSIONS OFF the flag is -std=gnu++17, so a GNU extension compiles
# here and fails wherever this is read as the C++17 the docs claim.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Emit compile_commands.json. clang-tidy and clangd both need it to know the
# flags each file is compiled with; scripts/tidy.sh points at it.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Release rather than the empty default. An empty CMAKE_BUILD_TYPE means no -O
# and no -DNDEBUG, which for this library means scrypt runs unoptimized — the
# KDF then costs seconds instead of ~100 ms and reads as a hang. A plain
# `cmake -S . -B build` should produce something usable.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  message(STATUS "CMAKE_BUILD_TYPE not set; defaulting to Release")
endif()

message(STATUS "CXX compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Build type:   ${CMAKE_BUILD_TYPE}")

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

# 1.1.1, not 3.0. Everything this library asks of libcrypto exists there:
# AES-256-GCM through EVP_Cipher*, and scrypt through EVP_PBE_scrypt, which
# predates the EVP_KDF interface by a major version and is not deprecated in
# 3.x. crypt/kdf.cc says more about that choice.
#
# The floor is 1.1.1 rather than 1.1.0 because 1.1.0 is long out of support
# everywhere. Newer is fine and is what CI actually builds against on both
# platforms — the version is a floor for older systems, not a pin.
#
# macOS still needs Homebrew's openssl@3: Apple's system LibreSSL headers are
# not OpenSSL and the SDK does not publish them for linking anyway.
# scripts/build-env.sh sets OPENSSL_ROOT_DIR to the Homebrew prefix.
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
message(STATUS "OpenSSL:      ${OPENSSL_VERSION} (${OPENSSL_CRYPTO_LIBRARY})")

find_package(ZLIB REQUIRED)
message(STATUS "zlib:         ${ZLIB_VERSION_STRING}")

# For ThreadingTests only. Found here rather than beside the test target, because
# find_package must run before the target_link_libraries that names Threads::
# Threads — CMake reads this file top to bottom, and an imported target that does
# not exist yet is a link error naming a library nobody asked for.
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Generated version header
# ---------------------------------------------------------------------------

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/src/util/version.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/generated/util/version.h
  @ONLY)

# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------

# THIS BLOCK MUST STAY ABOVE EVERY add_library AND add_executable IN THIS FILE.
#
# add_compile_options is directory-scoped and applies only to targets created
# *after* it. Placed below the library, as it was until this was noticed, it
# reaches the test binary and the CLI but not the library itself — so
# `--asan` instruments the harness and not the code under test, and `--coverage`
# reports on nothing. Neither failure is visible from the outside: the build
# succeeds, the suites pass, and the sanitizer sits there finding nothing. It
# showed up only as a coverage report listing a single header.
#
# Applied to every target through add_compile_options rather than per target,
# because the runtime has to be present in the process that runs, and mixing
# instrumented and uninstrumented translation units in one binary is how you get
# a link error about __asan_report_load8.
#
# Sanitizers must not be combined with the Release default: -O3 inlines the
# frames their reports are made of. scripts/build.sh switches to Debug
# automatically when either is asked for.
option(MODEL_CRYPT_ASAN "Build with AddressSanitizer" OFF)
option(MODEL_CRYPT_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)
option(MODEL_CRYPT_TSAN "Build with ThreadSanitizer" OFF)
option(MODEL_CRYPT_COVERAGE "Build with source-based coverage instrumentation" OFF)

if(MODEL_CRYPT_TSAN AND (MODEL_CRYPT_ASAN OR MODEL_CRYPT_UBSAN))
  # Not a style preference: ASan and TSan use incompatible shadow memory layouts
  # and clang rejects the combination outright. Saying so here is clearer than
  # the linker's version of the same news.
  message(FATAL_ERROR "MODEL_CRYPT_TSAN cannot be combined with ASan or UBSan")
endif()

if(MODEL_CRYPT_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address)
  message(STATUS "AddressSanitizer enabled")
endif()

if(MODEL_CRYPT_UBSAN)
  # -fno-sanitize-recover makes a finding abort the process, so CI fails on it
  # instead of printing a diagnostic and carrying on green. vptr is off because
  # it needs RTTI on both sides of a cast and there is no polymorphism here to
  # check anyway.
  add_compile_options(-fsanitize=undefined -fno-sanitize=vptr
    -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=undefined -fno-sanitize=vptr)
  message(STATUS "UndefinedBehaviorSanitizer enabled")
endif()

if(MODEL_CRYPT_TSAN)
  # The library holds no global mutable state and takes no locks, so TSan is not
  # checking model-crypt against itself — it is checking the promise the docs
  # make, that two threads may encrypt and decrypt concurrently as long as they
  # do not share a buffer. ThreadingTests exercises exactly that.
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=thread)
  message(STATUS "ThreadSanitizer enabled")
endif()

if(MODEL_CRYPT_COVERAGE)
  add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
  add_link_options(-fprofile-instr-generate)
  message(STATUS "Source-based coverage enabled")
endif()

# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------

# An OBJECT library, with the real library built from its objects.
#
# The tests need to call into the internal layers -- crypt_test.cc calls
# format::ParseFileHeader and kdf::DeriveKey directly -- which
# -fvisibility=hidden deliberately keeps out of the shared library. Linking the
# object files instead is what lets those layers be tested without punching a
# hole in the export list.
#
# On CMake 3.21 and newer this could be a plain library, because
# $<TARGET_OBJECTS:> accepts any binary target there. The minimum here is 3.16,
# where that generator expression works only for an OBJECT library -- so the
# objects are their own target and both consumers name it.
#
# Listed explicitly rather than globbed. A glob is evaluated at configure time,
# so a new source is silently left out of the build until something reconfigures;
# CONFIGURE_DEPENDS fixes that but costs a stat of the tree on every build. With
# ten files, naming them is cheaper and makes an accidental addition to the
# library — a test helper, say — visible in review.
add_library(model_crypt_objects OBJECT
  src/api/c_api.cc
  src/crypt/aead.cc
  src/crypt/compress.cc
  src/crypt/decrypt.cc
  src/crypt/encrypt.cc
  src/crypt/format.cc
  src/crypt/kdf.cc
  src/crypt/random.cc
  src/crypt/secure_buffer.cc
  src/util/file_io.cc)

target_include_directories(model_crypt_objects
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated)

# Header paths and macros only. An OBJECT library does not link, so this
# propagates OpenSSL's and zlib's include directories to the compile without
# implying anything about who links them; model_crypt below does that.
target_link_libraries(model_crypt_objects PRIVATE OpenSSL::Crypto ZLIB::ZLIB)

# POSITION_INDEPENDENT_CODE on the objects, not only on model_crypt: with
# -DBUILD_SHARED_LIBS=ON the shared library is built from these objects, and an
# object compiled without -fPIC cannot go into one. Setting it here means the
# same objects serve both configurations.
set_target_properties(model_crypt_objects PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON)

add_library(model_crypt $<TARGET_OBJECTS:model_crypt_objects>)

# include/ is PUBLIC because a consumer needs model_crypt/model_crypt.h; src/ and
# the generated directory are PRIVATE because nothing outside this build may
# include crypt/format.h. That distinction is what keeps the internal C++ layer
# from becoming an accidental API, and the visibility settings below are the
# link-time half of the same rule.
target_include_directories(model_crypt
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated)

target_link_libraries(model_crypt PRIVATE OpenSSL::Crypto ZLIB::ZLIB)

# PRIVATE, so a consumer of the shared library does not inherit them: OpenSSL and
# zlib are implementation details, and a caller that ends up linking them because
# model-crypt did is a caller whose build breaks when this switches to a
# different AEAD.
#
# -fvisibility=hidden is what makes MC_API mean something. Without it every
# symbol in the internal namespaces — format::ParseFileHeader, aead::open — lands
# in the shared library's dynamic symbol table, becomes something a consumer can
# link against, and thereby becomes an ABI that cannot be changed. With it, the
# eleven MC_API functions are the entire surface.
# LINKER_LANGUAGE is stated rather than inferred. This target's only "sources"
# are the object files named by $<TARGET_OBJECTS:>, which carry no language of
# their own, and CMake normally derives the linker driver from source file
# extensions. Newer CMake works it out; older versions report "Cannot determine
# link language for target", which is a confusing way to learn that an
# object-only library needs to say so. Naming it costs nothing and holds on
# every version in the supported range.
set_target_properties(model_crypt PROPERTIES
  LINKER_LANGUAGE CXX
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})

# ---------------------------------------------------------------------------
# Warnings, and the options that turn them into errors
# ---------------------------------------------------------------------------

# The extra three beyond -Wall -Wextra are each here for a specific class of bug
# this code could have:
#
#   -Wconversion       a size_t narrowed into the uInt zlib wants, or an int
#                      OpenSSL wants, is how a large chunk becomes a short one.
#                      Every such conversion in the tree is an explicit cast with
#                      a range check in front of it; this is what keeps a new one
#                      from being implicit.
#   -Wshadow           a `size` shadowing an outer `size` in the chunk walk would
#                      compile and be wrong in the quietest possible way.
#   -Wold-style-cast   the C API's boundary is where a (uint8_t*) cast is
#                      tempting; naming the cast says whether const is being
#                      dropped.
set(MODEL_CRYPT_WARNINGS
  -Wall -Wextra -Wconversion -Wshadow -Wold-style-cast -Wpedantic)

option(MODEL_CRYPT_WERROR "Treat compiler warnings as errors" OFF)

# A function rather than repeating five lines per target: the CLI and the tests
# must be built with the same warnings as the library, or a warning is only an
# error in the place it is least likely to appear.
function(model_crypt_configure target)
  target_compile_options(${target} PRIVATE ${MODEL_CRYPT_WARNINGS})
  if(MODEL_CRYPT_WERROR)
    target_compile_options(${target} PRIVATE -Werror)
  endif()
endfunction()

# The objects, not just the library: model_crypt is now built from
# $<TARGET_OBJECTS:>, so it compiles nothing of its own and warning flags
# applied to it alone would reach no source file. Both are configured because
# model_crypt still owns the link, and a future source added directly to it
# should get the same treatment.
model_crypt_configure(model_crypt_objects)
model_crypt_configure(model_crypt)

# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------

add_executable(model-crypt src/cli/main.cc)
target_include_directories(model-crypt PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(model-crypt PRIVATE model_crypt)
model_crypt_configure(model-crypt)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

option(MODEL_CRYPT_BUILD_TESTS "Build the test suite" ON)

if(MODEL_CRYPT_BUILD_TESTS)
  enable_testing()

  # The tests link the library's object files rather than the library itself.
  #
  # They have to: crypt_test.cc calls format::ParseFileHeader and
  # kdf::DeriveKey, which -fvisibility=hidden deliberately keeps out of the
  # shared library's symbol table. Linking the objects instead is what lets the
  # internal layers be tested without punching a hole in the export list —
  # which would mean the thing being tested is not the thing being shipped.
  #
  # model_crypt_objects rather than model_crypt: see the note on the OBJECT
  # library above for why the objects are a target of their own.
  add_executable(model_crypt_tests
    tests/test_main.cc
    tests/corpus.cc
    tests/api_test.cc
    tests/crypt_test.cc
    tests/round_trip_test.cc
    tests/tamper_test.cc
    tests/threading_test.cc
    tests/vector_test.cc
    $<TARGET_OBJECTS:model_crypt_objects>)

  target_include_directories(model_crypt_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_BINARY_DIR}/generated)

  # OpenSSL and zlib directly, because $<TARGET_OBJECTS:> carries object files
  # and nothing else — a target's own link libraries do not come along with them.
  target_link_libraries(model_crypt_tests PRIVATE OpenSSL::Crypto ZLIB::ZLIB
    Threads::Threads)

  # An absolute path baked in, so the vector suite finds tests/vectors/ no matter
  # what directory the binary is run from. VectorTests still lets
  # MODEL_CRYPT_TEST_DATA_DIR override it at run time, for a build tree that was
  # moved after being configured.
  target_compile_definitions(model_crypt_tests PRIVATE
    MODEL_CRYPT_TEST_DATA_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors\")

  model_crypt_configure(model_crypt_tests)

  add_executable(model_crypt_make_vector
    tests/make_vector.cc
    tests/corpus.cc)
  target_include_directories(model_crypt_make_vector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(model_crypt_make_vector PRIVATE model_crypt)
  model_crypt_configure(model_crypt_make_vector)

  # One CTest entry per suite, not one for the whole binary. `ctest` then names
  # the failing suite, and `ctest -j` runs them in parallel — which the suites
  # are safe under because corpus::TempPath includes the process id.
  #
  # Adding a suite means adding it here as well as to the source list above. That
  # is a real footgun, and it is why testing::run() treats "no test matched" as a
  # failure: a suite renamed in one place and not the other fails loudly instead
  # of quietly running nothing.
  foreach(suite Api Format Compress Kdf Aead SecureBuffer RoundTrip Tamper
                Threading Vector)
    add_test(NAME ${suite} COMMAND model_crypt_tests ${suite})
    # The whole suite must fit well inside this; the slowest (Tamper, which runs
    # a few thousand decryptions) takes seconds natively and about a minute under
    # ASan. A timeout is here at all so a deadlock in the threading suite fails
    # rather than hanging a CI job until the runner's own limit.
    set_tests_properties(${suite} PROPERTIES TIMEOUT 900)
  endforeach()

  # The CLI is tested from a shell script rather than from C++, because what
  # needs checking is its interface: exit codes, refusing --key, prompting only
  # on a tty, not overwriting a key file. Driving that through fork/exec in a
  # test binary would be more code than the thing it tests.
  add_test(NAME Cli
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-cli.sh
            $<TARGET_FILE:model-crypt>)
  set_tests_properties(Cli PROPERTIES TIMEOUT 300)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS model_crypt model-crypt
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

# The public header only. src/ is not installed, which is the same boundary the
# visibility settings enforce at link time — a consumer that cannot include
# crypt/format.h cannot come to depend on it.
install(DIRECTORY include/model_crypt
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
