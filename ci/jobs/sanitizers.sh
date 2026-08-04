#!/bin/sh
# Build with AddressSanitizer + UndefinedBehaviorSanitizer and run the
# whole suite, including the corpus replay, under them.
#
# This is the job most likely to find something new: the regression tests
# drive the exact code paths the analyzers flagged, and ASan/UBSan see
# violations that a plain build silently tolerates.  Several findings in
# SECURITY-FINDINGS.md (the re_conv heap overflow, the mktemp over-read)
# were confirmed exactly this way.
set -eu

cd "$(dirname "$0")/../.."

BUILD_DIR=${BUILD_DIR:-build-asan}
CC=${CC:-clang}
CXX=${CXX:-clang++}
export CC CXX

printf '=== configure with asan+ubsan\n'
rm -rf "$BUILD_DIR"
# -O1 rather than -O0 or -O2: at -O0 _FORTIFY_SOURCE is disabled and the
# corpus replay crawls, while at -O2 the optimizer removes some of the
# undefined behaviour before UBSan can observe it.
meson setup "$BUILD_DIR" \
    -Doptimization=1 \
    -Ddebug=true \
    -Db_sanitize=address,undefined \
    -Db_lundef=false

printf '=== build\n'
ninja -C "$BUILD_DIR"

# halt_on_error makes UBSan fail the test rather than log and continue.
# detect_leaks is off: these are short-lived CLI tools that deliberately
# let the exit path reclaim memory, and the leak triage for the long-lived
# tools is tracked separately (PLAN.md P6).
ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:strict_string_checks=1:detect_stack_use_after_return=1}
UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}
export ASAN_OPTIONS UBSAN_OPTIONS

# ASan reserves terabytes of virtual address space, so the suite's
# `ulimit -v` guards have to be switched off in this configuration.
export CU_NO_MEMLIMIT=1
export CU_TIMEOUT=${CU_TIMEOUT:-60}

printf '=== functional suite under sanitizers\n'
sh tests/run-tests.sh --build "$BUILD_DIR" \
    00-smoke 10-regress 11-regress 12-regress 13-regress

printf '=== corpus replay under sanitizers (full)\n'
# Under sanitizers the whole corpus is worth the wall-clock: this is the
# configuration that turns a silent out-of-bounds access into a failure.
CU_FUZZ_FULL=${CU_FUZZ_FULL:-1} \
    sh tests/run-tests.sh --build "$BUILD_DIR" 20-fuzz-corpus
