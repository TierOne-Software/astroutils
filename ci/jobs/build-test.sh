#!/bin/sh
# Configure, build and run the functional suite.
#
# Parameterised entirely by the environment so the same script serves the
# gcc, clang and musl jobs:
#   CC, CXX        compiler to use (default: system cc)
#   BUILD_DIR      build tree (default: build-ci)
#   MESON_ARGS     extra arguments to meson setup
#   TEST_FILTERS   test files to run (default: all but the corpus replay)
#   WERROR         1 to build with --werror
set -eu

cd "$(dirname "$0")/../.."

BUILD_DIR=${BUILD_DIR:-build-ci}
MESON_ARGS=${MESON_ARGS:-}
TEST_FILTERS=${TEST_FILTERS:-00-smoke 10-regress 11-regress 12-regress 13-regress}
WERROR=${WERROR:-0}

werror_arg=
[ "$WERROR" = "1" ] && werror_arg=--werror

printf '=== configure (%s)\n' "${CC:-cc}"
rm -rf "$BUILD_DIR"
# shellcheck disable=SC2086
meson setup "$BUILD_DIR" $werror_arg -Dbuildtype=debugoptimized $MESON_ARGS

printf '=== build\n'
ninja -C "$BUILD_DIR"

printf '=== compiler warnings\n'
# A build that emits new warnings is worth seeing even when it succeeds;
# unchecked-allocation findings in this tree started life as warnings.
ninja -C "$BUILD_DIR" -t clean >/dev/null 2>&1 || true
ninja -C "$BUILD_DIR" 2>&1 | grep -E 'warning:' | sort | uniq -c | sort -rn | head -30 || true

printf '=== functional suite\n'
# shellcheck disable=SC2086
sh tests/run-tests.sh --build "$BUILD_DIR" $TEST_FILTERS
