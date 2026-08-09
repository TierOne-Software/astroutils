#!/bin/sh
# MemorySanitizer pass: build every fuzz harness with MSan and replay
# the saved corpora (-runs=0).  MSan catches uninitialized reads that
# ASan/UBSan and the static analyzers miss (the Infer uninit cluster
# suggests the class is live in this tree).  The current harness set
# replays clean under it; glibc-noise was checked for and is absent on
# this corpus set.
set -eu

cd "$(dirname "$0")/../.."

CC=${CC:-clang}
export CC
BUILD_DIR=${BUILD_DIR:-build-ci-msan}
export BUILD_DIR
# only for the harness builds below: a fuzzer+msan CFLAGS value breaks
# meson's compiler sanity check (no main() in a probe program)
MSAN_CFLAGS="-g -O1 -fsanitize=fuzzer,memory -fsanitize-memory-track-origins -fno-omit-frame-pointer"

printf '=== meson tree for generated sources and libcompat (MSan)\n'
# the support libraries must be instrumented too, or their writes are
# invisible to MSan and every read after one looks uninitialized
[ -f "$BUILD_DIR/build.ninja" ] || \
    CC=clang CXX=clang++ meson setup "$BUILD_DIR" \
    -Dbuildtype=debugoptimized -Db_sanitize=memory -Db_lundef=false
ninja -C "$BUILD_DIR"

printf '=== build harnesses (MSan)\n'
CFLAGS=$MSAN_CFLAGS sh fuzz/build-fuzz.sh

status=0
printf '=== replay corpora under MSan (-runs=0)\n'
# telnet is excluded: it links system ncurses (libtinfo), which is
# uninstrumented and produces unavoidable MSan noise.
for t in unvis getdate setmode patch http sh zopen awkb \
    grepdata sedcompile seddata awkdata patch_struct; do
    bin=fuzz/bin/fuzz_$t
    corpus=fuzz/corpus/$t
    [ -x "$bin" ] || { printf 'missing %s\n' "$bin"; status=1; continue; }
    if [ ! -d "$corpus" ] || [ -z "$(ls -A "$corpus" 2>/dev/null)" ]; then
        printf 'skip %s: empty corpus\n' "$t"
        continue
    fi
    printf -- '--- %s\n' "$t"
    # see fuzz-regress.sh for the detect_leaks rationale
    if ! ASAN_OPTIONS=detect_leaks=0 "$bin" "$corpus" -runs=0 \
            -rss_limit_mb=4096 -timeout=10 \
            -artifact_prefix=fuzz/artifacts/ ; then
        printf 'FAIL: %s flagged under MSan\n' "$t"
        status=1
    fi
done

exit $status
