#!/bin/sh
# Build the libFuzzer harnesses and replay the saved corpora through them.
#
# Deterministic regression pass, not a fuzzing campaign: -runs=0 executes
# each corpus input exactly once and exits.  Set FUZZ_TIME to a non-zero
# number of seconds to also fuzz for real after the replay.
set -eu

cd "$(dirname "$0")/../.."

CC=${CC:-clang}
export CC
FUZZ_TIME=${FUZZ_TIME:-0}
# Its own tree, not build-meson: a meson build directory records absolute
# paths, so a developer's host-configured tree cannot be reconfigured
# inside the container (and vice versa).
BUILD_DIR=${BUILD_DIR:-build-ci-fuzz}
export BUILD_DIR

printf '=== meson tree for generated sources and libcompat\n'
[ -f "$BUILD_DIR/build.ninja" ] || meson setup "$BUILD_DIR" -Dbuildtype=debugoptimized
ninja -C "$BUILD_DIR"

printf '=== build harnesses\n'
sh fuzz/build-fuzz.sh

status=0

printf '=== replay corpora (-runs=0)\n'
for t in unvis getdate setmode patch http telnet sh zopen awkb; do
    bin=fuzz/bin/fuzz_$t
    corpus=fuzz/corpus/$t
    [ -x "$bin" ] || { printf 'missing %s\n' "$bin"; status=1; continue; }
    if [ ! -d "$corpus" ] || [ -z "$(ls -A "$corpus" 2>/dev/null)" ]; then
        printf 'skip %s: empty corpus\n' "$t"
        continue
    fi
    printf -- '--- %s (%s inputs)\n' "$t" "$(ls -1 "$corpus" | wc -l | tr -d ' ')"
    # fuzz_patch deliberately leaks hunk storage for fatal-rejected inputs
    # (freeing them is unsafe — see SECURITY-FINDINGS.md), so it needs a
    # raised RSS limit and leak detection off.
    if ! ASAN_OPTIONS=detect_leaks=0 "$bin" "$corpus" -runs=0 \
            -rss_limit_mb=4096 -artifact_prefix=fuzz/artifacts/ ; then
        printf 'FAIL: %s crashed replaying its corpus\n' "$t"
        status=1
    fi
done

if [ "$FUZZ_TIME" -gt 0 ]; then
    printf '=== fuzz for %ss per target\n' "$FUZZ_TIME"
    for t in unvis getdate setmode patch http telnet sh zopen awkb; do
        bin=fuzz/bin/fuzz_$t
        [ -x "$bin" ] || continue
        printf -- '--- %s\n' "$t"
        if ! ASAN_OPTIONS=detect_leaks=0 "$bin" "fuzz/corpus/$t" \
                -max_total_time="$FUZZ_TIME" -rss_limit_mb=4096 \
                -artifact_prefix=fuzz/artifacts/ ; then
            printf 'FAIL: %s found a new crash\n' "$t"
            status=1
        fi
    done
fi

printf '=== crash artifacts\n'
left=$(find fuzz/artifacts -type f ! -name '.gitignore' ! -name 'README*' 2>/dev/null | wc -l | tr -d ' ')
if [ "$left" -eq 0 ]; then
    printf 'none\n'
else
    printf '%s new artifact(s) in fuzz/artifacts:\n' "$left"
    find fuzz/artifacts -type f ! -name '.gitignore' ! -name 'README*'
    status=1
fi

exit $status
