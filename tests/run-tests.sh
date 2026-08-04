#!/bin/sh
#
# run-tests.sh — chimerautils functional and security regression suite.
#
# Runs against any set of built binaries: a meson build directory (whose
# tools live in per-tool subdirectories), a flat directory such as
# zig-out/bin, or an installed image.
#
# Usage:
#   tests/run-tests.sh                      # auto-detect a build (zig first)
#   tests/run-tests.sh --zig                # zig build, then test zig-out/bin
#   tests/run-tests.sh --build build-meson  # meson build tree
#   tests/run-tests.sh --bindir zig-out/bin # flat directory
#   tests/run-tests.sh regress-patch smoke  # only matching test files
#
# Options:
#   --zig          rebuild with `zig build` first (ZIG_BUILD_ARGS passes
#                  extra flags, e.g. ZIG_BUILD_ARGS=-Doptimize=ReleaseSafe)
#   --build DIR    meson/ninja build tree; tools are found by scanning it
#   --bindir DIR   flat directory containing the tools
#   --quiet        only report failures and the summary
#   --list         list available test files and exit
#   --timeout N    per-command timeout in seconds (default 15)
#
# Exit status: 0 when every test passed or skipped, 1 otherwise.

set -u

srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
testdir="$srcdir/tests"

zigbuild=0
build=
bindir=
quiet=0
list=0
timeout_s=15
filters=

while [ $# -gt 0 ]; do
    case $1 in
        --zig)     zigbuild=1; shift ;;
        --build)   build=$2; shift 2 ;;
        --bindir)  bindir=$2; shift 2 ;;
        --quiet|-q) quiet=1; shift ;;
        --list)    list=1; shift ;;
        --timeout) timeout_s=$2; shift 2 ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --) shift; break ;;
        -*) printf 'run-tests.sh: unknown option %s\n' "$1" >&2; exit 2 ;;
        *)  filters="$filters $1"; shift ;;
    esac
done

if [ $list -eq 1 ]; then
    for f in "$testdir"/t/*.sh; do
        [ -f "$f" ] && printf '%s\n' "$(basename "$f" .sh)"
    done
    exit 0
fi

# ---------------------------------------------------------------------
# Locate the binaries under test
# ---------------------------------------------------------------------

if [ "$zigbuild" = 1 ]; then
    # shellcheck disable=SC2086
    (cd "$srcdir" && zig build ${ZIG_BUILD_ARGS:-}) || exit 2
    bindir=$srcdir/zig-out/bin
fi

if [ -z "$bindir" ] && [ -z "$build" ]; then
    if [ -d "$srcdir/zig-out/bin" ]; then
        bindir=$srcdir/zig-out/bin
    elif [ -f "$srcdir/build-meson/build.ninja" ]; then
        build=$srcdir/build-meson
    elif [ -f "$srcdir/build/build.ninja" ]; then
        build=$srcdir/build
    else
        printf 'run-tests.sh: no build found; pass --zig, --build or --bindir\n' >&2
        exit 2
    fi
fi

work_root=${CU_WORK_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/chimerautils-tests.XXXXXX")}
keep_work=${CU_KEEP_WORK:-0}
mkdir -p "$work_root"

cleanup() {
    [ "$keep_work" = "1" ] || rm -rf "$work_root"
}
trap cleanup EXIT INT TERM

CU_BIN=$work_root/bin
mkdir -p "$CU_BIN"

if [ -n "$bindir" ]; then
    bindir=$(CDPATH= cd -- "$bindir" && pwd)
    for f in "$bindir"/*; do
        [ -f "$f" ] && [ -x "$f" ] && ln -sf "$f" "$CU_BIN/$(basename "$f")"
    done
else
    build=$(CDPATH= cd -- "$build" && pwd)
    # Meson puts each tool in its own subdirectory alongside a <tool>.p
    # object directory; skip those, the private dirs and shared objects.
    find "$build" -type f -perm -u+x \
        ! -path '*.p/*' ! -path '*meson-private*' \
        ! -name '*.so' ! -name '*.so.*' ! -name '*.a' ! -name '*.exe' \
        2>/dev/null |
    while IFS= read -r f; do
        ln -sf "$f" "$CU_BIN/$(basename "$f")" 2>/dev/null || true
    done
fi

ntools=$(ls -1 "$CU_BIN" 2>/dev/null | wc -l | tr -d ' ')
if [ "$ntools" -eq 0 ]; then
    printf 'run-tests.sh: no executables found in %s\n' "${bindir:-$build}" >&2
    exit 2
fi

# Stale-build check: running the suite against binaries that predate the
# sources silently validates the wrong tree.  Compare the newest source
# file against the newest tested binary and warn loudly on mismatch.
newest_bin=$(
    for f in "$CU_BIN"/*; do
        [ -f "$f" ] || continue
        readlink "$f" 2>/dev/null || printf '%s\n' "$f"
    done | xargs ls -td 2>/dev/null | head -1
)
if [ -n "$newest_bin" ]; then
    stale=$(find "$srcdir/src.freebsd" "$srcdir/src.custom" \
        "$srcdir/src.compat" "$srcdir/src.safestr" "$srcdir/include" \
        "$srcdir/build-data" "$srcdir/build.zig" "$srcdir/meson.build" \
        -type f -newer "$newest_bin" -print -quit 2>/dev/null)
    if [ -n "$stale" ]; then
        printf 'run-tests.sh: WARNING: sources are newer than the tested binaries\n' >&2
        printf 'run-tests.sh:   (e.g. %s)\n' "$stale" >&2
        printf 'run-tests.sh: results may reflect a stale build; rebuild first (--zig)\n' >&2
    fi
fi

# nvi installs as `vi`; several tests want the ex personality, which nvi
# selects from argv[0].  Provide it when only `vi` was built.
if [ -x "$CU_BIN/vi" ] && [ ! -e "$CU_BIN/ex" ]; then
    ln -sf "$(readlink "$CU_BIN/vi" 2>/dev/null || printf '%s' "$CU_BIN/vi")" "$CU_BIN/ex" 2>/dev/null || true
fi

export CU_BIN
export CU_SRCDIR=$srcdir
export CU_LIB=$testdir
export CU_QUIET=$quiet
export CU_TIMEOUT=$timeout_s

# ---------------------------------------------------------------------
# Run the test files
# ---------------------------------------------------------------------

printf 'chimerautils test suite\n'
printf '  tools:  %s (%s executables)\n' "${bindir:-$build}" "$ntools"
printf '  work:   %s\n' "$work_root"

total_pass=0
total_fail=0
total_skip=0
total_xfail=0
failed_files=

for f in "$testdir"/t/*.sh; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .sh)

    if [ -n "$filters" ]; then
        matched=0
        for pat in $filters; do
            case $name in *"$pat"*) matched=1 ;; esac
        done
        [ $matched -eq 1 ] || continue
    fi

    [ $quiet -eq 1 ] || printf '\n=== %s\n' "$name"

    CU_WORK=$work_root/$name
    mkdir -p "$CU_WORK"
    CU_RESULT=$work_root/$name.result
    export CU_WORK CU_RESULT

    # Each file runs in its own process and its own directory, so a test
    # that leaves debris behind cannot affect the next one.
    ( cd "$CU_WORK" && sh "$f" ) || true

    if [ -f "$CU_RESULT" ]; then
        read -r p fl sk xf < "$CU_RESULT"
        : "${xf:=0}"
    else
        p=0; fl=1; sk=0; xf=0
        printf '  %s: produced no result (crashed or exited early)\n' "$name"
    fi
    total_pass=$((total_pass + p))
    total_fail=$((total_fail + fl))
    total_skip=$((total_skip + sk))
    total_xfail=$((total_xfail + xf))
    [ "$fl" -gt 0 ] && failed_files="$failed_files $name"
done

printf '\n----------------------------------------\n'
printf '%s passed, %s failed, %s skipped' "$total_pass" "$total_fail" "$total_skip"
if [ "$total_xfail" -gt 0 ]; then
    printf ', %s known failures' "$total_xfail"
fi
printf '\n'

if [ "$total_fail" -gt 0 ]; then
    printf 'failing files:%s\n' "$failed_files"
    [ "$keep_work" = "1" ] && printf 'work tree kept at %s\n' "$work_root"
    exit 1
fi
exit 0
