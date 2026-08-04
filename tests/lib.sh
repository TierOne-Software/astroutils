# tests/lib.sh — assertion helpers for the chimerautils functional suite.
#
# Sourced by every file in tests/t/.  Portable POSIX sh: must work under
# dash, busybox ash (Alpine/musl CI) and bash.  No bashisms, no GNU-only
# utilities in the harness itself.
#
# Environment provided by run-tests.sh:
#   CU_BIN     directory of symlinks to the tools under test
#   CU_WORK    per-test scratch directory (cwd when the test runs)
#   CU_SRCDIR  repository root
#
# Every helper records a result; the runner tallies them.

: "${CU_BIN:?lib.sh: CU_BIN not set — run via tests/run-tests.sh}"

cu_pass_count=0
cu_fail_count=0
cu_skip_count=0
cu_xfail_count=0

# Colour only when stdout is a terminal and not disabled.
if [ -t 1 ] && [ "${CU_NO_COLOR:-0}" != "1" ]; then
    _c_red=$(printf '\033[31m'); _c_grn=$(printf '\033[32m')
    _c_yel=$(printf '\033[33m'); _c_rst=$(printf '\033[0m')
else
    _c_red=; _c_grn=; _c_yel=; _c_rst=
fi

pass() {
    cu_pass_count=$((cu_pass_count + 1))
    [ "${CU_QUIET:-0}" = "1" ] || printf '  %sok%s   %s\n' "$_c_grn" "$_c_rst" "$1"
}

fail() {
    cu_fail_count=$((cu_fail_count + 1))
    printf '  %sFAIL%s %s\n' "$_c_red" "$_c_rst" "$1"
    [ -n "${2:-}" ] && printf '       %s\n' "$2"
    return 0
}

skip() {
    cu_skip_count=$((cu_skip_count + 1))
    [ "${CU_QUIET:-0}" = "1" ] || printf '  %sskip%s %s (%s)\n' "$_c_yel" "$_c_rst" "$1" "${2:-unavailable}"
    return 0
}

# xfail <label> <reason> — a known, documented defect that this build is
# expected to exhibit.  Reported prominently but does not fail the run,
# so a real regression elsewhere is not buried by a red suite.  Every
# xfail must correspond to an OPEN entry in SECURITY-FINDINGS.md.
xfail() {
    cu_xfail_count=$((cu_xfail_count + 1))
    printf '  %sXFAIL%s %s\n' "$_c_yel" "$_c_rst" "$1"
    printf '        known defect: %s\n' "${2:-see SECURITY-FINDINGS.md}"
    return 0
}

# is_musl — true when the C library is musl (Alpine, Chimera, Astro).
is_musl() {
    if [ -n "${CU_IS_MUSL:-}" ]; then
        [ "$CU_IS_MUSL" = "1" ]
        return
    fi
    CU_IS_MUSL=0
    if ldd --version 2>&1 | grep -qi musl; then
        CU_IS_MUSL=1
    elif ldd /bin/sh 2>/dev/null | grep -qi 'musl'; then
        CU_IS_MUSL=1
    fi
    export CU_IS_MUSL
    [ "$CU_IS_MUSL" = "1" ]
}

# tool <name> — absolute path to a tool under test.
tool() { printf '%s/%s' "$CU_BIN" "$1"; }

# have <name>... — true when every named tool was built.
have() {
    for _t in "$@"; do
        [ -x "$CU_BIN/$_t" ] || return 1
    done
    return 0
}

# require <label> <tool>... — true when every tool exists; otherwise
# records one skip for <label> and returns 1.  Guards a whole group:
#
#   if require "patch parser" patch; then ... fi
require() {
    _label=$1; shift
    if have "$@"; then
        return 0
    fi
    skip "$_label" "not built: $*"
    return 1
}

# group <title> — section header in the output.
group() {
    [ "${CU_QUIET:-0}" = "1" ] || printf '\n%s\n' "$1"
}

# have_host <cmd>... — true when a *host* helper (not under test) exists.
have_host() {
    for _t in "$@"; do
        command -v "$_t" >/dev/null 2>&1 || return 1
    done
    return 0
}

# ---------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------

# assert_eq <name> <expected> <actual>
assert_eq() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1" "expected [$2], got [$3]"
    fi
}

# assert_out <name> <expected-stdout> <cmd>...
# Runs cmd, compares stdout (stderr discarded, trailing newline stripped).
assert_out() {
    _name=$1; _want=$2; shift 2
    _got=$("$@" 2>/dev/null)
    assert_eq "$_name" "$_want" "$_got"
}

# assert_status <name> <expected-status> <cmd>...
assert_status() {
    _name=$1; _want=$2; shift 2
    "$@" >/dev/null 2>&1
    _got=$?
    assert_eq "$_name" "$_want" "$_got"
}

# assert_ok <name> <cmd>... — command must exit 0.
assert_ok() {
    _name=$1; shift
    if "$@" >/dev/null 2>&1; then
        pass "$_name"
    else
        fail "$_name" "exit status $? from: $*"
    fi
}

# assert_contains <name> <needle> <cmd>... — stdout+stderr must contain needle.
assert_contains() {
    _name=$1; _needle=$2; shift 2
    _got=$("$@" 2>&1)
    case $_got in
        *"$_needle"*) pass "$_name" ;;
        *) fail "$_name" "output did not contain [$_needle]: $_got" ;;
    esac
}

# ---------------------------------------------------------------------
# Crash / resource assertions — the core of the security regressions.
# ---------------------------------------------------------------------

# A process killed by a signal exits with status > 128 under POSIX sh.
# 124 is timeout(1)'s "timed out"; 137/152 are SIGKILL/SIGXCPU from our
# own ulimit, which we treat separately from a genuine crash.

# assert_no_crash <name> <cmd>...
# The command may fail — it must not die from a signal (SIGSEGV, SIGABRT,
# SIGBUS...) and must not hang.  This is the assertion that catches
# memory-safety regressions in parsers fed hostile input.
assert_no_crash() {
    _name=$1; shift
    if [ "${CU_VERBOSE:-0}" = "1" ]; then
        cu_run_limited "$@"
    else
        cu_run_limited "$@" >/dev/null 2>&1
    fi
    _st=$?
    case $_st in
        139) fail "$_name" "SIGSEGV (segmentation fault)" ;;
        134) fail "$_name" "SIGABRT (abort — assertion, fortify or sanitizer)" ;;
        135) fail "$_name" "SIGBUS" ;;
        136) fail "$_name" "SIGFPE" ;;
        124) fail "$_name" "timed out after ${CU_TIMEOUT}s (possible hang)" ;;
        137) fail "$_name" "SIGKILL (likely memory-limit exhaustion)" ;;
        *)
            if [ "$_st" -gt 128 ] && [ "$_st" -ne 152 ]; then
                fail "$_name" "killed by signal $((_st - 128))"
            else
                pass "$_name"
            fi
            ;;
    esac
}

# assert_bounded <name> <mem-kb> <cmd>...
# Command must complete within an address-space limit *and* not crash.
# Catches unbounded-allocation DoS regressions: the pre-fix binary is
# killed by the limit instead of exiting with a diagnostic.
#
# Under a sanitizer build the harness reserves terabytes of address space,
# so `ulimit -v` is meaningless; CU_NO_MEMLIMIT=1 downgrades this to a
# plain crash check (ASan itself reports the allocation failure).
assert_bounded() {
    if [ "${CU_NO_MEMLIMIT:-0}" = "1" ]; then
        _name=$1; shift 2
        assert_no_crash "$_name" "$@"
        return
    fi
    _name=$1; _mem=$2; shift 2
    if [ "${CU_VERBOSE:-0}" = "1" ]; then
        CU_MEMLIMIT=$_mem cu_run_limited "$@"
    else
        CU_MEMLIMIT=$_mem cu_run_limited "$@" >/dev/null 2>&1
    fi
    _st=$?
    case $_st in
        137|139|134) fail "$_name" "died under ${_mem}KB limit (status $_st) — unbounded allocation?" ;;
        124) fail "$_name" "timed out under ${_mem}KB limit" ;;
        *)
            if [ "$_st" -gt 128 ] && [ "$_st" -ne 152 ]; then
                fail "$_name" "killed by signal $((_st - 128)) under ${_mem}KB limit"
            else
                pass "$_name"
            fi
            ;;
    esac
}

# cu_run_limited <cmd>... — run under CU_TIMEOUT seconds and, when
# CU_MEMLIMIT is set, an address-space cap.  Returns the child status.
CU_TIMEOUT=${CU_TIMEOUT:-15}
cu_run_limited() {
    if [ -n "${CU_MEMLIMIT:-}" ] && [ "${CU_NO_MEMLIMIT:-0}" != "1" ]; then
        (
            ulimit -v "$CU_MEMLIMIT" 2>/dev/null || true
            if have_host timeout; then
                exec timeout "$CU_TIMEOUT" "$@"
            else
                exec "$@"
            fi
        )
    else
        if have_host timeout; then
            timeout "$CU_TIMEOUT" "$@"
        else
            "$@"
        fi
    fi
}

# ---------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------

# utf8_locale — echo a usable UTF-8 locale name, or empty if none.
utf8_locale() {
    for _l in C.UTF-8 en_US.UTF-8 C.utf8 en_US.utf8; do
        if [ -n "$(LC_ALL=$_l locale charmap 2>/dev/null | grep -i utf)" ]; then
            printf '%s' "$_l"
            return 0
        fi
    done
    # musl accepts any name and is always UTF-8.
    if [ "$(LC_ALL=C.UTF-8 printf 'x' 2>/dev/null)" = "x" ] && ! have_host locale; then
        printf 'C.UTF-8'
        return 0
    fi
    printf ''
}

# corpus_dir <target> — path to a fuzz corpus, or empty when absent.
corpus_dir() {
    _d="$CU_SRCDIR/fuzz/corpus/$1"
    [ -d "$_d" ] && printf '%s' "$_d"
}

# cu_finish — end of a test file: publish counts and set exit status.
# The runner reads CU_RESULT; standalone runs just get the status.
cu_finish() {
    if [ -n "${CU_RESULT:-}" ]; then
        printf '%s %s %s %s\n' "$cu_pass_count" "$cu_fail_count" \
            "$cu_skip_count" "$cu_xfail_count" > "$CU_RESULT"
    fi
    [ "$cu_fail_count" -eq 0 ]
}
