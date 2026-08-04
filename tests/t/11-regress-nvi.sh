#!/bin/sh
# Regression tests for the nvi (vi/ex) defects in SECURITY-FINDINGS.md.
#
# nvi carries the largest share of the analyzer findings.  Everything here
# is driven through ex script mode (vi -e -s), so no pty is needed.

. "$CU_LIB/lib.sh"

require "nvi regressions" vi || { cu_finish; exit; }

VI=$(tool vi)

# ex <file> <command>... — run ex commands against a file, then write.
# Uses printf '%s\n' so '%' in commands is never taken as a format.
ex_run() {
    _f=$1; shift
    printf '%s\n' "$@" 'wq' | cu_run_limited "$VI" -e -s "$_f" >/dev/null 2>&1
}

# ex_nocrash <label> <file> <command>... — the edit may fail (no match,
# bad option) but must not die from a signal.
ex_nocrash() {
    _label=$1; _f=$2; shift 2
    _cmds=$(printf '%s\n' "$@" 'wq')
    printf '%s\n' "$_cmds" | cu_run_limited "$VI" -e -s "$_f" >/dev/null 2>&1
    _st=$?
    case $_st in
        139) fail "$_label" "SIGSEGV" ;;
        134) fail "$_label" "SIGABRT" ;;
        124) fail "$_label" "timed out (hang)" ;;
        *)
            if [ "$_st" -gt 128 ] && [ "$_st" -ne 152 ]; then
                fail "$_label" "killed by signal $((_st - 128))"
            else
                pass "$_label"
            fi ;;
    esac
}

group "nvi: ex_subst '~' expansion with no previous replacement"

# With sp->repl == NULL, all-'~' patterns and replacements left the build
# buffer NULL and passed it to memcpy.  Trapped live under zig ReleaseSafe.
printf 'a~b\n' > t1.txt
ex_nocrash "s/~/X/ with no previous replacement" t1.txt 's/~/X/'

printf 'a~b\n' > t2.txt
ex_nocrash "s/a/~/ with no previous replacement" t2.txt 's/a/~/'

printf 'a~b\n' > t3.txt
ex_nocrash "nomagic s/\\~/X/" t3.txt 'set nomagic|s/\~/X/'

# The re_conv() counting pass undercounted literal '~' by one CHAR_T in
# two cases, giving a 1-CHAR_T heap overflow when the allocation size was
# an exact power of two >= 256.  Drive a range of pattern lengths so one
# of them lands on the boundary.
i=1
overflow_fail=0
while [ "$i" -le 80 ]; do
    pat=$(awk -v n="$i" 'BEGIN{s="";for(j=0;j<n;j++)s=s "~";print s}')
    printf '%s\n' "$pat" > tw.txt
    printf '%s\n' "set nomagic|s/\\~/X/" 'wq' | cu_run_limited "$VI" -e -s tw.txt >/dev/null 2>&1
    st=$?
    if [ "$st" -gt 128 ] && [ "$st" -ne 152 ]; then
        overflow_fail=1
        break
    fi
    i=$((i + 7))
done
if [ "$overflow_fail" -eq 0 ]; then
    pass "re_conv tilde counting across pattern lengths 1..80"
else
    fail "re_conv tilde counting across pattern lengths 1..80" "crashed at length $i"
fi

group "nvi: ex_subst BUILD macro, match at offset 0"

# A match at offset 0 on the first substituted line did MEMCPY(lb, s, 0)
# with lb still NULL.
printf '1abc\n' > t4.txt
ex_run t4.txt '%s/1/x/g'
assert_out "substitution matching at offset 0" "xabc" "$(tool cat)" t4.txt

group "nvi: empty lines through the recno/db layer"

# WR_RLEAF did memmove(dest, NULL, 0) when nvi stored an empty line with a
# still-NULL conversion buffer; db_get/db_last did MEMCPY(ep->c_lp, wp, 0)
# when caching an empty line.  Trigger: the *first* line is empty (a
# non-empty first line hides it by leaving the reused buffer non-NULL).
printf '\nsecond\nthird\n' > t5.txt
ex_nocrash "file whose first line is empty" t5.txt '%s/second/2nd/'
assert_out "empty first line preserved" "" sh -c "$(tool sed) -n 1p t5.txt"
assert_out "edit applied after empty first line" "2nd" sh -c "$(tool sed) -n 2p t5.txt"

printf '\n\n\n\n' > t6.txt
ex_nocrash "file of nothing but empty lines" t6.txt '1'

printf '\n' > t7.txt
ex_nocrash "single empty line, appending text" t7.txt '$a' 'appended' '.'

group "nvi: CONVERT2 iconv output pointer after buffer growth"

# outleft/obp were computed before the growth check, so a mid-conversion
# realloc left obp dangling and outleft stale — an unbounded E2BIG retry
# loop.  Live repro: UTF-8 locale, fe=utf-32, a 2048-char line reached
# 527 MB RSS in 0.4 s.  Post-fix the same edit uses a few MB.
loc=$(utf8_locale)
if [ -n "$loc" ]; then
    awk 'BEGIN{s="";for(i=0;i<2048;i++)s=s "a";print s}' > t8.txt
    assert_bounded "utf-32 file encoding on a 2048-char line stays bounded" 262144 \
        env LC_ALL="$loc" sh -c "printf '%s\n' 'set fe=utf-32' '%s/a/b/g' 'wq' | '$VI' -e -s t8.txt >/dev/null 2>&1"
    # The conversion must actually have happened, or the test proves
    # nothing: UTF-32LE puts a BOM and 3 NUL bytes per ASCII character.
    if [ -s t8.txt ]; then
        sz=$(wc -c < t8.txt | tr -d ' ')
        if [ "$sz" -gt 8000 ]; then
            pass "output really is UTF-32 encoded ($sz bytes)"
        else
            fail "output really is UTF-32 encoded" "expected >8000 bytes, got $sz — conversion path not exercised"
        fi
    else
        fail "output really is UTF-32 encoded" "file is empty"
    fi
else
    skip "utf-32 file encoding" "no UTF-8 locale available"
fi

group "nvi: binc() failure leaves no dangling buffer"

# BINC_RET returned without clearing the caller's pointer after binc()
# freed the old buffer (reallocf semantics) — dangling pointer reused by
# the next conversion, then double-freed by conv_end().  Exercised by
# repeated growth of the conversion buffer.
if [ -n "$loc" ]; then
    awk 'BEGIN{for(i=0;i<50;i++){s="";for(j=0;j<200;j++)s=s "x";print s}}' > t9.txt
    ex_nocrash "repeated conversion buffer growth" t9.txt '%s/x/yy/g'
else
    skip "repeated conversion buffer growth" "no UTF-8 locale available"
fi

group "nvi: msgq prefix length double-count"

# On the msgq(sp, M_SYSERR, NULL) path, len still held the consumed prefix
# length at the nofmt label, so the strerror text was written past a gap
# of uninitialized bytes and the message came out truncated.  Provoke a
# system error by reading a file that cannot be opened.
mkdir -p noperm && : > noperm/secret.txt && chmod 000 noperm/secret.txt 2>/dev/null
if [ -r noperm/secret.txt ]; then
    # Running as root, or a filesystem that ignores the mode.
    skip "msgq system-error message is intact" "cannot create an unreadable file"
else
    printf 'x\n' > t10.txt
    out=$(printf '%s\n' 'r noperm/secret.txt' 'q!' | cu_run_limited "$VI" -e -s t10.txt 2>&1)
    case $out in
        *[Pp]ermission*) pass "msgq system-error message is intact" ;;
        *) fail "msgq system-error message is intact" "expected a permission diagnostic, got [$out]" ;;
    esac
fi
chmod 644 noperm/secret.txt 2>/dev/null

group "nvi: startup and basic editing still work"

# The TMAP/vs_crel and vs_sm_up/vs_sm_down changes touch screen setup and
# scrolling; make sure ordinary editing is unaffected.
printf 'one\ntwo\nthree\n' > t11.txt
ex_run t11.txt '2d'
assert_out "delete line" "one
three" "$(tool cat)" t11.txt

printf 'one\ntwo\n' > t12.txt
ex_run t12.txt '1a' 'inserted' '.'
assert_out "append line" "one
inserted
two" "$(tool cat)" t12.txt

printf 'a\nb\nc\n' > t13.txt
ex_nocrash "global command over all lines" t13.txt 'g/./s/^/> /'

cu_finish
