#!/bin/sh
# Regression tests for the per-tool fixes in SECURITY-FINDINGS.md that are
# not patch(1) or nvi: coreutils, grep, ed, awk, hexdump, xargs, mcookie.

. "$CU_LIB/lib.sh"

group "jot: default output format on glibc"

# getformat() ran while prec == -1 for the single-argument form and the
# prec = 0 normalization happened afterwards, so `jot 3` printed the
# invalid format %.0-1f instead of counting.
if require "jot" jot; then
    assert_out "jot 3 counts" "1
2
3" "$(tool jot)" 3
    assert_out "jot with explicit range" "5
6" "$(tool jot)" 2 5
    assert_out "jot -w format" "x1" sh -c "$(tool jot) -w 'x%d' 1 1"
fi

group "grep: pointer arithmetic before the allocation with -B 0"

# initqueue() computed qend = qpool + (Bflag - 1) with Bflag == 0, forming
# a pointer before the allocation.
if require "grep" grep; then
    printf 'aaa\nbbb\nccc\n' > g.txt
    assert_out "grep with no -B" "bbb" "$(tool grep)" bbb g.txt
    assert_out "grep -B0" "bbb" "$(tool grep)" -B0 bbb g.txt
    assert_out "grep -B1" "aaa
bbb" "$(tool grep)" -B1 bbb g.txt
    assert_out "grep -A1" "bbb
ccc" "$(tool grep)" -A1 bbb g.txt
    assert_no_crash "grep -B0 over a larger input" \
        sh -c "$(tool jot) 500 2>/dev/null | $(tool grep) -B0 7 >/dev/null"
fi

group "cut/join: unsigned-wrap pointer arithmetic"

# f_cut() did putchar(p[i - clen]) with i int and clen size_t, computing
# p + (SIZE_MAX - ...); mbssep() did s[-n] with n size_t.
if require "cut" cut; then
    assert_out "cut -c single column" "b" sh -c "echo abc | $(tool cut) -c2"
    assert_out "cut -c range" "bc" sh -c "echo abcd | $(tool cut) -c2-3"
    assert_out "cut -b bytes" "a" sh -c "echo abc | $(tool cut) -b1"
    loc=$(utf8_locale)
    if [ -n "$loc" ]; then
        assert_no_crash "cut -c over multibyte input" \
            sh -c "printf 'caf\303\251 na\303\257ve\n' | LC_ALL=$loc $(tool cut) -c1-6 >/dev/null"
    else
        skip "cut -c over multibyte input" "no UTF-8 locale"
    fi
fi

if require "join" join; then
    printf '1 a\n2 b\n' > j1.txt
    printf '1 x\n2 y\n' > j2.txt
    assert_out "join on first field" "1 a x
2 b y" "$(tool join)" j1.txt j2.txt
    printf '1:a\n' > j3.txt
    printf '1:x\n' > j4.txt
    assert_out "join -t separator" "1:a:x" "$(tool join)" -t: j3.txt j4.txt
fi

group "sort: zero-length memcpy from a NULL leaf array"

# radixsort.c copied sl->leaves unconditionally; with leaves_num == 0 the
# pointer is NULL, so this was memcpy(dst, NULL, 0) — the same UB class
# already fixed in nvi, ed and dbcompat.  Only a sanitizer build shows
# it; found by ci/jobs/sanitizers.sh with UBSAN halt_on_error=1.
if require "sort" sort; then
    assert_out "sort ascending" "1" sh -c "printf '3\n1\n2\n' | $(tool sort) | $(tool head) -1"
    assert_out "sort reverse" "3" sh -c "printf '3\n1\n2\n' | $(tool sort) -r | $(tool head) -1"
    assert_no_crash "sort empty input" sh -c ": | $(tool sort) >/dev/null"
    assert_no_crash "sort -r empty input" sh -c ": | $(tool sort) -r >/dev/null"
    assert_no_crash "sort single empty line" sh -c "printf '\n' | $(tool sort) >/dev/null"
    assert_no_crash "sort -u over duplicates" sh -c \
        "printf 'a\na\nb\n' | $(tool sort) -u >/dev/null"
    assert_out "sort -n numeric" "2" sh -c "printf '10\n2\n' | $(tool sort) -n | $(tool head) -1"
fi

group "env: unchecked malloc in split_spaces"

if require "env" env; then
    assert_out "env passes a variable" "bar" "$(tool env)" FOO=bar sh -c 'echo $FOO'
    assert_no_crash "env -S with many spaced words" \
        "$(tool env)" -S "A=1    B=2    C=3    printf x"
fi

group "cat: unchecked fdopen in scanfiles"

if require "cat" cat; then
    printf 'x\n' > c.txt
    assert_out "cat regular file" "x" "$(tool cat)" c.txt
    assert_status "cat missing file errors" 1 "$(tool cat)" no-such-file-here
    assert_no_crash "cat mixing missing and present files" \
        "$(tool cat)" no-such-file-here c.txt
    assert_out "cat -" "y" sh -c "echo y | $(tool cat) -"
fi

group "ed: zero-length memcpy in join_lines, dead initializer in append_lines"

if require "ed" ed; then
    printf 'a\nb\nc\n' > e.txt
    printf '%s\n' '1,2j' 'w' 'q' | assert_no_crash "ed join lines" "$(tool ed)" -s e.txt
    printf 'a\n\n\nb\n' > e2.txt
    printf '%s\n' '1,4j' 'w' 'q' | cu_run_limited "$(tool ed)" -s e2.txt >/dev/null 2>&1
    assert_no_crash "ed join over empty lines" sh -c \
        "printf '1,\$j\nw\nq\n' | $(tool ed) -s e2.txt >/dev/null 2>&1"
    assert_no_crash "ed append then write" sh -c \
        "printf 'a\nnewline\n.\nw\nq\n' | $(tool ed) -s e.txt >/dev/null 2>&1"
fi

group "awk: unchecked calloc in cclenter, regex engine"

if require "awk" awk; then
    assert_out "awk character class" "match" sh -c "echo abc | $(tool awk) '/[a-c]+/{print \"match\"}'"
    assert_out "awk negated class" "match" sh -c "echo abc | $(tool awk) '/[^x]/{print \"match\"}'"
    assert_no_crash "awk wide character class" sh -c \
        "echo test | $(tool awk) '/[a-zA-Z0-9_-]+/{print}' >/dev/null"
    assert_no_crash "awk repetition patterns" sh -c \
        "echo aaaa | $(tool awk) '/a{2,3}/{print}' >/dev/null"
    assert_out "awk substr" "bc" sh -c "$(tool awk) 'BEGIN{print substr(\"abcd\",2,2)}'"
fi

group "hexdump: null nextpr dereference in rewrite"

if require "hexdump" hexdump; then
    printf 'abcd' > h.bin
    assert_no_crash "hexdump default" "$(tool hexdump)" h.bin
    assert_no_crash "hexdump -C" "$(tool hexdump)" -C h.bin
    assert_no_crash "hexdump custom format" "$(tool hexdump)" -e '"%02x"' h.bin
    assert_no_crash "hexdump empty input" sh -c ": | $(tool hexdump) >/dev/null"
fi

group "xargs: err(3) in the vfork'd child"

# err(3) between vfork and exec runs atexit/stdio cleanup in the shared
# address space; replaced with warn(3) + _exit(1).  Triggered when the
# command cannot be executed.
if require "xargs" xargs; then
    assert_no_crash "xargs with a nonexistent command" sh -c \
        "echo x | $(tool xargs) /nonexistent/command/xyz >/dev/null 2>&1"
    assert_out "xargs still works" "a b" sh -c "printf 'a\nb\n' | $(tool xargs) $(tool echo)"
    assert_no_crash "xargs -n1 with a failing command" sh -c \
        "printf 'a\nb\n' | $(tool xargs) -n1 /nonexistent/command/xyz >/dev/null 2>&1"
fi

group "mcookie: stack buffer overflow in hex output"

# The hex loop wrote 2 * (sizeof(mdbuf) - 1) = 62 bytes plus NUL into a
# 32-byte stack buffer and read 31 bytes from a 16-byte MD5 digest.
# Caught by _FORTIFY_SOURCE=3 as an abort.
if require "mcookie" mcookie; then
    assert_no_crash "mcookie runs without a fortify abort" "$(tool mcookie)"
    out=$("$(tool mcookie)" 2>/dev/null)
    len=$(printf '%s' "$out" | wc -c | tr -d ' ')
    assert_eq "mcookie emits 32 hex digits" "32" "$len"
    case $out in
        *[!0-9a-f]*) fail "mcookie output is hex" "got [$out]" ;;
        *) pass "mcookie output is hex" ;;
    esac
fi

group "ee: unchecked allocations and fopen"

if require "ee" ee; then
    # ee is a full-screen editor; without a terminal it should decline
    # cleanly rather than crash.
    assert_no_crash "ee without a terminal" sh -c \
        "$(tool ee) /dev/null < /dev/null > /dev/null 2>&1"
fi

group "tail: r_buf on empty input"

if require "tail" tail; then
    : > empty.txt
    assert_no_crash "tail -r on an empty file" "$(tool tail)" -r empty.txt
    assert_no_crash "tail -r on an empty pipe" sh -c ": | $(tool tail) -r >/dev/null"
    printf '1\n2\n3\n' > tl.txt
    assert_out "tail -r reverses" "3
2
1" "$(tool tail)" -r tl.txt
fi

group "stty: csearch with a missing argument"

if require "stty" stty; then
    assert_no_crash "stty intr with no argument" sh -c \
        "$(tool stty) intr < /dev/null > /dev/null 2>&1"
fi

group "sed: compile_stream on a script ending in ';'"

if require "sed" sed; then
    assert_no_crash "sed script ending in a semicolon" sh -c \
        "printf 's/a/b/;' > sc.sed; echo a | $(tool sed) -f sc.sed >/dev/null 2>&1"
    assert_no_crash "sed empty script" sh -c \
        ": > empty.sed; echo a | $(tool sed) -f empty.sed >/dev/null 2>&1"
    assert_out "sed still substitutes" "b" sh -c "echo a | $(tool sed) 's/a/b/'"
fi

cu_finish
