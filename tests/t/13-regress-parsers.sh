#!/bin/sh
# Regression tests for the shared parsers in src.freebsd/compat and the
# date parser — the code the fuzz harnesses target, exercised here through
# the real tools so the suite needs no libFuzzer build.

. "$CU_LIB/lib.sh"

group "unvis: signed-shift UB on high-byte escapes"

# (*cp << 3) / (*cp << 4) overflowed signed char for escapes above \177.
if require "unvis/vis" unvis vis; then
    # Decode a vis-encoded escape and report the resulting bytes in hex.
    # Written through files rather than nested sh -c so the backslashes
    # survive exactly one level of shell quoting.
    unvis_hex() {
        printf '%s' "$1" > esc.in
        "$(tool unvis)" < esc.in > esc.out 2>/dev/null
        od -An -tx1 < esc.out | tr -d ' \n'
    }

    assert_eq "octal escape above \\177" "ff" "$(unvis_hex '\377')"
    assert_eq "octal escape \\200" "80" "$(unvis_hex '\200')"
    assert_eq "octal escape \\377 upper bound" "ff" "$(unvis_hex '\377')"
    assert_eq "hex escape \\xff" "ff" "$(unvis_hex '\xff')"
    assert_eq "meta escape \\M^?" "ff" "$(unvis_hex '\M^?')"

    # NetBSD 1.45 S_NUMBER botch: `*cp += (*cp * 10) + d` computed
    # cp*11 + d, corrupting every &#NN; entity with >= 2 digits.
    unvis_http1866_hex() {
        printf '%s' "$1" > esc.in
        "$(tool unvis)" -H < esc.in > esc.out 2>/dev/null
        od -An -tx1 < esc.out | tr -d ' \n'
    }
    assert_eq "numeric entity &#65;" "41" "$(unvis_http1866_hex '&#65;')"
    assert_eq "numeric entity &#233;" "e9" "$(unvis_http1866_hex '&#233;')"
    assert_eq "numeric entity &#1;" "01" "$(unvis_http1866_hex '&#1;')"
    assert_eq "numeric entity &#256; rejected" "3b" \
        "$(unvis_http1866_hex '&#256;')"

    # Round-trip every byte value: vis must encode and unvis decode back
    # to exactly the same bytes.  This covers the whole escape table.
    awk 'BEGIN{for(i=1;i<256;i++)printf "%c",i}' > allbytes.bin
    cu_run_limited sh -c "$(tool vis) < allbytes.bin | $(tool unvis) > roundtrip.bin" 2>/dev/null
    if cmp -s allbytes.bin roundtrip.bin 2>/dev/null; then
        pass "vis/unvis round-trips all byte values 1..255"
    else
        fail "vis/unvis round-trips all byte values 1..255" \
            "output differs from input"
    fi

    for enc in -c -o -h -m; do
        assert_no_crash "vis $enc encoding round-trip" sh -c \
            "$(tool vis) $enc < allbytes.bin | $(tool unvis) > /dev/null 2>&1"
    done

    assert_no_crash "unvis on truncated escape" sh -c \
        "printf '\\\\\\\\' | $(tool unvis) >/dev/null 2>&1"
    assert_no_crash "unvis on incomplete hex escape" sh -c \
        "printf '\\\\\\\\x4' | $(tool unvis) >/dev/null 2>&1"
fi

group "setmode: symbolic mode parser (via chmod)"

if require "chmod" chmod; then
    : > m.txt
    assert_ok "numeric mode" "$(tool chmod)" 644 m.txt
    assert_ok "symbolic mode" "$(tool chmod)" u+rwx,go-rwx m.txt
    assert_ok "mode with X" "$(tool chmod)" a+X m.txt
    assert_ok "mode with =" "$(tool chmod)" u=rw m.txt
    assert_ok "multiple clauses" "$(tool chmod)" u+r,g+w,o-x m.txt

    # Malformed modes must be rejected cleanly, not crash the parser.
    for bad in '+' 'u+' ',,,' 'z+r' 'u+z' '8888' 'u+rwxrwxrwxrwx' '=' '+++'; do
        assert_no_crash "rejects malformed mode [$bad]" \
            "$(tool chmod)" -- "$bad" m.txt
    done
fi

group "getdate: signed overflow and localtime NULL derefs (via find)"

# Fuzzing found signed-overflow UB in the date arithmetic and NULL derefs
# when localtime() fails on an out-of-range time_t, reachable with huge
# numbers.  getdate is now built with -fwrapv.
if require "find" find; then
    mkdir -p dated && : > dated/f

    assert_ok "relative date" "$(tool find)" dated -maxdepth 0 -newermt "1 hour ago"
    assert_ok "absolute date" "$(tool find)" dated -maxdepth 0 -newermt "2020-01-01"
    assert_ok "date with time" "$(tool find)" dated -maxdepth 0 -newermt "2020-01-01 12:00:00"

    # Out-of-range and malformed dates: reject, do not crash.
    for d in \
        "99999999999999999999 years ago" \
        "999999999999999999 seconds" \
        "-99999999999999999999" \
        "9999999999-99-99" \
        "0000-00-00 00:00:00" \
        "99999999999999999999/99999999999999999999" \
        "Jan 99999999999999999999" \
        "999999999999999999999999 days ago" \
        "@99999999999999999999" \
        ""; do
        assert_no_crash "rejects out-of-range date [$(printf '%.24s' "$d")]" \
            "$(tool find)" dated -maxdepth 0 -newermt "$d"
    done
fi

group "mktemp: padchar indexed with its NUL"

# _gettemp() used sizeof(padchar) including the terminator, planting '\0'
# in templates and over-reading the global by one byte on the EEXIST carry
# path.  Generated names must contain only characters from the pad set.
if require "mktemp" mktemp; then
    ok=1
    i=0
    while [ "$i" -lt 30 ]; do
        n=$("$(tool mktemp)" -u "tmpXXXXXXXXXX" 2>/dev/null)
        case $n in
            tmp*[!0-9a-zA-Z]*) ok=0; break ;;
            tmp??????????) ;;
            *) ok=0; break ;;
        esac
        i=$((i + 1))
    done
    if [ "$ok" -eq 1 ]; then
        pass "mktemp templates use only alphanumeric pad characters"
    else
        fail "mktemp templates use only alphanumeric pad characters" "got [$n]"
    fi

    assert_ok "mktemp creates a file" sh -c \
        "f=\$($(tool mktemp) tmp.XXXXXX) && test -f \"\$f\" && rm -f \"\$f\""

    # Exhaust a tiny template so the EEXIST carry path runs.
    mkdir -p mtdir
    assert_no_crash "mktemp under template collision pressure" sh -c \
        "i=0; while [ \$i -lt 40 ]; do $(tool mktemp) mtdir/tXX >/dev/null 2>&1; i=\$((i+1)); done; true"
fi

group "compat: string and conversion helpers under load"

if require "printf" printf; then
    assert_no_crash "printf with many conversions" sh -c \
        "$(tool printf) '%s %d %x %o %c\n' a 1 255 8 z >/dev/null 2>&1"
    assert_no_crash "printf with a malformed format" sh -c \
        "$(tool printf) '%' >/dev/null 2>&1"
    assert_no_crash "printf with excess arguments" sh -c \
        "$(tool printf) '%s\n' a b c d e >/dev/null 2>&1"
fi

cu_finish
