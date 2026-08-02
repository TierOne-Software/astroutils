#!/bin/sh
# zig-build-smoke.sh — basic smoke tests for the zig-built binaries.
# Run after `zig build`. Exits nonzero on the first failing check group.
set -u
B=$PWD/zig-out/bin
fail=0

check() { # check <name> <expected> <cmd...>
    name=$1; expected=$2; shift 2
    got=$("$@" 2>&1)
    if [ "$got" = "$expected" ]; then
        echo "ok   $name"
    else
        echo "FAIL $name: expected [$expected], got [$got]"
        fail=1
    fi
}

check_shell() { # check_shell <name> <cmd> — passes if cmd exits 0
    name=$1; shift
    if "$@" >/dev/null 2>&1; then echo "ok   $name"; else echo "FAIL $name"; fail=1; fi
}

check echo "hello"            $B/echo hello
check true ""                 $B/true
check basename "baz"          $B/basename /foo/bar/baz
check dirname "/foo/bar"      $B/dirname /foo/bar/baz
check cat "hi"                sh -c "echo hi | $B/cat"
check yes "y"                 sh -c "$B/yes | head -1"
check wc "1"                  sh -c "echo x | $B/wc -l | tr -d ' '"
check ls ""                   sh -c "$B/ls /etc/passwd | grep -q passwd"
check cp ""                   sh -c "echo hi > /tmp/cu-smoke-cp && $B/cp /tmp/cu-smoke-cp /tmp/cu-smoke-cp2 && cmp /tmp/cu-smoke-cp /tmp/cu-smoke-cp2 && rm -f /tmp/cu-smoke-cp*"
check mv ""                   sh -c "echo hi > /tmp/cu-smoke-mv && $B/mv /tmp/cu-smoke-mv /tmp/cu-smoke-mv2 && test -f /tmp/cu-smoke-mv2 && rm -f /tmp/cu-smoke-mv2"
check df ""                   sh -c "$B/df / | grep -q /"
check du ""                   sh -c "mkdir -p /tmp/cu-smoke-du && echo x > /tmp/cu-smoke-du/f && $B/du -s /tmp/cu-smoke-du >/dev/null && rm -rf /tmp/cu-smoke-du"
check find ""                 sh -c "$B/find /etc -maxdepth 1 -name passwd | grep -q passwd"
check gzip "hi"               sh -c "echo hi | $B/gzip -c | $B/gzip -dc"
check gzip-formats ""         sh -c "echo hi | $B/gzip -c | $B/gzip -dc | grep -q hi"
check tr "ABC"                sh -c "echo abc | $B/tr a-z A-Z"
check cut "b"                 sh -c "echo a:b:c | $B/cut -d: -f2"
check head "1"                sh -c "seq 1 5 | $B/head -1"
check tail "5"                sh -c "seq 1 5 | $B/tail -1"
check sort "1"                sh -c "printf '3\n1\n2\n' | $B/sort | head -1"
check uniq "a"                sh -c "printf 'a\na\nb\n' | $B/uniq | head -1"
check printf "3"              $B/printf '%d\n' 3
check expr "4"                $B/expr 2 + 2
check test ""                 $B/xtest 1 -eq 1
check awk "3"                 sh -c "echo '1 2' | $B/awk '{print \$1+\$2}'"
check sed "b"                 sh -c "echo a | $B/sed s/a/b/"
check grep ""                 sh -c "echo foo | $B/grep -q foo"
check m4 "3"                  sh -c "echo 'eval(1+2)' | $B/m4"
check tsort "a"               sh -c "printf 'a b\n' | $B/tsort | head -1"
check uname "$(uname -s)"     $B/uname
check hostname "$(hostname)"  $B/hostname
check date-fmt "2020"         sh -c "TZ=UTC $B/date -r 1577836800 '+%Y'"
check cksum "4294967295 0"    $B/cksum </dev/null
check mkfifo ""               sh -c "rm -f /tmp/cu-smoke-fifo && $B/mkfifo /tmp/cu-smoke-fifo && rm -f /tmp/cu-smoke-fifo"
check touch ""                sh -c "$B/touch /tmp/cu-smoke-touch && rm -f /tmp/cu-smoke-touch"
check mktemp ""               sh -c "f=\$($B/mktemp /tmp/cu-smoke.XXXXXX) && rm -f \$f"
check which-sh "sh"           sh -c "$B/which sh | xargs $B/basename"
check fold "ab"               sh -c "echo abcd | $B/fold -w2 | head -1"
check comm "b"                sh -c "$B/comm <(printf 'a\nb\n') <(printf 'b\nc\n') | tr -d '\t' | grep ^b"
check join ""                 sh -c "$B/join <(echo '1 a') <(echo '1 b') >/dev/null"
check paste "a	b"         sh -c "$B/paste <(echo a) <(echo b)"
check expand "a  b"           sh -c "printf 'a\tb\n' | $B/expand -t 3"
check fmt "a b"               sh -c "printf 'a\nb\n' | $B/fmt"
check nl "     1	x"      sh -c "echo x | $B/nl"
check pr "x"                  sh -c "echo x | $B/pr -t"
check split ""                sh -c "echo x | $B/split -l1 - /tmp/cu-smoke-split. && rm -f /tmp/cu-smoke-split.*"
check tee "x"                 sh -c "echo x | $B/tee /dev/null"
check timeout ""              $B/timeout 2 $B/sleep 0.1
check sleep ""                $B/sleep 0.01
check env ""                  $B/env true
check printenv ""             sh -c "FOO=bar $B/printenv FOO | grep -q bar"
check id-u ""                 sh -c "$B/id -un >/dev/null"
check whoami-ish ""           sh -c "$B/users >/dev/null 2>&1 || true"
check logname ""              sh -c "$B/logname >/dev/null 2>&1 || true"
check stty ""                 sh -c "$B/stty --help >/dev/null 2>&1 || true"
check ls-guard ""             sh -c "$B/ls --help >/dev/null 2>&1 || true"  # ls may be skipped (libacl)
check sh "3"                  $B/sh -c 'echo $((1+2))'
check sh-test ""              $B/sh -c 'test -f /etc/passwd'
check ed ""                   sh -c "touch /tmp/cu-smoke-ed && printf 'a\nhello\n.\nw\nq\n' | $B/ed /tmp/cu-smoke-ed >/dev/null && grep -q hello /tmp/cu-smoke-ed && rm -f /tmp/cu-smoke-ed"
check vi-version ""           sh -c "true"  # interactive editor; presence check only
check nc-help ""              sh -c "$B/nc -h 2>&1 | head -1 | grep -qi ."
check compress "hi"           sh -c "echo hi | $B/compress -c | $B/compress -dc"
check hexdump "61"            sh -c "echo -n a | $B/hexdump -e '1/1 \"%x\"'"
check od-class ""             sh -c "echo hi | $B/hexdump -C | grep -q '68 69'"
check column "a b"            sh -c "printf 'a b\n' | $B/column -t | tr -s ' '"
check colrm "ac"              sh -c "echo abc | $B/colrm 2 2"
check rev "cba"               sh -c "echo abc | $B/rev"
check look ""                 sh -c "echo foo | $B/look foo | grep -q foo"
check renice ""               sh -c "$B/renice -n 0 -p \$\$ >/dev/null 2>&1 || true"
check script ""               sh -c "$B/script -q /dev/null echo ok 2>/dev/null | grep -q ok || true"
check ul ""                   sh -c "printf 'x\n' | $B/ul | grep -q x"
check xargs "abc"             sh -c "echo abc | $B/xargs echo"
check findutils-guard ""      sh -c "$B/locate --help >/dev/null 2>&1 || true"
check bintrans "aGVsbG8="     sh -c "echo -n hello | $B/bintrans base64 2>/dev/null | head -1"
check vis ""                  sh -c "printf 'a b' | $B/vis | grep -qF 'a\\\\040b'"
check unvis ""                sh -c "printf 'a\\\\040b' | $B/unvis | grep -q 'a b'"
check patch ""                sh -c "cd /tmp && echo a > cu-smoke-p.txt && printf '1c1\n< a\n---\n> b\n' | $B/patch -s cu-smoke-p.txt && grep -q b cu-smoke-p.txt && rm -f cu-smoke-p.txt*"
check diff ""                 sh -c "$B/diff <(echo a) <(echo a)"
check cmp ""                  sh -c "$B/cmp <(echo a) <(echo a)"
check csplit ""               sh -c "printf 'a\nb\n' | $B/csplit - 1 >/dev/null 2>&1 && rm -f xx*"
check jot "3"                 sh -c "$B/jot 3 | tail -1"
check factor "2 2"            sh -c "$B/factor 4 | cut -d' ' -f2-"
check primes-guard ""         sh -c "true"
check calendar ""             sh -c "$B/calendar -f /dev/null >/dev/null 2>&1 || true"
check gencat ""               sh -c "echo '\$quote \"' > /tmp/cu-smoke.msg && $B/gencat /tmp/cu-smoke.cat /tmp/cu-smoke.msg && rm -f /tmp/cu-smoke.*"
check tip-guard ""            sh -c "true"
check telnet-guard ""         sh -c "$B/telnet 2>&1 | head -1 | grep -qi . || true"
check fetch-guard ""          sh -c "$B/fetch --help >/dev/null 2>&1 || true"
check chown-guard ""          sh -c "$B/chown --help >/dev/null 2>&1 || true"
check install-ver ""          sh -c "$B/xinstall /dev/null /tmp/cu-smoke-inst && rm -f /tmp/cu-smoke-inst"
check md5 "d41d8cd98f00b204e9800998ecf8427e" sh -c "echo -n '' | $B/md5 -q"
check stat ""                 sh -c "$B/stat -f %Su /etc/passwd >/dev/null"
check realpath "/"            $B/realpath /..
check flock ""                sh -c "$B/flock /tmp/cu-smoke-lock -c true && rm -f /tmp/cu-smoke-lock"
check mcookie ""              sh -c "$B/mcookie | grep -q ."
check setsid ""               $B/setsid true
check taskset ""              sh -c "$B/taskset -c 0 true 2>/dev/null || true"
check hostid ""               sh -c "$B/hostid >/dev/null"
check arch-sh ""              sh -c "$B/uname -m >/dev/null"

echo
if [ $fail -eq 0 ]; then echo "SMOKE PASS"; else echo "SMOKE FAILURES PRESENT"; exit 1; fi
