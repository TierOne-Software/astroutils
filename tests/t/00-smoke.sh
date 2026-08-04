#!/bin/sh
# Basic functional smoke tests — does each tool do its primary job?
# Supersedes zig-build-smoke.sh; kept deliberately shallow, the point is
# to catch a tool that is broken outright, not to test every option.

. "$CU_LIB/lib.sh"

group "core file and text tools"

if require "echo/true/false" echo true false; then
    assert_out "echo" "hello" "$(tool echo)" hello
    assert_status "true exits 0" 0 "$(tool true)"
    assert_status "false exits 1" 1 "$(tool false)"
fi

if require "basename/dirname" basename dirname; then
    assert_out "basename" "baz" "$(tool basename)" /foo/bar/baz
    assert_out "dirname" "/foo/bar" "$(tool dirname)" /foo/bar/baz
    assert_out "basename with suffix" "baz" "$(tool basename)" /foo/baz.txt .txt
fi

if require "cat" cat; then
    printf 'hi\n' > in.txt
    assert_out "cat file" "hi" "$(tool cat)" in.txt
    printf 'a\nb\n' > two.txt
    assert_out "cat -n" "     1	a
     2	b" "$(tool cat)" -n two.txt
fi

if require "head/tail" head tail; then
    printf '1\n2\n3\n4\n5\n' > nums.txt
    assert_out "head -1" "1" "$(tool head)" -1 nums.txt
    assert_out "tail -1" "5" "$(tool tail)" -1 nums.txt
    assert_out "tail -r" "5" sh -c "$(tool tail) -r nums.txt | $(tool head) -1"
fi

if require "wc" wc; then
    printf 'a b c\nd e f\n' > wc.txt
    assert_out "wc -l" "2" sh -c "$(tool wc) -l < wc.txt | tr -d ' '"
    assert_out "wc -w" "6" sh -c "$(tool wc) -w < wc.txt | tr -d ' '"
fi

if require "cut" cut; then
    assert_out "cut -d -f" "b" sh -c "echo a:b:c | $(tool cut) -d: -f2"
    assert_out "cut -c" "bc" sh -c "echo abcd | $(tool cut) -c2-3"
fi

if require "sort/uniq" sort uniq; then
    assert_out "sort" "1" sh -c "printf '3\n1\n2\n' | $(tool sort) | $(tool head) -1"
    assert_out "sort -n" "2" sh -c "printf '10\n2\n' | $(tool sort) -n | $(tool head) -1"
    assert_out "uniq" "a" sh -c "printf 'a\na\nb\n' | $(tool uniq) | $(tool head) -1"
    assert_out "uniq -c" "2 a" sh -c "printf 'a\na\n' | $(tool uniq) -c | tr -s ' ' | sed 's/^ //'"
fi

if require "tr" tr; then
    assert_out "tr upper" "ABC" sh -c "echo abc | $(tool tr) a-z A-Z"
    assert_out "tr -d" "ac" sh -c "echo abc | $(tool tr) -d b"
fi

if require "grep" grep; then
    printf 'foo\nbar\nbaz\n' > g.txt
    assert_out "grep match" "foo" "$(tool grep)" foo g.txt
    assert_out "grep -c" "2" "$(tool grep)" -c 'ba' g.txt
    assert_out "grep -v" "foo" sh -c "$(tool grep) -v 'ba' g.txt"
    assert_status "grep -q no match" 1 "$(tool grep)" -q nomatch g.txt
    assert_out "grep -E" "baz" "$(tool grep)" -E 'b.z' g.txt
fi

if require "sed" sed; then
    assert_out "sed substitute" "b" sh -c "echo a | $(tool sed) s/a/b/"
    assert_out "sed delete" "b" sh -c "printf 'a\nb\n' | $(tool sed) '1d'"
fi

if require "awk" awk; then
    assert_out "awk arithmetic" "3" sh -c "echo '1 2' | $(tool awk) '{print \$1+\$2}'"
    assert_out "awk NR" "2" sh -c "printf 'a\nb\n' | $(tool awk) 'END{print NR}'"
    assert_out "awk field sep" "b" sh -c "echo a:b | $(tool awk) -F: '{print \$2}'"
fi

group "file management"

if require "cp/mv/rm" cp mv rm; then
    printf 'data\n' > src.txt
    assert_ok "cp" "$(tool cp)" src.txt copy.txt
    assert_out "cp content preserved" "data" "$(tool cat)" copy.txt
    assert_ok "mv" "$(tool mv)" copy.txt moved.txt
    assert_ok "rm" "$(tool rm)" moved.txt
    assert_status "rm removed it" 1 test -f moved.txt
fi

if require "mkdir/rmdir" mkdir rmdir; then
    assert_ok "mkdir -p" "$(tool mkdir)" -p a/b/c
    assert_ok "created nested" test -d a/b/c
    assert_ok "rmdir" "$(tool rmdir)" a/b/c
fi

if require "ln" ln; then
    printf 'x\n' > link-target.txt
    assert_ok "ln -s" "$(tool ln)" -s link-target.txt symlink.txt
    assert_ok "symlink resolves" test -L symlink.txt
fi

if require "ls" ls; then
    assert_contains "ls lists a file" "in.txt" "$(tool ls)" .
    assert_ok "ls -l" "$(tool ls)" -l .
fi

if require "find" find; then
    assert_contains "find -name" "in.txt" "$(tool find)" . -name in.txt
    assert_ok "find -type f" "$(tool find)" . -type f
fi

if require "xargs" xargs; then
    assert_out "xargs echo" "a b" sh -c "printf 'a\nb\n' | $(tool xargs) $(tool echo)"
fi

group "misc"

if require "printf" printf; then
    assert_out "printf %d" "3" "$(tool printf)" '%d\n' 3
    assert_out "printf %s" "hi" "$(tool printf)" '%s\n' hi
fi

if require "expr" expr; then
    assert_out "expr arithmetic" "4" "$(tool expr)" 2 + 2
fi

if require "seq/jot" jot; then
    assert_out "jot count" "1
2
3" "$(tool jot)" 3
fi

if require "cksum" cksum; then
    printf 'hello\n' > ck.txt
    assert_ok "cksum" "$(tool cksum)" ck.txt
fi

if require "gzip" gzip; then
    assert_out "gzip roundtrip" "hi" sh -c "echo hi | $(tool gzip) -c | $(tool gzip) -dc"
fi

if require "cmp/diff" cmp; then
    printf 'a\n' > c1.txt; printf 'a\n' > c2.txt; printf 'b\n' > c3.txt
    assert_status "cmp identical" 0 "$(tool cmp)" c1.txt c2.txt
    assert_status "cmp differing" 1 "$(tool cmp)" c1.txt c3.txt
fi

if require "vis/unvis" vis unvis; then
    assert_out "vis/unvis roundtrip" "hello" sh -c "echo hello | $(tool vis) | $(tool unvis)"
fi

cu_finish
