#!/bin/sh
# Regression tests for the patch(1) parser defects in SECURITY-FINDINGS.md.
#
# patch(1) consumes fully attacker-controlled input (a diff), so every bug
# here is directly reachable.  These are the highest-severity findings in
# the tree; each test below fails on the pre-fix binary.

. "$CU_LIB/lib.sh"

require "patch regressions" patch || { cu_finish; exit; }

PATCH=$(tool patch)

# Fresh target file for each invocation: patch may rewrite or reject it.
mktarget() {
    printf 'alpha\nbravo\ncharlie\ndelta\necho\n' > "$1"
}

group "patch: unbounded hunk allocation (memory-exhaustion DoS)"

# An 89-byte context diff claiming a ~4e17-line hunk drove the unfixed
# binary to 16 GB RSS.  Two of the four hunkmax grow sites lacked the
# MAXHUNKSIZE check.  Post-fix it must reject the hunk immediately and
# comfortably inside a 256 MB address-space limit.
cat > dos-context.diff <<'EOF'
*** target.txt	2020-01-01
--- target.txt	2020-01-01
***************
*** 1,400000000000000000 ****
--- 1,1 ----
EOF
mktarget target.txt
assert_bounded "context diff with 4e17-line hunk stays bounded" 262144 \
    "$PATCH" -t -C -i dos-context.diff target.txt
# 64-bit: parsed fine, rejected as "hunk too large".  32-bit: does not
# fit LINENUM at all, rejected as "... is too large" at parse time.
# Either diagnostic proves a bounded rejection.
assert_contains "rejects oversized hunk with a diagnostic" "too large" \
    "$PATCH" -t -C -i dos-context.diff target.txt

# 2e9 lines: fits a 32-bit LINENUM, so the MAXHUNKSIZE check itself is
# what rejects it — the "hunk too large" diagnostic on every arch.
cat > dos-context-max.diff <<'EOF'
*** target.txt	2020-01-01
--- target.txt	2020-01-01
***************
*** 1,2000000000 ****
  alpha
--- 1,1 ----
EOF
mktarget target-max.txt
assert_contains "2e9-line hunk hits the hunk-size limit" "hunk too large" \
    "$PATCH" -t -C -i dos-context-max.diff target-max.txt

# Same class via the unified-diff @@ header path.
cat > dos-unified.diff <<'EOF'
--- target.txt	2020-01-01
+++ target.txt	2020-01-01
@@ -1,400000000000000000 +1,1 @@
-alpha
EOF
mktarget target2.txt
assert_bounded "unified diff with 4e17-line hunk stays bounded" 262144 \
    "$PATCH" -t -C -i dos-unified.diff target2.txt

group "patch: out-of-bounds read on malformed '--' line"

# pch.c evaluated p_char[p_end - 1] with p_end == 0 — a read before the
# allocation — when a context hunk began with a '--' line.
cat > oob-read.diff <<'EOF'
*** target.txt	2020-01-01
--- target.txt	2020-01-01
***************
--
*** 1,1 ****
EOF
mktarget target3.txt
assert_no_crash "malformed '--' before any hunk line" \
    "$PATCH" -t -C -i oob-read.diff target3.txt

group "patch: empty hunk lines (p_len underflow -> OOB write)"

# remove_special_line() did p_len[x] -= 1 on an empty line, wrapping to
# SIZE_MAX and then writing a NUL out of bounds (six sites).
printf '*** target.txt\n--- target.txt\n***************\n*** 1,3 ****\n\n\n\n--- 1,3 ----\n\n\n\n' > empty-lines.diff
mktarget target4.txt
assert_no_crash "context hunk of empty lines" \
    "$PATCH" -t -C -i empty-lines.diff target4.txt

printf -- '--- target.txt\n+++ target.txt\n@@ -1,2 +1,2 @@\n\n\n' > empty-unified.diff
mktarget target5.txt
assert_no_crash "unified hunk of empty lines" \
    "$PATCH" -t -C -i empty-unified.diff target5.txt

group "patch: stale p_len on header lines (OOB write)"

# Header lines assigned p_line[]/p_char[] but not p_len[], so a later
# remove_special_line() rewrite used a length left over from a previous
# hunk.  Needs two hunks: a long one, then a short one.
{
    printf '*** target.txt\n--- target.txt\n***************\n'
    printf '*** 1,2 ****\n! aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n! bbbb\n'
    printf -- '--- 1,2 ----\n! cccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n! dddd\n'
    printf '***************\n'
    printf '*** 4,4 ****\n! x\n'
    printf -- '--- 4,4 ----\n! y\n'
} > stale-len.diff
mktarget target6.txt
assert_no_crash "long hunk followed by short hunk" \
    "$PATCH" -t -C -i stale-len.diff target6.txt

group "patch: zero-length pattern line under-read in patch_match"

# patch_match() indexed plineptr[plinelen - 1] to test for a trailing
# newline on the last line of the file, under an upstream comment
# asserting "plinelen > 0".  A malformed hunk can leave a zero-length
# line, making that a read one byte *before* the allocation.  Invisible
# on a normal build (it reads adjacent heap); the sanitizer job is what
# fails.  Needs the hunk to reach the final line of the target.
mktarget target7.txt
{
    printf -- '--- target7.txt\n+++ target7.txt\n'
    printf '@@ -5,1 +5,1 @@\n'
    printf '\n'
    printf '+replaced\n'
} > zerolen.diff
assert_no_crash "zero-length pattern line at end of file" \
    "$PATCH" -t -C -i zerolen.diff target7.txt

group "patch: NULL pattern line dereference in patch_match (apply path)"

# Found by replaying the fuzz corpus through the real binary rather than
# the parse-only harness.  The "old lines were omitted" path advances
# p_end past slots the fill never reaches, leaving p_line[] entries NULL
# while p_ptrn_lines still counts them; patch_match() then passed NULL to
# strncmp.  Every input in tests/data/crashers/patch segfaulted the
# pre-fix binary.
crashers=$CU_SRCDIR/tests/data/crashers/patch
if [ -d "$crashers" ]; then
    n=0
    bad=0
    for c in "$crashers"/*; do
        [ -f "$c" ] || continue
        n=$((n + 1))
        mktarget crash-target.txt
        CU_MEMLIMIT=1048576 cu_run_limited "$PATCH" -t -C -i "$c" crash-target.txt >/dev/null 2>&1
        st=$?
        if [ "$st" -gt 128 ] && [ "$st" -ne 152 ]; then
            bad=$((bad + 1))
            [ "$bad" -le 3 ] && printf '       crashed (status %s) on %s\n' "$st" "$(basename "$c")"
        fi
    done
    if [ "$n" -eq 0 ]; then
        skip "known patch crashers" "fixture directory empty"
    elif [ "$bad" -eq 0 ]; then
        pass "$n known crash inputs all handled without a signal"
    else
        fail "$n known crash inputs" "$bad still crash"
    fi
else
    skip "known patch crashers" "tests/data/crashers/patch missing"
fi

group "patch: still applies valid diffs"

# The guards above must not have broken ordinary operation.
mktarget good.txt
cat > good.diff <<'EOF'
--- good.txt	2020-01-01
+++ good.txt	2020-01-01
@@ -1,3 +1,3 @@
 alpha
-bravo
+BRAVO
 charlie
EOF
assert_ok "applies a valid unified diff" "$PATCH" -t -i good.diff good.txt
assert_out "unified diff applied correctly" "BRAVO" \
    sh -c "$(tool sed) -n 2p good.txt"

mktarget goodc.txt
cat > goodc.diff <<'EOF'
*** goodc.txt	2020-01-01
--- goodc.txt	2020-01-01
***************
*** 1,3 ****
  alpha
! bravo
  charlie
--- 1,3 ----
  alpha
! BRAVO
  charlie
EOF
assert_ok "applies a valid context diff" "$PATCH" -t -i goodc.diff goodc.txt
assert_out "context diff applied correctly" "BRAVO" \
    sh -c "$(tool sed) -n 2p goodc.txt"

cu_finish
