#!/bin/sh
# Sandbox (capsicum shim) tests.  The shim is Landlock + seccomp-BPF;
# enforcement is required by default, ASTROUTILS_SANDBOX=NONE disables.

. "$CU_LIB/lib.sh"

group "capsicum shim: enforcement and stub mode"

sandbox_available=1
if require "shimtest" shimtest; then
    run_shimtest() {
        _name=$1; shift
        _out=$("$@" 2>&1); _rc=$?
        case $_rc in
            0)  pass "$_name" ;;
            77) skip "$_name" "sandbox unavailable on this runtime" ;;
            *)  fail "$_name" "$_out" ;;
        esac
        return $_rc
    }

    run_shimtest "shimtest: full lockdown enforced" "$(tool shimtest)"
    [ $? -eq 77 ] && sandbox_available=0
    run_shimtest "shimtest: casper read-only mode enforced" \
        "$(tool shimtest)" casper
    run_shimtest "shimtest: ASTROUTILS_SANDBOX=NONE disables" \
        env ASTROUTILS_SANDBOX=NONE "$(tool shimtest)" stub
fi

group "capsicum shim: sandboxed tools still work"

# These tools run their main loops inside the sandbox now; the checks
# below double as the over-restriction regression test.  Where the
# runtime lacks Landlock/seccomp (e.g. qemu-user), the tools fail by
# design -- skip rather than fail there.
printf 'alpha\nbeta\n' > input.txt

if [ "$sandbox_available" = 0 ]; then
    skip "sandboxed tools" "sandbox unavailable on this runtime"
elif require "cat/tee" cat tee; then
    assert_out "sandboxed cat reads a named file" "alpha
beta" "$(tool cat)" input.txt

    assert_out "sandboxed cat reads stdin" "alpha
beta" sh -c "$(tool cat) < input.txt"

    assert_out "sandboxed tee writes pre-opened output" "alpha
beta" sh -c "$(tool cat) input.txt | $(tool tee) tee.out" && \
        assert_out "tee output file correct" "alpha
beta" "$(tool cat)" tee.out
fi

if [ "$sandbox_available" = 1 ] && require "md5" md5; then
    assert_contains "sandboxed md5 sums a named file" "input.txt" \
        "$(tool md5)" input.txt
fi

if [ "$sandbox_available" = 1 ] && require "wc" wc; then
    assert_out "sandboxed wc counts a named file" "2 2 11 input.txt" \
        sh -c "$(tool wc) input.txt | awk '{print \$1\" \"\$2\" \"\$3\" \"\$4}'"
fi

group "capsicum shim: escape hatch"

# With NONE the sandbox is a no-op; a named-file read via the casper
# tools must work identically.
if have cat; then
    assert_out "ASTROUTILS_SANDBOX=NONE keeps stub behavior" "alpha
beta" env ASTROUTILS_SANDBOX=NONE "$(tool cat)" input.txt
fi

group "capsicum shim: patch(1) path-scoped mode"

enforced=1
[ "$sandbox_available" = 0 ] && enforced=0
[ "${ASTROUTILS_SANDBOX:-}" = "NONE" ] && enforced=0

if [ "$enforced" = 0 ]; then
    skip "patch path-scoped mode" "sandbox not enforcing on this runtime"
elif require "patch" patch; then
    mkdir -p ptest ptest/tmp
    printf 'alpha\nbeta\n' > ptest/f.txt
    cat > ptest/ch.diff <<'EOF'
--- f.txt.orig	2020-01-01
+++ f.txt	2020-01-01
@@ -1,2 +1,2 @@
 alpha
-beta
+GAMMA
EOF
    assert_ok "sandboxed patch applies a patch" \
        sh -c "cd ptest && TMPDIR=\$PWD/tmp $(tool patch) f.txt < ch.diff"
    assert_out "patch result correct" "alpha
GAMMA" "$(tool cat)" ptest/f.txt

    # hostile: an absolute target path outside the allowed roots
    cat > ptest/evil.diff <<'EOF'
--- /dev/null	2020-01-01
+++ ../escape-marker.txt	2020-01-01
@@ -0,0 +1 @@
+pwned
EOF
    (
        cd ptest && TMPDIR="$PWD/tmp" \
            "$(tool patch)" -t -p0 < evil.diff >/dev/null 2>&1
    )
    if [ -e escape-marker.txt ]; then
        fail "path escape blocked" "escape-marker.txt was created"
        rm -f escape-marker.txt
    else
        pass "path escape blocked"
    fi
fi

cu_finish
