#!/bin/sh
# Verify that built binaries actually carry the hardening the build system
# claims to enable, so a flag silently dropped by a compiler probe or a
# meson refactor is caught mechanically rather than by review.
#
# Two tiers:
#   enforced  — mitigations this tree has committed to; a regression fails
#               the job.
#   reported  — mitigations on the roadmap (PLAN.md P3) but not yet
#               enabled.  Printed as informational counts, and enforced
#               too when HARDENING_STRICT=1, which is how the gate gets
#               turned on once the flags land.
set -eu

cd "$(dirname "$0")/../.."

BUILD_DIR=${BUILD_DIR:-build-ci}
HARDENING_STRICT=${HARDENING_STRICT:-0}

if [ ! -d "$BUILD_DIR" ]; then
    printf 'hardening-check: %s does not exist; run a build job first\n' "$BUILD_DIR" >&2
    exit 2
fi

readelf_bin=$(command -v readelf || command -v llvm-readelf || true)
if [ -z "$readelf_bin" ]; then
    printf 'hardening-check: no readelf available; skipping\n' >&2
    exit 0
fi

# Collect the built tools (skip meson's own probe binaries and objects).
bins=$(find "$BUILD_DIR" -type f -perm -u+x \
        ! -path '*.p/*' ! -path '*meson-private*' \
        ! -name '*.so' ! -name '*.so.*' ! -name '*.a' ! -name '*.exe' \
        2>/dev/null | sort)

total=0
n_ssp=0; n_fortify=0; n_pie=0; n_relro=0; n_now=0
no_ssp=; no_pie=; no_relro=; no_now=

for b in $bins; do
    file "$b" 2>/dev/null | grep -q 'ELF' || continue
    total=$((total + 1))

    dyn=$("$readelf_bin" -d "$b" 2>/dev/null || true)
    hdr=$("$readelf_bin" -lh "$b" 2>/dev/null || true)
    sym=$("$readelf_bin" -sW "$b" 2>/dev/null || true)

    # Stack protector: the guard-failure handler is linked in.
    if printf '%s' "$sym" | grep -q '__stack_chk_fail'; then
        n_ssp=$((n_ssp + 1))
    else
        no_ssp="$no_ssp $(basename "$b")"
    fi

    # _FORTIFY_SOURCE: at least one checked libc entry point.  Not every
    # tool calls a fortifiable function, so this is counted, not required
    # per binary.
    printf '%s' "$sym" | grep -qE '__[a-z_]+_chk' && n_fortify=$((n_fortify + 1))

    # PIE: ET_DYN with an INTERP segment (a shared library is also DYN).
    if printf '%s' "$hdr" | grep -q 'Type:[[:space:]]*DYN' &&
       printf '%s' "$hdr" | grep -q 'INTERP'; then
        n_pie=$((n_pie + 1))
    else
        no_pie="$no_pie $(basename "$b")"
    fi

    # RELRO and BIND_NOW.
    if printf '%s' "$hdr" | grep -q 'GNU_RELRO'; then
        n_relro=$((n_relro + 1))
    else
        no_relro="$no_relro $(basename "$b")"
    fi
    if printf '%s' "$dyn" | grep -qE 'BIND_NOW|FLAGS_1.*NOW'; then
        n_now=$((n_now + 1))
    else
        no_now="$no_now $(basename "$b")"
    fi
done

if [ "$total" -eq 0 ]; then
    printf 'hardening-check: no ELF binaries found in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

printf '=== hardening report over %s binaries\n' "$total"
printf '  stack protector : %s/%s\n' "$n_ssp" "$total"
printf '  fortify (_chk)  : %s/%s (informational — not every tool calls one)\n' "$n_fortify" "$total"
printf '  PIE             : %s/%s\n' "$n_pie" "$total"
printf '  RELRO (partial) : %s/%s\n' "$n_relro" "$total"
printf '  BIND_NOW        : %s/%s (RELRO is only "full" with this)\n' "$n_now" "$total"

status=0

# --- enforced ---------------------------------------------------------

# -fstack-protector-strong instruments only functions that actually have
# stack buffers, so trivial tools (true, yes, sync, tty...) legitimately
# have no canary and a whole-tree percentage would be measuring program
# complexity rather than build flags.  Enforce instead on tools that
# certainly do use stack buffers — if the flag stops reaching the compile
# line, every one of these loses its canary at once.
ssp_required="patch grep sed awk ls cp vi hexdump find sort"
ssp_missing=
ssp_checked=0
for t in $ssp_required; do
    b=$(printf '%s\n' $bins | grep "/$t\$" | head -1)
    [ -n "$b" ] || continue
    ssp_checked=$((ssp_checked + 1))
    "$readelf_bin" -sW "$b" 2>/dev/null | grep -q '__stack_chk_fail' || \
        ssp_missing="$ssp_missing $t"
done
if [ "$ssp_checked" -eq 0 ]; then
    printf 'WARN: none of the stack-protector reference tools were built\n'
elif [ -n "$ssp_missing" ]; then
    printf 'FAIL: buffer-using tools without a stack canary:%s\n' "$ssp_missing"
    printf '      -fstack-protector-strong is not reaching the compile line\n'
    status=1
else
    printf 'ok: stack protector on all %s reference tools (%s/%s tree-wide)\n' \
        "$ssp_checked" "$n_ssp" "$total"
fi

if [ "$n_fortify" -eq 0 ]; then
    printf 'FAIL: no binary references a fortified libc entry point —\n'
    printf '      _FORTIFY_SOURCE is probably not reaching the compile line\n'
    status=1
else
    printf 'ok: fortified entry points present on %s/%s\n' "$n_fortify" "$total"
fi

# --- enforced: PIE / RELRO / BIND_NOW (landed in P3) -------------------

require_all() {
    _label=$1; _have=$2; _missing=$3
    if [ "$_have" -eq "$total" ]; then
        printf 'ok: %s on all %s\n' "$_label" "$total"
    else
        printf 'FAIL: %s missing on %s binaries:%s\n' \
            "$_label" "$((total - _have))" "$(printf '%s' "$_missing" | cut -c1-200)"
        status=1
    fi
}

require_all "PIE" "$n_pie" "$no_pie"
require_all "RELRO" "$n_relro" "$no_relro"
require_all "BIND_NOW" "$n_now" "$no_now"

# --- roadmap -----------------------------------------------------------
# Future mitigations land here first: reported as TODO, enforced under
# HARDENING_STRICT=1, then moved to require_all above once adopted.

# --- sandbox engagement ----------------------------------------------
# A sandboxed tool must actually be running under seccomp filter mode;
# the behavioral suite cannot tell the shim apart from the stub.  Skip
# when the escape hatch is set; report TODO (not FAIL) when the runtime
# lacks Landlock/seccomp (the tool then exits immediately).
if [ -z "${ASTROUTILS_SANDBOX:-}" ]; then
    sb_bin=$(printf '%s\n' $bins | grep '/yes$' | head -1)
    if [ -n "$sb_bin" ]; then
        "$sb_bin" >/dev/null 2>&1 &
        sb_pid=$!
        sleep 1
        if [ -d "/proc/$sb_pid" ]; then
            sb_sec=$(awk '/^Seccomp:/ {print $2}' "/proc/$sb_pid/status")
            if [ "$sb_sec" = "2" ]; then
                printf 'ok: sandboxed tool is under seccomp filter mode\n'
            else
                printf 'FAIL: %s running with Seccomp: %s — sandbox not engaged\n' \
                    "$(basename "$sb_bin")" "$sb_sec"
                status=1
            fi
            kill "$sb_pid" 2>/dev/null || true
            # wait returns 128+SIGTERM for the killed tool; under set -e
            # that would abort the script before the successful exit below.
            wait "$sb_pid" 2>/dev/null || true
        else
            printf 'TODO: sandbox check skipped (tool exited; runtime lacks Landlock/seccomp?)\n'
        fi
    fi
fi

exit $status
