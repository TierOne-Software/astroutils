#!/bin/sh
# Build with zig and run the full suite against the result.
#
# The zig build is becoming the primary build system (src.safestr is
# implemented in zig), and its ReleaseSafe mode is what turned up several
# of the bugs in SECURITY-FINDINGS.md that the static analyzers missed
# (grep initqueue UB, nvi vs_crel/ex_subst, ...), so CI runs the suite
# against the UB-checking binaries, not just a plain build.
#
# Environment:
#   ZIG_OPTIMIZE   optimize mode (default: ReleaseSafe)
set -eu

cd "$(dirname "$0")/../.."

OPT=${ZIG_OPTIMIZE:-ReleaseSafe}

printf '=== zig-configure\n'
./zig-configure.sh

printf '=== zig build -Doptimize=%s\n' "$OPT"
zig build -Doptimize="$OPT"

printf '=== smoke tests\n'
sh zig-build-smoke.sh

printf '=== functional and security suite\n'
sh tests/run-tests.sh --bindir zig-out/bin
