#!/bin/sh
# build-fuzz.sh — build the libFuzzer harnesses with the system clang.
# Requires: clang (with libFuzzer), a configured build-meson/ tree
# (for config-compat.h, generated getdate.c and libcompat.a).
set -eu
cd "$(dirname "$0")/.."

CC=${CC:-clang}
# Which configured meson tree to take generated sources and libcompat
# from.  Overridable so CI can use its own tree: a build directory
# records absolute paths, so one configured on the host cannot be reused
# inside a container.
BUILD_DIR=${BUILD_DIR:-build-meson}
CFLAGS="-g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer"
DEF="-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_CHIMERAUTILS_BUILD -Dlint"
INC="-I include -I src.freebsd/include -I $BUILD_DIR/include"
GETDATE_C=$BUILD_DIR/src.freebsd/findutils/find/find.p/getdate.c
LIBCOMPAT=$BUILD_DIR/src.freebsd/compat/libcompat.a

for f in "$GETDATE_C" "$LIBCOMPAT" "$BUILD_DIR/include/config-compat.h"; do
    [ -f "$f" ] || { echo "missing $f — run 'meson setup $BUILD_DIR && ninja -C $BUILD_DIR' first"; exit 1; }
done

mkdir -p fuzz/bin fuzz/artifacts
for c in unvis getdate setmode patch; do mkdir -p "fuzz/corpus/$c"; done

set -x
$CC $CFLAGS $DEF $INC -o fuzz/bin/fuzz_unvis \
    fuzz/fuzz_unvis.c src.freebsd/compat/unvis.c

$CC $CFLAGS -fwrapv $DEF $INC -o fuzz/bin/fuzz_getdate \
    fuzz/fuzz_getdate.c "$GETDATE_C"

$CC $CFLAGS $DEF $INC -o fuzz/bin/fuzz_setmode \
    fuzz/fuzz_setmode.c src.freebsd/compat/setmode.c

$CC $CFLAGS -fwrapv $DEF $INC -I src.freebsd/patch -Dmain=patch_disabled_main \
    -Dexit=fuzz_skip_exit \
    -o fuzz/bin/fuzz_patch \
    fuzz/fuzz_patch.c \
    src.freebsd/patch/patch.c src.freebsd/patch/pch.c \
    src.freebsd/patch/inp.c src.freebsd/patch/util.c \
    src.freebsd/patch/backupfile.c src.freebsd/patch/mkpath.c \
    "$LIBCOMPAT"
set +x
echo "built: $(ls fuzz/bin)"
