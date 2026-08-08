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
for c in unvis getdate setmode patch http telnet sh zopen awkb; do mkdir -p "fuzz/corpus/$c"; done

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

$CC $CFLAGS $DEF -DFTP_COMBINE_CWDS -DINET6 -DWITH_SSL \
    -Wno-deprecated-declarations \
    $INC -I src.freebsd/libfetch -I "$BUILD_DIR/src.freebsd/libfetch" \
    -o fuzz/bin/fuzz_http \
    fuzz/fuzz_http.c \
    src.freebsd/libfetch/common.c src.freebsd/libfetch/fetch.c \
    src.freebsd/libfetch/file.c src.freebsd/libfetch/ftp.c \
    src.freebsd/libfetch/sandbox.c src.compat/capsicum.c \
    "$LIBCOMPAT" -lssl -lcrypto

$CC $CFLAGS $DEF \
    -DUSE_TERMIO -DKLUDGELINEMODE -DENV_HACK -DINET6 -DNOPAM \
    -DHAVE_NCURSESW_NCURSES_H \
    $INC -I src.freebsd/telnet -I src.freebsd/telnet/telnet \
    -o fuzz/bin/fuzz_telnet \
    fuzz/fuzz_telnet.c src.freebsd/telnet/telnet/ring.c \
    "$LIBCOMPAT" -lncursesw

$CC $CFLAGS $DEF $INC -I src.freebsd/compress \
    -o fuzz/bin/fuzz_zopen \
    fuzz/fuzz_zopen.c src.freebsd/compress/zopen.c \
    "$LIBCOMPAT"

$CC $CFLAGS $DEF $INC -I src.freebsd/awk -I "$BUILD_DIR/src.freebsd/awk" \
    -o fuzz/bin/fuzz_awkb \
    fuzz/fuzz_awkb.c src.freebsd/awk/b.c \
    "$LIBCOMPAT"

# sh: two compile groups because the bltin sources #define main under
# -DSHELL, which fights a global -Dmain rename
mkdir -p fuzz/obj-sh
SH_INC="$INC -I src.freebsd/sh -I src.freebsd/sh/bltin -I $BUILD_DIR/src.freebsd/sh"
for f in fuzz/fuzz_sh.c src.freebsd/sh/*.c \
    "$BUILD_DIR/src.freebsd/sh/nodes.c" "$BUILD_DIR/src.freebsd/sh/syntax.c" \
    "$BUILD_DIR/src.freebsd/sh/builtins.c"; do
    case $f in
        */mknodes.c|*/mksyntax.c) continue ;;
    esac
    o="fuzz/obj-sh/$(basename "$f" .c).o"
    $CC $CFLAGS $DEF -DNO_HISTORY $SH_INC -Dmain=sh_disabled_main -c "$f" -o "$o"
done
for f in src.freebsd/sh/bltin/echo.c src.freebsd/miscutils/kill/kill.c \
    src.freebsd/coreutils/printf/printf.c src.freebsd/coreutils/test/test.c; do
    o="fuzz/obj-sh/$(basename "$f" .c).o"
    $CC $CFLAGS $DEF -DNO_HISTORY $SH_INC -DSHELL -c "$f" -o "$o"
done
$CC $CFLAGS fuzz/obj-sh/*.o "$LIBCOMPAT" -o fuzz/bin/fuzz_sh
set +x
echo "built: $(ls fuzz/bin)"
