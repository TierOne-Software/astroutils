#!/bin/sh
# zig-configure.sh — probe the system for dependencies and write
# build-data/deps.json, which build.zig consumes at configure time.
# Run this once before `zig build`, and again whenever system deps change.
set -eu

have_pc() { pkg-config --exists "$1" >/dev/null 2>&1 && echo true || echo false; }
have_prog() { command -v "$1" >/dev/null 2>&1 && echo true || echo false; }
have_header() { [ -f "/usr/include/$1" ] && echo true || echo false; }

# ncurses: prefer wide, then narrow, then generic curses
if [ "$(have_pc ncursesw)" = true ]; then NCURSES=ncursesw
elif [ "$(have_pc ncurses)" = true ]; then NCURSES=ncurses
elif [ "$(have_pc curses)" = true ]; then NCURSES=curses
else NCURSES=null; fi

# tinfo: standalone, else provided by the curses lib
if [ "$(have_pc tinfo)" = true ]; then TINFO=tinfo
else TINFO=$NCURSES; fi

[ "$NCURSES" = null ] && NCURSES_JSON=null || NCURSES_JSON="\"$NCURSES\""
[ "$TINFO" = null ] && TINFO_JSON=null || TINFO_JSON="\"$TINFO\""

# libedit may lack a pkg-config file; fall back to the header
if [ "$(have_pc libedit)" = true ] || [ "$(have_header editline/readline.h)" = true ]; then EDIT=true; else EDIT=false; fi
# bzip2/lzma/zlib headers are enough to link
Z=false;   [ "$(have_pc zlib)" = true ]   || [ "$(have_header zlib.h)" = true ] && Z=true
BZ2=false; [ "$(have_header bzlib.h)" = true ] && BZ2=true
LZMA=false;[ "$(have_pc liblzma)" = true ] || [ "$(have_header lzma.h)" = true ] && LZMA=true
ZSTD=false;[ "$(have_pc libzstd)" = true ] || [ "$(have_header zstd.h)" = true ] && ZSTD=true

cat > build-data/deps.json <<EOF
{
 "ncurses": $NCURSES_JSON,
 "tinfo": $TINFO_JSON,
 "acl": $(have_pc libacl),
 "xo": $(have_pc libxo),
 "crypto": $(have_pc libcrypto),
 "ssl": $(have_pc libssl),
 "edit": $EDIT,
 "z": $Z,
 "bz2": $BZ2,
 "lzma": $LZMA,
 "zstd": $ZSTD,
 "selinux": $(have_pc libselinux),
 "byacc": $(have_prog byacc),
 "flex": $(have_prog flex)
}
EOF
echo "wrote build-data/deps.json:"
cat build-data/deps.json
