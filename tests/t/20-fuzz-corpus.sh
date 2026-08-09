#!/bin/sh
# Fuzz-corpus replay: feed saved fuzzer inputs to the real binaries and
# assert none of them dies from a signal.
#
# This is a *regression* pass, not a fuzzing run — it is deterministic,
# needs no libFuzzer or clang, and runs everywhere the tools build.  It
# complements fuzz/build-fuzz.sh, which drives the in-process harnesses.
#
# Value beyond the harnesses: the harnesses cover a chosen entry point
# (for patch, parse only), while this replays through main() and so also
# covers the apply path — which is exactly where the patch_match() NULL
# dereference was found.
#
# By default a deterministic sample of each corpus is used so the suite
# stays fast.  Set CU_FUZZ_FULL=1 to replay every input.

. "$CU_LIB/lib.sh"

sample=${CU_FUZZ_SAMPLE:-150}
[ "${CU_FUZZ_FULL:-0}" = "1" ] && sample=0   # 0 means "everything"

# replay <label> <corpus-dir> <runner-fn>
# Reports one pass/fail for the whole corpus, listing up to three
# offending inputs so a failure is actionable.
replay() {
    _label=$1; _dir=$2; _run=$3

    if [ -z "$_dir" ] || [ ! -d "$_dir" ]; then
        skip "$_label" "no corpus"
        return
    fi

    _n=0; _bad=0; _first=
    for _f in "$_dir"/*; do
        [ -f "$_f" ] || continue
        if [ "$sample" -gt 0 ] && [ "$_n" -ge "$sample" ]; then
            break
        fi
        _n=$((_n + 1))
        CU_MEMLIMIT=${CU_FUZZ_MEMLIMIT:-1048576} cu_run_limited "$_run" "$_f" >/dev/null 2>&1
        _st=$?
        # 152 is SIGXCPU from our own ulimit, not a defect.
        if { [ "$_st" -gt 128 ] && [ "$_st" -ne 152 ]; } || [ "$_st" -eq 124 ]; then
            _bad=$((_bad + 1))
            [ "$_bad" -le 3 ] && _first="$_first
       status $_st: $(basename "$_f")"
        fi
    done

    if [ "$_n" -eq 0 ]; then
        skip "$_label" "corpus is empty"
    elif [ "$_bad" -eq 0 ]; then
        pass "$_label ($_n inputs)"
    else
        fail "$_label ($_n inputs)" "$_bad crashed or hung:$_first"
    fi
}

# Each runner takes one corpus file and must exit with the tool's status.
# They live in the work directory, which the runner made our cwd.

if require "patch corpus replay" patch; then
    cat > run-patch.sh <<EOF
#!/bin/sh
d=\$(mktemp -d)
printf 'alpha\nbravo\ncharlie\ndelta\necho\n' > "\$d/t.txt"
'$(tool patch)' -t -C -i "\$1" "\$d/t.txt" >/dev/null 2>&1
st=\$?
rm -rf "\$d"
exit \$st
EOF
    chmod +x run-patch.sh
    replay "patch corpus replays without a crash" "$(corpus_dir patch)" ./run-patch.sh
fi

if require "unvis corpus replay" unvis; then
    cat > run-unvis.sh <<EOF
#!/bin/sh
'$(tool unvis)' < "\$1" >/dev/null 2>&1
EOF
    chmod +x run-unvis.sh
    replay "unvis corpus replays without a crash" "$(corpus_dir unvis)" ./run-unvis.sh
fi

if require "setmode corpus replay" chmod; then
    cat > run-setmode.sh <<EOF
#!/bin/sh
d=\$(mktemp -d)
: > "\$d/f"
m=\$(head -c 200 "\$1" | tr -d '\\0\\n')
'$(tool chmod)' -- "\$m" "\$d/f" >/dev/null 2>&1
st=\$?
rm -rf "\$d"
exit \$st
EOF
    chmod +x run-setmode.sh
    replay "setmode corpus replays without a crash" "$(corpus_dir setmode)" ./run-setmode.sh
fi

if require "getdate corpus replay" find; then
    cat > run-getdate.sh <<EOF
#!/bin/sh
d=\$(mktemp -d)
: > "\$d/f"
m=\$(head -c 200 "\$1" | tr -d '\\0\\n')
'$(tool find)' "\$d" -maxdepth 0 -newermt "\$m" >/dev/null 2>&1
st=\$?
rm -rf "\$d"
exit \$st
EOF
    chmod +x run-getdate.sh
    replay "getdate corpus replays without a crash" "$(corpus_dir getdate)" ./run-getdate.sh
fi

if require "sh corpus replay" sh; then
    cat > run-sh.sh <<EOF
#!/bin/sh
'$(tool sh)' -n < "\$1" >/dev/null 2>&1
EOF
    chmod +x run-sh.sh
    replay "sh corpus replays without a crash" "$(corpus_dir sh)" ./run-sh.sh
fi

if require "zopen corpus replay" compress; then
    cat > run-zopen.sh <<EOF
#!/bin/sh
'$(tool compress)' -dc < "\$1" >/dev/null 2>&1
EOF
    chmod +x run-zopen.sh
    replay "zopen corpus replays without a crash" "$(corpus_dir zopen)" ./run-zopen.sh
fi

if require "grepdata corpus replay" grep; then
    cat > run-grepdata.sh <<EOF
#!/bin/sh
'$(tool grep)' -a -E 'foo[0-9]{1,3}(bar|baz)+' < "\$1" >/dev/null 2>&1
EOF
    chmod +x run-grepdata.sh
    replay "grepdata corpus replays without a crash" "$(corpus_dir grepdata)" ./run-grepdata.sh
fi

if require "seddata corpus replay" sed; then
    cat > run-seddata.sh <<EOF
#!/bin/sh
'$(tool sed)' -e 's/foo/bar/g; /GAME/,/END/d' "\$1" >/dev/null 2>&1
EOF
    chmod +x run-seddata.sh
    replay "seddata corpus replays without a crash" "$(corpus_dir seddata)" ./run-seddata.sh
fi

if require "awkdata corpus replay" awk; then
    cat > run-awkdata.sh <<EOF
#!/bin/sh
'$(tool awk)' '{n+=NF} END{print n+0}' "\$1" >/dev/null 2>&1
EOF
    chmod +x run-awkdata.sh
    replay "awkdata corpus replays without a crash" "$(corpus_dir awkdata)" ./run-awkdata.sh
fi

if require "sedcompile corpus replay" sed; then
    printf 'one\nfoo two\nthree\n' > sample.txt
    cat > run-sedcompile.sh <<EOF
#!/bin/sh
'$(tool sed)' -f "\$1" sample.txt >/dev/null 2>&1
EOF
    chmod +x run-sedcompile.sh
    replay "sedcompile corpus replays without a crash" "$(corpus_dir sedcompile)" ./run-sedcompile.sh
fi

if require "patch_struct corpus replay" patch; then
    replay "patch_struct corpus replays without a crash" \
        "$(corpus_dir patch_struct)" ./run-patch.sh
fi

group "saved crash inputs"

# Anything the fuzzer ever produced a crash for lives here permanently,
# independent of corpus sampling.
for d in "$CU_SRCDIR"/tests/data/crashers/*/; do
    [ -d "$d" ] || continue
    t=$(basename "$d")
    case $t in
        patch)
            # Covered in detail by 10-regress-patch.sh; skip the
            # duplicate work unless a full run was requested.
            [ "${CU_FUZZ_FULL:-0}" = "1" ] || continue
            require "crashers/$t" patch || continue
            replay "saved $t crashers" "$d" ./run-patch.sh ;;
        unvis)
            require "crashers/$t" unvis || continue
            replay "saved $t crashers" "$d" ./run-unvis.sh ;;
        setmode)
            require "crashers/$t" chmod || continue
            replay "saved $t crashers" "$d" ./run-setmode.sh ;;
        getdate)
            require "crashers/$t" find || continue
            replay "saved $t crashers" "$d" ./run-getdate.sh ;;
        *)  skip "saved $t crashers" "no runner defined" ;;
    esac
done

# Anything libFuzzer dropped in fuzz/artifacts is an unfixed crash.
artifacts=$CU_SRCDIR/fuzz/artifacts
if [ -d "$artifacts" ]; then
    left=$(find "$artifacts" -type f ! -name '.gitignore' ! -name 'README*' 2>/dev/null | wc -l | tr -d ' ')
    if [ "$left" -eq 0 ]; then
        pass "no unresolved crash artifacts in fuzz/artifacts"
    else
        fail "no unresolved crash artifacts in fuzz/artifacts" \
            "$left file(s) present — triage them into tests/data/crashers/"
    fi
fi

cu_finish
