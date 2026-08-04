# chimerautils test suite

Functional and security regression tests. Portable POSIX sh — it runs
under dash, busybox ash (Alpine/musl) and bash, and needs nothing beyond
the tools under test plus `awk`, `od` and (optionally) `timeout`.

## Running

```sh
tests/run-tests.sh                       # auto-detect a build (zig first)
tests/run-tests.sh --zig                 # zig build, then test zig-out/bin
tests/run-tests.sh --build build-meson   # a meson/ninja tree
tests/run-tests.sh --bindir zig-out/bin  # a flat directory
tests/run-tests.sh --bindir /usr/bin     # an installed image
tests/run-tests.sh 10-regress-patch      # only matching files
```

The runner warns when the tested binaries are older than the sources —
if you see that warning, rebuild first (`--zig` does it for you).

Through meson:

```sh
meson test -C build-meson --suite functional   # fast: everything but the corpus
meson test -C build-meson                      # adds the corpus replay
```

The runner stages symlinks to every executable it finds, so it does not
care whether the tools sit in per-tool subdirectories (meson) or in one
flat directory (zig, an installed image).

Useful environment variables:

| Variable | Effect |
|---|---|
| `CU_KEEP_WORK=1` | keep the scratch tree for debugging |
| `CU_VERBOSE=1` | show output of commands under `assert_no_crash` |
| `CU_TIMEOUT=N` | per-command timeout, default 15s |
| `CU_NO_MEMLIMIT=1` | disable `ulimit -v` guards (required under ASan) |
| `CU_FUZZ_FULL=1` | replay entire corpora instead of a 150-input sample |
| `CU_FUZZ_SAMPLE=N` | corpus sample size |

## Layout

```
run-tests.sh        runner: locates binaries, executes t/*.sh, tallies
lib.sh              assertion helpers
t/00-smoke.sh       does each tool do its primary job?
t/10-regress-patch.sh    patch(1) parser and apply defects
t/11-regress-nvi.sh      nvi/vi/ex defects
t/12-regress-tools.sh    coreutils, grep, ed, awk, hexdump, xargs, mcookie
t/13-regress-parsers.sh  unvis, setmode, getdate, mktemp
t/20-fuzz-corpus.sh      replay saved fuzzer corpora and crashers
data/crashers/<tool>/    inputs that once crashed a tool — permanent
```

## Writing a test

Each file in `t/` is an independent `sh` script run in its own scratch
directory. It sources `lib.sh`, records results with the assertions
below, and ends with `cu_finish`.

```sh
. "$CU_LIB/lib.sh"

group "jot: default output format"
if require "jot" jot; then
    assert_out "jot 3 counts" "1
2
3" "$(tool jot)" 3
fi

cu_finish
```

Assertions:

| Helper | Checks |
|---|---|
| `assert_eq NAME WANT GOT` | string equality |
| `assert_out NAME WANT CMD...` | stdout of CMD |
| `assert_status NAME WANT CMD...` | exit status |
| `assert_ok NAME CMD...` | exits 0 |
| `assert_contains NAME NEEDLE CMD...` | output contains NEEDLE |
| `assert_no_crash NAME CMD...` | may fail, must not die on a signal or hang |
| `assert_bounded NAME KB CMD...` | completes inside an address-space limit |

`require LABEL TOOL...` skips a group when a tool was not built (many
tools are optional depending on available libraries), and `tool NAME`
gives the absolute path to a tool under test.

## What these tests are for

The security regressions are the load-bearing part. Every fix recorded in
`SECURITY-FINDINGS.md` that is observable from the command line has a test
here, so a future FreeBSD import cannot silently revert one.

Two assertions carry most of that weight:

- **`assert_no_crash`** — the input is hostile and the tool is expected to
  reject it; what matters is that it rejects it rather than segfaulting.
  This is what catches memory-safety regressions in parsers.
- **`assert_bounded`** — the tool must fail *fast and small* on input
  claiming absurd sizes. The pre-fix patch(1) reached 16 GB RSS on an
  89-byte diff; the pre-fix nvi reached 527 MB editing one line. Both are
  caught by an address-space cap that a correct build never approaches.

When adding a fix to `SECURITY-FINDINGS.md`, add a test here that fails
against the unfixed binary. Verify that it does — a regression test that
was never seen to fail is not yet a regression test.

## Fuzz corpus replay

`t/20-fuzz-corpus.sh` feeds saved fuzzer inputs to the **real binaries**,
which is deliberately different from `fuzz/build-fuzz.sh` driving the
in-process harnesses:

- it needs no clang or libFuzzer, so it runs in every CI job and on any
  developer machine;
- it goes through `main()`, so it covers code the harness's chosen entry
  point misses.

That difference is not theoretical. The harness for patch covers parsing
only (`open_patch_file` → `another_hunk`); replaying the same corpus
through the real binary found a NULL dereference in `patch_match()` on
the *apply* path, which the harness could never have reached.

Inputs that ever crashed a tool are copied into `data/crashers/<tool>/`
and replayed unconditionally, independent of corpus sampling.
