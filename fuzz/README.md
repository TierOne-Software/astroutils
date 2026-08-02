# Fuzzing chimerautils parsers

libFuzzer harnesses for code paths that consume untrusted input.

## Targets

- `fuzz_unvis` — `strunvis`/`unvis` (src.freebsd/compat/unvis.c): decodes
  vis(3)-encoded strings.
- `fuzz_getdate` — `getdate()` (src.freebsd/findutils/find/getdate.y): yacc
  date parser, reachable via `find -newermt` and others.
- `fuzz_setmode` — `setmode`/`getmode` (src.freebsd/compat/setmode.c):
  symbolic mode parser, reachable via `chmod`/`mkdir -m`/`install -m`.
- `fuzz_patch` — patch(1)'s diff parser: `open_patch_file` +
  `there_is_another_patch` + `another_hunk` over attacker input. Ed scripts
  are never executed (`ED_DIFF` breaks out before `do_ed_script`).

## Building

Requires the system clang (libFuzzer) and a configured meson tree:

```sh
meson setup build-meson && ninja -C build-meson   # once, for config-compat.h/getdate.c/libcompat.a
sh fuzz/build-fuzz.sh
```

## Running

```sh
ASAN_OPTIONS=detect_leaks=0 fuzz/bin/fuzz_unvis   fuzz/corpus/unvis   -max_total_time=300 -artifact_prefix=fuzz/artifacts/
ASAN_OPTIONS=detect_leaks=0 fuzz/bin/fuzz_getdate fuzz/corpus/getdate -max_total_time=300 -artifact_prefix=fuzz/artifacts/
ASAN_OPTIONS=detect_leaks=0 fuzz/bin/fuzz_setmode fuzz/corpus/setmode -max_total_time=300 -artifact_prefix=fuzz/artifacts/
ASAN_OPTIONS=detect_leaks=0 fuzz/bin/fuzz_patch   fuzz/corpus/patch   -max_total_time=300 -rss_limit_mb=4096 -artifact_prefix=fuzz/artifacts/
```

Note: `fuzz_patch` deliberately leaks hunk-line storage of fatal-rejected
inputs (freeing them is unsafe — see SECURITY-FINDINGS.md), so long runs
need a raised `-rss_limit_mb` or periodic restarts.

Crashes land in `fuzz/artifacts/`. Minimize with
`fuzz/bin/fuzz_<t> fuzz/artifacts/crash-* -minimize_crash=1`, then file
the repro in SECURITY-FINDINGS.md.

Candidate next targets: `sed` script compiler, `awk` program parser,
`nvi` ex command parser, `libfetch` HTTP response parsing.
