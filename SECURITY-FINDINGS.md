# Security findings — chimerautils

Work queue for the hardening effort. Sources:

- **zig-safety**: runtime UB checks of `zig build -Doptimize=Debug` (zig's
  bundled clang UBSan-style checks) firing on normal input.
- **jot-gcc**: reproduced with both gcc and zig clang; a port/env bug.
- **infer**: Facebook Infer static analysis (pending; needs the full meson
  build, which needs libacl-devel, libxo-devel, libedit-devel,
  libzstd-devel installed).
- **scan-build**: clang static analyzer cross-check (pending, same blocker).

Status legend: OPEN / FIXED / WONTFIX (with rationale).

---

## Buffer overflow / memory safety candidates

### FIXED — zig-safety — grep: out-of-bounds pointer arithmetic
- `src.freebsd/grep/queue.c:61` `initqueue()`: with `Bflag == 0`,
  `qend = qpool + (Bflag - 1)` forms a pointer before the allocation
  (UB, panics under zig Debug). Never dereferenced on that path, but UB.
- Fixed: clamp to `qend = qpool` when `Bflag == 0`. Verified with
  `-Doptimize=ReleaseSafe` (`grep -B1` and plain grep both pass).

### FIXED — zig-safety — cut: unsigned-wrap pointer arithmetic (UB)
- `src.freebsd/coreutils/cut/cut.c:453` `f_cut()`: `putchar(p[i - clen])`
  with `i` int and `clen` size_t computed `p + (SIZE_MAX - …)` — pointer
  arithmetic wrapping the address space (UB in C, trapped by zig). Not an
  actual out-of-bounds access on glibc.
- Fixed: signed subscript `p[i - (int)clen]`. Verified under ReleaseSafe.

### FIXED — zig-safety — join: unsigned-wrap pointer arithmetic (UB)
- `src.freebsd/coreutils/join/join.c:375` `mbssep()`: `s[-n] = '\0'` with
  `n` size_t — same unsigned-wrap UB class as cut.
- Fixed: `s[-(ptrdiff_t)n]`. Verified under ReleaseSafe.

## Functional bugs (port/env, security-adjacent)

### FIXED — jot default format broken on glibc
- `jot 3` printed `%.0-1f` (glibc echoing the invalid format `%.-1f`)
  instead of `1 2 3`. Root cause: `getformat()` was called while
  `prec == -1` for the single-argument form; the `prec = 0` normalization
  ran afterwards. Reproduced with gcc and zig clang.
- Fixed: normalize `prec` before `getformat()`. `jot 3` now prints `1 2 3`.

### FIXED — fortify — mcookie: stack buffer overflow + OOB read
- `src.custom/mcookie/mcookie.c`: hex loop wrote `2 * (sizeof(mdbuf)-1)` = 62
  bytes + NUL into a 32-byte stack buffer, and read 31 bytes from a 16-byte
  MD5 digest. Caught immediately by `-D_FORTIFY_SOURCE=3` ("buffer overflow
  detected" abort). Fixed: buffer sized 33, loop bounded by `mdlen`,
  `sprintf` → `snprintf`.

### NOT REPRODUCIBLE — infer — sed: possible null deref on trailing `;`
- `src.freebsd/sed/compile.c:188` `compile_stream()`: infer reported `p`
  NULL dereferenced by `addrchar(*p)` when a script ends after `;`.
  Could not reproduce with `printf 's/a/b/;' | sed -f -` on either the
  zig or meson build (clean exit 0). Left as-is; the `if (p)` guard at
  :171 appears to cover EOF in practice.

### FIXED — infer — env: unchecked malloc in split_spaces
- `src.freebsd/coreutils/env/envopts.c:187` (`newargv`) and :180 (`newstr`):
  malloc results dereferenced without a null check (null-deref on OOM).
  Fixed: both allocations now `err(1, "malloc")` on failure.

### OPEN — infer — tail: possible null deref
- `src.freebsd/coreutils/tail/reverse.c:278` `r_buf()`: `first` could be
  null (from line 195) and is dereferenced. Needs verification.

### OPEN — infer — stty: possible null deref
- `src.freebsd/coreutils/stty/cchar.c:111` `csearch()`: `arg` could be null
  (from line 104). Needs verification.

### OPEN — infer — nvi: use-after-free candidates (5)
- `src.freebsd/nvi/common/cut.c:322` `text_lfree()`
- `src.freebsd/nvi/ex/ex_tag.c:687` `tagq_free()`
- `src.freebsd/nvi/ex/ex_tag.c:850` `ex_tagf_alloc()`
- `src.freebsd/nvi/common/conv.c:245` `default_int2char()` (via `binc`)
- `src.freebsd/nvi/regex/regcomp.c:1240` `mcadd()`
- All follow the "access queue/link pointer after free()" pattern; need
  per-site verification (the BSD queue macros often make these FPs).

### OPEN — infer — nvi: stack variable address escape
- `src.freebsd/nvi/vi/v_yank.c:75` `v_yank()`: infer reports the address of
  stack variable `len` escapes the function. Needs verification.

### OPEN — infer — uninitialized value reads (78 total)
Concentrations worth fixing first:
- `src.freebsd/awk/b.c` (13 reports: `mkdfa`, `relex`, `cgoto`) — regex
  engine, reachable from user-supplied patterns.
- `src.freebsd/nvi/vi/vs_smap.c` (~30 reports, `vs_sm_up`/`vs_sm_down`) —
  likely one root cause (partially initialized struct copy).
- `src.freebsd/nvi/common/msg.c:315` `msgq()` — `len` read uninit.
- `src.freebsd/sh/exec.c:477` `find_builtin()` — `bp` read uninit.
- `src.freebsd/tip/tip/acu.c:143` `con()` — `phnum` read uninit.

### FALSE POSITIVE — triaged out
- `src.freebsd/m4/misc.c:337` `xrealloc` UAF — `err(1, ...)` is noreturn;
  the `free(old)` before it is redundant but harmless.
- `src.freebsd/dbcompat/mpool.c:305` `mpool_close` UAF — `bp` is removed
  from the queue before `free(bp)` and never touched after.
- `src.freebsd/netcat/netcat.c:1114` `fdpass` null deref — `CMSG_FIRSTHDR`
  is non-null here: `msg_controllen` exceeds `sizeof(cmsghdr)`.
- `src.freebsd/awk/lib.c:72`, `awk/parse.c:39`, `awk/tran.c:167`,
  `awk/run.c:487` null derefs — all guarded by `FATAL`/null checks that
  infer's model misses.
- `src.freebsd/ee/ee.c:1062` — `txtalloc()` failure path exits via
  `writeline()`-style longjmp; needs one more look but likely FP.
- 165 DEAD_STORE and 56 MEMORY_LEAK_C reports: not triaged — mostly benign
  for short-lived CLI tools (memory is reclaimed at exit).

## scan-build results

Run: `scan-build meson setup build-scan && scan-build ninja -C build-scan`
(reports kept in `scanbuild-out/`). 560 reports:

- 185 Logic error — incl. **82 "Dereference of null pointer"**, 19 "Result
  of operation is garbage or undefined", 14 "Assigned value is
  uninitialized", 13 "Dangerous construct in a vforked process" (mostly
  `nvi`/`tip`/`ee` vfork usage, needs per-site review)
- 140 Unused code (dead assignments — not security-relevant, not triaged)
- 88 Stream handling error (35 "Invalid stream state", 30 "Stream already
  in EOF", 21 "Resource leak") — mostly noisy, some real fd leaks
- 66 API — "Argument with 'nonnull' attribute passed null"
- 26 Memory error (24 leaks + 2 other)
- 20 Error handling (errno not checked)
- 9 Security group (insecureAPI checker hits)

### scan-build hotspots (null-deref / nonnull-arg clusters)
Recurring functions across both analyzers — highest triage value:

- `src.freebsd/awk/tran.c` `qstring`/`makesymtab` (8 reports), `awk/run.c`
  `format`/`bltin`, `awk/lex.c` `string` — awk parser/evaluator on
  user-supplied programs.
- `src.freebsd/nvi/ex/ex_subst.c` `re_conv`/`ex_s`/`s` (7), `nvi/ex/ex_argv.c`
  `argv_esc` (2), `nvi/common/delete.c` `del` (2), `nvi/common/put.c` `put` (2),
  `nvi/vi/v_search.c` `v_searchw` (3) — ex/vi command handling.
- `src.freebsd/sed/main.c` `cu_fgets` (2) — sed's line reader.
- `src.freebsd/m4/gnum4.c` `doindir`/`do_subst`/`doformat` (3) — GNU m4
  compat paths.
- `src.freebsd/findutils/find/function.c` `f_exec` (3) — find -exec.
- `src.freebsd/coreutils/test/test.c` `binop`/`newerf` (4).
- `src.freebsd/ed/main.c`/`glbl.c`/`re.c` (4).
- `src.freebsd/telnet/telnet/commands.c` `sourceroute` — network-reachable.
- `src.freebsd/gzip/gzip.c` `prepend_gzip` (2).
- `src.freebsd/coreutils/ls/print.c` `printcol`,
  `src.freebsd/coreutils/tail/forward.c` `rlines`,
  `src.freebsd/coreutils/du/du.c` `ignoreadd`,
  `src.freebsd/coreutils/cat/cat.c` `scanfiles`/`cook_cat` (2),
  `src.freebsd/miscutils/hexdump/parse.c` `rewrite`/`add` (2).

### Cross-analyzer agreement (fix first)
Reported by BOTH infer and scan-build:
- `awk/parse.c` `nodealloc`, `awk/tran.c` `makesymtab`
- `nvi` ex-substitution / msg paths
- `sed` compile/read paths

Note: many reports in both analyzers assume malloc/getenv/rewind can fail
in ways FreeBSD's code doesn't check. Each needs a reachability judgment;
the clusters above are where to start.

## Fuzzing results (libFuzzer; harnesses in fuzz/)

### FIXED — fuzz — unvis: signed-shift UB on high-byte escapes
- `src.freebsd/compat/unvis.c:359,372` (octal), `:399,419` (hex/mime):
  `*cp = (*cp << 3) + …` / `(*cp << 4)` overflow signed char for escapes
  above `\177`. Found in the first 90s run (6.2M execs).
- Fixed: arithmetic via `unsigned char`, cast back. Behavior unchanged.

### FIXED — fuzz — patch: unlink(NULL) on early exit
- `src.freebsd/patch/util.c` `my_exit()`: the four temp-file globals are
  only allocated in `main()`; a `fatal()` before that (or any reentrant
  use) called `unlink(NULL)` (nonnull-attribute UB). Fixed: NULL guards.

### FIXED — fuzz — patch: unbounded memory DoS
- An 89-byte context diff claiming a hunk of ~4×10¹⁷ lines drove the real
  patch binary to **16 GB RSS** before failing: the `*** a,b ****` and
  `@@` header paths grew `hunkmax` without bound (two of four grow sites
  lacked the existing `MAXHUNKSIZE` check). Fixed: both sites now
  `fatal()` beyond `MAXHUNKSIZE` (200k lines), matching the other two.
  Repro now uses 2 MB and exits cleanly with an error.

### FIXED — fuzz — patch: out-of-bounds read in context diff parse
- `src.freebsd/patch/pch.c:693`: `p_char[p_end - 1]` evaluated with
  `p_end == 0` on a malformed `--` line → read before the allocation.
  Fixed: `p_end > 0 &&` guard.

### FIXED — fuzz — patch: empty-line underflow writes (6 sites)
- `remove_special_line()` on an empty hunk line: `p_len[x] -= 1` wrapped
  to `SIZE_MAX`, followed by an OOB NUL write (`pch.c` :792, :927, :1033,
  :1062, :1080, plus the `i-1` sites :1166/:1210 which also needed an
  `i > 0` guard). Fixed: length guards at all sites.

### FIXED — fuzz — patch: stale p_len → OOB write
- Header lines in the normal/context diff parsers assigned `p_line[]` and
  `p_char[]` but never `p_len[]` (pch.c :994, :1155, :1194), so the
  `remove_special_line()` rewrite used a length left over from a previous
  hunk — arbitrary OOB write. Fixed: set `p_len[] = strlen(...)` at all
  three assignment sites.

### FIXED — fuzz — getdate: signed overflow class + localtime NULL derefs
- Fuzzing found signed-overflow UB in the date arithmetic (grammar
  actions and `Convert()`/`DSTcorrect()`) and NULL derefs when
  `localtime()` fails on out-of-range `time_t` (5 sites, reachable via
  huge fuzzed numbers → crash).
- Fixed: `localtime` NULL guards; the accumulation sites use unsigned
  arithmetic; and since the parser's date arithmetic pervasively relies
  on wrap semantics, getdate is now compiled with `-fwrapv` (both builds).
  The same applies to patch's line-number arithmetic (`-fwrapv` on
  patch, both builds).

### Fuzz harness notes
- `fuzz_patch` runs in-process with patch's `exit()` rewritten to a
  longjmp (`-Dexit=fuzz_skip_exit`) plus `pch_reset()` (new, exported)
  between inputs; `close_patch_file()` (new) closes the patch FILE*.
  `pch_reset` deliberately does not free hunk-line storage — `fatal()`
  can fire with `p_end` pointing at stale/never-initialized slots, so
  freeing is unsafe; the bounded leak only affects the harness (the real
  tool exits on `fatal()`). Run long sessions with a raised
  `-rss_limit_mb` or periodic restarts.
- A fork-per-input variant was tried and abandoned: coverage never
  reaches the parent, so the fuzzer runs blind.
- Final state: all four targets (unvis, getdate, setmode, patch) run
  clean — patch went 2.3M executions with no findings after the fixes.

## Remediation approach (Phase 3)

- Confirmed risky `strcpy`/`strcat`/`sprintf`/`strncpy` call sites get
  replaced by `safestr` calls (`src.safestr/`, zig-implemented C ABI) or
  idiomatic `strlcpy`/`strlcat`/`snprintf` where equivalent.
- Priority: network/setuid-facing tools (`telnet`, `fetch`, `tip`, `vi`,
  `su`) and every analyzer finding that is confirmed reachable.

## Hardening status

- Compiler hardening (both builds, default on): `-fstack-protector-strong`,
  `-fstack-clash-protection`, `-ftrivial-auto-var-init=zero`,
  `-D_FORTIFY_SOURCE=3`. (zig build: `-Dharden=false` to disable.)
- Production trap-mode UB checks (zig build only, opt-in):
  `zig build -Dprod-sanitize=true` adds `-fsanitize=bounds,object-size`
  with `-fsanitize-minimal-runtime -fsanitize-trap=bounds,object-size`.
- `__counted_by` adoption (incremental): macro `__cu_counted_by` in
  `include/sys/cdefs.h` (empty on pre-clang-18/gcc-15). Annotated so far:
  - `struct fetchconn.buf` (libfetch, network-facing) — `bufsize` is a true
    capacity member.
  - `ARGS.bp` (nvi) — `blen` capacity member.
  Note: clang requires the count member declared before the pointer.
  Next candidate: `sort/bwstring.h` `wstr`/`cstr` — blocked on semantics
  (allocation is always `len + 1` for the terminator slot; annotating
  `len` would flag intentional terminator writes under `-fsanitize=bounds`).
- Fuzzing: `fuzz/` — libFuzzer harnesses for parsers consuming untrusted
  input (see fuzz/README.md).
