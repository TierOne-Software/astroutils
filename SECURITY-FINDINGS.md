# Security findings — chimerautils

Work queue for the hardening effort. Sources:

- **zig-safety**: runtime UB checks of `zig build -Doptimize=Debug` (zig's
  bundled clang UBSan-style checks) firing on normal input.
- **jot-gcc**: reproduced with both gcc and zig clang; a port/env bug.
- **infer**: Facebook Infer static analysis (reports in `infer-out/`).
- **scan-build**: clang static analyzer cross-check (reports in
  `scanbuild-out/`).

Status legend: OPEN / FIXED / WONTFIX (with rationale).

---

## Buffer overflow / memory safety candidates

### FIXED — zig-safety — nvi: TMAP formed from NULL map at startup
- `src.freebsd/nvi/vi/v_z.c:138` `vs_crel()`: runs during option init
  (O_WINDOW), before `vs_screen()` allocates the screen map —
  `TMAP = HMAP + (t_rows - 1)` is pointer arithmetic on NULL (UB,
  trapped by zig ReleaseSafe on every vi/ex startup). Never
  dereferenced on that path (map refill happens after allocation).
- Fixed: only compute TMAP when HMAP != NULL. Verified with pty-driven
  vi scroll session (ReleaseSafe, clean exit).

### FIXED — zig-safety — nvi: zero-length copy from NULL build buffer
- `src.freebsd/nvi/ex/ex_subst.c:321` `BUILD()` macro: a match at
  offset 0 on the first substituted line did `MEMCPY(lb + 0, s, 0)`
  with `lb` still NULL — pointer arithmetic on NULL (UB, trapped by
  zig ReleaseSafe on e.g. `%s/1/x/g`).
- Fixed: skip the copy when `len == 0`. Verified with ex-mode
  substitute/filter/search session (ReleaseSafe, clean exit).

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

### FIXED — infer — ee: unchecked allocations (was "likely FP")
- `src.freebsd/ee/ee.c:1062` `insert_line()`: `txtalloc()` and `malloc()`
  results dereferenced unchecked; `ee_init()` read from an unchecked
  `fopen()` result after `access()` (TOCTOU race makes failure real).
  Fixed: NULL checks (`err(1)` for allocations, skip unreadable init
  file).

### FALSE POSITIVE — infer — tail: possible null deref
- `src.freebsd/coreutils/tail/reverse.c:278` `r_buf()`: `first` from
  `TAILQ_FIRST` reported possibly null. The `feof(fp)` guard guarantees
  the read loop runs at least once on any freshly opened stream (no
  prior reads on `fp`), so the list is never empty when `first` is
  taken; infer can't model feof's EOF-indicator state. Verified with
  `tail -r` on empty pipe and empty regular file (clean exit 0).

### FALSE POSITIVE — infer — stty: possible null deref
- `src.freebsd/coreutils/stty/cchar.c:111` `csearch()`: NULL `arg` is
  guarded at :105-108 via `usage()`, which exits — unreachable. Infer
  can't see `usage()` as noreturn because `__dead2` expands to empty in
  this port's `include/sys/cdefs.h`. Verified: `stty intr` with missing
  argument errors and exits 1 cleanly.

### TRIAGED — infer — nvi: use-after-free candidates (5)
- `src.freebsd/nvi/regex/regcomp.c` — FIXED via `doinsert()`: bail out
  when `EMIT()` sets `p->error` instead of indexing the stale strip.
- `src.freebsd/nvi/common/conv.c` — REAL, FIXED (two fixes):
  - `BINC_RET` (common/mem.h): `binc()` frees the old buffer on realloc
    failure (reallocf semantics) but the macro returned without clearing
    the caller's pointer — dangling pointer + zero length, so the next
    conversion reusing `sp->cw.bp1` passed freed memory to realloc and
    `conv_end()` double-freed it. Fixed: NULL the pointer on failure.
  - `CONVERT2` macro (the more serious find, see "FIXED — nvi: CONVERT2
    iconv buffer growth" below).
- `src.freebsd/nvi/common/cut.c:322` `text_lfree()` — FALSE POSITIVE:
  `TAILQ_REMOVE` unlinks `tp` strictly before `text_free(tp)`, and
  repoints the successor's `tqe_prev` into the queue head; infer
  mis-orders the macro-expanded access vs. the free.
- `src.freebsd/nvi/ex/ex_tag.c:687` `tagq_free()` and :850
  `ex_tagf_alloc()` — FALSE POSITIVE: canonical TAILQ drain idiom
  (unlink head before free); infer loses the head update through the
  `tqe_prev` indirection.

### FIXED — nvi: CONVERT2 iconv output pointer stale after buffer growth
- `src.freebsd/nvi/common/conv.c` `CONVERT2` (used by `fe_int2char`):
  `outleft`/`obp` were computed before the `BINC_RETC` growth check, so
  a mid-conversion realloc left `obp` dangling and `outleft` stale —
  an infinite E2BIG retry loop growing the buffer without bound.
  Reproduced live: UTF-8 locale + `set fe=utf-32` + editing a 2048-char
  line drove vi to 527 MB RSS in 0.4 s (memory-exhaustion DoS); on
  iconv implementations that write before reporting E2BIG it is also a
  heap UAF write. Present verbatim in upstream FreeBSD contrib/nvi.
- Fixed: growth check first, then derive `outleft`/`obp` from the
  post-growth buffer. Verified: same repro now completes in 0.01 s /
  3.7 MB RSS with correct UTF-32 output.

### FALSE POSITIVE — infer — nvi: stack variable address escape
- `src.freebsd/nvi/vi/v_yank.c:75` `v_yank()`: `&len` is an out-param
  to `db_get()` (common/line.c), which only writes through it and never
  stores the pointer; cross-TU analysis artifact, no escape exists.

### TRIAGED — infer — uninitialized value reads (78 total)
Fixed:
- `src.freebsd/nvi/vi/vs_smap.c` (~30 reports, `vs_sm_up`/`vs_sm_down`) —
  root cause fixed: uninitialized `s2` on first loop iteration and a
  stale-copy scroll-up loop (scroll loop reworked to fill in place).
- `src.freebsd/nvi/ex/ex_filter.c` `ex_filter()` — `nread` initialized.
- `src.freebsd/awk/b.c` `cclenter()` — unchecked calloc fixed.
- `src.freebsd/nvi/common/msg.c` `msgq()` — on the
  `msgq(sp, M_SYSERR, NULL)` path, `len` still held the already-consumed
  prefix length at the `nofmt` label and was double-counted: the
  strerror text was written past a gap of uninitialized bytes and the
  printed error was truncated. Fixed: `len = 0` on that path.

False positives (no code change):
- `src.freebsd/awk/b.c` remaining cluster (~12, `mkdfa`/`relex`/`cgoto`) —
  relex `{n,m}` locals are initialized on the only path reaching the
  parse loop; `mkdfa`'s `p1` is fully initialized via `op2`/`nodealloc`
  (cross-TU gap); `cgoto` reads stay within regions the resize loops
  initialize (infer's realloc model). Clean under gcc
  `-O2 -Wmaybe-uninitialized`; repetition patterns behave correctly.
- `src.freebsd/sh/exec.c:477` `find_builtin()` — `bp` is initialized by
  the for-loop init clause before `*bp` is tested; `builtincmd` is a
  statically initialized NUL-terminated table.
- `src.freebsd/tip/tip/acu.c:143` `con()` — `conflag` guards the
  `phnum` read and is only assigned immediately after `phnum` in both
  dialing loops; `con()` runs once per process.

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

### scan-build hotspots — TRIAGED
All hotspot clusters triaged (per-report reasoning preserved in session
notes; report IDs reference `scanbuild-out/2026-08-01-200052-2978396-1/`).

Fixed:
- `nvi/ex/ex_subst.c` `re_conv`/`ex_s`/`s` (7 reports): with no previous
  replacement (`sp->repl == NULL`), all-`~` patterns/replacements left
  the build buffer NULL and passed it to memcpy (UB; trapped live under
  zig ReleaseSafe on `:s/~/X/`, `:s/a/~/`, nomagic `:s/\~/X/`). Fixed:
  zero-length guards on the three `~`-expansion MEMCPYs and the
  confirm-mode copy, `MAX(needlen, 1)` allocation. (2 further reports
  already covered by the BUILD-macro guard; remaining re_conv/ex_s
  reports are FPs — the counting passes guarantee non-zero sizes.)
- `xargs` vfork child (`xargs.c:611`): `err(3)` between vfork and exec
  runs atexit/stdio cleanup in the shared address space. Fixed:
  `warn(3)` + `_exit(1)` (2 sites).
- `ed/main.c` `append_lines`: dead `lp` initializer removed (dead-store
  report). ed `join_lines` report already fixed earlier.
- `cat/cat.c` `cook_cat` NULL-arg report: already fixed by the earlier
  `scanfiles` fdopen check.

False positives (no change), with root cause:
- awk evaluator cluster (18 reports: `tran.c` `qstring`/`makesymtab`,
  `run.c` `format`/`bltin`, `lex.c` `string`): every path exits through
  `FATAL`, which is `noreturn` — but awk is built `-std=c99`, and
  `awk.h` defines `noreturn` away for C99, so both analyzers model the
  fatal path as returning.
- nvi ex/vi command handling (16 reports: `argv_esc`, `del`, `put`,
  `v_searchw`): all require the GET_SPACE scratch buffer to be NULL
  without taking the error exit — only possible for zero-byte requests,
  and every flagged path provably requests > 0 bytes (gdb-verified
  `tmp_bp` allocated during option init). Closest case (`delete.c:78`,
  `fm->cno == 0`) additionally needs `sp == NULL` (never) — not
  reproducible.
- sed `cu_fgets` (2), m4 `gnum4.c` (3), test `binop`/`newerf` (6),
  gzip `prepend_gzip` (3), du `ignoreadd`: noreturn error functions
  (`m4errx`, `error`/`verrx`, `xo_errx`) hidden behind the port's empty
  `__dead2` — same pattern as the awk FATAL cluster.
- find `f_exec` (3), telnet `sourceroute`, ed glbl.c/re.c (3), ls
  `printcol` (2), tail `rlines`, hexdump `add`: infeasible analyzer
  paths (tandem static invariants, arithmetic relations the analyzer
  lost, caller-guaranteed non-empty inputs).
- cat stream-state reports (5): experimental alpha.unix.Stream checker
  noise; the mid-multibyte EOF path is explicitly handled.

### vfork reports — TRIAGED (13)
- FIXED: `xargs` (above); `nvi/ex/ex_cscope.c` `run_cscope()` (see
  follow-ups — command-string construction hoisted into the parent).
- FALSE POSITIVE (11): nvi ex_filter/ex_argv/ex_shell, telnet `shell`,
  sh `vforkexecshell`, tip `expand`, apply `exec_shell` — flagged calls
  are async-signal-safe (dup2/close/open/sigprocmask), read-only
  (getenv/strrchr), local-only assignments, or explicitly permitted
  (execl/_exit). Noted caveat, not changed: several nvi children call
  `msgq_str` on the execl-failure path before `_exit` — non-conforming
  upstream idiom that only runs when exec already failed.

### Follow-ups found during triage
Fixed:
- `src.freebsd/dbcompat/recno/rec_put.c:263` — `WR_RLEAF`
  (`btree/btree.h`) did `memmove(dest, NULL, 0)` when nvi stored an
  empty line with a still-NULL conversion buffer. Exact trigger: a file
  whose first line is empty (traps on initial load, no `:w` needed);
  a non-empty first line hides it because the reused CONVWIN buffer is
  non-NULL. Reproduced under clang `-fsanitize=undefined`; fixed by
  skipping the zero-length copy.
- `nvi/ex/ex_subst.c` `re_conv()` counting pass undercounted by one
  CHAR_T in two tilde cases (bare `~` under nomagic, `\~` under magic)
  vs. the emitting pass's literal `~` — 1-CHAR_T heap overflow when
  `needlen*sizeof(CHAR_T)` is an exact power of two ≥ 256. Reproduced
  under ASan; fixed (`else needlen += 1` in both branches). Present
  verbatim in upstream contrib/nvi.
- `nvi/ex/ex_cscope.c` `run_cscope()` vfork window — fixed by hoisting
  the command-string construction into the parent (was: malloc/
  asprintf/free/msgq between vfork and execl, plus freeing `cmd` in
  the parent's heap on the execl-failure path). Verified
  behavior-identical.

Still open:
- `nvi/ex/ex_subst.c` `s()` lb leak on OOM (`ADD_SPACE_RETW` returns
  without freeing `lb`): real, low value, needs the `_GOTO` macro
  rework (BINC_GOTO leaves `bp` dangling, so not a minimal swap).

(Also fixed in the same pass: `nvi/common/line.c` `db_get()`/`db_last()`
did `MEMCPY(ep->c_lp, wp, 0)` with `ep->c_lp == NULL` when caching an
empty line — trapped on loading an all-empty-lines file; and
`compat/mktemp.c` `_gettemp()` indexed `padchar` with `sizeof`
including the NUL, planting `'\0'` in templates and causing a 1-byte
global over-read on the EEXIST carry path — ASan-verified, fixed with
`% (sizeof(padchar) - 1)` matching upstream libc.)

### Cross-analyzer agreement — RESOLVED
The clusters reported by BOTH infer and scan-build are all closed:
- `awk/parse.c` `nodealloc`, `awk/tran.c` `makesymtab` — false positives
  (noreturn FATAL, see above).
- `nvi` ex-substitution / msg paths — fixed (BUILD guard, `~`-expansion
  NULL buffer, msgq prefix double-count).
- `sed` compile/read paths — not reproducible / false positive.

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

## Regression-suite findings (tests/ + ci/)

Found by replaying the saved fuzz corpora through the **real binaries**
rather than the in-process harnesses (`tests/t/20-fuzz-corpus.sh`), and by
running the suite under ASan/UBSan (`ci/jobs/sanitizers.sh`). The patch
harness only covers parsing (`open_patch_file` → `another_hunk`), so
everything below was unreachable from it.

### FIXED — patch: NULL pattern line dereferenced in patch_match
- `src.freebsd/patch/patch.c` `patch_match()`: `ilineptr` is NULL-checked,
  `plineptr = pfetch(pline)` is not, and goes straight to `strncmp`.
  A malformed hunk reaches `patch_match` with `p_line[]` slots unfilled
  while `p_ptrn_lines` still counts them — the "old lines were omitted"
  path (`pch.c:707`) advances `p_end` to `p_ptrn_lines + 1` and leaves
  slots 2..`p_ptrn_lines` for a fill that a truncated hunk never performs.
- **46 of the 8001 saved corpus inputs segfaulted the real binary**
  (SIGSEGV on the apply path, after "Hunk #1 failed"). Reachable from any
  malicious diff; a plain DoS here, but note the pre-`calloc` upstream
  code reaches the same site with *uninitialized* `p_line[]`, making it an
  arbitrary-pointer read rather than a NULL dereference.
- Fixed: NULL check in `patch_match` (a hunk with missing pattern lines
  does not match). `p_len`/`p_char` also switched to `calloc` and their
  grown halves zeroed, so an unfilled slot has length 0 rather than
  uninitialized heap — `p_len` was `malloc`'d, so the stale length was
  feeding `strncmp` too. Repro inputs kept in `tests/data/crashers/patch/`.

### FIXED — patch: heap use-after-free via the faked-up line range
- `src.freebsd/patch/pch.c` `another_hunk()` cleanup loop: the fill logic
  sets `p_line[filldst] = p_line[fillsrc]` (`pch.c:918`), so the range
  `[p_bfake, p_efake]` *aliases* storage owned by other slots. The cleanup
  loop correctly skips freeing that range — but never cleared it, leaving
  dangling pointers once the owning slots were freed. The next hunk's
  error path (`abort_context_hunk` → `fprintf("%s", pfetch(i))`) then read
  freed memory.
- ASan `heap-use-after-free`, READ of size 2; 12 corpus inputs. Invisible
  without a sanitizer.
- Fixed: clear the aliased range instead of skipping it entirely.

### FIXED — patch: out-of-bounds read on a zero-length pattern line
- `src.freebsd/patch/patch.c` `patch_match()`: the last-line
  end-of-line check indexes `plineptr[plinelen - 1]` under an upstream
  comment asserting "Note that plinelen > 0". A malformed hunk can carry
  a zero-length line, making that a read **one byte before** the
  allocation.
- ASan `heap-buffer-overflow`, READ of size 1, "1 bytes before a 1-byte
  region"; 29 corpus inputs, on the *successful* apply path. Silent on a
  normal build.
- Fixed: treat a zero-length line as having no trailing newline, which is
  the only consistent reading, and leave behaviour for non-empty lines
  unchanged.

### FIXED — counted_by breaks the build on gcc
- `include/sys/cdefs.h`: `__cu_counted_by` was enabled on any compiler
  answering `__has_attribute(counted_by)`. gcc 15 answers yes but accepts
  the attribute **only on flexible array members**, rejecting pointers
  with a hard error, so `struct fetchconn.buf` failed to compile on
  Alpine/gcc — the entire musl build was broken.
- Fixed: restrict to clang, which supports the pointer form. The
  annotation is a checking aid with no semantic effect, so compiling it
  away elsewhere is safe. Found by the musl CI job on its first run.

### FIXED — sort: zero-length memcpy from a NULL leaf array
- `src.freebsd/coreutils/sort/radixsort.c:593` and :628
  (`run_sort_level_next`): both the forward and reverse branches copied
  `sl->leaves` unconditionally, and the pointer is NULL when
  `sl->leaves_num == 0` — `memcpy(dst, NULL, 0)`, the same UB class
  already fixed in nvi (`BUILD`, `db_get`), ed (`join_lines`) and
  dbcompat (`WR_RLEAF`).
- Fires on an ordinary `sort` of three lines; UBSan reports "null pointer
  passed as argument 2, which is declared to never be null". Invisible on
  a normal build, which is why it survived the earlier analyzer passes —
  neither Infer nor scan-build models the `nonnull` attribute on
  `memcpy` here.
- Fixed: skip the copy when `leaves_num == 0`, both branches.
  Found by `ci/jobs/sanitizers.sh` on its first containerized run.

### FIXED — unvis: &#NN; numeric entities decoded incorrectly
- `src.freebsd/compat/unvis.c` `S_NUMBER`: accumulated with
  `*cp += (*cp * 10) + d` — computing `cp*11 + d`, so every numeric
  character reference with ≥ 2 digits decoded wrong (`&#65;` → 'G',
  `&#233;` silently wrapped). Upstream NetBSD bug (PR lib/60111),
  present on all platforms; found during the musl wide-char audit of
  `src.freebsd/compat/` (the only wide-char consumer there was vis.c;
  everything else runtime-verified musl ≡ glibc).
- Fixed by cherry-picking the upstream 1.46 accumulation fix and the
  1.47 `UCHAR_MAX` overflow check. Regression tests in
  `tests/t/13-regress-parsers.sh`.

### FIXED — vis(1) corrupts bytes >= 0x80 on musl
- `vis | unvis` did not round-trip binary data on musl: byte `0x80` came
  back as `0xDF 0x80`. Reproduced in the Alpine CI container; correct on
  glibc.
- Mechanism: musl's C locale has `MB_CUR_MAX == 1` and represents bytes
  `0x80..0xFF` as `wchar_t 0xDF80..0xDFFF` (its surrogate-escape
  convention). `mbrtowc()` therefore **succeeds** on such a byte, so
  `src.freebsd/compat/vis.c` never takes its conversion-error path
  (`vis.c:487`, which would have handled the byte as a byte), and the
  escape logic in `do_svis()` — `c & 0200`, `c &= 0177` (`vis.c:273`) —
  did byte arithmetic on a 16-bit value. glibc's single-byte C locale
  hid this completely.
- Fixed: in the `istrsenvisx()` input loop, a single-byte decode landing
  in the surrogate range (impossible for a genuine multibyte decoding)
  whose low byte matches the input byte is folded back to the raw byte.
  `0x80` now encodes as `\M-^@` and all 256 byte values round-trip on
  musl; glibc behavior unchanged (musl-only code path). The XFAIL in
  `tests/t/13-regress-parsers.sh` is now a hard regression test.

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

- Sandboxing (both builds, default on): the Capsicum compatibility layer
  is real.  `caph_enter()` applies a full Landlock filesystem lockdown
  plus a seccomp namespace denylist; `caph_enter_casper()` applies a
  read-only-filesystem mode (all mutation denied, O_RDONLY opens
  allowed — the property is "no write, no exec, no network", not
  per-path capability brokerage); the `caph_*_limit` family enforces
  per-fd rights via seccomp argument filters, consolidated into one
  filter per type at enter time.  Enforcement is required — if the
  kernel lacks Landlock/seccomp the tools fail at startup; set
  `ASTROUTILS_SANDBOX=NONE` to fall back to the no-op stub.  See the
  header comment in `src.compat/capsicum.c` for the known limitations
  (fd-number-keyed rights, in-process casper stubs).
- Compiler hardening (both builds, default on): `-fstack-protector-strong`,
  `-fstack-clash-protection`, `-ftrivial-auto-var-init=zero`,
  `-D_FORTIFY_SOURCE=3`. (zig build: `-Dharden=false` to disable.)
- Exploit mitigations (both builds, default on, CI-enforced): PIE
  executables, full RELRO (`-Wl,-z,now` / zig defaults), and per-arch
  control-flow protection (`-fcf-protection=full` on x86_64,
  `-mbranch-protection=standard` on aarch64). Verified mechanically by
  `ci/jobs/hardening-check.sh` (fails on any binary missing PIE/RELRO/
  BIND_NOW).
- `-fstrict-flex-arrays=3` was evaluated and rejected for now: this tree
  uses old-style trailing arrays pervasively, and any strict level turns
  those into runtime fortify aborts / ReleaseSafe traps on ordinary
  commands. Blocked on the `__counted_by` trailing-array audit.
- Production trap-mode UB checks (opt-in): zig `-Dprod-sanitize=true`,
  meson `-Dprod_sanitize=true` (clang only) — adds
  `-fsanitize=bounds,object-size` with `-fsanitize-minimal-runtime
  -fsanitize-trap=bounds,object-size`.
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
- Regression suite: `tests/` — a functional and security regression suite
  covering every command-line-observable fix above, wired into
  `meson test` (see tests/README.md).
- CI: `ci/` — podman-based local-first pipeline (gcc, clang, musl,
  ASan+UBSan, fuzz replay, hardening verification), run identically by
  `ci/run-ci.sh` and `.github/workflows/ci.yml` (see ci/README.md).
