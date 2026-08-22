# Upstream patch candidates

Bug fixes found during the static-analysis/fuzzing hardening pass
(see SECURITY-FINDINGS.md in the repo root). Generated with
`git format-patch`; apply with `git am` in order.

- 0001 counted_by: hardening annotation (buffer/count pairs in libfetch
  and nvi); optional but recommended — enables -fsanitize=bounds checks.
- 0002 grep: UB pointer arithmetic in initqueue (Bflag == 0).
- 0003 cut: unsigned-wrap subscript UB in f_cut.
- 0004 join: unsigned-wrap subscript UB in mbssep.
- 0005 jot: broken default output format on glibc (invalid printf format
  built while prec == -1).
- 0006 env: unchecked mallocs in split_spaces (Infer).
- 0007 mcookie: stack buffer overflow + OOB read in hex output
  (_FORTIFY_SOURCE=3 catch). HIGH severity.
- 0008 fetch: once_flag name conflict with newer glibc <stdlib.h>
  (build fix).
- 0009 cp: open_how shim conflicts with linux/openat2.h (build fix).
- 0010 src.custom: __progname constness conflict (build fix).
- 0011 unvis: signed-shift UB for high-byte escapes (fuzz/UBSan).
- 0012 getdate: localtime NULL derefs (crash on adversarial date
  strings) + signed-overflow UB; adds -fwrapv. HIGH severity.
- 0013 patch: memory-safety fixes from fuzzing — 16GB memory DoS via
  unbounded hunk size, OOB read, six OOB writes, unlink(NULL).
  HIGH severity.
- 0014 awk: unchecked calloc in cclenter (Infer).
- 0015 cat: unchecked fdopen in scanfiles (scan-build).
- 0016 ed: zero-length memcpy UB in join_lines.
- 0017 ee: unchecked txtalloc/malloc/fopen (Infer).
- 0018 hexdump: null nextpr dereference in rewrite (scan-build).
- 0019 nvi: uninitialized SMAP reads in vs_sm_up/vs_sm_down — root
  cause of ~30 Infer uninit reports.
- 0020 nvi: uninitialized nread in ex_filter (Infer).
- 0021 nvi: doinsert continued on stale strip after EMIT failure
  (Infer UAF cluster).
- 0022 nvi: TMAP computed from NULL map during option init — UB
  pointer arithmetic (zig ReleaseSafe trap on startup).
- 0023 nvi: zero-length MEMCPY from NULL build buffer on match at
  offset 0 (zig ReleaseSafe trap on `%s` at line start).
- 0024 nvi: dangling buffer pointer left on binc() failure — UAF /
  double-free on OOM (Infer).
- 0025 nvi: double-counted message-prefix length in msgq — strerror
  text written past uninitialized gap, truncated error messages
  (Infer).
- 0026 nvi: stale iconv output pointer after buffer growth in
  CONVERT2 — infinite E2BIG retry loop with unbounded memory growth
  (observed 527 MB RSS in 0.4 s), plus UAF write on iconv
  implementations that write before reporting E2BIG. HIGH severity.
- 0027 nvi: NULL build buffer on all-`~` patterns/replacements with no
  previous replacement — NULL passed to memcpy (scan-build; traps under
  zig ReleaseSafe/UBSan on `:s/~/X/`, `:s/a/~/`).
- 0028 xargs: err(3) in the vfork'd child runs atexit/stdio cleanup in
  the shared pre-exec address space; use warn(3) + _exit(1).
- 0029 ed: drop dead initializer in append_lines (dead store).
- 0030 dbcompat: WR_RLEAF did memmove(p, NULL, 0) for empty records —
  triggers when nvi loads a file whose first line is empty (UBSan).
- 0031 nvi: re_conv counting pass undercounted literal '~' by one
  CHAR_T in two cases — 1-CHAR_T heap overflow when
  needlen*sizeof(CHAR_T) is an exact power of two ≥ 256 (ASan-verified).
- 0032 nvi: run_cscope child did malloc/asprintf/free/msgq between
  vfork and execl — command string now built in the parent.
- 0033 nvi: db_get/db_last did MEMCPY(NULL, wp, 0) caching an empty
  last line — traps on loading an all-empty-lines file (UBSan).
- 0034 compat: mktemp _gettemp indexed padchar with sizeof including
  the NUL — planted '\0' in templates, 1-byte global over-read on the
  EEXIST carry path (ASan).
- 0038 compat: fold musl surrogate-escape decodes (U+DF80..U+DFFF) back
  to raw bytes in vis — every byte ≥ 0x80 was double-encoded on musl,
  corrupting vis|unvis round-trips (data-integrity bug; musl-only
  trigger, harmless on glibc/FreeBSD).
- 0039 compat: unvis &#NN; numeric entities decoded as cp*11+d
  (NetBSD PR lib/60111; cherry-pick of upstream 1.46+1.47 including
  the UCHAR_MAX overflow check). Data corruption on unvis -H.
- 0040 fetch: initialize url_stat before the transfer loop — the
  mirror-mode check read an uninitialized struct when fetchXGet failed
  before filling it.
- 0041 awk: six regex-engine bug classes reachable from user patterns —
  replace_repeat stale/NULL lastatom (heap overflow), trailing-backslash
  and [. /[= overreads, repetition-bound int overflow + 255 cap,
  cclenter off-by-one, hexstr signed overflow. HIGH severity. NOTE:
  awk's b.c is onetrueawk lineage — submit to onetrueawk, not FreeBSD
  (the bound cap and NULL guard mirror upstream; the other four still
  crash upstream master).
- 0042 sed: free the first s-command regex compilation — one regex_t
  leaked per s command per process (fuzz/LSan find; minor).
- 0043 awk: cap total repetition expansion — nested {n}{m}… bounds
  compound multiplicatively because replace_repeat() expands textually
  ((x{215}){215}){7} ≈ 320k copies; a 117-byte pattern kept makedfa()
  for 111 s). Compile-time DoS from user patterns; onetrueawk master
  has the same hole (submit there, like 0041).
- 0044 sed: skip the zero-length memmove in cspace — g/G with an
  untouched hold space pass NULL with count 0; UBSan nonnull violation
  (11 corpus inputs abort the asan+ubsan CI job). Same guard idiom as
  the ed/sort zero-length memcpy fixes.
- 0045 libfetch: unsigned-wrap strncpy stack smash in fetchListFile —
  a file: doc path of exactly PATH_MAX-2 leaves l=0 and the loop's
  strncpy(p, name, l-1) passes (size_t)-1; deterministic stack smash on
  the first readdir entry, reachable via the public
  fetchListURL/fetchListFile API (fetch(1) itself never lists).
- 0046 telnet: three unbounded strcpy calls — ai_canonname into
  _hostname[64] (network-influenced), a 256-char -l user name into
  malloc(256) (1-byte heap overflow), a >255-char -n tracefile into
  NetTraceFile[256] (local-user only). All become strlcpy.
- 0047 ee: print_buffer() sprintf(buffer[256], ">!%s", print_command)
  — print_command holds up to ~498 chars from an init file, and init
  probing includes .init.ee relative to the cwd (.exrc-style planted
  config); menu -> file -> print smashes the stack. snprintf, plus
  dump_ee_conf snprintf and a get_string() 511-char input bound
  (hardening). Present verbatim in freebsd-src main (contrib/ee).
- 0048 calendar: CHECKSPECIAL stack smash — calendar files can
  redefine special-day names (Easter=<string>, no length cap in
  REPLACE); a date line of <name><modifier> strncpys lens2
  attacker-controlled bytes into specialday[100] on parsedaymonth's
  stack. Reject over-long names before the copy; also fix a
  wrong-size strlcpy in remember() (SLEN=100 into calloc(1, 20)).
  Present verbatim in freebsd-src main (usr.bin/calendar).
- 0049 stat/sort: two argv-only unbounded stack writes (hardening) —
  stat format1() lfmt[24] can receive 31 bytes of assembled printf
  format (widen to 64); sort parse_pos_obs() copies the obsolete +POS
  letter-run into a 128-byte stack buffer unchecked (reject over-long
  runs, which also secures the sopt[304] sprintfs).
- 0050 nvi: error-path memory safety, leaks, and tiny-screen
  underwrites — the long-path ellipsis logic underwrites its buffer by
  3 bytes at sp->cols <= 2 in file_write (stack) and msgq_status
  (heap; PoC-verified with a 2-column pty under ASan, startup and :w);
  double-fclose on failed fclose in ex_readfp/ex_writefp/rcv_mailfile;
  argv_sexp err-path fd typo (double-close + leak); uninit nlines from
  ex_readfp error paths; plus the error-path leak set (ex_move,
  msgq_status, exf:897, ex_read, ex_argv, ex_filter, recover, conv,
  ex_args, ex_tag, ex_at, ex_global) and OOM checks (file_backup,
  v_delete). All verbatim upstream in contrib/nvi.
- 0051 telnet: call() variadic terminator is int 0 at three sites but
  read as char * (UB, benign on LP64) → (char *)NULL; tn() leaks the
  strdup'd default port per failed `open` in the REPL (track
  portp_alloc, free at fail:); env_define malloc check.
- 0052 compress: double-fclose of ifp on fclose failure in both
  compress() and decompress() (ferror||fclose leaves ifp dangling into
  err:). Splits the branches, NULLs ifp on the failed-fclose path.
- 0053 ed: handle_hup() reads hup[-1] when HOME is set-but-empty
  (1-byte heap under-read on SIGHUP) — guard n == 0; plus a
  strip_escapes NULL check in get_shell_command.
- 0054 patch: fetchname() strchr/stat'd savestr() results unchecked —
  savestr returns NULL (no exit) under plan-A OOM during header
  parsing; crash-only DoS on a hostile patch under memory pressure.
  Propagate NULL (all callers already handle it).
- 0055 env: check the three expand_vars() mallocs — completes the
  malloc-check coverage 0006 started in split_spaces.
- 0056 ee: get_string() malloc(512) unchecked (OOM null-deref at any
  prompt); dump_ee_conf() leaks old_init_file when the new config
  can't be opened after the rename.
- 0057 misc OOM sweep: calendar createdate() ×3 + setnsequences(),
  wall -g, whereis scanopts realloc, find -printf open_memstream — all
  unchecked-allocation derefs, fixed in each file's own idiom.
- 0058 unvis/cmp/sdiff: stream closes — unvis leaked one fd per input
  file (per-file fopen loop, never closed); cmp's feof-mismatch and
  sdiff's binary paths skipped their fcloses.
- 0059 dbcompat btree: cherry-pick of freebsd-src 4bcc5a3cdc05
  (bt_seq __bt_first NULL derefs — hprev assignment + RET_SPECIAL).
  No in-tree btree consumer; keeps the file in step with upstream.
- 0060 tip: pipefile() leaks both pipe fds on fork failure.
- 0061 nvi: s() leaked the partially built line buffer on OOM
  (GET_SPACE_RETW/ADD_SPACE_RETW returned without freeing) — converted
  to the _GOTOW variants behind an alloc_err label; required BINC_GOTO
  (common/mem.h) to null the grown pointer after binc() frees it,
  mirroring BINC_RET (previously left dangling — a latent double-free
  for the txt_err users in v_txt/ex_txt).

- 0035 patch: three apply-path memory-safety bugs — NULL pattern line
  dereferenced in patch_match (46 corpus inputs segfault), heap
  use-after-free through the faked-up line range (ASan), and an
  out-of-bounds read on a zero-length pattern line (ASan). All reachable
  from a malicious diff. HIGH severity; see the note below.
- 0036 counted_by: gcc accepts the attribute only on flexible array
  members, so restrict 0001's annotation to clang (build fix — gcc 15
  fails to build libfetch otherwise).

- 0037 sort: memcpy(dst, NULL, 0) in radixsort run_sort_level_next, both
  branches — fires on an ordinary three-line sort (UBSan).

Notes for upstream:
- 0001 introduces __cu_counted_by in include/sys/cdefs.h; 0036 corrects
  its feature test. Squash them if 0001 has not been applied yet.
- 0035 should go to the Security Officer rather than through normal
  review, together with the earlier patch(1) findings in 0013: the
  combination is remotely triggerable memory corruption from an
  untrusted diff. Note that upstream is *more* exposed than this tree on
  the first bug — 0013 had already switched p_line to calloc, so the
  unfilled slot reads as NULL here but as uninitialized heap upstream.
- 0035 was found by replaying fuzz corpora through the real binary
  rather than the parse-only harness; the harness cannot reach any of
  the three sites. The replay driver is tests/t/20-fuzz-corpus.sh.
- 0012/0013 add -fwrapv to the affected targets in meson; equivalent
  flag already present in the (local) zig build.
- The fuzz harnesses that found 0011-0013 live in fuzz/ (not part of
  this series; can be submitted separately if wanted).
