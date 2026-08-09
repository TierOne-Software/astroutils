# Hardening plan — chimerautils (Astro fork)

Forward work queue for the security and robustness effort. Companion to
`SECURITY-FINDINGS.md`, which records what has already been found and
fixed; this file records what is *next* and why.

Context: this fork feeds [Astro](../Astro), an embedded appliance distro
(musl, aarch64 + x86_64, read-only rootfs, network-facing update and
config daemons). Priorities below are ordered for that threat model —
untrusted input arrives over the network and from files on `/data`, and
a device in the field cannot be trivially reflashed after a compromise.

Status legend: TODO / IN PROGRESS / DONE / DEFERRED.

---

## Where the effort stands

Done so far (see `SECURITY-FINDINGS.md` for detail):

- Five analyzers run and triaged: Infer, clang scan-build, zig
  ReleaseSafe UB traps, `_FORTIFY_SOURCE=3`, libFuzzer.
- ~30 real defects fixed, each with a live repro, including three of
  genuine severity: patch(1) stale-`p_len` OOB write from a malicious
  diff, patch(1) 16 GB memory-exhaustion DoS from an 89-byte input, and
  nvi CONVERT2 unbounded-growth/UAF on iconv buffer growth.
- 34-patch upstream-submittable series in `upstream-patches/`.
- Baseline compiler hardening in both build systems.
- Four libFuzzer harnesses over untrusted-input parsers.

Known gaps this plan addresses, in priority order.

---

## P0 — Regression tests and CI — DONE (extensions remain)

**Why first:** close to forty behaviour-affecting patches have landed
backed only by `zig-build-smoke.sh` and ad-hoc manual repros. Nothing
mechanically prevents a future FreeBSD import from silently reverting
any of them, and every later item on this list needs somewhere to run.

- [x] `tests/` — portable POSIX-sh functional suite, runnable against
      any bindir (meson, zig, or an installed image), wired into
      `meson test`.
- [x] A regression test for every fix in `SECURITY-FINDINGS.md` that is
      observable from the command line — this is the load-bearing part.
- [x] Fuzz regression: replay `fuzz/corpus/` and past crash artifacts as
      a fixed corpus, non-generative, on each run.
- [x] `ci/` — podman-based local-first pipeline (matches Astro's build
      philosophy): the same scripts run locally and in GitHub Actions.
- [x] CI jobs: glibc+gcc, glibc+clang, musl (Alpine), ASan+UBSan test
      run, fuzz regression, hardening-flag verification.
- [ ] Extend coverage by porting a subset of FreeBSD's ATF tests
      (`usr.bin/*/tests`) for the tools carrying the most patches.
- [ ] Coverage reporting (llvm-cov) over the suite, to find which
      patched code paths the regression tests still do not reach.

The first run of this pipeline found five defects, four of them fixed in
the same pass (see SECURITY-FINDINGS.md, "Regression-suite findings"):
patch(1) NULL pattern-line dereference (46 corpus inputs segfaulted the
real binary), patch(1) heap use-after-free through the faked-up line
range, patch(1) out-of-bounds read on a zero-length pattern line, and a
`counted_by` annotation that broke the entire musl build. The fifth,
vis(1) corrupting bytes >= 0x80 on musl, is open — see P4.

The lesson worth keeping: all three patch(1) bugs were reachable only
through `main()`, not through the fuzz harness's chosen entry point.
Replaying corpora through the real binaries is not redundant with
fuzzing them.

## P1 — Make the Capsicum shim real (Landlock + seccomp) — DONE

**Why:** `include/sys/capsicum.h` and `include/capsicum_helpers.h` are
no-op stubs that `return 0`. Tools that call `caph_enter()` — cat, tee,
cmp, hexdump, basename and others — *believe* they are sandboxed and
are not. The call sites and rights declarations already exist and are
maintained upstream, so implementing the shim gives dozens of tools
genuine post-open privilege dropping with no per-tool patching.

- [x] `caph_enter()` → full lockdown: Landlock ruleset handling all fs
      access with zero rules (no path-based fs access post-enter) +
      seccomp namespace denylist (exec/sockets/ptrace/mount/... →
      EPERM).  `caph_enter_casper()` → read-only mode: Landlock denies
      all fs mutation, seccomp allows only O_RDONLY opens.  The honest
      property is "no write, no exec, no network" — NOT per-path
      capability brokerage (any user-readable file stays readable,
      e.g. ~/.ssh); per-path narrowing for the argv-only tools
      (cat/head/wc) is possible later via a strict fileargs variant.
      Read-only opens are what keep `md5 -c` and `tail -F` working —
      FreeBSD's broker is credential-bound there too.
- [x] Startup cost: pre-enter limit calls are accumulated in userspace
      and flushed as one filter per type at enter (~110us per stacked
      filter saved; basename-class tools carry 4 filters, not 10-13).
      Sandboxing even the trivial tools (echo/yes/basename) was a
      deliberate choice: upstream call-site parity, and post-
      consolidation the cost is ~0.3-0.7 ms one-time per process.
- [x] Per-fd rights (`caph_rights_limit`, `caph_limit_stdio`,
      `caph_ioctls_limit`, `caph_fcntls_limit`) enforced with
      fd-number-keyed seccomp argument filters.  `CAP_LOOKUP` on a
      directory fd registers a Landlock+seccomp exception beneath it
      (write(1)'s /dev fd).
- [x] Failure mode: enforcement is **required by default** — if the
      kernel lacks Landlock/seccomp, caph_enter() fails and tools exit
      via their err(1) path.  `ASTROUTILS_SANDBOX=NONE` restores the
      no-op stub behavior.
- [x] Call-site audit: all 33 sandboxed tools traced for post-enter fs
      access; none need writes.  One tool needed a tweak: logname's
      `getlogin()` moved before `caph_enter()` (libc opens utmp by
      path).
- [x] Tests: `shimtest` (22 assertions over both modes + stub mode)
      plus `tests/t/14-sandbox.sh` driving it and the sandboxed CLI
      tools; the whole suite doubles as the over-restriction check.

Known limitations (documented in src.compat/capsicum.c): fd rights are
keyed on fd numbers (a dup'd fd escapes its limit; a reused number
inherits one — over-restriction, the safe direction); Casper services
(cap_net, cap_syslog) remain in-process stubs.

Follow-on: patch(1) is now path-scoped sandboxed (`caph_allow_path` +
`caph_enter_paths`, a port-extension mode): Landlock confines all fs
access to the target tree and TMPDIR, seccomp denies exec/sockets/
process control.  patch has the worst memory-safety track record in
this tree (8 fixes, all reachable from a hostile diff); a malicious
diff now buys at most writes inside the target directory.

Follow-on: libfetch/fetch(1) is brokered-sandboxed.  `fetch_sandbox_begin()`
splits the process: a broker child keeps the network rights
(resolve+connect, ports 21/80/443/8080 plus the run's first-requested
port), while fetch itself enters the path-scoped sandbox (cwd+TMPDIR
read/write, no connect/exec/sockets) with the TLS trust store
preloaded.  All connects — redirects, FTP PASV, SOCKS TCP legs — go
through the broker over a SEQPACKET socketpair (SCM_RIGHTS fd
passing).  A parser exploit now yields confined file writes and no
network channel.  Broker runs as the *child* so fetch's exit status
reaches the caller.  Caveats (documented): FTP active mode falls back
to PASV; file:// outside the allowed roots is denied; .netrc-based
auth is unavailable post-enter.

## P2 — Fuzz the network and decompression surface — MOSTLY DONE

**Why:** the four current targets are good, but the highest-risk parsers
remain unfuzzed. libfetch is what downloads software onto the device;
sh is the most security-critical tool in the set.

- [x] `libfetch` — `fuzz_http` drives chunked-transfer decoding, reply
      status/header parsing, and the mtime/length/range/lexer/auth
      parsers (1M execs clean).
- [x] `sh` — `fuzz_sh` drives `parsecmd()` (the `-n` path) in-process
      with dash's own longjmp/reset machinery (552k execs clean).
- [x] `compress`/`zopen` — `fuzz_zopen` decodes fuzzed `.Z` streams and
      roundtrips writes at maxbits 9-16 (70k execs clean).
- [x] `telnet` — `fuzz_telnet` drives `telrcv()` IAC negotiation and
      the TTYPE/TSPEED/LINEMODE/NEW_ENVIRON suboption parsers (1M
      execs clean).  Not covered: the ENCRYPTION/AUTHENTICATION arms
      (libtelnet auth/encrypt parsers) — follow-up.
- [x] awk's regex engine (`b.c`) — `fuzz_awkb` found **six bug
      classes** (see SECURITY-FINDINGS.md, fuzzing section); fixes and
      upstream submission are the current work item.  sed's script
      compiler remains.
- [x] Data-path harnesses — `fuzz_grepdata` (grep), `fuzz_seddata`
      (sed), `fuzz_awkdata` (awk): fixed program, fuzzed *input* — that
      is how untrusted data actually reaches them.  All clean.
- [x] MSan job — `ci/jobs/msan.sh` builds all harnesses with
      `-fsanitize=fuzzer,memory` (support libs instrumented via
      `-Db_sanitize=memory` so their writes are visible — an
      uninstrumented libcompat produced a convincing false positive on
      the first run) and replays every corpus.  llvm-cov coverage
      reports remain.
- [x] Structure-aware fuzzing for patch — `fuzz_patch_struct`'s grammar
      mutator reaches ~2x edge coverage from minimal seeds; clean.

## P3 — Complete the exploit-mitigation set — DONE

**Why:** current flags harden against memory-safety *bugs* but not
against *exploitation*; several standard mitigations are missing.

- [x] PIE — meson `b_pie=true` (default option) and zig `exe.pie`;
      146/146 binaries are ET_DYN PIE in both build systems.
- [x] Full RELRO / BIND_NOW — `-Wl,-z,now` in meson (native tools too);
      zig already links `link_z_relro`/`link_z_lazy=false` by default.
      146/146.
- [ ] `-fstrict-flex-arrays=3` — DEFERRED with evidence: tried it; with
      any strict level, `__builtin_object_size` treats this tree's
      old-style trailing arrays (`char buf[1]` idiom) as fixed, and
      `_FORTIFY_SOURCE=3` then aborts on ordinary commands (`ls -l`)
      while zig ReleaseSafe bounds checks trap.  Can only land together
      with the `__counted_by` trailing-array audit below.  The comment
      in meson.build records this.
- [x] aarch64 `-mbranch-protection=standard` (PAC/BTI) and x86_64
      `-fcf-protection=full` — both build systems, per-arch.
- [ ] `-fzero-call-used-regs=used-gpr` — DEFERRED: the benefit on top of
      the now-complete core mitigations is marginal, and the tree is
      longjmp-heavy (nvi/tip/sh), the interaction that has bitten this
      flag before.  Revisit if a threat-model need appears.
- [x] Trap-mode `-fsanitize=bounds,object-size` ported to meson:
      `-Dprod_sanitize=true` (clang only, errors on gcc).
- [ ] Continue `__counted_by` adoption; resolve the `sort/bwstring.h`
      terminator-slot semantics blocker.
- [x] Mitigation verification enforced in CI — `hardening-check.sh` now
      *fails* on any binary missing PIE/RELRO/BIND_NOW (was: reported as
      TODO under HARDENING_STRICT).
- [ ] Reconsider the global `-Wno-unused-result` — probed: removing the
      suppression produces 141 warnings tree-wide.  Keeping it for now
      (fixing 141 sites is a churn-heavy sweep against upstream); the
      count is recorded and the triage belongs to the P6 long tail.

## P4 — musl and aarch64 validation — DONE

**Why:** Astro is musl-based and ships on aarch64; this work has run on
glibc/x86_64. Locale, regex and `getopt` differences will surface bugs —
the jot format bug was exactly that class. aarch64's unsigned-by-default
`char` interacts directly with the signed-char bug class already fixed
in unvis.

- [x] **Fix vis(1) on musl** — DONE: `mbrtowc()` decodes landing in
      musl's surrogate-escape range (U+DF80..U+DFFF) are folded back to
      the raw byte in `istrsenvisx()`; all 256 byte values round-trip on
      musl and the XFAIL is now a hard regression test. See
      SECURITY-FINDINGS.md.
- [x] Audit the rest of `src.freebsd/compat` for the same assumption —
      DONE: only vis.c decodes multibyte input; every other file is
      byte-oriented or `(unsigned char)`-hardened, runtime-verified
      musl ≡ glibc. The audit did surface an unrelated upstream unvis
      `&#NN;` decode bug — fixed (see SECURITY-FINDINGS.md).
- [x] `zig build -Dtarget=aarch64-linux-musl` and
      `-Dtarget=arm-linux-musleabihf`, tests under qemu-user — DONE:
      bare musl cross builds work (bundled FreeBSD queue.h fallback for
      libcs without sys/queue.h; host-probed deps are zeroed on cross so
      library-dependent tools skip cleanly). 123/146 tools build; the
      suite passes on both arches (aarch64: all green; armv7 exposed
      only a 32-bit-`LINENUM` test assumption, fixed).  Skipped tools
      (sort, nvi, fetch, telnet, …) need a cross sysroot for
      crypto/ncurses/xo — revisit if Astro wants full-tool cross builds.
- [x] Re-run sanitizers cross-arch — DONE: both arches built with
      `-Dprod-sanitize=true` (trap-mode bounds/object-size) on top of
      ReleaseSafe UB checks; full suite including corpus replay passes
      clean under qemu on aarch64 and armv7. No new signed-char or
      alignment findings.
- [x] Alpine (musl) CI job running the new suite.

## P5 — Phase 3: unsafe string call sites

**Why:** `src.safestr/` exists but has zero consumers; ~200
`strcpy`/`strcat`/`sprintf` sites remain. Priority order below is by
exposure, per the approach already recorded in `SECURITY-FINDINGS.md`.

- [ ] `telnet` (37 sites) — network-facing, server-controlled input.
- [ ] `fetch` + `libfetch` (22) — network-facing.
- [ ] `ee` (29), `sh` (12), coreutils (44), miscutils (31).
- [ ] Choose per site: `strlcpy`/`strlcat`/`snprintf` where equivalent
      (keeps patches upstream-submittable), `safestr` only where it buys
      real checking. Do not churn call sites for their own sake.

## P6 — Second-wave analysis and the deferred long tail

- [ ] CodeQL — taint tracking from network input through libfetch and
      telnet is genuinely different from what Infer/scan-build model.
- [ ] gcc `-fanalyzer` (different engine, different false positives).
- [ ] Coverity Scan if the repo can be made public.
- [ ] Triage the 56 `MEMORY_LEAK_C` reports *for the long-lived tools
      only* — nvi, sh, telnet, tip. The "benign at exit" rationale does
      not hold for an editor or a shell session.
- [ ] Same for the "some real fd leaks" in the 88 stream-handling
      reports.
- [ ] Close the one open finding: `nvi/ex/ex_subst.c` `s()` lb leak on
      OOM (needs the `_GOTO` macro rework).
- [ ] Re-run all analyzers after P0–P3 land; record the deltas.

## P7 — Coordinated disclosure

**Why:** the patch(1) findings are attacker-controlled OOB writes from a
malicious diff, present verbatim upstream, and `pch.c` shares lineage
with OpenBSD and NetBSD. These want a security-officer report, not a
patch on a mailing list.

- [ ] Report to the FreeBSD Security Officer: patch(1) stale-`p_len` OOB
      write, patch(1) unbounded `hunkmax` DoS, nvi CONVERT2, nvi
      `re_conv` heap overflow. Request CVEs.
- [ ] Check OpenBSD/NetBSD `patch(1)` for the same defects; notify if
      present.
- [ ] Submit the remaining series (`upstream-patches/`) through the
      normal FreeBSD review process.
- [ ] Notify Chimera Linux — they ship this code today.

## P8 — Attack-surface reduction in the Astro image

**Why:** the cheapest hardening is not shipping the tool.

- [ ] Explicit ship / don't-ship decision, recorded in Astro's docs, for
      `telnet`, `tip`/`cu`, `ee`, `nvi`, and the experimental `su`.
- [ ] If `su` ships: dedicated audit. It is the only setuid binary in
      the set — environment scrubbing, tty handling, signal handling,
      dumpability.
- [ ] Consider a minimal-tool build profile for production images
      (meson option) distinct from the development image.

## P9 — Differential testing vs. GNU and upstream

**Why:** the jot bug is a class the analyzers cannot see — the port
behaving differently from both upstream FreeBSD and GNU. This is
robustness rather than security, but it is what protects Astro from
subtle script breakage after an import.

- [ ] Harness driving identical invocations through chimerautils, GNU
      coreutils and toybox; diff stdout/stderr/exit status.
- [ ] Run it against FreeBSD binaries too, to separate "port bug" from
      "BSD/GNU difference" (the latter belongs in `TRADEOFFS`).

---

## Suggested sequencing

P0 and P3 are largely mechanical and unblock everything else — CI gives
every later item somewhere to run, and the mitigation flags are a
one-time build change. P1 is the most interesting engineering and the
biggest differentiator for an appliance OS. P7 has a clock on it: those
patch(1) defects are sitting exploitable in three upstream BSDs right
now.
