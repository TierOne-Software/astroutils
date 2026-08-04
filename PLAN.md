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

## P1 — Make the Capsicum shim real (Landlock + seccomp)

**Why:** `include/sys/capsicum.h` and `include/capsicum_helpers.h` are
no-op stubs that `return 0`. Tools that call `caph_enter()` — cat, tee,
cmp, hexdump, basename and others — *believe* they are sandboxed and
are not. The call sites and rights declarations already exist and are
maintained upstream, so implementing the shim gives dozens of tools
genuine post-open privilege dropping with no per-tool patching.

- [ ] Map `cap_rights_limit` / `caph_limit_stdio` / `cap_enter` onto
      Landlock (filesystem) + seccomp-BPF (syscall surface).
- [ ] Decide and document the failure mode: kernels without Landlock
      must not break the tools, but Astro's kernel can require it.
      Suggested: `CHIMERA_SANDBOX=require` for Astro images, permissive
      elsewhere.
- [ ] Verify each existing `caph_*` call site's rights are honoured
      rather than silently widened.
- [ ] Test coverage per sandboxed tool: a denied operation must fail.

## P2 — Fuzz the network and decompression surface

**Why:** the four current targets are good, but the highest-risk parsers
remain unfuzzed. libfetch is what downloads software onto the device;
sh is the most security-critical tool in the set.

- [ ] `libfetch` — HTTP/FTP response parsing, chunked transfer decode,
      `fetchParseURL`, redirect and header handling. Highest priority.
- [ ] `sh` — parse-only harness (`-n`), never execute.
- [ ] `compress`/`zopen` LZW decoder and gzip's non-zlib format paths.
- [ ] `telnet` option negotiation (server-controlled input).
- [ ] awk's private regex engine (`awk/b.c`) and sed's script compiler.
- [ ] Data-path harnesses for awk/sed/grep: fixed program, fuzzed
      *input* — that is how untrusted data actually reaches them.
- [ ] Add an MSan job (the Infer uninit-read cluster suggests this class
      is live) and llvm-cov reports to find unreached parser code.
- [ ] Structure-aware fuzzing for patch (grammar-shaped diffs) to get
      past the shallow rejection paths.

## P3 — Complete the exploit-mitigation set

**Why:** current flags harden against memory-safety *bugs* but not
against *exploitation*; several standard mitigations are missing.

- [ ] PIE (`b_pie=true`) — confirmed absent: 0 of 146 binaries are
      position-independent (`ci/jobs/hardening-check.sh`).
- [ ] Full RELRO: partial RELRO is already present on all 146 binaries,
      but `BIND_NOW` is on none, so the GOT stays writable. Add `-z now`.
- [ ] `-fstrict-flex-arrays=3` — pairs with `__counted_by` and FORTIFY;
      this codebase is full of old-style trailing arrays.
- [ ] aarch64 `-mbranch-protection=standard` (PAC/BTI) — Astro targets
      Pi 4/5.
- [ ] x86_64 `-fcf-protection=full`.
- [ ] Evaluate `-fzero-call-used-regs=used-gpr` (cost vs. benefit).
- [ ] Port the zig-only trap-mode `-fsanitize=bounds,object-size` option
      to the meson build so production images can use it regardless of
      build system.
- [ ] Continue `__counted_by` adoption; resolve the `sort/bwstring.h`
      terminator-slot semantics blocker.
- [ ] Add annocheck/checksec verification to CI so hardening regressions
      are caught mechanically, not by review. (Partially done: `ci/`
      has a hardening job; extend it as flags are added.)
- [ ] Reconsider the global `-Wno-unused-result`: in a codebase where
      unchecked allocation was a recurring finding, that flag suppresses
      exactly the signal we want.

## P4 — musl and aarch64 validation

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
- [ ] Re-run sanitizers cross-arch; expect new signed/unsigned char and
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
