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

Notes for upstream:
- 0001 introduces __cu_counted_by in include/sys/cdefs.h.
- 0012/0013 add -fwrapv to the affected targets in meson; equivalent
  flag already present in the (local) zig build.
- The fuzz harnesses that found 0011-0013 live in fuzz/ (not part of
  this series; can be submitted separately if wanted).
