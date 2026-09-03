# CI

Local-first pipeline. The jobs are plain shell scripts in `ci/jobs/`;
`ci/run-ci.sh` runs them in podman containers so a full CI pass can be
reproduced on a laptop, and `.github/workflows/ci.yml` runs the *same*
scripts in GitHub Actions. Nothing in the pipeline exists only on the
server, which follows Astro's containerized, reproducible-build approach.

## Running locally

```sh
ci/run-ci.sh                  # every job, in containers
ci/run-ci.sh gcc musl         # selected jobs
ci/run-ci.sh --host gcc       # on this machine, no container
ci/run-ci.sh --list           # list jobs
ci/run-ci.sh --rebuild gcc    # rebuild the image first
FUZZ_TIME=300 ci/run-ci.sh fuzz          # fuzz, not just replay
HARDENING_STRICT=1 ci/run-ci.sh hardening # enforce the roadmap mitigations
```

The first containerized run builds the images (a few minutes); after that
they are cached by podman.

## Jobs

| Job | What it does |
|---|---|
| `gcc` | glibc build with gcc, then the functional suite |
| `clang` | glibc build with clang, then the functional suite |
| `musl` | Alpine/musl build and suite — the configuration Astro ships |
| `sanitizers` | ASan+UBSan build, full suite **and** full corpus replay |
| `fuzz` | builds the libFuzzer harnesses, replays every corpus |
| `msan` | MemorySanitizer build of the harnesses + corpus replay |
| `hardening` | checks built binaries carry the expected mitigations |
| `zig` | zig build (ReleaseSafe), smoke tests + full suite |

`sanitizers` is the job most likely to find something new: it drives the
regression tests and the whole fuzz corpus through instrumented binaries,
so a latent out-of-bounds access becomes a failure instead of silent
corruption. It found a heap use-after-free in patch(1) the first time it
ran.

`musl` matters more than its position in the list suggests. glibc hides
bugs that musl does not — `printf("%s", NULL)` prints `(null)` on glibc
and segfaults on musl, and locale and regex behaviour differ.

## Images

- `Containerfile.fedora` — glibc, gcc + clang, sanitizer runtimes,
  libFuzzer, and `libxo` from the distro.
- `Containerfile.alpine` — musl; `libxo` is built from source into the
  image layer rather than on every run.

Both create an unprivileged `build` user, because a few tests depend on
file permissions actually being enforced and would skip under root.

## Adding a job

Write `ci/jobs/<name>.sh` so that it works when invoked directly from the
repository root with no arguments, taking its configuration from the
environment (`CC`, `BUILD_DIR`, ...). Then add a case to `run_job()` in
`run-ci.sh` and a step to `.github/workflows/ci.yml`. Keeping the logic
in the script rather than in YAML is what makes the local and CI runs the
same thing.

## Hardening gate

`ci/jobs/hardening-check.sh` distinguishes two tiers:

- **enforced** — the stack protector (checked on tools that certainly
  have stack buffers, since `-fstack-protector-strong` legitimately skips
  trivial ones) and `_FORTIFY_SOURCE`. A regression fails the job.
- **reported** — PIE, full RELRO and `BIND_NOW`, which this tree does not
  enable yet (PLAN.md P3). They are printed as TODO counts, and become
  hard failures under `HARDENING_STRICT=1` — which is how the gate gets
  switched on once those flags land.

## Upstream watch

`ci/upstream-check.sh` reports what changed upstream since the last
check, so drift from our two parents gets noticed nightly instead of at
the next painful rebase:

- **chimera-linux/chimerautils** (master) — our fork parent; all commits
  are reported, the repo is low-traffic (one API call).
- **freebsd/freebsd-src** (main) — the paths our `src.freebsd/` tree was
  imported from. The mapping lives in `ci/upstream-watch.list` and
  follows chimera's own `import-src.sh`.

```sh
ci/upstream-check.sh                  # report since the last stamp
ci/upstream-check.sh --since 2026-08-01T00:00:00Z   # ad-hoc look back
ci/upstream-check.sh --update         # report, then stamp the state
ci/upstream-check.sh --freebsd-mode api   # use the API, no local cache
```

The FreeBSD section does not use the API by default — ~135 watched
paths would need ~135 requests against the unauthenticated 60/hour
limit. Instead it keeps a blobless partial clone at
`$XDG_CACHE_HOME/astroutils/freebsd-src.git` (default
`~/.cache/astroutils/freebsd-src.git`, outside the repo): full
commit/tree history, blobs on demand. The first run does a one-time
clone of ~700 MB (progress on stderr); after that a nightly run is a
tiny `git fetch` plus local `git log` queries — a couple of seconds,
with no rate limits. `--freebsd-mode api` keeps the old behavior for
machines without the cache; export `GITHUB_TOKEN` there.

The state is two ISO dates in `ci/.upstream-sync.state` (gitignored);
without it the window defaults to the last 7 days. `--update` only
stamps a clean full run, so a failed night is retried rather than
silently skipped.

The script only reports. A reviewing agent triages the output against
our local patches (`upstream-patches/`, `patches/`) and recommends what
to import; nothing is pulled in automatically.
