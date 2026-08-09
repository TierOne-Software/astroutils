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
