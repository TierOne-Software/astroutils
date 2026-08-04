#!/bin/sh
#
# run-ci.sh — local-first CI driver.
#
# Runs the same job scripts that GitHub Actions runs, in podman containers
# built from ci/Containerfile.*, so a full CI pass can be reproduced on a
# laptop before pushing.  This mirrors Astro's build philosophy: the
# pipeline is a thin wrapper around scripts that work locally.
#
# Usage:
#   ci/run-ci.sh                 # every job
#   ci/run-ci.sh gcc musl        # selected jobs
#   ci/run-ci.sh --host gcc      # on this machine, no container
#   ci/run-ci.sh --list          # show jobs
#
# Jobs:
#   gcc         glibc build with gcc, functional suite
#   clang       glibc build with clang, functional suite
#   musl        Alpine/musl build, functional suite
#   sanitizers  ASan+UBSan build, full suite and corpus replay
#   fuzz        libFuzzer harnesses, corpus replay (FUZZ_TIME=N to fuzz)
#   hardening   verify built binaries carry the expected mitigations
#
# Options:
#   --host          run directly instead of in a container
#   --engine CMD    container engine (default: podman, then docker)
#   --rebuild       rebuild the container images first
#   --keep-going    run remaining jobs after a failure
#   --list          list jobs and exit
set -eu

srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

engine=
use_container=1
rebuild=0
keep_going=0
jobs=

all_jobs="gcc clang musl sanitizers fuzz hardening"

while [ $# -gt 0 ]; do
    case $1 in
        --host)       use_container=0; shift ;;
        --engine)     engine=$2; shift 2 ;;
        --rebuild)    rebuild=1; shift ;;
        --keep-going) keep_going=1; shift ;;
        --list)       printf '%s\n' $all_jobs; exit 0 ;;
        -h|--help)    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)           printf 'run-ci.sh: unknown option %s\n' "$1" >&2; exit 2 ;;
        *)            jobs="$jobs $1"; shift ;;
    esac
done

[ -n "$jobs" ] || jobs=$all_jobs

if [ "$use_container" = "1" ] && [ -z "$engine" ]; then
    if command -v podman >/dev/null 2>&1; then
        engine=podman
    elif command -v docker >/dev/null 2>&1; then
        engine=docker
    else
        printf 'run-ci.sh: no podman or docker found; use --host\n' >&2
        exit 2
    fi
fi

img_fedora=chimerautils-ci-fedora
img_alpine=chimerautils-ci-alpine

build_image() {
    _name=$1; _file=$2
    if [ "$rebuild" = "1" ] || ! $engine image exists "$_name" 2>/dev/null; then
        printf '=== building image %s\n' "$_name"
        $engine build -t "$_name" -f "$srcdir/ci/$_file" "$srcdir/ci"
    fi
}

# in_container <image> <script> [env=value...]
in_container() {
    _img=$1; _script=$2; shift 2
    _envs=
    for _e in "$@"; do
        _envs="$_envs -e $_e"
    done
    # Rootless podman maps the invoking user to root inside the container,
    # so the unprivileged build user could not write the mounted tree;
    # keep-id maps it to the same uid instead.  Docker and rootful podman
    # do not need (or accept) it.
    _userns=
    if [ "$engine" = "podman" ] && [ "$(id -u)" -ne 0 ]; then
        _userns=--userns=keep-id
    fi

    # The source tree is mounted read-write because the jobs build into it.
    # :Z relabels for SELinux; harmless where SELinux is not enforcing.
    # shellcheck disable=SC2086
    $engine run --rm \
        $_userns \
        -v "$srcdir:/src:Z" \
        -w /src \
        $_envs \
        "$_img" \
        sh -c "$_script"
}

run_job() {
    _job=$1
    printf '\n########################################\n'
    printf '# job: %s\n' "$_job"
    printf '########################################\n'

    case $_job in
        gcc)
            if [ "$use_container" = "1" ]; then
                build_image "$img_fedora" Containerfile.fedora
                in_container "$img_fedora" 'sh ci/jobs/build-test.sh' \
                    CC=gcc CXX=g++ BUILD_DIR=build-ci-gcc
            else
                CC=gcc CXX=g++ BUILD_DIR=build-ci-gcc sh "$srcdir/ci/jobs/build-test.sh"
            fi ;;
        clang)
            if [ "$use_container" = "1" ]; then
                build_image "$img_fedora" Containerfile.fedora
                in_container "$img_fedora" 'sh ci/jobs/build-test.sh' \
                    CC=clang CXX=clang++ BUILD_DIR=build-ci-clang
            else
                CC=clang CXX=clang++ BUILD_DIR=build-ci-clang sh "$srcdir/ci/jobs/build-test.sh"
            fi ;;
        musl)
            if [ "$use_container" = "1" ]; then
                build_image "$img_alpine" Containerfile.alpine
                in_container "$img_alpine" 'sh ci/jobs/build-test.sh' \
                    CC=gcc CXX=g++ BUILD_DIR=build-ci-musl
            else
                printf 'skip: the musl job needs the Alpine container\n'
            fi ;;
        sanitizers)
            if [ "$use_container" = "1" ]; then
                build_image "$img_fedora" Containerfile.fedora
                in_container "$img_fedora" 'sh ci/jobs/sanitizers.sh' \
                    CC=clang CXX=clang++ BUILD_DIR=build-ci-asan
            else
                CC=clang CXX=clang++ BUILD_DIR=build-ci-asan sh "$srcdir/ci/jobs/sanitizers.sh"
            fi ;;
        fuzz)
            if [ "$use_container" = "1" ]; then
                build_image "$img_fedora" Containerfile.fedora
                in_container "$img_fedora" 'sh ci/jobs/fuzz-regress.sh' \
                    CC=clang "FUZZ_TIME=${FUZZ_TIME:-0}"
            else
                CC=clang FUZZ_TIME=${FUZZ_TIME:-0} sh "$srcdir/ci/jobs/fuzz-regress.sh"
            fi ;;
        hardening)
            # Reuses the gcc job's tree; build it first if absent.
            if [ "$use_container" = "1" ]; then
                build_image "$img_fedora" Containerfile.fedora
                in_container "$img_fedora" \
                    '[ -d build-ci-gcc ] || sh ci/jobs/build-test.sh; sh ci/jobs/hardening-check.sh' \
                    CC=gcc CXX=g++ BUILD_DIR=build-ci-gcc \
                    "HARDENING_STRICT=${HARDENING_STRICT:-0}"
            else
                [ -d "$srcdir/build-ci-gcc" ] || \
                    CC=gcc BUILD_DIR=build-ci-gcc sh "$srcdir/ci/jobs/build-test.sh"
                BUILD_DIR=build-ci-gcc HARDENING_STRICT=${HARDENING_STRICT:-0} \
                    sh "$srcdir/ci/jobs/hardening-check.sh"
            fi ;;
        *)
            printf 'run-ci.sh: unknown job %s (see --list)\n' "$_job" >&2
            return 2 ;;
    esac
}

failed=
for j in $jobs; do
    if run_job "$j"; then
        printf '=== job %s: PASS\n' "$j"
    else
        printf '=== job %s: FAIL\n' "$j"
        failed="$failed $j"
        [ "$keep_going" = "1" ] || break
    fi
done

printf '\n========================================\n'
if [ -n "$failed" ]; then
    printf 'failed jobs:%s\n' "$failed"
    exit 1
fi
printf 'all jobs passed:%s\n' " $jobs"
