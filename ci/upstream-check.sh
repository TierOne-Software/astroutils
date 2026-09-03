#!/bin/sh
#
# upstream-check.sh — report what changed upstream since the last check.
#
# Tracks the two projects we follow (see ci/upstream-watch.list):
#
#   chimera-linux/chimerautils  master, all commits (GitHub API, 1 call)
#   freebsd/freebsd-src         main, per watched path (local git cache)
#
# The report is meant to be triaged by a reviewing agent before anything
# is imported; this script never touches the source tree.
#
# Usage:
#   ci/upstream-check.sh                  # both sections
#   ci/upstream-check.sh --update         # run, then stamp the state file
#   ci/upstream-check.sh --since 2026-08-01T00:00:00Z
#   ci/upstream-check.sh --chimera-only   # or --freebsd-only
#   ci/upstream-check.sh --freebsd-mode api   # query the API instead
#
# State: ci/.upstream-sync.state holds CHIMERA_SINCE / FREEBSD_SINCE
# (ISO dates).  If absent, the window defaults to the last 7 days.
#
# FreeBSD mode: the default "git" mode keeps a blobless partial clone at
# $XDG_CACHE_HOME/astroutils/freebsd-src.git (default ~/.cache/...) —
# full commit/tree history, blobs on demand.  The first run clones it
# (one-time download, ~700 MB on disk, progress on stderr); later
# runs fetch a tiny increment and query locally, so there are no rate
# limits.  "api" mode instead makes one GitHub API request per watched
# path (~135) — that needs GITHUB_TOKEN (or GH_TOKEN) in the environment
# to stay under the unauthenticated 60 requests/hour limit.  If the rate
# limit is hit mid-run the remaining paths are skipped, the exit status
# is nonzero, and --update refuses to stamp an incomplete run.
set -eu

srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
watch_list=$srcdir/ci/upstream-watch.list
state_file=$srcdir/ci/.upstream-sync.state
api=https://api.github.com

update=0
since_override=
do_chimera=1
do_freebsd=1
freebsd_mode=git
freebsd_repo=https://github.com/freebsd/freebsd-src.git
cache_dir=${XDG_CACHE_HOME:-$HOME/.cache}/astroutils/freebsd-src.git

while [ $# -gt 0 ]; do
    case $1 in
        --update)       update=1; shift ;;
        --since)        since_override=$2; shift 2 ;;
        --chimera-only) do_freebsd=0; shift ;;
        --freebsd-only) do_chimera=0; shift ;;
        --freebsd-mode) freebsd_mode=$2; shift 2 ;;
        -h|--help)      sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)             printf 'upstream-check.sh: unknown option %s\n' "$1" >&2; exit 2 ;;
        *)              printf 'upstream-check.sh: unexpected argument %s\n' "$1" >&2; exit 2 ;;
    esac
done

case $freebsd_mode in
    git|api) ;;
    *) printf 'upstream-check.sh: --freebsd-mode must be git or api\n' >&2; exit 2 ;;
esac

if [ "$update" = 1 ] && { [ "$do_chimera" = 0 ] || [ "$do_freebsd" = 0 ]; }; then
    printf 'upstream-check.sh: --update only makes sense on a full run\n' >&2
    exit 2
fi

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
# -d @epoch works with both GNU coreutils and busybox date
utc_days_ago() { date -u -d "@$(( $(date '+%s') - $1 * 86400 ))" '+%Y-%m-%dT%H:%M:%SZ'; }

chimera_since=
freebsd_since=
if [ -f "$state_file" ]; then
    chimera_since=$(sed -n 's/^CHIMERA_SINCE=//p' "$state_file")
    freebsd_since=$(sed -n 's/^FREEBSD_SINCE=//p' "$state_file")
fi
[ -n "$chimera_since" ] || chimera_since=$(utc_days_ago 7)
[ -n "$freebsd_since" ] || freebsd_since=$(utc_days_ago 7)
if [ -n "$since_override" ]; then
    chimera_since=$since_override
    freebsd_since=$since_override
fi

auth_header=
if [ -n "${GITHUB_TOKEN:-}" ]; then
    auth_header="Authorization: Bearer $GITHUB_TOKEN"
elif [ -n "${GH_TOKEN:-}" ]; then
    auth_header="Authorization: Bearer $GH_TOKEN"
fi

gh_api() {
    if [ -n "$auth_header" ]; then
        curl -fsSL -H "$auth_header" "$1"
    else
        curl -fsSL "$1"
    fi
}

# parse_commits — read a commits API response on stdin, print
# "<sha12>  <date>  <subject>" per commit; fail on non-list JSON
parse_commits() {
    python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
if not isinstance(data, list):
    print(data.get("message", "unexpected API response"), file=sys.stderr)
    sys.exit(1)
for c in data:
    commit = c.get("commit", {})
    date = commit.get("committer", {}).get("date", "?")
    subject = (commit.get("message") or "").split("\n", 1)[0]
    print("%s  %s  %s" % (c.get("sha", "?")[:12], date, subject))
'
}

# ensure_freebsd_cache — clone the blobless partial clone of freebsd-src
# on first use, fetch main afterwards; print the mainline rev on stdout
ensure_freebsd_cache() {
    if [ -d "$cache_dir" ] && ! git -C "$cache_dir" rev-parse --git-dir >/dev/null 2>&1; then
        printf 'note: %s is not a usable git repo; re-cloning\n' "$cache_dir" >&2
        rm -rf "$cache_dir"
    fi
    if [ ! -d "$cache_dir" ]; then
        printf 'cloning %s into %s — blobless partial clone,\n' "$freebsd_repo" "$cache_dir" >&2
        printf 'a one-time download of ~700 MB (history metadata only)\n' >&2
        mkdir -p "$(dirname "$cache_dir")"
        if ! git clone --filter=blob:none --bare "$freebsd_repo" "$cache_dir" >&2; then
            rm -rf "$cache_dir"
            printf 'warning: freebsd-src clone failed\n' >&2
            return 1
        fi
    elif ! git -C "$cache_dir" fetch --filter=blob:none origin main >&2; then
        printf 'warning: freebsd-src fetch failed\n' >&2
        return 1
    fi
    # a bare clone stores the default branch as refs/heads/main
    for _r in origin/main main; do
        if git -C "$cache_dir" rev-parse --verify --quiet "$_r" >/dev/null; then
            printf '%s\n' "$_r"
            return 0
        fi
    done
    printf 'warning: no mainline ref found in %s\n' "$cache_dir" >&2
    return 1
}

# show_hits <path> <lines> — print a path header plus indented commits
show_hits() {
    freebsd_hit_paths=$((freebsd_hit_paths + 1))
    printf '%s\n' "$1"
    printf '%s\n' "$2" | sed 's/^/  /'
    freebsd_commits=$((freebsd_commits + $(printf '%s\n' "$2" | grep -c . || true)))
}

errf=$(mktemp)
trap 'rm -f "$errf"' EXIT

chimera_commits=0
freebsd_commits=0
freebsd_hit_paths=0
failed=0
rate_limited=0
skipped=0

if [ "$do_chimera" = 1 ]; then
    printf '=== chimera-linux/chimerautils: commits on master since %s\n' "$chimera_since"
    _url="$api/repos/chimera-linux/chimerautils/commits?sha=master&since=$chimera_since&per_page=100"
    if _json=$(gh_api "$_url" 2>"$errf") && _lines=$(printf '%s' "$_json" | parse_commits); then
        if [ -n "$_lines" ]; then
            printf '%s\n' "$_lines" | sed 's/^/  /'
            chimera_commits=$(printf '%s\n' "$_lines" | grep -c . || true)
        fi
        printf '  (%s commit%s)\n' "$chimera_commits" "$([ "$chimera_commits" = 1 ] || printf s)"
    else
        failed=$((failed + 1))
        grep -q 'error: 403\|error: 429' "$errf" && rate_limited=1
        printf 'warning: chimera API request failed: %s\n' "$(cat "$errf")" >&2
    fi
fi

if [ "$do_freebsd" = 1 ]; then
    printf '=== freebsd/freebsd-src: commits on main since %s (%s mode)\n' "$freebsd_since" "$freebsd_mode"
    # watched paths are the non-comment lines of the [FREEBSD] section
    _paths=$(sed -n '/^\[FREEBSD\]/,$p' "$watch_list" | sed 's/#.*//' | grep -v '^\[' | grep .)

    if [ "$freebsd_mode" = git ]; then
        # local blobless clone: no API calls, no rate limits
        if _rev=$(ensure_freebsd_cache); then
            for _p in $_paths; do
                _lines=$(git -C "$cache_dir" log --since="$freebsd_since" \
                    --format='%h %cs %s' "$_rev" -- "$_p")
                [ -n "$_lines" ] || continue
                show_hits "$_p" "$_lines"
            done
            [ "$freebsd_hit_paths" -gt 0 ] || printf '  (no changes)\n'
        else
            failed=$((failed + 1))
            printf 'warning: freebsd git cache unavailable; section skipped\n' >&2
        fi
    else
        if [ -z "$auth_header" ]; then
            printf 'note: no GITHUB_TOKEN set; unauthenticated limit is 60 requests/hour\n' >&2
        fi
        _total=$(printf '%s\n' "$_paths" | grep -c . || true)
        _done=0
        for _p in $_paths; do
            _done=$((_done + 1))
            _url="$api/repos/freebsd/freebsd-src/commits?path=$_p&since=$freebsd_since&per_page=100"
            if ! _json=$(gh_api "$_url" 2>"$errf"); then
                failed=$((failed + 1))
                # a rate limit only gets worse with more requests, so stop
                # the loop rather than hammering the API into a 429 ban
                if grep -q 'error: 403\|error: 429' "$errf"; then
                    rate_limited=1
                    skipped=$((_total - _done))
                    printf 'warning: %s: rate-limited; skipping the %s remaining path(s)\n' "$_p" "$skipped" >&2
                    printf '         set GITHUB_TOKEN — the unauthenticated limit is 60 requests/hour\n' >&2
                    break
                fi
                printf 'warning: %s: request failed: %s\n' "$_p" "$(cat "$errf")" >&2
                continue
            fi
            if ! _lines=$(printf '%s' "$_json" | parse_commits); then
                failed=$((failed + 1))
                printf 'warning: %s: could not parse API response\n' "$_p" >&2
                continue
            fi
            [ -n "$_lines" ] || continue
            show_hits "$_p" "$_lines"
        done
        if [ "$freebsd_hit_paths" = 0 ]; then
            if [ "$skipped" -gt 0 ]; then
                printf '  (no changes in the %s path(s) checked)\n' "$((_done - 1))"
            else
                printf '  (no changes)\n'
            fi
        fi
    fi
fi

printf '\n========================================\n'
[ "$do_chimera" = 1 ] && printf 'chimera: %s commit(s)\n' "$chimera_commits"
[ "$do_freebsd" = 1 ] && printf 'freebsd: %s commit(s) across %s path(s)\n' "$freebsd_commits" "$freebsd_hit_paths"
if [ "$skipped" -gt 0 ]; then
    printf 'note: rate-limited mid-run; %s freebsd path(s) not checked\n' "$skipped"
fi
if [ "$failed" -gt 0 ]; then
    _why=
    [ "$rate_limited" = 1 ] && _why=' (hit the GitHub rate limit — set GITHUB_TOKEN and rerun)'
    printf 'warning: %s API request(s) failed%s\n' "$failed" "$_why"
fi

if [ "$update" = 1 ]; then
    if [ "$failed" -gt 0 ]; then
        printf 'not updating state file: rerun cleanly before stamping it\n' >&2
        exit 1
    fi
    _now=$(utc_now)
    printf 'CHIMERA_SINCE=%s\nFREEBSD_SINCE=%s\n' "$_now" "$_now" > "$state_file"
    printf 'state file updated: %s\n' "$_now"
fi

[ "$failed" = 0 ]
