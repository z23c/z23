#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Host garbage collector — keeps the maintainer box clean without a human.
#
# DRY-RUN BY DEFAULT. Nothing is removed, moved, killed, or capped unless
# --apply is passed. `--status` prints one screen of host hygiene facts and
# exits without touching anything.
#
# WHY THIS EXISTS. The box grew to 281 GB of ~/github with no cap on any
# cache and no watcher on free space. The single largest consumer was a
# directory nothing on the host knew how to reclaim: `.z23p`, the proof
# generation pool created by tools/dev/dev_proof.c (see CATEGORY z23p below).
# The pre-existing timers each guard one narrow thing — worktree_gc.sh
# classifies named worktrees, test-tmp-clean sweeps scratch, logrotate
# rotates logs. Nobody capped ccache, nobody capped the zcc cache, nobody
# reaped a detached proof generation, and nobody noticed the disk filling.
# This script is the missing whole-host sweep; it does NOT reimplement the
# parts that already work, it calls them.
#
# WHAT IT WILL NEVER TOUCH (hard protect list, enforced in is_protected()
# and re-checked immediately before every destructive action):
#
#   $HOME/.zclassic*             live datadirs (~215 GB) and every sibling
#   $HOME/.zclassic-c23-backups  block/db backups
#   $HOME/wallet_backups         wallet custody
#   $HOME/.zcash-params          proving/verifying keys
#   $HOME/.ssh                   host keys
#   $HOME/.config/zclassic23     node configuration
#   $HOME/github/zclassic23      the main checkout itself
#   $HOME/.local/state/zclassic23-quality/*   registered quality checkouts
#   /tmp/zcl-pristine-*          registered pristine reference checkout
#   anything under systemd management, and the live node's process tree
#
# The protect list is a PREFIX test on a resolved absolute path, so a
# symlink or a `..` cannot walk into a protected tree and out again.
#
# QUARANTINE, NOT DELETE. Anything that is not a pure cache or build output
# is MOVED to $STATE/quarantine/<date>/ rather than unlinked, and swept 14
# days later. Caches and build outputs are exempt because they are, by
# definition, reproducible by rerunning the build — quarantining 49 GB of
# ccache would defeat the purpose of capping it.
#
# EVERY ACTION LOGS ONE LINE to $STATE/host_gc.log with the bytes it
# reclaimed, so "what did the janitor do last night" is one `tail` away and
# the byte totals in any report can be re-derived from the log rather than
# trusted.
#
# CATEGORIES (-a..-i map to the sweep order below):
#   ccache   cap ccache to 20 GB and collect
#   zcc      trim the zcc compile cache to 15 GB with its own evictor
#   z23p     reap dead dev-proof generations (the 158 GB leak) on the disk
#            pool AND on its tmpfs twin, which grew to 34 GB of RAM in one
#            unattended day while nothing here was looking at it
#   tmp      registered worktrees under /tmp
#   tmplitter unregistered /tmp test fixtures (no worktree behind them)
#   journal  vacuum the user journal to 512 MB
#   binbak   quarantine ~/bin/*.bak-* older than 60 days
#   testtmp  stale test scratch in idle worktrees
#   orphan   kill parentless processes whose checkout was deleted
#   deadexec WARN on user units whose ExecStart is missing or inside build/
#   worktree merged+clean named worktrees, via worktree_gc.sh --apply
#   units    landed units/lanes/trains, by PATCH equivalence (git cherry),
#            not ancestry — catches cherry-picked lanes worktree_gc.sh can't
#   scratch  scratch dirs whose owning worktree is gone; .gc_keep pins one
#   pressure not a sweep: reports free-space % and halves every age floor
#            above it when low, prints top dirs under $GC_HOME when critical
#
# FIXTURE MODE. Every host-global path and external binary is indirected
# through a ZCL_HOST_GC_* variable so tools/lint/check_host_gc.sh can run
# the whole sweep against a throwaway HOME and prove each category fires and
# each protected path survives. Production runs set none of them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- indirection seams (production defaults; the selftest overrides these) --
GC_HOME="${ZCL_HOST_GC_HOME:-$HOME}"
GC_TMP="${ZCL_HOST_GC_TMP:-/tmp}"
CCACHE_BIN="${ZCL_HOST_GC_CCACHE_BIN:-ccache}"
JOURNALCTL_BIN="${ZCL_HOST_GC_JOURNALCTL_BIN:-journalctl}"
ZCC_BIN="${ZCL_HOST_GC_ZCC_BIN:-$REPO_ROOT/build/bin/zcc}"
WORKTREE_GC="${ZCL_HOST_GC_WORKTREE_GC:-$SCRIPT_DIR/worktree_gc.sh}"
GC_REPO="${ZCL_HOST_GC_REPO:-$GC_HOME/github/zclassic23}"
PROC_ROOT="${ZCL_HOST_GC_PROC:-/proc}"

STATE="${ZCL_HOST_GC_STATE:-$GC_HOME/.local/state/server-cleanup}"
LOG="$STATE/host_gc.log"
QUARANTINE="$STATE/quarantine"

# --- policy constants (one place, so the doc and the code cannot drift) ----
CCACHE_CAP_GB="${ZCL_HOST_GC_CCACHE_CAP_GB:-20}"
ZCC_CAP_MB="${ZCL_HOST_GC_ZCC_CAP_MB:-15360}"      # 15 GB
JOURNAL_CAP="${ZCL_HOST_GC_JOURNAL_CAP:-512M}"
SYSTEM_JOURNAL_CAP="${ZCL_HOST_GC_SYSTEM_JOURNAL_CAP:-1G}"
# Lowered from the original 24h: a live generation is minutes old and the
# cwd/lock checks below already refuse anything still in use, so 24h of
# accumulation before the first look was pure waste on a box that mints a
# ~2 GB generation every few minutes.
Z23P_MIN_AGE_H="${ZCL_HOST_GC_Z23P_MIN_AGE_H:-6}"
# The tmpfs TWIN of that pool. dev_proof.c builds a generation in RAM when
# RAM scratch is reserved and on disk otherwise, so a sweep that only walks
# the disk pool watches half the leak: the RAM pool reached 34 GB in one
# unattended day while this script reported the z23p category clean.
Z23P_RAM="${ZCL_HOST_GC_RAM_ROOT:-/dev/shm/z23p}"
# The node binary. `z23 ops host gc` is preferred for the twin because it
# finds the repository behind each generation from the generation itself,
# so it reaches pools this script's single GC_REPO worktree listing cannot.
# The timer runs from ~/.local/lib/z23/tools, so the installed binary is
# that directory's sibling; anything else falls back to PATH, and a box
# with neither falls back to this script's own classifier.
Z23_BIN="${ZCL_HOST_GC_Z23_BIN:-$SCRIPT_DIR/../z23}"
TMP_MIN_AGE_D="${ZCL_HOST_GC_TMP_MIN_AGE_D:-2}"
# tmplitter: unregistered /tmp entries (no worktree of any kind, not one of
# the standing exemptions below). Separate knob from TMP_MIN_AGE_D because
# these are throwaway test fixtures, not a worktree somebody meant to keep.
TMPLITTER_MIN_AGE_D="${ZCL_HOST_GC_TMPLITTER_MIN_AGE_D:-2}"
# units: worktrees under ~/.z23/units and ~/.z23/lanes whose HEAD is
# patch-equivalent to main (git cherry, not ancestry — every landed unit is
# cherry-picked into a train, so its HEAD is never main's ancestor and the
# ancestry-based worktree_gc.sh classifier can never see it as merged).
UNITS_MIN_AGE_H="${ZCL_HOST_GC_UNITS_MIN_AGE_H:-12}"
UNITS_DIR="${ZCL_HOST_GC_UNITS_DIR:-$GC_HOME/.z23/units}"
LANES_DIR="${ZCL_HOST_GC_LANES_DIR:-$GC_HOME/.z23/lanes}"
TRAINS_DIR="${ZCL_HOST_GC_TRAINS_DIR:-$GC_HOME/.z23/trains}"
# scratch: dated/named scratch dirs with no worktree behind them any more.
SCRATCH_MIN_AGE_D="${ZCL_HOST_GC_SCRATCH_MIN_AGE_D:-7}"
SCRATCH_DIR="${ZCL_HOST_GC_SCRATCH_DIR:-$GC_HOME/.local/state/zclassic23/scratch}"
# pressure: below this free-space percentage, every age floor above is
# halved for this run (reported in the summary); below 5% the ten largest
# directories under $GC_HOME are also printed as a report line.
PRESSURE_MIN_FREE_PCT="${ZCL_HOST_GC_PRESSURE_MIN_FREE_PCT:-15}"
PRESSURE_CRITICAL_FREE_PCT="${ZCL_HOST_GC_PRESSURE_CRITICAL_FREE_PCT:-5}"
BINBAK_MIN_AGE_D="${ZCL_HOST_GC_BINBAK_MIN_AGE_D:-60}"
TESTTMP_MIN_AGE_D="${ZCL_HOST_GC_TESTTMP_MIN_AGE_D:-1}"
# Per-entry age floor for the main checkout's own test-tmp/.zcl_test_render
# (category repotmp). Two days, matching tools/scripts/test_tmp_clean.sh:
# fresh failure diagnostics survive a day of triage; nothing older is
# anything but landfill.
REPOTMP_MIN_AGE_D="${ZCL_HOST_GC_REPOTMP_MIN_AGE_D:-2}"
# One run reaps at most this many stale entries, oldest arbitrary (readdir
# order). The backlog on a host that never had the category is a one-time
# hundred-thousand-entry population; du+rm on all of it in one run would
# starve every later category for the hour — the measured dry-run cost of
# the uncapped population was >10 min on the live host, while a bounded
# 5000-entry batch costs ~19 s end to end including the full scan. 20000
# keeps one hourly run at about a minute and drains the measured 204k-entry
# backlog in roughly half a day of hourly runs; steady state is seconds.
REPOTMP_BATCH_MAX="${ZCL_HOST_GC_REPOTMP_BATCH_MAX:-20000}"
WORKTREE_IDLE_D="${ZCL_HOST_GC_WORKTREE_IDLE_D:-3}"
ORPHAN_MIN_AGE_H="${ZCL_HOST_GC_ORPHAN_MIN_AGE_H:-24}"
QUARANTINE_TTL_D="${ZCL_HOST_GC_QUARANTINE_TTL_D:-14}"
# Two thresholds, not one, because the disk on this host actually reached
# zero once and the node logged disk_full_pause CRITICAL. Below LOW_DISK_GB
# the sweep runs and the per-category age floors are relaxed. Below
# CACHE_FREEZE_GB the caches are additionally forbidden to GROW: the cap is
# lowered to whatever they currently occupy, so a build in flight cannot
# claim the space the sweep just recovered. A cache that re-fills the disk
# faster than the janitor drains it is how free space reaches zero while an
# hourly janitor is running and reporting success.
LOW_DISK_GB="${ZCL_HOST_GC_LOW_DISK_GB:-150}"
CACHE_FREEZE_GB="${ZCL_HOST_GC_CACHE_FREEZE_GB:-100}"
SYSTEMCTL_BIN="${ZCL_HOST_GC_SYSTEMCTL_BIN:-systemctl}"

APPLY=0
CHECK_PROTECTED=""
STATUS=0
ONLY=""

usage() {
    cat <<'USAGE'
usage: tools/scripts/host_gc.sh [--apply] [--dry-run] [--status] [--only CAT]

Sweep the maintainer host for reclaimable space. DRY-RUN by default: every
category is classified and the reclaimable byte total is printed, but
nothing is removed, moved, or killed.

  --apply        execute the sweep (removals, quarantine moves, kills)
  --dry-run      classify and report only (the default)
  --status       print one screen of host hygiene facts and exit
  --only CAT     run a single category. CAT is one of:
                 ccache zcc z23p tmp tmplitter journal binbak testtmp repotmp
                 orphan deadexec worktree units scratch wtbuild landtmp
                 landed lowdisk
  --wt-build-idle-h=N      hours an idle worktree's build/ output is kept (12)
  --reap-landed-worktrees  also remove clean, fully landed, idle worktrees

Thresholds: below the low-disk floor the sweep relaxes its age floors (idle
worktree build/ output: 2h) and, after the sweep, posts one agent-mail
warning naming the largest consumers (at most once per 6h); below the
cache-freeze floor the caches are also capped at their current size so they
cannot reclaim the space the sweep just freed.

Log:        ~/.local/state/server-cleanup/host_gc.log
Quarantine: ~/.local/state/server-cleanup/quarantine/<date>/ (swept after 14 days)
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --dry-run|--plan) APPLY=0 ;;
        --status) STATUS=1 ;;
        --only) shift || { echo "host-gc: --only needs a category" >&2; exit 2; }
            ONLY="$1" ;;
        # Knobs that postdate the ZCL_HOST_GC_* seams above: the hours a
        # worktree's build/ must sit idle, and the landed-worktree opt-in.
        --wt-build-idle-h=*) WT_BUILD_IDLE_H="${1#*=}" ;;
        --reap-landed-worktrees) REAP_LANDED=1 ;;
        # Ask the protect predicate about one path and exit. This exists so
        # the gate can test is_protected() DIRECTLY rather than grepping the
        # source for the tree names: a grep for "wallet_backups" matches the
        # header comment above and keeps passing after the real entry has
        # been deleted from the case statement, which is exactly the kind of
        # gate that reports clean while the guarantee is gone.
        --check-protected) shift || { echo "host-gc: --check-protected needs a path" >&2; exit 2; }
            CHECK_PROTECTED="$1" ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'host-gc: unknown arg %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------- protection
# A PREFIX test on the RESOLVED path. Resolving first is the whole point: a
# symlink under a sweep root that points into ~/.zclassic would otherwise be
# classified by its innocent-looking name. `realpath -m` resolves a path that
# does not exist yet (a quarantine target), which `realpath` alone refuses.
is_protected() {
    local p resolved
    p="$1"
    resolved="$(realpath -m -- "$p" 2>/dev/null || printf '%s' "$p")"
    case "$resolved" in
        "$GC_HOME"/.zclassic*) return 0 ;;
        "$GC_HOME"/wallet_backups|"$GC_HOME"/wallet_backups/*) return 0 ;;
        "$GC_HOME"/.zcash-params|"$GC_HOME"/.zcash-params/*) return 0 ;;
        "$GC_HOME"/.ssh|"$GC_HOME"/.ssh/*) return 0 ;;
        "$GC_HOME"/.config/zclassic23|"$GC_HOME"/.config/zclassic23/*) return 0 ;;
        "$GC_REPO"|"$GC_REPO"/*) return 0 ;;
        "$GC_HOME"/.local/state/zclassic23-quality|"$GC_HOME"/.local/state/zclassic23-quality/*) return 0 ;;
        "$STATE"|"$STATE"/*) return 0 ;;
        /tmp/zcl-pristine-*|/tmp/claude-*|/private/tmp/zcl-pristine-*|/private/tmp/claude-*|"$GC_TMP"/claude-*|*/github/qedc*|*/.qedc|*/.qedc/*|*/qedc-lanes|*/qedc-lanes/*) return 0 ;;
        /|"$GC_HOME") return 0 ;;
        *) return 1 ;;
    esac
}

# The last line of defence. Every destructive helper calls this on the exact
# path it is about to act on, AFTER classification, so a bug in a classifier
# cannot reach a protected tree.
refuse_if_protected() {
    if is_protected "$1"; then
        printf 'host-gc: REFUSING protected path: %s\n' "$1" >&2
        log_line "refuse" "$1" 0 "protected path"
        return 1
    fi
    return 0
}

# Answer the predicate and exit, before any sweep machinery runs.
if [ -n "$CHECK_PROTECTED" ]; then
    if is_protected "$CHECK_PROTECTED"; then echo PROTECTED; exit 0; fi
    echo UNPROTECTED; exit 0
fi

# ------------------------------------------------------------------ plumbing
human() {
    local b="${1:-0}"
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$b" 2>/dev/null || printf '%s' "$b"
    else
        printf '%s' "$b"
    fi
}

# du that never aborts the sweep. A directory being written by a live build
# makes du exit non-zero with a partial (still useful) total; a missing path
# is 0. Neither is a reason to stop cleaning.
dir_bytes() {
    local out
    out="$(du -sb -- "$1" 2>/dev/null | awk 'NR==1{print $1}')" || true
    [ -n "$out" ] || out=0
    printf '%s' "$out"
}

free_bytes() {
    # -Pk, not GNU's -B1: macOS df has no -B, its usage error (exit 64) under
    # set -e + pipefail killed the whole sweep from the driver's unguarded
    # FREE_AT_START call before the first category ever ran. POSIX -Pk gives
    # 1 KiB blocks on every host; scale back to bytes here.
    df -Pk -- "$GC_HOME" 2>/dev/null | awk 'NR==2{print $4 * 1024}'
}

now_epoch() { date +%s; }

# mtime age in seconds; a vanished path reads as 0 (too young to touch),
# which is the fail-safe direction.
age_secs() {
    local flag fmt m
    case "$(uname -s 2>/dev/null)" in
        Darwin|*BSD*) flag='-f' fmt='%m' ;;
        *)            flag='-c' fmt='%Y' ;;
    esac
    m="$(stat "$flag" "$fmt" -- "$1" 2>/dev/null)" || { printf '0'; return; }
    printf '%s' "$(( $(now_epoch) - m ))"
}

LOG_READY=0
ensure_state() {
    [ "$LOG_READY" = 1 ] && return 0
    mkdir -p -- "$STATE" "$QUARANTINE" 2>/dev/null || true
    LOG_READY=1
}

# ONE line per action, append-only, tab separated so the log is greppable
# and the byte columns sum with awk. Dry runs log too, tagged "plan", so a
# report can be reconstructed from the log alone.
log_line() {
    local action="$1" target="$2" bytes="${3:-0}" note="${4:-}"
    ensure_state
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$([ "$APPLY" = 1 ] && echo apply || echo plan)" \
        "$action" "$target" "$bytes" "$note" >> "$LOG" 2>/dev/null || true
}

# Per-category running totals, reported at the end and used by the caller to
# answer "bytes per category" without re-reading the log. NOT an associative
# array: macOS still ships bash 3.2, which rejects `declare -A`, and this
# script must run under the stock shell of every host it sweeps. One
# "category bytes count" row per call, aggregated by cat_totals() below.
CAT_RESULTS=""
add_result() {
    local cat="$1" bytes="${2:-0}" n="${3:-1}"
    CAT_RESULTS="$CAT_RESULTS$cat $bytes $n
"
}

# The summary's per-category table: one "category count bytes" row per known
# category in the fixed display order, aggregated from CAT_RESULTS. awk (not
# bash arrays) does the summing so the arithmetic itself is not a bash-4
# feature either.
cat_totals() {
    printf '%s' "$CAT_RESULTS" | awk '
        BEGIN { n = split("ccache zcc z23p tmp tmplitter journal binbak testtmp repotmp orphan deadexec worktree units scratch wtbuild landtmp landed quarantine", o, " ") }
        { b[$1] += $2; c[$1] += $3 }
        END { for (i = 1; i <= n; i++) printf "%s %d %d\n", o[i], c[o[i]] + 0, b[o[i]] + 0 }'
}

say() { printf '%s\n' "$*"; }
hdr() { printf '\n== %s ==\n' "$*"; }

want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# Move into quarantine instead of deleting. Returns the bytes moved.
quarantine_path() {
    local src="$1" cat="$2" dest bytes
    refuse_if_protected "$src" || return 1
    bytes="$(dir_bytes "$src")"
    dest="$QUARANTINE/$(date -u +%Y-%m-%d)/$cat"
    if [ "$APPLY" = 1 ]; then
        ensure_state
        mkdir -p -- "$dest" 2>/dev/null || true
        if mv -f -- "$src" "$dest/" 2>/dev/null; then
            log_line "quarantine" "$src" "$bytes" "-> $dest"
        else
            log_line "quarantine-failed" "$src" 0 "mv refused"
            printf '%s' 0
            return 0
        fi
    else
        log_line "quarantine" "$src" "$bytes" "-> $dest"
    fi
    printf '%s' "$bytes"
}

# ----------------------------------------------------------- process mapping
# Build the set of directories some live process is sitting in, ONCE. A
# per-worktree `lsof`/`fuser` shell-out would be O(worktrees x processes) and
# slow enough on a loaded box that the sweep would be skipped in practice.
# Unreadable /proc entries (other users, races) are simply absent; that makes
# the set an UNDER-estimate of occupancy, so the occupancy test is advisory
# and never the only reason a directory survives.
CWD_SET=""
CWD_SET_BUILT=0
build_cwd_set() {
    local d f target
    CWD_SET=""
    for d in "$PROC_ROOT"/[0-9]*; do
        [ -e "$d" ] || continue
        target="$(readlink -- "$d/cwd" 2>/dev/null)" || continue
        [ -n "$target" ] || continue
        CWD_SET="$CWD_SET
$target"
        # Open file descriptors, not just cwd: a litter dir under /tmp can be
        # held open (a log fd, a mapped file) by a process chdir'd elsewhere.
        # This is the ONE "is this path in use" set every category below
        # shares via cwd_occupied(), rather than each writing its own
        # lsof/fuser-style check.
        for f in "$d"/fd/*; do
            [ -e "$f" ] || continue
            target="$(readlink -- "$f" 2>/dev/null)" || continue
            case "$target" in /*) ;; *) continue ;; esac
            CWD_SET="$CWD_SET
$target"
        done
    done
    CWD_SET_BUILT=1
}

# Build the set once per sweep run, not once per category — categories call
# this defensively but the cost is only paid the first time.
ensure_cwd_set() {
    [ "$CWD_SET_BUILT" = 1 ] && return 0
    build_cwd_set
}

# Is this directory, or any directory below it, some process's cwd?
# Both tests matter: a proof runs `make` from the generation root (exact
# match) and its compiler children sit in subdirectories (prefix match).
cwd_occupied() {
    local dir="$1" line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [ "$line" = "$dir" ] && return 0
        case "$line" in "$dir"/*) return 0 ;; esac
    done <<< "$CWD_SET"
    return 1
}

# --------------------------------------------------------------- git helpers
# Registered worktrees of a repo, one absolute path per line.
worktree_paths() {
    local repo="$1"
    git -C "$repo" worktree list --porcelain 2>/dev/null \
        | awk '/^worktree /{print substr($0,10)}'
}

# A worktree is reapable only if git itself says the HEAD is detached AND
# the working tree is clean. Both come from git, not from a heuristic: the
# whole risk of this script is deleting somebody's uncommitted work.
worktree_detached() {
    git -C "$1" symbolic-ref -q HEAD >/dev/null 2>&1 && return 1
    return 0
}
worktree_clean() {
    local out
    out="$(git -C "$1" status --porcelain 2>/dev/null)" || return 1
    [ -z "$out" ]
}
worktree_locked() {
    local dir="$1" gitfile common name
    [ -f "$dir/.git" ] || return 1
    gitfile="$(awk '/^gitdir:/{print substr($0,9)}' "$dir/.git" 2>/dev/null)"
    [ -n "$gitfile" ] || return 1
    [ -e "$gitfile/locked" ] && return 0
    return 1
}

# ============================================================ CATEGORY ccache
# ccache ships its own evictor and its own size accounting; capping it is
# `-M` plus a `-c` to make the cap take effect now rather than at the next
# miss. Reproducible build output, so it is deleted, not quarantined.
sweep_ccache() {
    want ccache || return 0
    hdr "ccache (cap ${CCACHE_CAP_GB}G)"
    local dir="$GC_HOME/.ccache" before after freed
    if ! command -v "$CCACHE_BIN" >/dev/null 2>&1; then
        say "ccache: binary not found ($CCACHE_BIN) — skipped"
        return 0
    fi
    [ -d "$dir" ] || { say "ccache: no cache directory — skipped"; return 0; }
    before="$(dir_bytes "$dir")"
    # Under the freeze threshold the cap becomes the smaller of the policy
    # cap and what the cache holds right now, so it cannot reclaim the space
    # this sweep just freed while the sweep is still running.
    local cap_gb="$CCACHE_CAP_GB"
    if [ "$CACHE_FREEZE" = 1 ]; then
        local held_gb=$(( before / 1024 / 1024 / 1024 ))
        [ "$held_gb" -lt "$cap_gb" ] && cap_gb="$held_gb"
        [ "$cap_gb" -lt 1 ] && cap_gb=1
        say "ccache: FREEZE active — cap lowered to ${cap_gb}G (no growth)"
    fi
    say "ccache: current $(human "$before"), cap ${cap_gb}G"
    if [ "$APPLY" = 1 ]; then
        "$CCACHE_BIN" -M "${cap_gb}G" >/dev/null 2>&1 || true
        "$CCACHE_BIN" -c >/dev/null 2>&1 || true
        after="$(dir_bytes "$dir")"
        freed=$(( before > after ? before - after : 0 ))
        say "ccache: now $(human "$after"), reclaimed $(human "$freed")"
        log_line "ccache-cap" "$dir" "$freed" "cap=${cap_gb}G freeze=$CACHE_FREEZE"
        add_result ccache "$freed" 1
    else
        local cap_bytes=$(( cap_gb * 1024 * 1024 * 1024 ))
        freed=$(( before > cap_bytes ? before - cap_bytes : 0 ))
        say "ccache: would reclaim about $(human "$freed")"
        log_line "ccache-cap" "$dir" "$freed" "cap=${cap_gb}G freeze=$CACHE_FREEZE"
        add_result ccache "$freed" 1
    fi
}

# =============================================================== CATEGORY zcc
# The zcc cache has a real evictor of its own (`zcc --zcc-trim MB`, the same
# eviction the cache performs on itself). Using it rather than an atime sort
# keeps ONE eviction policy: an external sweeper deleting entries the cache
# still believes it owns is how a cache index goes stale.
#
# ONE WALK PER RUN. `du -sb` over a multi-million-file cache is expensive on
# a rotational box: measured on a fleet HDD host 2026-09-10, the hourly unit
# ran 18:49-19:19 (30 min wall, 1.9s CPU, all I/O wait) with the `du -sb --
# ~/.cache/zcc` call alone sitting 27 min in D state, holding
# /proc/pressure/io avg10 at 60-67% for the whole hour and starving the live
# node — even with Nice=19 + IOSchedulingClass=idle, which does not help a
# seek-bound HDD. The evictor (`zcc --zcc-trim`) already walks the tree once
# to do the eviction and prints what it found in its own report line
# ("zcc: N MB held, N MB ceiling, N MB freed"); the APPLY path below reads
# THAT line instead of measuring the directory again, so a normal apply run
# costs exactly the evictor's one walk, never du before AND after it.
# Dry-run still needs the current size before the evictor runs at all, so it
# keeps exactly one measurement of its own — never a second on top of it.
# A cache FREEZE on the apply path is recorded from the evictor's held
# figure, never measured first: trimming to min(held, cap) frees exactly
# what trimming to cap frees, so the freeze changes the log row, not the
# eviction, and buying it with a walk of its own would put the second walk
# back on every low-disk box.
sweep_zcc() {
    want zcc || return 0
    hdr "zcc cache (cap $(( ZCC_CAP_MB / 1024 ))G)"
    local dir="${ZCL_HOST_GC_ZCC_DIR:-$GC_HOME/.cache/zcc}" before after freed
    [ -d "$dir" ] || { say "zcc: no cache directory — skipped"; return 0; }
    local cap_mb="$ZCC_CAP_MB"
    if [ "$CACHE_FREEZE" = 1 ] && [ "$APPLY" != 1 ]; then
        before="$(dir_bytes "$dir")"
        local held_mb=$(( before / 1024 / 1024 ))
        [ "$held_mb" -lt "$cap_mb" ] && cap_mb="$held_mb"
        [ "$cap_mb" -lt 64 ] && cap_mb=64
        say "zcc: FREEZE active — cap lowered to ${cap_mb}MB (no growth)"
    fi
    # Resolve a working evictor before giving up. $REPO_ROOT/build/bin/zcc is
    # correct for a checkout that has built it; it is silently ABSENT for a
    # lane worktree that has not, which is exactly the case that made this
    # sweep report nothing for days without saying why. Fall back to a zcc
    # on PATH, then the installed copy, before reporting a skip.
    local bin="$ZCC_BIN"
    if [ ! -x "$bin" ]; then
        bin="$(command -v zcc 2>/dev/null || true)"
    fi
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        [ -x "$GC_HOME/.local/lib/z23/bin/zcc" ] && bin="$GC_HOME/.local/lib/z23/bin/zcc"
    fi
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        # Deliberately NOT falling back to an atime sweep. Deleting objects
        # behind the cache's back is worse than leaving it uncapped for one
        # cycle; name the one command that fixes it instead.
        say "zcc: evictor not built — checked $ZCC_BIN, PATH, and $GC_HOME/.local/lib/z23/bin/zcc — run 'make cc-cache' then rerun"
        log_line "zcc-skip" "$dir" 0 "evictor not found: tried $ZCC_BIN, PATH, $GC_HOME/.local/lib/z23/bin/zcc"
        return 0
    fi
    if [ "$APPLY" = 1 ]; then
        # ONE call, ONE walk: no dir_bytes before or after. held/freed come
        # only from the evictor's own report line — see the ONE WALK
        # comment above the category. That one walk is still unbounded work
        # on a cold rotational disk holding tens of thousands of small
        # files, so it runs under a wall-clock budget: on 2026-09-10 the
        # walk alone ran past this unit's 30-minute TimeoutStartSec and
        # systemd SIGKILLed the whole sweep mid-walk, so every category
        # after zcc silently never ran. `timeout --foreground` gives the
        # evictor's own SIGTERM/SIGKILL handling a chance and keeps the
        # budget itself in the foreground process group so it is not
        # swallowed by this script's own signal handling.
        local budget="${ZCL_HOST_GC_ZCC_BUDGET_S:-900}"
        local trim_out held_mb freed_mb rc=0
        # `timeout` is GNU coreutils; a stock macOS box has none, and "trim
        # FAILED (timeout: command not found)" would report a trim that never
        # ran. Without a timeout binary the trim runs unbudgeted instead —
        # the budget is a guard against slow disks, not a precondition.
        if command -v timeout >/dev/null 2>&1; then
            trim_out="$(timeout --foreground "$budget" "$bin" --zcc-trim "$cap_mb" 2>&1)" || rc=$?
        else
            trim_out="$("$bin" --zcc-trim "$cap_mb" 2>&1)" || rc=$?
        fi
        if [ "$rc" -eq 124 ]; then
            say "zcc: trim gave up after ${budget}s (cache left untouched; raise ZCL_HOST_GC_ZCC_BUDGET_S on a box whose walk is slower) — ${budget}s of the unit's TimeoutStartSec were spent"
            log_line "zcc-trim-timeout" "$dir" 0 "bin=$bin cap=${cap_mb}MB budget=${budget}s"
        elif [ "$rc" -eq 0 ]; then
            held_mb="$(printf '%s\n' "$trim_out" | sed -n 's/^zcc: \([0-9][0-9]*\) MB held,.*/\1/p')"
            freed_mb="$(printf '%s\n' "$trim_out" | sed -n 's/.* \([0-9][0-9]*\) MB freed$/\1/p')"
            if [ -n "$held_mb" ] && [ -n "$freed_mb" ]; then
                if [ "$CACHE_FREEZE" = 1 ] && [ "$held_mb" -lt "$cap_mb" ]; then
                    cap_mb="$held_mb"
                    [ "$cap_mb" -lt 64 ] && cap_mb=64
                    say "zcc: FREEZE active — cap held at ${cap_mb}MB (no growth)"
                fi
                after=$(( held_mb * 1024 * 1024 ))
                freed=$(( freed_mb * 1024 * 1024 ))
                say "zcc: now $(human "$after"), reclaimed $(human "$freed") (via $bin)"
                log_line "zcc-trim" "$dir" "$freed" "cap=${cap_mb}MB freeze=$CACHE_FREEZE bin=$bin"
                add_result zcc "$freed" 1
            else
                # Unparsable output is a failed trim, not a silent 0-freed
                # success — never report a success row without a real number.
                say "zcc: trim FAILED (could not parse '$bin --zcc-trim $cap_mb' report: ${trim_out:-<empty output>}) — cache left untouched"
                log_line "zcc-trim-failed" "$dir" 0 "bin=$bin cap=${cap_mb}MB unparsable-report"
            fi
        else
            say "zcc: trim FAILED ($bin --zcc-trim $cap_mb exited non-zero) — cache left untouched"
            log_line "zcc-trim-failed" "$dir" 0 "bin=$bin cap=${cap_mb}MB"
        fi
    else
        [ -n "${before:-}" ] || before="$(dir_bytes "$dir")"
        say "zcc: current $(human "$before"), cap ${cap_mb}MB"
        local cap_bytes=$(( cap_mb * 1024 * 1024 ))
        freed=$(( before > cap_bytes ? before - cap_bytes : 0 ))
        say "zcc: would reclaim about $(human "$freed") (via $bin)"
        log_line "zcc-trim" "$dir" "$freed" "cap=${cap_mb}MB freeze=$CACHE_FREEZE bin=$bin"
        add_result zcc "$freed" 1
    fi
}

# ============================================================== CATEGORY z23p
# THE LEAK. tools/dev/dev_proof.c:generation_prepare() creates one detached
# worktree per (checkout, commit) pair under <parent-of-checkout>/.z23p, keyed
# by a hash of both, and NEVER removes one. The push hook proves every commit
# pair, so the pool grows by a ~2 GB worktree every few minutes and nothing
# on the host had the authority to reclaim it: `git worktree prune` finds
# nothing because every generation is still correctly registered.
#
# THE POOL COMES IN TWO HALVES. dev_proof.c builds a generation in RAM when
# RAM scratch is reserved and on disk otherwise, so both are swept here: the
# disk pool by the classifier below, the tmpfs twin by `z23 ops host gc`
# when a binary is available (it finds the repository behind a generation
# from the generation itself, so it sees twins this script's single GC_REPO
# listing cannot) and by the same classifier when none is.
#
# A generation is reapable when ALL of these hold:
#   older than Z23P_MIN_AGE_H     (a proof in flight is minutes old)
#   no process has it as cwd      (a proof in flight is chdir'd into it)
#   not git-locked                (an explicit "leave this alone")
#   detached HEAD and clean       (git's own verdict, not ours)
# Anything failing the last test is REPORTED, never removed — a generation
# holding uncommitted content is a bug worth a human's attention, not a
# deletion candidate.
# A generation directory left behind by dev_proof.c may carry a top-level
# *.lock/*.pid file naming the pid that created it (state layout is an
# internal detail of dev_proof.c and may not always be present — this is a
# best-effort check, never the only reason a generation is kept). When one
# exists and names a pid that is gone, the creator is PROVABLY dead and the
# generation is reapable regardless of the age floor; when it names a pid
# that is alive, the generation is kept regardless of age.
z23p_creator_status() {
    local wt="$1" f pid
    for f in "$wt"/*.lock "$wt"/*.pid; do
        [ -f "$f" ] || continue
        pid="$(head -1 -- "$f" 2>/dev/null | tr -dc '0-9')"
        [ -n "$pid" ] || continue
        if [ -e "$PROC_ROOT/$pid" ]; then
            printf 'alive'; return 0
        fi
        printf 'dead'; return 0
    done
    printf 'unknown'
}

# Classify, and with --apply reap, every generation of ONE pool. Split out
# of sweep_z23p so the disk pool and its tmpfs twin run byte-identical
# rules. Only generations `git worktree list` reports for GC_REPO are
# visible here: that is the whole registry for the disk pool, but a RAM
# generation minted by a different checkout is not in it, which is why the
# twin prefers the native sweep below.
z23p_sweep_pool() {
    local pool="$1"
    [ -d "$pool" ] || { say "z23p: no pool at $pool — skipped"; return 0; }
    local min_age=$(( Z23P_MIN_AGE_H * 3600 ))
    local total=0 removed=0 kept=0 dirty=0 busy=0 young=0 bytes
    local wt creator
    while IFS= read -r wt; do
        [ -n "$wt" ] || continue
        case "$wt" in "$pool"/*) ;; *) continue ;; esac
        [ -d "$wt" ] || continue
        total=$(( total + 1 ))
        creator="$(z23p_creator_status "$wt")"
        if [ "$creator" = "alive" ]; then
            busy=$(( busy + 1 ))
            say "z23p: KEEP (creating process still alive): $wt"
            continue
        fi
        if [ "$creator" != "dead" ] \
            && [ "$(age_secs "$wt")" -lt "$min_age" ] && [ "$LOW_DISK" = 0 ]; then
            young=$(( young + 1 )); continue
        fi
        if worktree_locked "$wt" || z23p_keep_donor "$pool" "$wt"; then kept=$(( kept + 1 )); continue; fi
        if cwd_occupied "$wt"; then busy=$(( busy + 1 )); continue; fi
        if ! worktree_detached "$wt"; then
            dirty=$(( dirty + 1 ))
            say "z23p: KEEP (has a branch, not detached): $wt"
            continue
        fi
        if ! worktree_clean "$wt"; then
            dirty=$(( dirty + 1 ))
            say "z23p: KEEP (uncommitted content): $wt"
            continue
        fi
        refuse_if_protected "$wt" || continue
        bytes="$(dir_bytes "$wt")"
        if [ "$APPLY" = 1 ]; then
            # --force is safe ONLY because detached+clean was just proven by
            # git above; it is here to defeat the read-only test scratch that
            # makes a provably dead worktree undeletable.
            chmod -R u+w "$wt" 2>/dev/null || true
            if git -C "$GC_REPO" worktree remove --force -- "$wt" 2>/dev/null; then
                removed=$(( removed + 1 ))
                add_result z23p "$bytes" 1
                log_line "z23p-remove" "$wt" "$bytes" "detached+clean"
            else
                log_line "z23p-remove-failed" "$wt" 0 "git refused"
                say "z23p: git refused to remove $wt (left in place)"
            fi
        else
            removed=$(( removed + 1 ))
            add_result z23p "$bytes" 1
            log_line "z23p-remove" "$wt" "$bytes" "detached+clean"
        fi
    done < <(worktree_paths "$GC_REPO")
    say "z23p: $pool — $total registered, $removed reapable, $young too young, $busy in use, $kept locked, $dirty need review"
    [ "$APPLY" = 1 ] && git -C "$GC_REPO" worktree prune >/dev/null 2>&1 || true
    return 0
}

# The node binary: $Z23_BIN (the installed sibling unless the flag says
# otherwise), then PATH. Prints the path and returns 0, or prints nothing
# and returns 1 so the caller can fall back to classifying the pool itself.
z23p_native_bin() {
    local c="$Z23_BIN"
    if [ ! -x "$c" ]; then c="$(command -v z23 2>/dev/null || true)"; fi
    if [ -n "$c" ] && [ -x "$c" ]; then printf '%s' "$c"; return 0; fi
    return 1
}

# bytes_reclaimed out of a zcl.host_gc.v1 report. `totals` is emitted after
# the per-class rows, so the LAST occurrence is the whole-run figure. An
# unparsable report reads as 0 rather than aborting the sweep.
z23p_native_bytes() {
    local n=""
    n="$(printf '%s' "$1" \
        | grep -o '"bytes_reclaimed"[[:space:]]*:[[:space:]]*[0-9][0-9]*' \
        | tail -1 | grep -o '[0-9][0-9]*$')" || true
    [ -n "$n" ] || n=0
    printf '%s' "$n"
}

# The tmpfs twin, swept by the native verb when one is available and by this
# script's own classification when it is not. HOME and the RAM scratch root
# are handed to the binary explicitly so the pools it anchors are exactly
# the pools this run is configured for — that is what keeps the fixture in
# tools/scripts/host_gc_selftest.sh off the real host. ONE log line per run,
# carrying the byte total the report itself gave.
z23p_sweep_ram() {
    local bin out bytes floor apply_arg
    [ -d "$Z23P_RAM" ] || { say "z23p: no tmpfs pool at $Z23P_RAM — skipped"; return 0; }
    if ! bin="$(z23p_native_bin)"; then
        say "z23p: no z23 binary (checked $Z23_BIN and PATH) — classifying $Z23P_RAM from this script instead"
        z23p_sweep_pool "$Z23P_RAM"
        return 0
    fi
    floor="$Z23P_MIN_AGE_H"
    if [ "$LOW_DISK" = 1 ]; then floor=0; fi
    apply_arg=false
    if [ "$APPLY" = 1 ]; then apply_arg=true; fi
    out="$(env HOME="$GC_HOME" ZCL_RAM_SCRATCH_ROOT="$(dirname -- "$Z23P_RAM")" \
        "$bin" ops host gc "--apply=$apply_arg" "--floor_hours=$floor" 2>&1)" || true
    bytes="$(z23p_native_bytes "$out")"
    say "z23p: tmpfs pool $Z23P_RAM — $(human "$bytes") reclaimed via $bin"
    add_result z23p "$bytes" 1
    log_line "z23p-ram" "$Z23P_RAM" "$bytes" "native ops.host.gc floor=${floor}h"
    return 0
}

sweep_z23p() {
    want z23p || return 0
    hdr "dev-proof generations (.z23p, older than ${Z23P_MIN_AGE_H}h)"
    build_cwd_set
    z23p_sweep_pool "${ZCL_HOST_GC_Z23P:-$GC_HOME/github/.z23p}"
    z23p_sweep_ram
    z23p_sweep_other_pools
    return 0
}

# ------------------------------------------------------- z23p warm donors
# The newest COMPLETE generation of each build identity is the next proof's
# warm donor: tools/dev/dev_proof.c seeds a new generation's objects from it
# instead of building cold. Reaping it by age made the next landing pay the
# whole cold build. So a generation carrying build/.proof-build-complete is
# kept when it is the newest such generation of its identity (the marker's
# root, compiler, flags, environment and build_graph lines) that no process
# is sitting in, and the keep is bounded: across one pool at most
# Z23P_DONOR_MAX generations survive this way, newest first. Every other
# generation is classified exactly as before.
Z23P_DONOR_MAX=2
Z23P_DONOR_POOL=""
Z23P_DONOR_SET=""

# One line "completed<TAB>identity" for a generation's marker, or nothing
# when the marker is absent, of another schema, or missing a field.
z23p_marker_line() {
    local m="$1/build/.proof-build-complete"
    [ -f "$m" ] || return 1
    awk -F= '
        NR == 1 { if ($0 != "zcl.proof_build_complete.v1") exit 1; next }
        { v[$1] = substr($0, length($1) + 2) }
        END {
            if (NR < 1 || v["completed"] !~ /^[0-9]+$/) exit 1
            if (v["root"] == "" || v["compiler"] == "" || v["flags"] == "" ||
                v["environment"] == "" || v["build_graph"] == "") exit 1
            printf "%s\t%s|%s|%s|%s|%s\n", v["completed"], v["root"],
                v["compiler"], v["flags"], v["environment"], v["build_graph"]
        }' "$m" 2>/dev/null
}

# The donor set of one pool: newest idle complete generation per identity,
# then the Z23P_DONOR_MAX newest of those. Computed once per pool.
z23p_donor_set() {
    local pool="$1" wt line
    [ "$Z23P_DONOR_POOL" = "$pool" ] && return 0
    Z23P_DONOR_POOL="$pool"
    ensure_cwd_set
    Z23P_DONOR_SET="$(
        while IFS= read -r wt; do
            [[ "$wt" == "$pool/"* ]] || continue
            [ -d "$wt" ] || continue
            cwd_occupied "$wt" && continue
            line="$(z23p_marker_line "$wt")" || continue
            if [ -n "$line" ]; then printf '%s\t%s\n' "$line" "$wt"; fi
        done < <(worktree_paths "$GC_REPO") \
            | sort -t "$(printf '\t')" -k1,1nr \
            | awk -F '\t' -v max="$Z23P_DONOR_MAX" \
                '!seen[$2]++ { if (n++ < max) print $3 }'
    )"
}

# Keep verdict for z23p_sweep_pool: returns 0 (and says why) for a donor.
z23p_keep_donor() {
    local pool="$1" wt="$2" line
    z23p_donor_set "$pool"
    while IFS= read -r line; do
        if [ -n "$line" ] && [ "$line" = "$wt" ]; then
            say "z23p: KEEP (newest warm donor for its build identity): $wt"
            return 0
        fi
    done <<< "$Z23P_DONOR_SET"
    return 1
}

# Every proof pool git knows about beyond the two swept above. dev_proof.c
# puts a pool beside EVERY checkout it proves from (<checkout parent>/.z23p),
# so lanes, the landing worktree, and scratch checkouts each grow their own;
# only the one under ~/github was ever swept. They are found from git's own
# worktree list, not guessed, and run the same classifier.
z23p_sweep_other_pools() {
    local main_pool="${ZCL_HOST_GC_Z23P:-$GC_HOME/github/.z23p}" pool
    while IFS= read -r pool; do
        [ -n "$pool" ] || continue
        [ "$pool" = "$main_pool" ] && continue
        [ "$pool" = "$Z23P_RAM" ] && continue
        is_protected "$pool" && continue
        z23p_sweep_pool "$pool"
    done < <(worktree_paths "$GC_REPO" | while IFS= read -r wt; do
                 z23p_generation_pool "$wt"
             done | sort -u)
}

# A proof generation is a direct child of a pool: <parent>/.z23p/<tag> or
# $Z23P_RAM/<tag>. Prints that pool. A worktree nested deeper (a test fixture
# under a generation's test-tmp) is not a generation and prints nothing.
z23p_generation_pool() {
    local parent
    parent="$(dirname -- "$1")"
    case "$parent" in */.z23p|"$Z23P_RAM") printf '%s\n' "$parent" ;; esac
}

# ========================================================= CATEGORY wtbuild
# build/ output inside idle registered worktrees. On 2026-09-27 this host
# reached 97% full with ~230 GB of obj/bin/toolchain trees spread over ~140
# lane worktrees nobody had built in for days, while every category above
# reported ~0 B reclaimable — none of them ever looked inside a lane's
# build/. Build output is reproducible (each lane rebuilds on demand), so it
# is DELETED, not quarantined, one log line per build/ child with its bytes.
#
# A worktree is left entirely alone when a live process has its cwd, an
# open file, or its executable inside it, or when anything under its build/
# changed within the idle window (WT_BUILD_IDLE_H, default 12h; 2h below the
# low-disk floor). Inside an idle worktree these build/ children survive:
#   evidence   scratch, handoff, devverify, clang-facts, and any name with
#              stopwatch, acceptance, evidence or receipt in it
#   hidden     .locks, markers and leases: tiny, and live build machinery
#   bin        when a systemd user unit's ExecStart points into it (and
#              whenever the unit list cannot be read at all: fail closed)
# The idle worktree's own test-tmp/ is emptied under the same rule.
WT_BUILD_LOWDISK_IDLE_H=2
EXE_SET=""
EXE_SET_BUILT=0
UNIT_EXEC_SET=""
UNIT_EXEC_STATE=""

# Executables of live processes: a binary running out of a build/bin keeps
# that worktree, even when its cwd is elsewhere.
ensure_exe_set() {
    [ "$EXE_SET_BUILT" = 1 ] && return 0
    local d t
    for d in "$PROC_ROOT"/[0-9]*; do
        t="$(readlink -- "$d/exe" 2>/dev/null)" || continue
        EXE_SET="$EXE_SET
$t"
    done
    EXE_SET_BUILT=1
}

# Is a live process sitting in, holding open, or executing from $1?
wt_in_use() {
    local dir="$1" line
    ensure_cwd_set
    cwd_occupied "$dir" && return 0
    ensure_exe_set
    while IFS= read -r line; do
        case "$line" in "$dir"/*) return 0 ;; esac
    done <<< "$EXE_SET"
    return 1
}

# ExecStart paths of every user unit, read once. UNIT_EXEC_STATE is
# "unknown" when systemctl is unavailable: then no build/bin is removable.
ensure_unit_exec_set() {
    [ -n "$UNIT_EXEC_STATE" ] && return 0
    local unit path units
    if ! command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1; then
        UNIT_EXEC_STATE=unknown
        return 0
    fi
    units="$( { "$SYSTEMCTL_BIN" --user list-unit-files --type=service \
                    --no-legend --no-pager 2>/dev/null
                "$SYSTEMCTL_BIN" --user list-units --type=service --all \
                    --plain --no-legend --no-pager 2>/dev/null
              } | awk '{print $1}' | sort -u)" || true
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        case "$unit" in *@.service) continue ;; esac
        path="$("$SYSTEMCTL_BIN" --user show -p ExecStart --value "$unit" 2>/dev/null \
                | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)" || true
        if [ -n "$path" ]; then UNIT_EXEC_SET="$UNIT_EXEC_SET
$path"; fi
    done <<< "$units"
    UNIT_EXEC_STATE=known
}

unit_runs_from() {
    local dir="$1" line
    ensure_unit_exec_set
    [ "$UNIT_EXEC_STATE" = known ] || return 0
    while IFS= read -r line; do
        case "$line" in "$dir"/*) return 0 ;; esac
    done <<< "$UNIT_EXEC_SET"
    return 1
}

# Anything under $1 written within the last $2 hours? Directories do not
# count: removing a child bumps its parent's mtime, so a directory this very
# sweep (or a hand cleanup) emptied would otherwise read as fresh work. find
# stops at the first hit, so a busy tree costs one lookup, an idle one a walk.
recent_under() {
    local hit
    hit="$(find "$1" ! -type d -mmin "-$(( $2 * 60 ))" -print -quit 2>/dev/null)" || true
    [ -n "$hit" ]
}

wtbuild_keeps_child() {
    case "$(basename -- "$1")" in
        .*) return 0 ;;
        scratch|handoff|devverify|clang-facts) return 0 ;;
        *stopwatch*|*acceptance*|*evidence*|*receipt*) return 0 ;;
        bin) unit_runs_from "$1" && return 0 ;;
    esac
    return 1
}

# Delete one reproducible tree (build output, test scratch) outright: no
# quarantine. The protect predicate is asked again on the exact path first.
# The bytes land in REAP_BYTES; REAP_QUIET=1 leaves the per-path screen line
# to the caller's summary (the log still gets one line per path).
REAP_BYTES=0
REAP_QUIET=0
reap_tree() {
    local cat="$1" action="$2" p="$3" note="$4" bytes
    REAP_BYTES=0
    refuse_if_protected "$p" || return 1
    bytes="$(dir_bytes "$p")"
    if [ "$APPLY" = 1 ]; then
        chmod -R u+w -- "$p" 2>/dev/null || true
        if ! rm -rf -- "$p" 2>/dev/null || [ -e "$p" ]; then
            log_line "$action-failed" "$p" 0 "rm refused"
            say "$cat: could not remove $p (left in place)"
            return 1
        fi
        [ "$REAP_QUIET" = 1 ] || say "$cat: removed $p ($(human "$bytes"))"
    else
        [ "$REAP_QUIET" = 1 ] || say "$cat: would remove $p ($(human "$bytes"))"
    fi
    log_line "$action" "$p" "$bytes" "$note"
    add_result "$cat" "$bytes" 1
    REAP_BYTES="$bytes"
}

# Every child of scratch directory $3, one log line each, one screen line.
reap_children() {
    local cat="$1" action="$2" dir="$3" note="$4" child n=0 total=0
    REAP_QUIET=1
    while IFS= read -r child; do
        if reap_tree "$cat" "$action" "$child" "$note"; then
            n=$(( n + 1 )); total=$(( total + REAP_BYTES ))
        fi
    done < <(dir_children "$dir")
    REAP_QUIET=0
    [ "$n" -gt 0 ] || return 0
    say "$cat: $([ "$APPLY" = 1 ] && echo removed || echo would remove) $n entr(y/ies) under $dir ($(human "$total"))"
}

# Children of $1, dotfiles included, one per line.
dir_children() {
    local c
    for c in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        [ -e "$c" ] || [ -L "$c" ] || continue
        printf '%s\n' "$c"
    done
}

# Registered worktrees of GC_REPO other than the main checkout, the proof
# pools (z23p owns those) and the /tmp registrations (tmp owns those).
z23_lane_worktrees() {
    local wt
    while IFS= read -r wt; do
        [ -n "$wt" ] || continue
        [ "$wt" = "$GC_REPO" ] && continue
        [ -n "$(z23p_generation_pool "$wt")" ] && continue
        case "$wt" in "$GC_TMP"/*) continue ;; esac
        [ -d "$wt" ] || continue
        printf '%s\n' "$wt"
    done < <(worktree_paths "$GC_REPO")
}

wtbuild_one() {
    local wt="$1" idle_h="$2" child
    [ -d "$wt/build" ] || [ -d "$wt/test-tmp" ] || return 0
    if is_protected "$wt"; then return 0; fi
    if wt_in_use "$wt"; then
        say "wtbuild: KEEP (live process inside): $wt"
        return 0
    fi
    if [ -d "$wt/build" ]; then
        if recent_under "$wt/build" "$idle_h"; then
            say "wtbuild: KEEP (built within ${idle_h}h): $wt"
        else
            while IFS= read -r child; do
                wtbuild_keeps_child "$child" && continue
                reap_tree wtbuild wtbuild-remove "$child" "idle>${idle_h}h" || true
            done < <(dir_children "$wt/build")
        fi
    fi
    if [ -d "$wt/test-tmp" ] && ! recent_under "$wt/test-tmp" "$idle_h"; then
        reap_children testtmp testtmp-remove "$wt/test-tmp" "idle worktree>${idle_h}h"
    fi
}

sweep_wtbuild() {
    want wtbuild || return 0
    local idle_h="$WT_BUILD_IDLE_H" wt n=0
    if [ "$LOW_DISK" = 1 ] && [ "$idle_h" -gt "$WT_BUILD_LOWDISK_IDLE_H" ]; then
        idle_h="$WT_BUILD_LOWDISK_IDLE_H"
    fi
    hdr "worktree build output (build/ idle more than ${idle_h}h)"
    while IFS= read -r wt; do
        n=$(( n + 1 ))
        wtbuild_one "$wt" "$idle_h"
    done < <(z23_lane_worktrees)
    say "wtbuild: $n registered worktree(s) examined"
}

# ========================================================= CATEGORY landtmp
# The landing worktree's test scratch (52 GB on 2026-09-27). The lander
# reuses one private worktree forever and every proof leaves its test-tmp
# behind. It is emptied ONLY when the land queue is provably idle: no row
# in queue.jsonl, step.lock free, and no live process inside the worktree.
# On --apply the step lock is TAKEN (non-blocking) for the removal itself,
# so a land step that starts meanwhile gets its ordinary retryable
# STEP_BUSY instead of racing a delete. Anything unprovable skips, by name.
LAND_DIR="$GC_HOME/.local/state/z23/dev/land"

# Prints why the queue is busy and returns 0; returns 1 when idle.
land_queue_busy() {
    local q="$LAND_DIR/queue.jsonl"
    if [ -s "$q" ]; then
        printf 'land queue has %s row(s) queued or in flight' "$(grep -c . "$q")"
        return 0
    fi
    if [ -e "$LAND_DIR/step.lock" ]; then
        if ! command -v flock >/dev/null 2>&1; then
            printf 'no flock binary to prove step.lock is free'
            return 0
        fi
        if ! flock -n -x "$LAND_DIR/step.lock" true 2>/dev/null; then
            printf 'step.lock is held by a land step or proof'
            return 0
        fi
    fi
    ensure_cwd_set
    if cwd_occupied "$LAND_DIR/wt"; then
        printf 'a live process is inside the landing worktree'
        return 0
    fi
    return 1
}

landtmp_reap_children() {
    local tt="$1"
    reap_children landtmp landtmp-remove "$tt" "land queue idle"
}

sweep_landtmp() {
    want landtmp || return 0
    hdr "landing worktree test scratch (only while the land queue is idle)"
    local tt="$LAND_DIR/wt/test-tmp" why
    [ -d "$tt" ] || { say "landtmp: no $tt — skipped"; return 0; }
    [ -n "$(dir_children "$tt")" ] || { say "landtmp: $tt is empty"; return 0; }
    if why="$(land_queue_busy)"; then
        say "landtmp: SKIP ($why): $tt"
        log_line "landtmp-skip" "$tt" 0 "$why"
        return 0
    fi
    if [ "$APPLY" = 1 ] && [ -e "$LAND_DIR/step.lock" ]; then
        # fd 8 carries the lock for exactly the removal below.
        exec 8>>"$LAND_DIR/step.lock"
        if ! flock -n -x 8; then
            exec 8>&-
            say "landtmp: SKIP (step.lock was taken before the removal began): $tt"
            log_line "landtmp-skip" "$tt" 0 "step.lock raced"
            return 0
        fi
        landtmp_reap_children "$tt"
        exec 8>&-
        return 0
    fi
    landtmp_reap_children "$tt"
}

# ========================================================== CATEGORY landed
# Whole registered worktrees that are clean, carry no commit main lacks
# (git cherry: patch equivalence, so cherry-picked lanes count as landed),
# and have been idle more than LANDED_IDLE_H. OPT-IN: without
# --reap-landed-worktrees this only reports the candidates, because
# docs/dev/HOST_GC.md sanctions whole-worktree removal only for the units,
# lanes and trains directories. Before each removal the worktree's path,
# commit and branch are appended to $STATE/landed_worktrees.tsv, so any one
# of them is `git worktree add <path> <commit>` away from coming back.
# `git worktree remove` refuses a tree with a submodule checkout, so the
# fallback is a guarded rm -rf plus `git worktree prune`.
LANDED_IDLE_H=24

landed_base_ref() {
    local r
    for r in origin/main main; do
        if git -C "$GC_REPO" rev-parse -q --verify "$r^{commit}" >/dev/null 2>&1; then
            printf '%s' "$r"
            return 0
        fi
    done
    return 1
}

# Clean with submodules included. The vendored tor checkout's untracked
# .provenance stamp is written by the build and is not work: a status whose
# only line is the submodule, whose own only change is that stamp, and whose
# recorded commit is unchanged, is clean.
landed_clean() {
    local wt="$1" out sub
    out="$(git -C "$wt" status --porcelain --ignore-submodules=none 2>/dev/null)" || return 1
    [ -z "$out" ] && return 0
    [ "$out" = " M vendor/tor" ] || [ "$out" = " m vendor/tor" ] || return 1
    sub="$(git -C "$wt/vendor/tor" status --porcelain --ignore-submodules=none 2>/dev/null)" || return 1
    [ "$sub" = "?? .provenance" ] || return 1
    git -C "$wt" diff --quiet --ignore-submodules=dirty -- vendor/tor 2>/dev/null
}

landed_unlanded_commits() {
    local out
    out="$(git -C "$1" cherry "$2" HEAD 2>/dev/null)" || return 0
    case "$out" in *$'\n+'*|+*) return 0 ;; esac
    return 1
}

worktree_gc_protected_name() {
    local names
    [ -f "$WORKTREE_GC" ] || return 1
    names="$(sed -n 's/^PROTECTED_NAMES="\(.*\)"$/\1/p' "$WORKTREE_GC" 2>/dev/null)"
    case " $names " in *" $1 "*) return 0 ;; esac
    return 1
}

# Returns 0 for a removal candidate; otherwise says why it is kept.
landed_candidate() {
    local wt="$1" base="$2"
    is_protected "$wt" && return 1
    case "$wt" in
        "$UNITS_DIR"/*|"$LANES_DIR"/*|"$TRAINS_DIR"/*|"$LAND_DIR"/*) return 1 ;;
    esac
    if worktree_gc_protected_name "$(basename -- "$wt")"; then
        say "landed: KEEP (hard-protected lane name): $wt"; return 1
    fi
    if worktree_locked "$wt"; then say "landed: KEEP (locked): $wt"; return 1; fi
    if wt_in_use "$wt"; then say "landed: KEEP (live process inside): $wt"; return 1; fi
    if ! landed_clean "$wt"; then say "landed: KEEP (dirty — uncommitted work): $wt"; return 1; fi
    if unit_has_review_ref "$wt"; then say "landed: KEEP (review ref exists): $wt"; return 1; fi
    if landed_unlanded_commits "$wt" "$base"; then
        say "landed: KEEP (unlanded commits — git cherry shows +): $wt"; return 1
    fi
    if recent_under "$wt" "$LANDED_IDLE_H"; then
        say "landed: KEEP (touched within ${LANDED_IDLE_H}h): $wt"; return 1
    fi
    return 0
}

landed_remove() {
    local wt="$1" bytes="$2" sha branch
    refuse_if_protected "$wt" || return 0
    sha="$(git -C "$wt" rev-parse HEAD 2>/dev/null)" || { say "landed: no HEAD for $wt (left in place)"; return 0; }
    branch="$(git -C "$wt" symbolic-ref -q --short HEAD 2>/dev/null || echo detached)"
    ensure_state
    printf '%s\t%s\t%s\t%s\n' "$wt" "$sha" "$branch" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "$STATE/landed_worktrees.tsv" || { say "landed: could not record $wt (left in place)"; return 0; }
    chmod -R u+w -- "$wt" 2>/dev/null || true
    if ! git -C "$GC_REPO" worktree remove --force -- "$wt" 2>/dev/null; then
        refuse_if_protected "$wt" || return 0
        rm -rf -- "$wt" 2>/dev/null || true
        git -C "$GC_REPO" worktree prune >/dev/null 2>&1 || true
    fi
    if [ -e "$wt" ]; then
        log_line "landed-remove-failed" "$wt" 0 "head=$sha"
        say "landed: could not remove $wt (left in place)"
        return 0
    fi
    log_line "landed-remove" "$wt" "$bytes" "head=$sha branch=$branch"
    add_result landed "$bytes" 1
    say "landed: removed $wt ($(human "$bytes")) — recorded at $sha"
}

sweep_landed() {
    want landed || return 0
    hdr "fully landed idle worktrees (clean, no unique commits, idle > ${LANDED_IDLE_H}h)"
    local base wt bytes n=0 total=0
    base="$(landed_base_ref)" || { say "landed: no main ref in $GC_REPO — skipped"; return 0; }
    while IFS= read -r wt; do
        landed_candidate "$wt" "$base" || continue
        bytes="$(dir_bytes "$wt")"
        n=$(( n + 1 )); total=$(( total + bytes ))
        if [ "$REAP_LANDED" = 1 ] && [ "$APPLY" = 1 ]; then
            landed_remove "$wt" "$bytes"
        else
            say "landed: candidate $wt ($(human "$bytes")) vs $base"
            log_line "landed-candidate" "$wt" "$bytes" "vs $base"
            if [ "$REAP_LANDED" = 1 ]; then add_result landed "$bytes" 1; fi
        fi
    done < <(z23_lane_worktrees)
    if [ "$REAP_LANDED" != 1 ]; then
        say "landed: opt-in (rerun with --reap-landed-worktrees to remove) — $n candidate(s), $(human "$total") left in place"
    fi
}

# ========================================================= CATEGORY lowdisk
# Early warning. When free space is still below LOW_DISK_GB AFTER the sweep,
# nothing reproducible was left to reclaim and a human or an agent has to
# act. One row goes to the dev agent mail leaf naming the five largest
# consumers, at most once per LOWDISK_MAIL_EVERY_H. The body crosses hosts,
# so it carries no absolute path: consumers are named relative to home
# with '>' for '/', which the mail leaf's body filter accepts.
LOWDISK_MAIL_EVERY_H=6
LOWDISK_DU_BUDGET_S=60
LOWDISK_TOTAL_BUDGET_S=300

# The dev binary: beside the z23 binary, then PATH, then ~/.local/bin (a
# systemd user unit's PATH does not include it).
dev_mail_bin() {
    local c
    for c in "$(dirname -- "$Z23_BIN")/z23-dev" "$(command -v z23-dev 2>/dev/null || true)" \
        "$GC_HOME/.local/bin/z23-dev"; do
        if [ -n "$c" ] && [ -x "$c" ]; then printf '%s' "$c"; return 0; fi
    done
    return 1
}

# "bytes<TAB>path" for the children of one top-level directory, bounded.
bounded_du_children() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$LOWDISK_DU_BUDGET_S" du -x -b -d 1 -- "$1" 2>/dev/null || true
    else
        du -x -b -d 1 -- "$1" 2>/dev/null || true
    fi | awk -F '\t' -v top="$1" '$2 != top'
}

# The five largest second-level directories under home, as mail-safe text.
# The live datadirs are never walked; neither is anything past the budget.
top_consumers() {
    local d deadline rel b p
    deadline=$(( $(now_epoch) + LOWDISK_TOTAL_BUDGET_S ))
    for d in "$GC_HOME"/* "$GC_HOME"/.[!.]*; do
        [ -d "$d" ] && [ ! -L "$d" ] || continue
        case "$d" in "$GC_HOME"/.zclassic*) continue ;; esac
        [ "$(now_epoch)" -lt "$deadline" ] || break
        bounded_du_children "$d"
    done | sort -rn | head -5 | while IFS=$'\t' read -r b p; do
        rel="${p#"$GC_HOME"/}"
        printf '%s %s; ' "$(printf '%s' "$rel" | tr '/' '>')" "$(human "$b")"
    done
}

warn_low_disk() {
    want lowdisk || return 0
    local free="$1" stamp="$STATE/lowdisk_mail.stamp" age body bin
    [ -n "$free" ] || return 0
    [ "$free" -lt $(( LOW_DISK_GB * 1024 * 1024 * 1024 )) ] || return 0
    hdr "low-disk warning"
    if [ -e "$stamp" ]; then
        age="$(age_secs "$stamp")"
        if [ "$age" -lt $(( LOWDISK_MAIL_EVERY_H * 3600 )) ]; then
            say "lowdisk: rate limited — last warning $(( age / 60 ))m ago (one per ${LOWDISK_MAIL_EVERY_H}h)"
            return 0
        fi
    fi
    body="host-gc: $(human "$free") free after the sweep, below the ${LOW_DISK_GB}G floor. top: $(top_consumers)"
    body="$(printf '%s' "$body" | head -c 4000)"
    if ! bin="$(dev_mail_bin)"; then
        say "lowdisk: no z23-dev to post with — $body"
        log_line "lowdisk-mail-failed" "$GC_HOME" "$free" "no z23-dev"
        return 0
    fi
    if [ "$APPLY" != 1 ]; then
        say "lowdisk: would post: $body"
        return 0
    fi
    if "$bin" dev agent mail --action=post --to=oauth --kind=problem --ref=host-gc \
        "--body=$body" >/dev/null 2>&1; then
        ensure_state
        : > "$stamp"
        say "lowdisk: posted: $body"
        log_line "lowdisk-mail" "$GC_HOME" "$free" "posted"
    else
        say "lowdisk: mail post failed ($bin) — $body"
        log_line "lowdisk-mail-failed" "$GC_HOME" "$free" "post refused"
    fi
}

# =============================================================== CATEGORY tmp
# /tmp is not a workspace on this host (agents are told to use
# ~/.local/state/<project>/scratch). Registered worktrees still end up there
# from ad-hoc experiments. Report all of them; reap only the ones git calls
# detached and clean and that nothing is sitting in.
sweep_tmp() {
    want tmp || return 0
    hdr "registered worktrees under $GC_TMP (older than ${TMP_MIN_AGE_D}d)"
    build_cwd_set
    local min_age=$(( TMP_MIN_AGE_D * 86400 ))
    local total=0 removed=0 kept=0 bytes wt
    while IFS= read -r wt; do
        [ -n "$wt" ] || continue
        case "$wt" in "$GC_TMP"/*) ;; *) continue ;; esac
        [ -d "$wt" ] || continue
        total=$(( total + 1 ))
        say "tmp: registered $wt ($(human "$(dir_bytes "$wt")"), age $(( $(age_secs "$wt") / 86400 ))d)"
        if is_protected "$wt"; then kept=$(( kept + 1 )); continue; fi
        if [ "$(age_secs "$wt")" -lt "$min_age" ] && [ "$LOW_DISK" = 0 ]; then
            kept=$(( kept + 1 )); continue
        fi
        if worktree_locked "$wt" || cwd_occupied "$wt"; then kept=$(( kept + 1 )); continue; fi
        if ! worktree_detached "$wt" || ! worktree_clean "$wt"; then
            kept=$(( kept + 1 ))
            say "tmp: KEEP (attached or dirty): $wt"
            continue
        fi
        refuse_if_protected "$wt" || continue
        bytes="$(dir_bytes "$wt")"
        if [ "$APPLY" = 1 ]; then
            chmod -R u+w "$wt" 2>/dev/null || true
            if git -C "$GC_REPO" worktree remove --force -- "$wt" 2>/dev/null; then
                removed=$(( removed + 1 )); add_result tmp "$bytes" 1
                log_line "tmp-remove" "$wt" "$bytes" "detached+clean"
            else
                log_line "tmp-remove-failed" "$wt" 0 "git refused"
            fi
        else
            removed=$(( removed + 1 )); add_result tmp "$bytes" 1
            log_line "tmp-remove" "$wt" "$bytes" "detached+clean"
        fi
    done < <(worktree_paths "$GC_REPO")
    say "tmp: $total registered under $GC_TMP — $removed reapable, $kept kept"
}

# ========================================================= CATEGORY tmplitter
# Unregistered top-level /tmp entries — test fixtures that were never a git
# worktree of anything, so sweep_tmp() (which only walks `git worktree list`)
# never sees them. Left alone for TMPLITTER_MIN_AGE_D days in case a test is
# still running, then deleted outright: they are reproducible fixtures, not
# work product, so quarantine would just delay the inevitable.
tmplitter_registered_set() {
    local repo d
    for d in "$GC_HOME"/github/*; do
        [ -d "$d/.git" ] || [ -f "$d/.git" ] || continue
        worktree_paths "$d"
    done
}

sweep_tmplitter() {
    want tmplitter || return 0
    hdr "unregistered /tmp litter (older than ${TMPLITTER_MIN_AGE_D}d)"
    [ -d "$GC_TMP" ] || { say "tmplitter: no $GC_TMP — skipped"; return 0; }
    ensure_cwd_set
    local registered
    registered="$(tmplitter_registered_set)"
    local min_age=$(( TMPLITTER_MIN_AGE_D * 86400 ))
    [ "$LOW_DISK" = 1 ] && min_age=$(( min_age / 2 ))
    local total=0 removed=0 kept=0 entry name bytes
    for entry in "$GC_TMP"/*; do
        [ -e "$entry" ] || continue
        name="$(basename -- "$entry")"
        case "$name" in
            zcl-pristine-*|claude-*|systemd-*|.X*|snap-*) continue ;;
        esac
        is_protected "$entry" && continue
        case "$(printf '%s\n' "$registered")" in
            *"$entry"*) continue ;;
        esac
        total=$(( total + 1 ))
        if [ "$(age_secs "$entry")" -lt "$min_age" ]; then
            kept=$(( kept + 1 ))
            continue
        fi
        if cwd_occupied "$entry"; then
            kept=$(( kept + 1 ))
            say "tmplitter: KEEP (open by a live process): $entry"
            continue
        fi
        refuse_if_protected "$entry" || continue
        bytes="$(dir_bytes "$entry")"
        if [ "$APPLY" = 1 ]; then
            chmod -R u+w "$entry" 2>/dev/null || true
            if rm -rf -- "$entry" 2>/dev/null; then
                removed=$(( removed + 1 )); add_result tmplitter "$bytes" 1
                log_line "tmplitter-remove" "$entry" "$bytes" "unregistered fixture"
            else
                log_line "tmplitter-remove-failed" "$entry" 0 "rm refused"
            fi
        else
            removed=$(( removed + 1 )); add_result tmplitter "$bytes" 1
            log_line "tmplitter-remove" "$entry" "$bytes" "unregistered fixture"
        fi
    done
    say "tmplitter: $total unregistered entr(y/ies) — $removed reapable, $kept kept"
}

# ============================================================= CATEGORY units
# Worktrees under ~/.z23/units and ~/.z23/lanes. worktree_gc.sh already owns
# the *named-lane* bucket rules, but its merge test is ANCESTRY (git
# merge-base --is-ancestor): every landed unit here is cherry-picked (`-x`)
# into a train, so its HEAD is never an ancestor of main and worktree_gc.sh
# can never see it as merged. `git cherry main HEAD` answers the right
# question instead — it diffs PATCH content, not commit identity, so a
# cherry-picked HEAD reads as "no + line" (nothing left to land) exactly
# like a fast-forward merge would.
unit_is_patch_equivalent() {
    local wt="$1" out
    out="$(git -C "$wt" cherry main HEAD 2>/dev/null)" || return 1
    case "$out" in
        *$'\n+'*|+*) return 1 ;;   # a "+" line: real unlanded content
        *) return 0 ;;
    esac
}

unit_has_review_ref() {
    git -C "$GC_REPO" show-ref --verify --quiet "refs/review/$(basename -- "$1")"
}

# One worktree's verdict, shared by the units and trains sweeps below so
# there is exactly one place that decides "safe to remove", not two rulesets
# that can quietly drift apart.
reap_landed_worktree() {
    local wt="$1" cat="$2" min_age_s="$3" bytes reason
    [ -d "$wt" ] || return 0
    if [ "$(age_secs "$wt")" -lt "$min_age_s" ] && [ "$LOW_DISK" = 0 ]; then
        say "$cat: KEEP (too young): $wt"
        return 0
    fi
    if worktree_locked "$wt"; then
        say "$cat: KEEP (locked): $wt"; return 0
    fi
    ensure_cwd_set
    if cwd_occupied "$wt"; then
        say "$cat: KEEP (live process inside): $wt"; return 0
    fi
    if ! worktree_clean "$wt"; then
        say "$cat: KEEP (dirty — uncommitted work): $wt"; return 0
    fi
    if unit_has_review_ref "$wt"; then
        say "$cat: KEEP (refs/review/$(basename -- "$wt") still exists): $wt"; return 0
    fi
    if ! unit_is_patch_equivalent "$wt"; then
        say "$cat: KEEP (unlanded commits — git cherry shows +): $wt"; return 0
    fi
    reason="patch-equivalent to main, no review ref, clean, idle"
    bytes="$(dir_bytes "$wt")"
    if [ "$APPLY" = 1 ]; then
        refuse_if_protected "$wt" || return 0
        if git -C "$GC_REPO" worktree remove --force -- "$wt" 2>/dev/null; then
            add_result "$cat" "$bytes" 1
            log_line "$cat-remove" "$wt" "$bytes" "$reason"
            say "$cat: removed $wt ($(human "$bytes"))"
        else
            log_line "$cat-remove-failed" "$wt" 0 "git refused"
            say "$cat: git refused to remove $wt (left in place)"
        fi
    else
        add_result "$cat" "$bytes" 1
        log_line "$cat-remove" "$wt" "$bytes" "$reason"
        say "$cat: would remove $wt ($(human "$bytes")) — $reason"
    fi
}

sweep_units() {
    want units || return 0
    hdr "landed units and lanes (patch-equivalent to main, older than ${UNITS_MIN_AGE_H}h)"
    local min_age=$(( UNITS_MIN_AGE_H * 3600 ))
    [ "$LOW_DISK" = 1 ] && min_age=$(( min_age / 2 ))
    local root d
    for root in "$UNITS_DIR" "$LANES_DIR"; do
        [ -d "$root" ] || { say "units: no $root — skipped"; continue; }
        for d in "$root"/*; do
            [ -d "$d/.git" ] || [ -f "$d/.git" ] || continue
            reap_landed_worktree "$d" units "$min_age"
        done
    done
    if [ "$APPLY" = 1 ]; then
        git -C "$GC_REPO" worktree prune >/dev/null 2>&1 || true
    fi
}

# The newest train dir is a running or just-finished pipeline stage, never a
# candidate regardless of its own patch-equivalence — sorted by mtime, not
# by name, because train names are not lexically ordered by recency.
newest_train_dir() {
    local root="$1" d age newest="" newest_age=""
    # Portable mtime pick. GNU find's -printf does not exist on macOS, and an
    # empty answer here would leave the NEWEST train unprotected — the one
    # running pipeline stage this sweep must never touch — so age_secs, which
    # already speaks Darwin stat, ranks the candidates instead: smallest age
    # is the most recently modified directory.
    for d in "$root"/*; do
        [ -d "$d" ] || continue
        age="$(age_secs "$d")"
        if [ -z "$newest_age" ] || [ "$age" -lt "$newest_age" ]; then
            newest="$d"; newest_age="$age"
        fi
    done
    printf '%s' "$newest"
}

sweep_trains_landed() {
    want units || return 0
    [ -d "$TRAINS_DIR" ] || return 0
    hdr "landed trains (patch-equivalent to main, not the newest)"
    local newest d
    newest="$(newest_train_dir "$TRAINS_DIR")"
    local min_age=$(( UNITS_MIN_AGE_H * 3600 ))
    [ "$LOW_DISK" = 1 ] && min_age=$(( min_age / 2 ))
    for d in "$TRAINS_DIR"/*; do
        [ -d "$d" ] || continue
        [ "$d" = "$newest" ] && { say "units: KEEP (newest train): $d"; continue; }
        if [ -d "$d/.git" ] || [ -f "$d/.git" ]; then
            reap_landed_worktree "$d" units "$min_age"
        else
            say "units: $d is not a worktree — left for a human"
        fi
    done
}

# ============================================================= CATEGORY scratch
# Dated/named directories under $SCRATCH_DIR with no worktree left behind
# them (their lane, unit, or train is long gone) and nothing live inside.
# Names in $SCRATCH_DIR/.gc_keep (one per line, exact basename match) are
# never touched — the standing way to pin a scratch dir open-endedly without
# editing this script.
scratch_is_kept_by_name() {
    local name="$1" keepfile="$SCRATCH_DIR/.gc_keep" line
    [ -f "$keepfile" ] || return 1
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in \#*) continue ;; esac
        [ "$line" = "$name" ] && return 0
    done < "$keepfile"
    return 1
}

scratch_has_live_worktree() {
    local name="$1" root
    for root in "$LANES_DIR" "$UNITS_DIR" "$TRAINS_DIR"; do
        [ -e "$root/$name" ] && return 0
    done
    return 1
}

sweep_scratch() {
    want scratch || return 0
    hdr "scratch (older than ${SCRATCH_MIN_AGE_D}d, no owning worktree)"
    [ -d "$SCRATCH_DIR" ] || { say "scratch: no $SCRATCH_DIR — skipped"; return 0; }
    ensure_cwd_set
    local min_age=$(( SCRATCH_MIN_AGE_D * 86400 ))
    [ "$LOW_DISK" = 1 ] && min_age=$(( min_age / 2 ))
    local total=0 removed=0 kept=0 d name bytes
    for d in "$SCRATCH_DIR"/*; do
        [ -d "$d" ] || continue
        name="$(basename -- "$d")"
        [ "$name" = "quarantine" ] && continue
        total=$(( total + 1 ))
        if scratch_is_kept_by_name "$name"; then
            kept=$(( kept + 1 )); say "scratch: KEEP (.gc_keep): $d"; continue
        fi
        if [ "$(age_secs "$d")" -lt "$min_age" ]; then
            kept=$(( kept + 1 )); continue
        fi
        if cwd_occupied "$d"; then
            kept=$(( kept + 1 )); say "scratch: KEEP (live process inside): $d"; continue
        fi
        if scratch_has_live_worktree "$name"; then
            kept=$(( kept + 1 )); say "scratch: KEEP (worktree still exists): $d"; continue
        fi
        bytes="$(quarantine_path "$d" scratch)" || { kept=$(( kept + 1 )); continue; }
        removed=$(( removed + 1 )); total=$(( total ));
        add_result scratch "$bytes" 1
        say "scratch: quarantine $name ($(human "$bytes"))"
    done
    say "scratch: $total dir(s) under $SCRATCH_DIR — $removed reapable, $kept kept"
}

# ============================================================ CATEGORY journal
# The user journal is ours to vacuum. The system journal needs root; this
# script never escalates, so when passwordless sudo is not available it
# PRINTS the command rather than pretending the cap was applied.
sweep_journal() {
    want journal || return 0
    hdr "journal (user cap $JOURNAL_CAP, system cap $SYSTEM_JOURNAL_CAP)"
    if ! command -v "$JOURNALCTL_BIN" >/dev/null 2>&1; then
        say "journal: journalctl not found — skipped"; return 0
    fi
    local before after freed
    before="$("$JOURNALCTL_BIN" --user --disk-usage 2>/dev/null \
              | grep -oE '[0-9.]+[KMG]' | head -1)"
    say "journal: user journal currently ${before:-unknown}"
    if [ "$APPLY" = 1 ]; then
        local b_bytes a_bytes
        b_bytes="$(journal_bytes)"
        "$JOURNALCTL_BIN" --user --vacuum-size="$JOURNAL_CAP" >/dev/null 2>&1 || true
        a_bytes="$(journal_bytes)"
        freed=$(( b_bytes > a_bytes ? b_bytes - a_bytes : 0 ))
        say "journal: reclaimed $(human "$freed")"
        log_line "journal-vacuum" "user" "$freed" "cap=$JOURNAL_CAP"
        add_result journal "$freed" 1
    else
        say "journal: would run '$JOURNALCTL_BIN --user --vacuum-size=$JOURNAL_CAP'"
        log_line "journal-vacuum" "user" 0 "cap=$JOURNAL_CAP"
    fi
    # System journal: only if it costs no password.
    if sudo -n true 2>/dev/null; then
        if [ "$APPLY" = 1 ]; then
            sudo -n "$JOURNALCTL_BIN" --vacuum-size="$SYSTEM_JOURNAL_CAP" >/dev/null 2>&1 || true
            log_line "journal-vacuum" "system" 0 "cap=$SYSTEM_JOURNAL_CAP"
            say "journal: system journal vacuumed to $SYSTEM_JOURNAL_CAP"
        else
            say "journal: would vacuum the system journal to $SYSTEM_JOURNAL_CAP"
        fi
    else
        say "journal: system journal needs root — run by hand:"
        say "         sudo journalctl --vacuum-size=$SYSTEM_JOURNAL_CAP"
    fi
}

journal_bytes() {
    local s n u
    s="$("$JOURNALCTL_BIN" --user --disk-usage 2>/dev/null \
         | grep -oE '[0-9.]+[KMG]' | head -1)" || true
    [ -n "$s" ] || { printf '0'; return; }
    n="${s%[KMG]}"; u="${s##*[0-9.]}"
    case "$u" in
        K) awk -v n="$n" 'BEGIN{printf "%d", n*1024}' ;;
        M) awk -v n="$n" 'BEGIN{printf "%d", n*1024*1024}' ;;
        G) awk -v n="$n" 'BEGIN{printf "%d", n*1024*1024*1024}' ;;
        *) printf '0' ;;
    esac
}

# ============================================================ CATEGORY binbak
# ~/bin holds hand-made rollback pins (zclassicd.bak-pre-shielded and
# friends). These are NOT reproducible build output — they are the binary
# somebody kept so a bad deploy could be undone — so they are quarantined,
# never deleted, and the quarantine holds them another two weeks.
sweep_binbak() {
    want binbak || return 0
    hdr "~/bin rollback pins (older than ${BINBAK_MIN_AGE_D}d)"
    local bindir="$GC_HOME/bin"
    [ -d "$bindir" ] || { say "binbak: no ~/bin — skipped"; return 0; }
    local min_age=$(( BINBAK_MIN_AGE_D * 86400 ))
    local n=0 bytes total=0 f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -e "$f" ] || continue
        [ "$(age_secs "$f")" -ge "$min_age" ] || continue
        is_protected "$f" && continue
        bytes="$(quarantine_path "$f" binbak)" || continue
        n=$(( n + 1 )); total=$(( total + bytes ))
        say "binbak: quarantine $(basename "$f") ($(human "$bytes"))"
    done < <(find "$bindir" -maxdepth 1 -name '*.bak-*' 2>/dev/null | sort)
    add_result binbak "$total" "$n"
    say "binbak: $n pins quarantined, $(human "$total")"
}

# =========================================================== CATEGORY testtmp
# Test scratch (test-tmp/, .zcl_test_render/) left behind in worktrees. The
# "worktree not modified in the last hour" guard is what makes this safe to
# run hourly: a lane that is actively building has a fresh worktree mtime,
# and its scratch is left alone even when a stale directory sits inside it.
sweep_testtmp() {
    want testtmp || return 0
    hdr "stale test scratch (older than ${TESTTMP_MIN_AGE_D}d in idle worktrees)"
    local min_age=$(( TESTTMP_MIN_AGE_D * 86400 ))
    local n=0 total=0 bytes d root
    for root in "$GC_HOME"/github/z23-lane-* "$GC_HOME"/z23-* "$GC_REPO"; do
        [ -d "$root" ] || continue
        # An actively building lane is off limits regardless of what is inside.
        [ "$(age_secs "$root")" -ge 3600 ] || continue
        while IFS= read -r d; do
            [ -n "$d" ] || continue
            [ -d "$d" ] || continue
            [ "$(age_secs "$d")" -ge "$min_age" ] || continue
            is_protected "$d" && continue
            bytes="$(dir_bytes "$d")"
            if [ "$APPLY" = 1 ]; then
                refuse_if_protected "$d" || continue
                chmod -R u+w "$d" 2>/dev/null || true
                rm -rf -- "$d" 2>/dev/null || { log_line "testtmp-failed" "$d" 0 "rm refused"; continue; }
            fi
            log_line "testtmp-remove" "$d" "$bytes" "stale scratch"
            n=$(( n + 1 )); total=$(( total + bytes ))
        done < <(find "$root" -maxdepth 3 \( -name 'test-tmp' -o -name '.zcl_test_render' \) -type d 2>/dev/null)
    done
    add_result testtmp "$total" "$n"
    say "testtmp: $n stale scratch dirs, $(human "$total")"
}

# =========================================================== CATEGORY repotmp
# The main checkout's own test-tmp (and its .zcl_test_render twin). Every
# other scratch sweep skips it: z23_lane_worktrees excludes GC_REPO by
# design, is_protected() shields the whole checkout tree, and sweep_testtmp
# keys on the scratch dir's own mtime — which a single fresh child keeps
# young forever, so the main checkout's test-tmp only grows (207,068
# entries measured on 2026-09-29; `du` over it no longer finished inside
# an 11-minute budget). This category reaps stale ENTRIES inside those two
# dirs, age-keyed like tools/scripts/test_tmp_clean.sh; the checkout, the
# scratch dirs themselves and every fresh entry stay put. The dirs are
# gitignored scratch by the tree's own contract — durable evidence lives in
# build/ artifact dirs and state ledgers, never here.
sweep_repotmp() {
    want repotmp || return 0
    hdr "main-checkout test scratch (entries older than ${REPOTMP_MIN_AGE_D}d under $GC_REPO)"
    local d child n=0 total=0 bytes shown cb
    local -a stale=()
    for d in "$GC_REPO/test-tmp" "$GC_REPO/.zcl_test_render"; do
        [ -d "$d" ] || continue
        stale=()
        while IFS= read -r -d '' child; do
            stale+=("$child")
        done < <(find "$d" -mindepth 1 -maxdepth 1 -mtime +"$REPOTMP_MIN_AGE_D" -print0 2>/dev/null)
        [ "${#stale[@]}" -gt 0 ] || continue
        local backlog=${#stale[@]}
        if [ "$backlog" -gt "$REPOTMP_BATCH_MAX" ]; then
            stale=("${stale[@]:0:$REPOTMP_BATCH_MAX}")
        fi
        bytes=0
        if [ "${#stale[@]}" -le 200 ]; then
            for child in "${stale[@]}"; do
                cb="$(dir_bytes "$child")"
                bytes=$(( bytes + cb ))
            done
        else
            # One batched du: per-entry du on a 200k-entry scratch dir would
            # dominate the sweep, and per-entry log lines would flood the
            # log. The summary line below carries the aggregate.
            bytes="$(printf '%s\0' "${stale[@]}" | xargs -0 du -sb 2>/dev/null | awk '{s+=$1} END{print s+0}')"
        fi
        shown=0
        for child in "${stale[@]}"; do
            if [ "$APPLY" = 1 ]; then
                # chmod follows a symlink to its target, so only real trees
                # get the u+w pass; removing a symlink needs no chmod.
                [ -L "$child" ] || chmod -R u+w -- "$child" 2>/dev/null || true
                if ! rm -rf -- "$child" 2>/dev/null || [ -e "$child" ] || [ -L "$child" ]; then
                    log_line "repotmp-failed" "$child" 0 "rm refused"
                    continue
                fi
            fi
            n=$(( n + 1 ))
            if [ "$shown" -lt 20 ]; then
                say "repotmp: $([ "$APPLY" = 1 ] && echo removed || echo would remove) $child"
                shown=$(( shown + 1 ))
            elif [ "$shown" -eq 20 ]; then
                say "repotmp: … further entries under $d not listed"
                shown=$(( shown + 1 ))
            fi
        done
        total=$(( total + bytes ))
        if [ "$backlog" -gt "${#stale[@]}" ]; then
            log_line "repotmp-remove" "$d" "$bytes" "batch of ${#stale[@]} of $backlog stale entries older than ${REPOTMP_MIN_AGE_D}d; backlog drains over future runs"
            say "repotmp: $([ "$APPLY" = 1 ] && echo removed || echo would remove) ${#stale[@]} of $backlog stale entries under $d ($(human "$bytes")); the backlog drains over future runs"
        else
            log_line "repotmp-remove" "$d" "$bytes" "${#stale[@]} stale entries older than ${REPOTMP_MIN_AGE_D}d"
            say "repotmp: $([ "$APPLY" = 1 ] && echo removed || echo would remove) ${#stale[@]} entries under $d ($(human "$bytes"))"
        fi
    done
    add_result repotmp "$total" "$n"
    [ "$n" -gt 0 ] || say "repotmp: nothing stale under $GC_REPO"
}

# ============================================================ CATEGORY orphan
# A process is an orphan when its parent is gone (ppid 1), it is old enough
# that it cannot be mid-startup, and the checkout it came from has been
# deleted out from under it. The deleted-cwd/deleted-exe test is the load
# bearing one: it is proof the process can no longer be doing useful work,
# not a guess from its name. Anything under systemd management keeps a live
# unit and therefore a live cgroup, so it never reaches this classifier with
# a deleted binary.
sweep_orphan() {
    want orphan || return 0
    hdr "orphan processes (ppid 1, older than ${ORPHAN_MIN_AGE_H}h, deleted checkout)"
    local min_age=$(( ORPHAN_MIN_AGE_H * 3600 ))
    local n=0 d pid ppid cwd exe start_ticks hz uptime age
    hz="$(getconf CLK_TCK 2>/dev/null || echo 100)"
    uptime="$(awk '{print int($1)}' "$PROC_ROOT/uptime" 2>/dev/null || echo 0)"
    for d in "$PROC_ROOT"/[0-9]*; do
        [ -e "$d/stat" ] || continue
        pid="$(basename "$d")"
        [ "$pid" = "$$" ] && continue
        # field 4 is ppid, field 22 is starttime, both after the comm field
        ppid="$(awk '{ s=$0; sub(/^[^)]*\) /, "", s); split(s, f, " "); print f[2] }' "$d/stat" 2>/dev/null)" || continue
        [ "$ppid" = "1" ] || continue
        start_ticks="$(awk '{ s=$0; sub(/^[^)]*\) /, "", s); split(s, f, " "); print f[20] }' "$d/stat" 2>/dev/null)" || continue
        [ -n "$start_ticks" ] || continue
        age=$(( uptime - start_ticks / hz ))
        [ "$age" -ge "$min_age" ] || continue
        cwd="$(readlink -- "$d/cwd" 2>/dev/null)" || continue
        exe="$(readlink -- "$d/exe" 2>/dev/null)" || continue
        # Both must point at something that is gone AND that came from a
        # build tree. A long-running daemon whose binary was replaced by a
        # package upgrade also shows "(deleted)" — the build/ path test is
        # what separates our dead lane leftovers from those.
        case "$exe" in *" (deleted)") ;; *) continue ;; esac
        case "$exe" in *"/build/bin/"*) ;; *) continue ;; esac
        case "$cwd" in *" (deleted)") ;; *) continue ;; esac
        # NOT the file protect list. Every lane worktree lives under the main
        # checkout, so a path test would protect exactly the processes this
        # category exists to reap (it did, on the first run: the one real
        # orphan on the host was skipped because its deleted cwd had been
        # under $GC_REPO). The right guard for a PROCESS is its cgroup: a
        # systemd-managed service — the live node, the fixture peer, any
        # timer unit — sits in a .service cgroup and is never touched here.
        if grep -q '\.service' "$d/cgroup" 2>/dev/null; then continue; fi
        say "orphan: pid $pid, age $(( age / 3600 ))h, exe $exe"
        log_line "orphan-kill" "pid=$pid" 0 "exe=$exe cwd=$cwd age=${age}s"
        if [ "$APPLY" = 1 ]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
        n=$(( n + 1 ))
    done
    add_result orphan 0 "$n"
    say "orphan: $n parentless processes from deleted checkouts"
}

# ========================================================== CATEGORY worktree
# Named lanes are NOT classified here. worktree_gc.sh already owns that
# decision — merged/unmerged, clean/dirty, locked, hard-protected — and
# duplicating its bucket rules is how two classifiers drift and one of them
# deletes a lane the other would have kept. This category is a call into it.
sweep_worktree() {
    want worktree || return 0
    hdr "named worktrees (delegated to worktree_gc.sh)"
    if [ ! -x "$WORKTREE_GC" ]; then
        say "worktree: worktree_gc.sh not found at $WORKTREE_GC — skipped"
        return 0
    fi
    local before after freed
    before="$(free_bytes)"
    if [ "$APPLY" = 1 ]; then
        "$WORKTREE_GC" --apply 2>&1 | sed 's/^/  /' || true
        after="$(free_bytes)"
        freed=$(( after > before ? after - before : 0 ))
        log_line "worktree-gc" "$GC_REPO" "$freed" "delegated --apply"
        add_result worktree "$freed" 1
    else
        "$WORKTREE_GC" 2>&1 | sed 's/^/  /' || true
        log_line "worktree-gc" "$GC_REPO" 0 "delegated dry-run"
    fi
}

# ========================================================= CATEGORY deadexec
# Units whose ExecStart names a binary or script that is not on disk.
#
# WHY THIS IS A DISK-JANITOR'S JOB. It is the same accident seen from the
# other end. A sweep (this one, a manual `rm -rf build/`, a lane teardown)
# removes a checkout's build/ directory; any linger unit whose ExecStart
# pointed into that build/ dies with 203/EXEC and STAYS dead, because
# nothing on the host was watching for it. Two units on this host died
# exactly this way and one of them was a probe, so its silence was read as a
# real fault and paged for more than a day. A janitor that can create this
# failure mode is obliged to detect it.
#
# REPORT ONLY, in every run including --apply. Disabling somebody's unit
# automatically is not hygiene, it is an outage with extra steps. The output
# is a WARN a human or an agent acts on.
#
# The policy this enforces by naming violations: no unit may point into a
# checkout's build/ directory. Build trees are disposable by design;
# installed binaries belong under the user's own lib tree.
sweep_deadexec() {
    want deadexec || return 0
    hdr "systemd --user units with a missing or misplaced ExecStart"
    if ! command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1; then
        say "deadexec: systemctl not found — skipped"
        return 0
    fi
    local unit path n_missing=0 n_policy=0 units
    units="$("$SYSTEMCTL_BIN" --user list-unit-files --type=service \
                --no-legend --no-pager 2>/dev/null | awk '{print $1}')" || true
    if [ -z "$units" ]; then
        say "deadexec: no user units visible — skipped"
        return 0
    fi
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        case "$unit" in *@.service) continue ;; esac   # templates have no path
        path="$("$SYSTEMCTL_BIN" --user show -p ExecStart --value "$unit" 2>/dev/null \
                | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)" || true
        [ -n "$path" ] || continue
        case "$path" in /*) ;; *) continue ;; esac
        if [ ! -x "$path" ]; then
            say "deadexec: WARN $unit -> $path (MISSING; unit cannot start, 203/EXEC)"
            log_line "deadexec-missing" "$unit" 0 "path=$path"
            n_missing=$(( n_missing + 1 ))
            continue
        fi
        # Present, but living somewhere a sweep is entitled to delete.
        case "$path" in
            */build/bin/*|*/build/*)
                say "deadexec: WARN $unit -> $path (points into a build tree; will die on the next clean)"
                log_line "deadexec-policy" "$unit" 0 "path=$path"
                n_policy=$(( n_policy + 1 ))
                ;;
        esac
    done <<< "$units"
    add_result deadexec 0 $(( n_missing + n_policy ))
    if [ $(( n_missing + n_policy )) -eq 0 ]; then
        say "deadexec: every user unit points at a binary that exists outside a build tree"
    else
        say "deadexec: $n_missing missing, $n_policy inside a build tree — install to ~/.local/lib/z23/ instead"
    fi
}

# ======================================================= quarantine expiry
# The quarantine is only a safety net if it also empties. Anything older
# than the TTL is deleted here — that is the promise made when a rollback
# pin was moved instead of removed.
sweep_quarantine_expiry() {
    local d bytes n=0 total=0
    [ -d "$QUARANTINE" ] || return 0
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        [ "$(age_secs "$d")" -ge $(( QUARANTINE_TTL_D * 86400 )) ] || continue
        bytes="$(dir_bytes "$d")"
        if [ "$APPLY" = 1 ]; then
            rm -rf -- "$d" 2>/dev/null || continue
        fi
        log_line "quarantine-expire" "$d" "$bytes" "ttl=${QUARANTINE_TTL_D}d"
        n=$(( n + 1 )); total=$(( total + bytes ))
    done < <(find "$QUARANTINE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    [ "$n" -gt 0 ] && say "quarantine: expired $n batch(es), $(human "$total")"
    add_result quarantine "$total" "$n"
    return 0
}

# ---------------------------------------------------------------- the status
# ONE screen. The point is that an agent starting work on this host can run
# this and know whether the box is healthy without reading nine directories.
print_status() {
    local free load lastrun
    free="$(free_bytes)"
    load="$(awk '{print $1", "$2", "$3}' /proc/loadavg 2>/dev/null)"
    say "host-gc status  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    say "-------------------------------------------------------------"
    printf '  free space      %s%s\n' "$(human "$free")" \
        "$([ "$free" -lt $(( LOW_DISK_GB * 1024 * 1024 * 1024 )) ] && echo '   *** BELOW THRESHOLD ***' || echo '')"
    printf '  load average    %s\n' "$load"
    printf '  low-disk floor  %s GB (sweep)   cache freeze %s GB\n' \
        "$LOW_DISK_GB" "$CACHE_FREEZE_GB"
    say ""
    local wt_total wt_z23p wt_tmp wt_named
    wt_total="$(worktree_paths "$GC_REPO" | wc -l | tr -d ' ')"
    wt_z23p="$(worktree_paths "$GC_REPO" | grep -c "^$GC_HOME/github/.z23p/" || true)"
    wt_tmp="$(worktree_paths "$GC_REPO" | grep -c "^$GC_TMP/" || true)"
    wt_named=$(( wt_total - wt_z23p - wt_tmp ))
    printf '  worktrees       %s registered\n' "$wt_total"
    printf '                  %s dev-proof generations (.z23p)\n' "$wt_z23p"
    printf '                  %s under %s\n' "$wt_tmp" "$GC_TMP"
    printf '                  %s named lanes and the main checkout\n' "$wt_named"
    say ""
    printf '  ccache          %s (cap %sG)\n' \
        "$(human "$(dir_bytes "$GC_HOME/.ccache")")" "$CCACHE_CAP_GB"
    printf '  zcc cache       %s (cap %sG)\n' \
        "$(human "$(dir_bytes "${ZCL_HOST_GC_ZCC_DIR:-$GC_HOME/.cache/zcc}")")" "$(( ZCC_CAP_MB / 1024 ))"
    printf '  user journal    %s (cap %s)\n' \
        "$("$JOURNALCTL_BIN" --user --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMG]' | head -1 || echo '?')" \
        "$JOURNAL_CAP"
    printf '  quarantine      %s (swept after %s days)\n' \
        "$(human "$(dir_bytes "$QUARANTINE")")" "$QUARANTINE_TTL_D"
    say ""
    # Counted, not swept: --status must not write the log or the quarantine,
    # so it cannot just call sweep_orphan (which logs every candidate).
    local orphans=0 d exe cwd
    for d in "$PROC_ROOT"/[0-9]*; do
        exe="$(readlink -- "$d/exe" 2>/dev/null)" || continue
        cwd="$(readlink -- "$d/cwd" 2>/dev/null)" || continue
        case "$exe" in *" (deleted)") ;; *) continue ;; esac
        case "$exe" in *"/build/bin/"*) ;; *) continue ;; esac
        case "$cwd" in *" (deleted)") ;; *) continue ;; esac
        orphans=$(( orphans + 1 ))
    done
    printf '  orphan procs    %s\n' "$orphans"

    # Dead units get their own status line because the failure is silent: a
    # unit whose ExecStart vanished stays "loaded" and simply never runs, and
    # when the unit is a probe its silence is indistinguishable from the thing
    # it probes being healthy. It paged falsely here for over a day.
    local unit path dead=0 inbuild=0 units
    units="$("$SYSTEMCTL_BIN" --user list-unit-files --type=service \
                --no-legend --no-pager 2>/dev/null | awk '{print $1}')" || true
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        case "$unit" in *@.service) continue ;; esac
        path="$("$SYSTEMCTL_BIN" --user show -p ExecStart --value "$unit" 2>/dev/null \
                | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)" || true
        case "$path" in /*) ;; *) continue ;; esac
        if [ ! -x "$path" ]; then
            dead=$(( dead + 1 ))
            printf '  DEAD UNIT       %s -> %s (missing)\n' "$unit" "$path"
        else
            case "$path" in
                */build/*) inbuild=$(( inbuild + 1 ))
                    printf '  UNIT IN BUILD   %s -> %s\n' "$unit" "$path" ;;
            esac
        fi
    done <<< "$units"
    printf '  dead units      %s missing, %s pointing into a build tree\n' \
        "$dead" "$inbuild"
    if [ -f "$LOG" ]; then
        lastrun="$(tail -1 "$LOG" 2>/dev/null | cut -f1)"
        printf '  last action     %s\n' "${lastrun:-never}"
        printf '  log             %s\n' "$LOG"
    else
        printf '  last action     never (no log yet)\n'
    fi
    say "-------------------------------------------------------------"
    say "  dry run:  tools/scripts/host_gc.sh"
    say "  sweep:    tools/scripts/host_gc.sh --apply"
}

# =========================================================== CATEGORY pressure
# Not a sweep of its own — a REPORT on how hard the other sweeps should push
# this run, computed once and read by every age check above via $LOW_DISK.
# Below PRESSURE_MIN_FREE_PCT free (percentage, not absolute — a floor in GB
# alone does not scale from a 200 GB box to a 2 TB one) every age floor in
# this run is already halved by the individual sweeps that check $LOW_DISK;
# this function's job is only to SAY so once, loudly, and — below the
# critical percentage — name the ten largest directories under $GC_HOME so
# the next agent does not have to go hunting for what is actually full.
free_pct() {
    df -P -- "$GC_HOME" 2>/dev/null | awk 'NR==2{u=$3+$4; if (u>0) printf "%d", $4*100/u; else print 0}'
}

report_pressure() {
    local pct
    pct="$(free_pct)"
    [ -n "$pct" ] || pct=100
    say "host-gc: free space is ${pct}% of $GC_HOME's filesystem"
    if [ "$pct" -lt "$PRESSURE_MIN_FREE_PCT" ]; then
        say "host-gc: *** PRESSURE (below ${PRESSURE_MIN_FREE_PCT}%) — every age floor above is halved this run ***"
        log_line "pressure" "$GC_HOME" 0 "free_pct=$pct floor=${PRESSURE_MIN_FREE_PCT}%"
    fi
    if [ "$pct" -lt "$PRESSURE_CRITICAL_FREE_PCT" ]; then
        say "host-gc: *** CRITICAL (below ${PRESSURE_CRITICAL_FREE_PCT}%) — ten largest dirs under $GC_HOME ***"
        find "$GC_HOME" -mindepth 1 -maxdepth 1 -type d \
            ! -name '.zclassic*' 2>/dev/null \
            | while IFS= read -r d; do printf '%s\t%s\n' "$(dir_bytes "$d")" "$d"; done \
            | sort -rn | head -10 \
            | while IFS=$'\t' read -r b d; do say "  $(human "$b")  $d"; done
        log_line "pressure-critical" "$GC_HOME" 0 "free_pct=$pct floor=${PRESSURE_CRITICAL_FREE_PCT}%"
    fi
}

# ------------------------------------------------------------------ options
# The knobs parsed at the top, defaulted and checked here, after every
# function they steer is defined.
WT_BUILD_IDLE_H="${WT_BUILD_IDLE_H:-12}"
REAP_LANDED="${REAP_LANDED:-0}"
case "$WT_BUILD_IDLE_H" in
    ''|*[!0-9]*) echo "host-gc: --wt-build-idle-h needs a whole number of hours" >&2; exit 2 ;;
esac

# ------------------------------------------------------------------- driver
LOW_DISK=0
CACHE_FREEZE=0
FREE_AT_START="$(free_bytes)"
if [ -n "$FREE_AT_START" ]; then
    [ "$FREE_AT_START" -lt $(( LOW_DISK_GB * 1024 * 1024 * 1024 )) ] && LOW_DISK=1
    [ "$FREE_AT_START" -lt $(( CACHE_FREEZE_GB * 1024 * 1024 * 1024 )) ] && CACHE_FREEZE=1
fi
PRESSURE_PCT="$(free_pct)"
[ -n "$PRESSURE_PCT" ] || PRESSURE_PCT=100
if [ "$PRESSURE_PCT" -lt "$PRESSURE_MIN_FREE_PCT" ]; then
    LOW_DISK=1
fi

if [ "$STATUS" = 1 ]; then
    print_status
    exit 0
fi

say "host-gc: $([ "$APPLY" = 1 ] && echo APPLY || echo 'DRY RUN — nothing will be changed')"
say "host-gc: free $(human "${FREE_AT_START:-0}") on $GC_HOME"
if [ "$LOW_DISK" = 1 ]; then
    say "host-gc: *** LOW DISK (below ${LOW_DISK_GB} GB) — age floors relaxed ***"
    log_line "low-disk" "$GC_HOME" "$FREE_AT_START" "threshold=${LOW_DISK_GB}G"
fi
if [ "$CACHE_FREEZE" = 1 ]; then
    say "host-gc: *** CACHE FREEZE (below ${CACHE_FREEZE_GB} GB) — caches may not grow ***"
    log_line "cache-freeze" "$GC_HOME" "$FREE_AT_START" "threshold=${CACHE_FREEZE_GB}G"
fi

report_pressure

# sweep_zcc runs LAST among the sweeps (see the ZCC_TRIM_BUDGET_S comment
# above sweep_zcc): its evictor does its own single walk of a cache that can
# hold tens of thousands of files on a slow disk, and on 2026-09-10 that one
# walk alone ran past the unit's 30-minute TimeoutStartSec and got SIGKILLed
# mid-sweep — every category listed after it that hour never ran at all.
# Every other category here is cheap (a du, a journalctl call, a worktree
# walk bounded by a small registry) and belongs before it so a slow zcc walk
# can never starve them again.
sweep_ccache
sweep_z23p
sweep_tmp
sweep_tmplitter
sweep_journal
sweep_binbak
sweep_testtmp
sweep_repotmp
sweep_orphan
sweep_deadexec
sweep_worktree
sweep_units
sweep_trains_landed
sweep_scratch
sweep_wtbuild
sweep_landtmp
sweep_landed
sweep_quarantine_expiry
sweep_zcc

hdr "summary"
TOTAL=0
while read -r cat c b; do
    [ -n "$cat" ] || continue
    TOTAL=$(( TOTAL + b ))
    printf '  %-10s %6s item(s)  %10s\n' "$cat" "$c" "$(human "$b")"
done <<< "$(cat_totals)"
printf '  %-10s %6s           %10s\n' "TOTAL" "" "$(human "$TOTAL")"
FREE_AT_END="$(free_bytes)"
say ""
say "host-gc: free $(human "${FREE_AT_END:-0}") after sweep"
if [ "$APPLY" = 0 ]; then
    say "host-gc: this was a DRY RUN — rerun with --apply to reclaim it"
fi
log_line "sweep-complete" "$GC_HOME" "$TOTAL" "free_before=$FREE_AT_START free_after=$FREE_AT_END"
warn_low_disk "${FREE_AT_END:-}"
exit 0
