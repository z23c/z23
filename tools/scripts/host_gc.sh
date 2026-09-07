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
#   z23p     reap dead dev-proof generations (the 158 GB leak)
#   tmp      registered worktrees under /tmp
#   journal  vacuum the user journal to 512 MB
#   binbak   quarantine ~/bin/*.bak-* older than 60 days
#   testtmp  stale test scratch in idle worktrees
#   orphan   kill parentless processes whose checkout was deleted
#   deadexec WARN on user units whose ExecStart is missing or inside build/
#   worktree merged+clean named worktrees, via worktree_gc.sh --apply
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
Z23P_MIN_AGE_H="${ZCL_HOST_GC_Z23P_MIN_AGE_H:-24}"
TMP_MIN_AGE_D="${ZCL_HOST_GC_TMP_MIN_AGE_D:-2}"
BINBAK_MIN_AGE_D="${ZCL_HOST_GC_BINBAK_MIN_AGE_D:-60}"
TESTTMP_MIN_AGE_D="${ZCL_HOST_GC_TESTTMP_MIN_AGE_D:-1}"
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
                 ccache zcc z23p tmp journal binbak testtmp orphan deadexec
                 worktree

Thresholds: below the low-disk floor the sweep relaxes its age floors; below
the cache-freeze floor the caches are additionally capped at their current
size so they cannot reclaim the space the sweep just freed.

Low-disk trigger: when free space on the filesystem holding $HOME is below
the low-disk threshold, a dry run says so loudly and an --apply run sweeps
regardless of the per-category age floors it would otherwise respect.

Log:        ~/.local/state/server-cleanup/host_gc.log
Quarantine: ~/.local/state/server-cleanup/quarantine/<date>/ (swept after 14 days)
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --dry-run|--plan) APPLY=0 ;;
        --status) STATUS=1 ;;
        --only)
            shift || { echo "host-gc: --only needs a category" >&2; exit 2; }
            ONLY="$1"
            ;;
        # Ask the protect predicate about one path and exit. This exists so
        # the gate can test is_protected() DIRECTLY rather than grepping the
        # source for the tree names: a grep for "wallet_backups" matches the
        # header comment above and keeps passing after the real entry has
        # been deleted from the case statement, which is exactly the kind of
        # gate that reports clean while the guarantee is gone.
        --check-protected)
            shift || { echo "host-gc: --check-protected needs a path" >&2; exit 2; }
            CHECK_PROTECTED="$1"
            ;;
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
        /tmp/zcl-pristine-*) return 0 ;;
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
    df -PB1 -- "$GC_HOME" 2>/dev/null | awk 'NR==2{print $4}'
}

now_epoch() { date +%s; }

# mtime age in seconds; a vanished path reads as 0 (too young to touch),
# which is the fail-safe direction.
age_secs() {
    local m
    m="$(stat -c %Y -- "$1" 2>/dev/null)" || { printf '0'; return; }
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
# answer "bytes per category" without re-reading the log.
declare -A CAT_BYTES CAT_COUNT
add_result() {
    local cat="$1" bytes="${2:-0}" n="${3:-1}"
    CAT_BYTES[$cat]=$(( ${CAT_BYTES[$cat]:-0} + bytes ))
    CAT_COUNT[$cat]=$(( ${CAT_COUNT[$cat]:-0} + n ))
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
build_cwd_set() {
    local d target
    CWD_SET=""
    for d in "$PROC_ROOT"/[0-9]*; do
        [ -e "$d" ] || continue
        target="$(readlink -- "$d/cwd" 2>/dev/null)" || continue
        [ -n "$target" ] || continue
        CWD_SET="$CWD_SET
$target"
    done
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
sweep_zcc() {
    want zcc || return 0
    hdr "zcc cache (cap $(( ZCC_CAP_MB / 1024 ))G)"
    local dir="${ZCL_HOST_GC_ZCC_DIR:-$GC_HOME/.cache/zcc}" before after freed
    [ -d "$dir" ] || { say "zcc: no cache directory — skipped"; return 0; }
    before="$(dir_bytes "$dir")"
    local cap_mb="$ZCC_CAP_MB"
    if [ "$CACHE_FREEZE" = 1 ]; then
        local held_mb=$(( before / 1024 / 1024 ))
        [ "$held_mb" -lt "$cap_mb" ] && cap_mb="$held_mb"
        [ "$cap_mb" -lt 64 ] && cap_mb=64
        say "zcc: FREEZE active — cap lowered to ${cap_mb}MB (no growth)"
    fi
    say "zcc: current $(human "$before"), cap ${cap_mb}MB"
    if [ ! -x "$ZCC_BIN" ]; then
        # Deliberately NOT falling back to an atime sweep. Deleting objects
        # behind the cache's back is worse than leaving it uncapped for one
        # cycle; name the one command that fixes it instead.
        say "zcc: evictor not built ($ZCC_BIN) — run 'make cc-cache' then rerun"
        log_line "zcc-skip" "$dir" 0 "evictor not built"
        return 0
    fi
    if [ "$APPLY" = 1 ]; then
        "$ZCC_BIN" --zcc-trim "$cap_mb" >/dev/null 2>&1 || true
        after="$(dir_bytes "$dir")"
        freed=$(( before > after ? before - after : 0 ))
        say "zcc: now $(human "$after"), reclaimed $(human "$freed")"
        log_line "zcc-trim" "$dir" "$freed" "cap=${cap_mb}MB freeze=$CACHE_FREEZE"
        add_result zcc "$freed" 1
    else
        local cap_bytes=$(( cap_mb * 1024 * 1024 ))
        freed=$(( before > cap_bytes ? before - cap_bytes : 0 ))
        say "zcc: would reclaim about $(human "$freed")"
        log_line "zcc-trim" "$dir" "$freed" "cap=${cap_mb}MB freeze=$CACHE_FREEZE"
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
# A generation is reapable when ALL of these hold:
#   older than Z23P_MIN_AGE_H     (a proof in flight is minutes old)
#   no process has it as cwd      (a proof in flight is chdir'd into it)
#   not git-locked                (an explicit "leave this alone")
#   detached HEAD and clean       (git's own verdict, not ours)
# Anything failing the last test is REPORTED, never removed — a generation
# holding uncommitted content is a bug worth a human's attention, not a
# deletion candidate.
sweep_z23p() {
    want z23p || return 0
    hdr "dev-proof generations (.z23p, older than ${Z23P_MIN_AGE_H}h)"
    local pool="${ZCL_HOST_GC_Z23P:-$GC_HOME/github/.z23p}"
    [ -d "$pool" ] || { say "z23p: no pool — skipped"; return 0; }
    build_cwd_set
    local min_age=$(( Z23P_MIN_AGE_H * 3600 ))
    local total=0 removed=0 kept=0 dirty=0 busy=0 young=0 bytes
    local wt
    while IFS= read -r wt; do
        [ -n "$wt" ] || continue
        case "$wt" in "$pool"/*) ;; *) continue ;; esac
        [ -d "$wt" ] || continue
        total=$(( total + 1 ))
        if [ "$(age_secs "$wt")" -lt "$min_age" ] && [ "$LOW_DISK" = 0 ]; then
            young=$(( young + 1 )); continue
        fi
        if worktree_locked "$wt"; then kept=$(( kept + 1 )); continue; fi
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
            chmod -R u+w -- "$wt" 2>/dev/null || true
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
    say "z23p: $total registered — $removed reapable, $young too young, $busy in use, $kept locked, $dirty need review"
    [ "$APPLY" = 1 ] && git -C "$GC_REPO" worktree prune >/dev/null 2>&1 || true
    return 0
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
            chmod -R u+w -- "$wt" 2>/dev/null || true
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

# =========================================================== CATEGORY journal
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
                chmod -R u+w -- "$d" 2>/dev/null || true
                rm -rf -- "$d" 2>/dev/null || { log_line "testtmp-failed" "$d" 0 "rm refused"; continue; }
            fi
            log_line "testtmp-remove" "$d" "$bytes" "stale scratch"
            n=$(( n + 1 )); total=$(( total + bytes ))
        done < <(find "$root" -maxdepth 3 \( -name 'test-tmp' -o -name '.zcl_test_render' \) -type d 2>/dev/null)
    done
    add_result testtmp "$total" "$n"
    say "testtmp: $n stale scratch dirs, $(human "$total")"
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

# ------------------------------------------------------------------- driver
LOW_DISK=0
CACHE_FREEZE=0
FREE_AT_START="$(free_bytes)"
if [ -n "$FREE_AT_START" ]; then
    [ "$FREE_AT_START" -lt $(( LOW_DISK_GB * 1024 * 1024 * 1024 )) ] && LOW_DISK=1
    [ "$FREE_AT_START" -lt $(( CACHE_FREEZE_GB * 1024 * 1024 * 1024 )) ] && CACHE_FREEZE=1
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

sweep_ccache
sweep_zcc
sweep_z23p
sweep_tmp
sweep_journal
sweep_binbak
sweep_testtmp
sweep_orphan
sweep_deadexec
sweep_worktree
sweep_quarantine_expiry

hdr "summary"
TOTAL=0
for cat in ccache zcc z23p tmp journal binbak testtmp orphan deadexec worktree quarantine; do
    b="${CAT_BYTES[$cat]:-0}"; c="${CAT_COUNT[$cat]:-0}"
    TOTAL=$(( TOTAL + b ))
    printf '  %-10s %6s item(s)  %10s\n' "$cat" "$c" "$(human "$b")"
done
printf '  %-10s %6s           %10s\n' "TOTAL" "" "$(human "$TOTAL")"
FREE_AT_END="$(free_bytes)"
say ""
say "host-gc: free $(human "${FREE_AT_END:-0}") after sweep"
if [ "$APPLY" = 0 ]; then
    say "host-gc: this was a DRY RUN — rerun with --apply to reclaim it"
fi
log_line "sweep-complete" "$GC_HOME" "$TOTAL" "free_before=$FREE_AT_START free_after=$FREE_AT_END"
exit 0
