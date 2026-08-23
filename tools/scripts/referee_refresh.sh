#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# referee_refresh.sh — rebuild (or audit) the devfleet referee's pinned
# checkout.
#
# ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
# The mesh referee deliberately runs from a PINNED detached checkout so the
# judging code cannot be mutated mid-cycle by the lanes it judges. That pin is
# correct. What was missing was any way to advance it: on 2026-08-23 the cron
# gate ran six commits behind main for hours, judging with a known false
# negative that had already been fixed on main, and the only "refresh"
# mechanism in evidence was a hand-made sequence of checkout/ checkout-v2/
# checkout-v3 directories with the crontab edited to match. Versioned
# directory sprawl is exactly what this repo forbids, and it left the running
# gate's identity untraceable.
#
# So: one canonical path, advanced by an explicit auditable command, plus a
# --check mode that makes "the referee is stale" a detectable condition
# instead of something discovered by reading a log by hand.
#
# The refresh is NOT automatic and must never become automatic. A referee that
# silently tracks main is no longer a referee.
#
# Usage:
#   referee_refresh.sh --check          report pinned vs origin/main; rc=1 if stale
#   referee_refresh.sh [--to <ref>]     rebuild the canonical checkout (default origin/main)
#
# Environment (all defaulted; overridden only by tests):
#   REFEREE_BASE   parent dir holding the canonical checkout
#   REFEREE_LOCK   flock path shared with the mesh gate and fleet_sync
#   REFEREE_SOURCE local repo to clone from (hardlinked objects, no network)
#
# This script never starts, stops, signals, or reads a node, never touches a
# datadir, and never pushes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SOURCE="$(cd "$SCRIPT_DIR/../.." && pwd)"

REFEREE_BASE="${REFEREE_BASE:-$HOME/.local/state/zclassic23-referee}"
REFEREE_LOCK="${REFEREE_LOCK:-$HOME/.local/state/zclassic23-fleetsync/node1.lock}"
REFEREE_SOURCE="${REFEREE_SOURCE:-$DEFAULT_SOURCE}"
CANONICAL="$REFEREE_BASE/checkout"
LOCK_WAIT="${REFEREE_LOCK_WAIT:-900}"

MODE=refresh
TARGET=origin/main
while [ $# -gt 0 ]; do
    case "$1" in
        --check) MODE=check ;;
        --to) shift; [ $# -gt 0 ] || { echo "referee_refresh: --to needs a ref" >&2; exit 2; }; TARGET="$1" ;;
        -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "referee_refresh: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

log() { printf '%s referee_refresh: %s\n' "$(date -u +%FT%TZ)" "$*"; }

pinned_sha() {
    [ -d "$CANONICAL/.git" ] || return 1
    git -C "$CANONICAL" rev-parse HEAD 2>/dev/null
}

# --check: is the pinned judge still current with main? Fail-closed: an absent
# or unreadable checkout is stale, not "fine".
if [ "$MODE" = check ]; then
    if ! have="$(pinned_sha)"; then
        log "STALE: no canonical checkout at $CANONICAL"
        exit 1
    fi
    if ! git -C "$REFEREE_SOURCE" fetch origin main --quiet 2>/dev/null; then
        log "UNKNOWN: could not fetch origin/main from $REFEREE_SOURCE"
        exit 2
    fi
    want="$(git -C "$REFEREE_SOURCE" rev-parse origin/main)"
    if [ "$have" = "$want" ]; then
        log "CURRENT: referee pinned at ${have:0:9} == origin/main"
        exit 0
    fi
    behind=UNKNOWN
    if git -C "$REFEREE_SOURCE" cat-file -e "$have^{commit}" 2>/dev/null; then
        behind="$(git -C "$REFEREE_SOURCE" rev-list --count "$have..$want" 2>/dev/null || echo UNKNOWN)"
    fi
    log "STALE: referee pinned at ${have:0:9}, origin/main ${want:0:9}, behind=$behind"
    log "advance it with: tools/scripts/referee_refresh.sh"
    exit 1
fi

# ── refresh ────────────────────────────────────────────────────────────────
mkdir -p "$REFEREE_BASE" "$(dirname "$REFEREE_LOCK")"
STAGING="$CANONICAL.new"
rm -rf "$STAGING"

log "staging a fresh checkout from $REFEREE_SOURCE"
git clone --quiet "$REFEREE_SOURCE" "$STAGING"

# Point the staged clone at the true upstream so its own `git fetch origin
# main` observes the real blackboard rather than this box's working copy.
if upstream="$(git -C "$REFEREE_SOURCE" remote get-url origin 2>/dev/null)"; then
    git -C "$STAGING" remote set-url origin "$upstream"
fi
git -C "$STAGING" fetch origin main --quiet

if ! git -C "$STAGING" rev-parse --verify --quiet "$TARGET^{commit}" >/dev/null; then
    rm -rf "$STAGING"
    echo "referee_refresh: target ref not found: $TARGET" >&2
    exit 2
fi
git -C "$STAGING" checkout --detach "$TARGET" --quiet
staged="$(git -C "$STAGING" rev-parse HEAD)"
log "staged at ${staged:0:9} ($TARGET)"

# The gate reads its own script incrementally as bash executes it. Swapping the
# tree under a live cycle is how you get a half-old half-new judge, so take the
# same lock the cycle takes and swap only when no cycle can be running.
exec 9>"$REFEREE_LOCK"
log "waiting up to ${LOCK_WAIT}s for the fleet lock"
if ! flock -w "$LOCK_WAIT" 9; then
    rm -rf "$STAGING"
    log "REFUSED: fleet lock busy after ${LOCK_WAIT}s; checkout unchanged"
    exit 1
fi

previous=""
if previous="$(pinned_sha)"; then :; else previous=""; fi
retired=""
if [ -d "$CANONICAL" ]; then
    retired="$CANONICAL.retired-$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$CANONICAL" "$retired"
fi
mv "$STAGING" "$CANONICAL"
now="$(pinned_sha)"
exec 9>&-

log "referee advanced ${previous:0:9}${previous:+ -> }${now:0:9}"

# Keep exactly one rollback copy; these are ~1.2G each.
mapfile -t old < <(find "$REFEREE_BASE" -maxdepth 1 -name 'checkout.retired-*' -printf '%f\n' 2>/dev/null | sort)
keep="${retired##*/}"
for d in "${old[@]}"; do
    [ "$d" = "$keep" ] && continue
    log "pruning stale rollback copy $d"
    rm -rf "${REFEREE_BASE:?}/$d"
done
[ -n "$retired" ] && log "rollback copy retained at ${retired##*/}"
exit 0
