#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# promote-shielded-copy-prove.sh — copy-prove harness for the FAST-CURE
# "promote" path (Lane C of the fast-cure driver work, 2026-07-17): prove
# that a finished PRODUCER datadir's already-folded complete shielded
# history (Sprout frontiers + the Sapling/Sprout nullifier set) can be
# PROMOTED into a fresh copy of a target datadir via a single terminal boot
# verb, -promote-shielded-history=<producer-datadir>, without ever writing
# to the producer or to any live datadir.
#
# This is a sibling of tools/scripts/cure-copy-prove.sh (the sovereign
# producer/BUNDLE cure, gated on an exported consensus-state-bundle +
# independent replay receipt) and of tools/scripts/import-copy-prove.sh
# (the operational IMPORT path, which re-derives shielded history from a
# live zclassicd chainstate LevelDB — CPU-bound, "many minutes" per that
# script's own runtime notes). This script proves a THIRD path: transplant
# already-folded shielded-history tables directly from one zclassic23
# producer datadir (e.g. a zclassic23-mint3-style full fold) into a target
# copy — no zclassicd, no from-genesis nullifier/anchor re-derivation.
#
# MANUAL-ONLY: not wired to any Makefile target, `make test`/`make
# test-parallel`, or CI. This is an operator-run copy-prove harness for the
# sovereign shielded-state cure (see CLAUDE.md "Tenacity & recovery" +
# docs/HANDOFF.md §0-LATEST for current live state; cure design/spine:
# docs/work/self-verified-tip-plan.md). Run it by hand:
#   tools/scripts/promote-shielded-copy-prove.sh --dry-run \
#     --producer=$HOME/.zclassic-c23-mint3-COPY-<ts>
# then for real (adds --expect-climb-past=H, drops --dry-run) once the plan
# looks right. Never point --producer or --copy-dir at a live datadir — see
# the safety invariants below, enforced by the script itself.
#
# ============================================================================
# STATUS (2026-07-19): -promote-shielded-history LANDED
# ============================================================================
# The DEPENDENCY NOTICE below described a state (2026-07-17, this script's
# original commit) where the flag/service this script drives did not exist
# yet anywhere on a local branch. That gap closed the same day, commit
# 3c316a452 "feat(cure): verified shielded-history promote into a wedged
# COPY datadir" — config/src/boot_promote_shielded_history.c,
# app/services/src/shielded_history_promote_service.c, and
# lib/test/src/test_shielded_history_promote.c are all present at HEAD.
# The success banner this script matches by default
# (PROMOTE_OK_REGEX='^PROMOTED: -promote-shielded-history:') was verified
# against config/src/boot_promote_shielded_history.c's actual fprintf
# literal ("PROMOTED: -promote-shielded-history: %s -> %s installed ...")
# — no override needed. This script is live-functional, not aspirational;
# the DEPENDENCY NOTICE below is kept verbatim as the historical record of
# the fail-closed design (PROMOTE_OK_REGEX stays overridable regardless, in
# case the banner literal ever changes) but its "does NOT exist" claim is
# STALE — read this STATUS block first.
# ============================================================================
#
# ============================================================================
# DEPENDENCY NOTICE (historical, as of 2026-07-17 — see STATUS above)
# ============================================================================
# As of this writing, -promote-shielded-history does NOT exist on any local
# branch (verified via `git grep` across every refs/heads/* branch, no match
# for "promote-shielded-history" or "promote_shielded_history"). What DOES
# exist, landed by a sibling lane building toward the same mechanism:
#   - app/services/include/services/shielded_history_body_crosscheck.h: a
#     read-only local-body witness that re-derives Sprout frontiers + the
#     nullifier set from PoW/merkle-verified block bodies and compares them
#     against a producer's tables — its header comment explicitly says it
#     feeds "shielded_history_promote_service.h ... the installer that
#     consumes this result (gates G3/G3b/G4)", i.e. the very flag this
#     script drives.
#   - That promote SERVICE header/implementation, and therefore the exact
#     argv flag name and its stdout success-banner literal, do not exist in
#     the repo yet as of this commit — lane/fast-cure-promote and
#     lane/fast-cure-crosscheck are building it concurrently with this
#     script in sibling worktrees.
# The argv loop silently ignores unknown flags (see docs/HANDOFF.md /
# CLAUDE.md), so running this script for real against a build that predates
# the flag will NOT crash — it will boot normally, and phase 1 below FAILS
# closed because the required banner never appears (never a false PASS from
# a bare exit 0). PROMOTE_OK_REGEX is deliberately overridable via the
# environment so this script keeps working the moment the flag lands,
# without an edit:
#   PROMOTE_OK_REGEX='^PROMOTED: -promote-shielded-history:' \
#     tools/scripts/promote-shielded-copy-prove.sh ...
# ============================================================================
#
# Safety invariants (same class as cure-copy-prove.sh / import-copy-prove.sh
# / app/controllers/src/agent_copy_prove_controller.c cp_path_safety_ok()):
#   - --producer is a READ-ONLY input: this script never writes into it, in
#     dry-run or real mode. It must itself already be a throwaway COPY of
#     the real producer (never point this at a live producer directly) —
#     refuses unless the path contains the literal "-COPY-" marker AND does
#     not exactly equal one of the known live/protected producer or
#     canonical datadir names ($HOME/.zclassic-c23, $HOME/.zclassic-c23-mint,
#     $HOME/.zclassic-c23-mint3, $HOME/.zclassic).
#   - --copy-dir (or its generated default) must contain the literal
#     "/.zclassic-c23-COPY-" marker, must not equal a known live/protected
#     datadir, and must not already exist — mirrors cure-copy-prove.sh
#     exactly.
#   - --dry-run prints the exact plan (including the promote invocation) and
#     exits 0 without touching disk or launching a process.
#
# Usage:
#   tools/scripts/promote-shielded-copy-prove.sh [--dry-run] \
#     --producer=PATH_TO_FINISHED_PRODUCER_COPY_DATADIR \
#     [--src=DIR]                 (default: $HOME/.zclassic-c23)
#     [--copy-dir=DIR]            (default: $HOME/.zclassic-c23-COPY-<ts>-promote)
#     [--expect-climb-past=H]     (required unless --dry-run)
#     [--deadline=SECS]           (default 3600)
#     [--rpcport=N] [--p2p-port=N] [--fs-port=N] [--https-port=N]
#
# Exit codes: 0 PASS, 1 FAIL (promote gate not cleared), 2 usage/precondition
# error.
#
# What it does NOT do: write into --producer, write into --src beyond a
# read-only `cp -a` source, set ZCL_DEPLOY_ALLOW_CANONICAL, restart/stop any
# systemd unit, or delete anything outside its own --copy-dir.
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"

# See the DEPENDENCY NOTICE above — override without editing this file.
PROMOTE_OK_REGEX="${PROMOTE_OK_REGEX:-^PROMOTED: -promote-shielded-history:}"

PRODUCER=""
SRC="$HOME/.zclassic-c23"
COPY_DIR=""
EXPECT_CLIMB_PAST=""
DEADLINE=3600
RPCPORT=18599
P2PPORT=19233
FSPORT=19234
HTTPSPORT=19235
DRY_RUN=0

usage() {
    sed -n '2,85p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)              DRY_RUN=1 ;;
        --producer=*)            PRODUCER="${1#--producer=}" ;;
        --src=*)                 SRC="${1#--src=}" ;;
        --copy-dir=*)            COPY_DIR="${1#--copy-dir=}" ;;
        --expect-climb-past=*)   EXPECT_CLIMB_PAST="${1#--expect-climb-past=}" ;;
        --deadline=*)            DEADLINE="${1#--deadline=}" ;;
        --rpcport=*)             RPCPORT="${1#--rpcport=}" ;;
        --p2p-port=*)            P2PPORT="${1#--p2p-port=}" ;;
        --fs-port=*)             FSPORT="${1#--fs-port=}" ;;
        --https-port=*)          HTTPSPORT="${1#--https-port=}" ;;
        -h|--help)               usage; exit 0 ;;
        *) echo "promote-shielded-copy-prove: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ── validation ──────────────────────────────────────────────────────────

[ -n "$PRODUCER" ] || { echo "promote-shielded-copy-prove: --producer=PATH is required" >&2; exit 2; }

# Producer safety invariant: must itself be a throwaway copy, never the real
# producer or any live/canonical datadir. The producer is a READ-ONLY input —
# it is never the cp -a target and this script never writes into it.
case "$PRODUCER" in
    *-COPY-*) : ;;
    *) echo "promote-shielded-copy-prove: REFUSED — --producer must contain the '-COPY-' marker (pass a COPY of the producer, never the producer itself): $PRODUCER" >&2
       exit 2 ;;
esac
for live in "$HOME/.zclassic-c23" "$HOME/.zclassic-c23-mint" "$HOME/.zclassic-c23-mint3" "$HOME/.zclassic"; do
    if [ "$PRODUCER" = "$live" ]; then
        echo "promote-shielded-copy-prove: REFUSED — --producer aliases a known live/protected datadir: $PRODUCER" >&2
        exit 2
    fi
done

[ -d "$PRODUCER" ] || { echo "promote-shielded-copy-prove: producer datadir not found: $PRODUCER" >&2; exit 2; }
[ -d "$SRC" ]      || { echo "promote-shielded-copy-prove: source datadir not found: $SRC" >&2; exit 2; }

if [ -z "$COPY_DIR" ]; then
    COPY_DIR="$HOME/.zclassic-c23-COPY-$(date +%Y%m%d%H%M%S)-promote"
fi

# Copy-target safety invariant: never a live datadir, always the throwaway
# marker — same rule as cure-copy-prove.sh / agent_copy_prove_controller.c
# cp_path_safety_ok().
case "$COPY_DIR" in
    *"/.zclassic-c23-COPY-"*) : ;;
    *) echo "promote-shielded-copy-prove: REFUSED — --copy-dir must contain the '/.zclassic-c23-COPY-' marker: $COPY_DIR" >&2
       exit 2 ;;
esac
for live in "$HOME/.zclassic-c23" "$HOME/.zclassic-c23-dev" "$HOME/.zclassic-c23-soak" \
            "$HOME/.zclassic-c23-mint" "$HOME/.zclassic-c23-mint3" "$HOME/.zclassic-c23-mint-receipt" "$HOME/.zclassic"; do
    if [ "$COPY_DIR" = "$live" ]; then
        echo "promote-shielded-copy-prove: REFUSED — --copy-dir aliases a known live/protected datadir: $COPY_DIR" >&2
        exit 2
    fi
done
if [ "$COPY_DIR" = "$PRODUCER" ]; then
    echo "promote-shielded-copy-prove: REFUSED — --copy-dir must not equal --producer: $COPY_DIR" >&2
    exit 2
fi
if [ -e "$COPY_DIR" ]; then
    echo "promote-shielded-copy-prove: REFUSED — --copy-dir already exists, refusing to overwrite: $COPY_DIR" >&2
    exit 2
fi

if [ "$DRY_RUN" = "0" ]; then
    case "$EXPECT_CLIMB_PAST" in
        ""|*[!0-9]*)
            echo "promote-shielded-copy-prove: --expect-climb-past=H (non-negative integer) is required unless --dry-run" >&2
            exit 2 ;;
    esac
    [ -x "$NODE_BIN" ] || { echo "promote-shielded-copy-prove: $NODE_BIN not built (run make build-only)" >&2; exit 2; }
    [ -x "$RPC_BIN" ]  || { echo "promote-shielded-copy-prove: $RPC_BIN not built (run make zcl-rpc)" >&2; exit 2; }
fi

# ── plan (always printed) ──────────────────────────────────────────────

echo "======================================================================"
echo "  promote-shielded-copy-prove plan"
echo "  producer (read-only input):      $PRODUCER"
echo "  src (cp -a from):                $SRC"
echo "  copy_dir (cp -a to, must not pre-exist): $COPY_DIR"
echo "  expect_climb_past:               ${EXPECT_CLIMB_PAST:-<none, dry-run only>}"
echo "  deadline_secs:                   $DEADLINE"
echo "  node_bin:                        $NODE_BIN"
echo "  promote_ok_regex:                $PROMOTE_OK_REGEX"
echo "  ports:                            rpc=$RPCPORT p2p=$P2PPORT fs=$FSPORT https=$HTTPSPORT"
echo "  steps:"
echo "    1. cp -a \"$SRC\" \"$COPY_DIR\""
echo "    2. \"$NODE_BIN\" -datadir=\"$COPY_DIR\" -promote-shielded-history=\"$PRODUCER\""
echo "       (terminal; require exit 0 AND stdout matching /$PROMOTE_OK_REGEX/ —"
echo "       see the DEPENDENCY NOTICE at the top of this script if this flag"
echo "       does not exist yet on this build)"
echo "    2b. clear any stale \$COPY_DIR/auto_reindex_request left over from the"
echo "       copied source datadir — never let the proving boot silently"
echo "       detour into -reindex-chainstate instead of exercising the promote"
echo "    3. \"$NODE_BIN\" -datadir=\"$COPY_DIR\" -rpcport=$RPCPORT -port=$P2PPORT"
echo "       -connect=127.0.0.1:39999 -nolegacyimport -nofilesync (isolated boot)"
echo "    4. poll getblockcount + dumpstate reducer_frontier until"
echo "       height > $EXPECT_CLIMB_PAST or deadline"
echo "    5. print PASS/FAIL with full evidence; kill the copy's node"
echo "  does NOT do: write into --producer (read-only input, never the cp -a"
echo "  target), touch --src beyond the read-only cp -a source, set"
echo "  ZCL_DEPLOY_ALLOW_CANONICAL, restart/stop any systemd unit, or delete"
echo "  anything outside --copy-dir."
echo "======================================================================"

if [ "$DRY_RUN" = "1" ]; then
    echo "[promote-shielded-copy-prove] --dry-run: no filesystem or process action taken."
    exit 0
fi

RUN_START_EPOCH=$(date +%s)

# ── step 1: copy ────────────────────────────────────────────────────────

echo "[promote-shielded-copy-prove] cp -a $SRC -> $COPY_DIR"
cp -a "$SRC" "$COPY_DIR"
rm -f "$COPY_DIR"/*.pid "$COPY_DIR"/.lock 2>/dev/null || true

cleanup() {
    if [ -n "${NODE_PID:-}" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -TERM "$NODE_PID" 2>/dev/null || true
        sleep 2
        kill -KILL "$NODE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

ISO_HOME="$COPY_DIR/.isolated-home"
mkdir -p "$ISO_HOME"
[ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

NODE_ISO_ARGS="-fsport=$FSPORT -httpsport=$HTTPSPORT -connect=127.0.0.1:39999 -nolegacyimport -nofilesync"

# ── step 2: terminal promote call (phase 1) ────────────────────────────

PROMOTE_LOG="$COPY_DIR/promote_shielded_history.log"
echo "[promote-shielded-copy-prove] phase 1: terminal -promote-shielded-history=$PRODUCER (timeout ${DEADLINE}s)"
promote_rc=0
if command -v timeout >/dev/null 2>&1; then
    HOME="$ISO_HOME" timeout "${DEADLINE}s" \
        "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
        $NODE_ISO_ARGS -promote-shielded-history="$PRODUCER" \
        > "$PROMOTE_LOG" 2>&1 || promote_rc=$?
else
    HOME="$ISO_HOME" \
        "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
        $NODE_ISO_ARGS -promote-shielded-history="$PRODUCER" \
        > "$PROMOTE_LOG" 2>&1 || promote_rc=$?
fi

if [ "$promote_rc" != "0" ] || ! grep -aqE "$PROMOTE_OK_REGEX" "$PROMOTE_LOG"; then
    echo "======================================================================"
    echo "  promote-shielded-copy-prove VERDICT: FAIL"
    echo "  copy:    $COPY_DIR"
    echo "  reason:  terminal -promote-shielded-history did not match"
    echo "           /$PROMOTE_OK_REGEX/ (exit=$promote_rc). Inspect $PROMOTE_LOG."
    echo "           Nothing further was booted."
    echo "  NOTE:    if $PROMOTE_LOG shows no mention of -promote-shielded-history"
    echo "           at all, the promote service is not yet merged on this build"
    echo "           (see the DEPENDENCY NOTICE at the top of this script) — the"
    echo "           argv loop silently ignores unknown flags, so an unimplemented"
    echo "           flag looks like a normal (unpromoted) boot, not a crash; this"
    echo "           is exactly why phase 1 requires the explicit banner regex"
    echo "           instead of trusting a plain exit 0."
    echo "======================================================================"
    exit 1
fi
echo "[promote-shielded-copy-prove] promote matched /$PROMOTE_OK_REGEX/ — booting normally to prove H* CLIMB"

# ── step 2b: clear any stale auto_reindex_request ──────────────────────
# The copy was cp -a'd from --src; if that datadir had ever armed a
# self-rebuild request (config/src/boot_crashonly.c
# boot_crashonly_consume_reindex_request(), storage/boot_auto_reindex.h) the
# sentinel file <datadir>/auto_reindex_request rides along in the copy. The
# terminal -promote-shielded-history argv path returns before the normal
# boot sequence ever runs, so phase 1 above does NOT consume or clear it —
# left in place, the very next normal boot (phase 2, right below) would
# silently detour into -reindex-chainstate instead of exercising the state
# this harness just promoted (same reasoning tools/scripts/import-copy-prove.sh
# applies at its own step 3b). Clear it unconditionally here.
if [ -e "$COPY_DIR/auto_reindex_request" ]; then
    echo "[promote-shielded-copy-prove] step 2b: stale auto_reindex_request found in the copy — clearing before boot"
    rm -f "$COPY_DIR/auto_reindex_request"
else
    echo "[promote-shielded-copy-prove] step 2b: no stale auto_reindex_request present — nothing to clear"
fi

# ── step 3: normal boot (phase 2) ──────────────────────────────────────

HOME="$ISO_HOME" ZCL_MIRROR_SYNC=0 \
"$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
    $NODE_ISO_ARGS \
    > "$COPY_DIR/promote_node.log" 2>&1 &
NODE_PID=$!

rpc() { HOME="$ISO_HOME" ZCL_DATADIR="$COPY_DIR" ZCL_RPCPORT="$RPCPORT" "$RPC_BIN" "$@" 2>/dev/null || true; }
tip() {
    resp="$(rpc getblockcount)"
    printf '%s\n' "$resp" |
        sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1
}

# ── step 4: poll for H* CLIMB ───────────────────────────────────────────

deadline_epoch=$(( $(date +%s) + DEADLINE ))
max_tip=-1
first_tip=-1
climbed_past=0
cookie="$COPY_DIR/.cookie"
while [ "$(date +%s)" -lt "$deadline_epoch" ]; do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "[promote-shielded-copy-prove] node exited early (see $COPY_DIR/promote_node.log)"
        break
    fi
    if [ -f "$cookie" ]; then
        t="$(tip)"; t="${t:--1}"
        if [ "$t" -ge 0 ] 2>/dev/null; then
            [ "$first_tip" -lt 0 ] && first_tip="$t" && echo "[promote-shielded-copy-prove] first tip: $t"
            [ "$t" -gt "$max_tip" ] && max_tip="$t"
            if [ "$t" -gt "$EXPECT_CLIMB_PAST" ] 2>/dev/null; then
                climbed_past=1
                echo "[promote-shielded-copy-prove] H* CLIMBED to $t (> $EXPECT_CLIMB_PAST)"
                break
            fi
        fi
    fi
    sleep 5
done

# ── coins_applied continuity ────────────────────────────────────────────

frontier_json="$(rpc dumpstate '"reducer_frontier"')"
coins_applied="$(printf '%s' "$frontier_json" | sed -n 's/.*"coins_applied_height":\([0-9-]*\).*/\1/p' | head -1)"
hstar_now="$(printf '%s' "$frontier_json" | sed -n 's/.*"hstar":\([0-9-]*\).*/\1/p' | head -1)"
continuity_ok=0
if [ -n "${coins_applied:-}" ] && [ -n "${hstar_now:-}" ] && \
   [ "$coins_applied" = "$((hstar_now + 1))" ] 2>/dev/null; then
    continuity_ok=1
fi

DURATION_SECS=$(( $(date +%s) - RUN_START_EPOCH ))

echo "======================================================================"
if [ "$climbed_past" = "1" ] && [ "$continuity_ok" = "1" ]; then
    verdict="PASS"
    rc=0
else
    verdict="FAIL"
    rc=1
fi
echo "  promote-shielded-copy-prove VERDICT: $verdict"
echo "  copy:                   $COPY_DIR"
echo "  producer:                $PRODUCER"
echo "  first_tip:               $first_tip"
echo "  max_tip:                 $max_tip"
echo "  expect_climb_past:       $EXPECT_CLIMB_PAST"
echo "  PROMOTE.1 climbed_past:  $climbed_past"
echo "  PROMOTE.2 coins_applied: $coins_applied (hstar=$hstar_now, want coins_applied==hstar+1) ok=$continuity_ok"
echo "  duration_secs:           $DURATION_SECS"
echo "  promote_log:             $PROMOTE_LOG"
echo "  node_log:                $COPY_DIR/promote_node.log"
if [ "$verdict" = "FAIL" ]; then
    echo "  NOTE: this is a false-green trap if you only look at climbed_past —"
    echo "        both PROMOTE.1 AND PROMOTE.2 are required. Same-height"
    echo "        hash-agreement against zclassicd/mirrors is NOT automated"
    echo "        here (unlike import-copy-prove.sh's GATE (c)) — cross-check"
    echo "        by hand before any live step, or extend this script with"
    echo "        that pattern first."
fi
echo "======================================================================"
exit "$rc"
