#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# import-copy-prove.sh — the ONE canonical copy-prove driver for the
# shielded-state cure family. It proves a cure on a THROWAWAY -COPY- of a
# datadir and gates on H* CLIMB before any live cutover is ever considered —
# never live surgery. Two cure mechanisms, selected by --mode (default
# import); everything else (the -COPY- safety scaffolding, the isolated
# throwaway boot, the H* CLIMB / continuity gates, the fail-closed banner
# discipline) is shared and identical across both:
#
#   --mode=import  (default)  the OPERATIONAL import path — re-derive the
#       complete Sprout+Sapling anchor + nullifier set from a co-located
#       zclassicd chainstate via the terminal boot flag
#         zclassic23 -datadir=COPY -import-complete-shielded=ZCLASSICD-DATADIR
#       This is the NAMED CANONICAL CURE the live node's own remedy machinery
#       points operators at (engine/controllers/src/shielded_gap_remedy_controller.c
#       SGR_REMEDY_COPY_PROVE_STEP hard-codes this script + these flags; keep
#       the bare `--src=... --chainstate-src=...` invocation working). It is
#       self_folded=false BY DESIGN (release_assisted trust, not sovereign),
#       so it does NOT require the coins_kv_self_folded provenance marker the
#       way --mode=bundle does. Full gate set (a)+(b)+(c) below.
#
#   --mode=bundle             the SOVEREIGN producer/BUNDLE cure — install an
#       exported consensus-state bundle plus its independent replay receipt via
#         zclassic23 -datadir=COPY -install-consensus-bundle=BUNDLE
#       (the receipt is placed inside the COPY's own datadir_fd path BEFORE the
#       install so consensus_state_replay_receipt_authority_available() can read
#       it). This is the only mode that proves the SOVEREIGN posture: it gates
#       additionally on the coins_kv_migration_complete + coins_kv_self_folded
#       provenance markers (G-SOV.3).
#
# (A third, `promote`, harness for a -promote-shielded-history flag once
# existed but drove a flag present on NO branch — dead scaffolding, removed in
# the 2026-07 copy-prove consolidation. If that flag ever lands, add a
# `--mode=promote` here rather than a new sibling script.)
#
# ============================================================================
# HEADER-REFRESH STEP (import mode, before phase 1)
# ============================================================================
# A real diagnostic run against a wedged clone found the importer's tip-bind
# refusing with:
#   "tip bind FAILED: best Sapling anchor != expected header hashFinalSaplingRoot
#    at h=3151581 — refusing"
#   "Tip bind: height=3151581 hashFinalSaplingRoot=0000...0000"
# i.e. the clone's own blocks.sapling_root column was ALL-ZERO at the bind
# height because the clone's header chain was stale relative to zclassicd's
# current chainstate tip. Before phase 1 (the -import-complete-shielded call)
# import mode runs the proven read-only two-step recipe's step 1
# (docs/HANDOFF.md "legacy TWO-step recipe"):
#   "$NODE_BIN" --importblockindex "$ZD_DATADIR" "$COPY_DIR/node.db"
# against the COPY's node.db — refreshing the copy's SQLite `blocks` header
# chain (and blocks.sapling_root) from zclassicd's live LevelDB block index,
# read-only, same LOCK-avoidance as the existing recipe. Skippable with
# --skip-header-refresh; on failure the run FAILs (never silently proceeds
# with stale headers into phase 1).
# ============================================================================
#
# ============================================================================
# CONTRACT — read before running this for real
# ============================================================================
# import mode drives the terminal boot flag
#     zclassic23 -datadir=TARGET-COPY -import-complete-shielded=ZCLASSICD-DATADIR
#   The importer reads ZCLASSICD-DATADIR/chainstate via its own FNV-stable
#   point-in-time snapshot (ldb_snapshot_make, manifest-changed retry — mirrors
#   --gen-utxo-snapshot), so it is handed the LIVE zclassicd datadir directly
#   and never a torn image; zclassicd keeps running untouched. On success it
#   prints, to stdout, exactly one line matching
#       ^IMPORT COMPLETE (committed=.*$
#   and exits 0; the node's LOG line additionally carries "boundary=<height>"
#   — the copy's own wedge height, parsed automatically for the H* CLIMB gate
#   (pass --expect-climb-past=H to override, e.g. against a build whose
#   importer does not log boundary=). On any refusal it prints
#       ^IMPORT REFUSED .*$
#   and exits nonzero (wedge intact, both cursors stay positive).
# bundle mode drives
#     zclassic23 -datadir=TARGET-COPY -install-consensus-bundle=BUNDLE
#   and requires the exact banner ^INSTALLED: -install-consensus-bundle: + exit 0.
# BOTH modes ENFORCE THE EXACT BANNER: the argv loop silently ignores unknown
# flags, so an unmerged flag looks like a normal (still-wedged) boot rather
# than a crash — a plain exit-0 is NEVER trusted (fail-closed).
# ============================================================================
#
# What import mode proves (design doc section 6):
#   (a) H* CLIMBS past the wedge height and the
#       utxo_apply.anchor_backfill_gap / utxo_apply.nullifier_backfill_gap
#       blockers are both ABSENT from `dumpstate blocker`.
#   (b) coins_applied_height == hstar + 1 (continuity — the reducer is folding
#       forward from the wedge, not skipping/duplicating).
#   (c) EXACT same-height tip-block-hash parity against zclassicd at the wedge
#       height, wedge+1, and the copy's own final tip — the check that
#       actually catches a missing anchor/nullifier: a partial import that
#       wrongly flipped the activation cursor either re-wedges (caught by (a))
#       or, worse, folds a DIFFERENT chain (only (c) catches that).
# This is an operational-readiness proof, not a sovereignty proof: it does NOT
# require coins_kv_self_folded — see design doc section 5. Expect
# `trust_mode: release_assisted` after a real cutover, not `sovereign`.
#
# What bundle mode proves (G-SOV, the sovereign acceptance bar):
#   G-SOV.1 H* CLIMBS past --expect-climb-past.
#   G-SOV.2 coins_applied_height == hstar + 1 (continuity).
#   G-SOV.3 the coins_kv_migration_complete + coins_kv_self_folded provenance
#       markers are both present in progress_meta (the sovereign, self-folded
#       posture — the thing import mode deliberately does NOT claim).
#   Item 4 of the runbook's bar (hash-agreement vs zclassicd/mirrors) is NOT
#   automated in bundle mode; cross-check by hand before any live step, or run
#   --mode=import (which automates it as gate (c)).
#
# Safety invariants (identical in both modes):
#   - --copy-dir (or the generated default) MUST contain the literal
#     "/.zclassic-c23-COPY-" marker and MUST NOT equal a known live/protected
#     datadir path — refuses otherwise (mirrors
#     cognition/controllers/src/agent_copy_prove_controller.c's cp_path_safety_ok()).
#   - --copy-dir must not already exist (never silently overwrites/reuses).
#   - the live `~/.zclassic/chainstate` LevelDB is never opened directly (import
#     mode): the importer takes its own FNV-stable point-in-time snapshot
#     before iterating, so a concurrent zclassicd write can never hand it a
#     torn manifest.
#   - zclassicd itself is only ever read (getblockhash / getblockcount over its
#     existing RPC port, or --importblockindex against its LevelDB) — never
#     stopped, restarted, or written to.
#   - the copy is LEFT on disk on exit (pass, fail, or interrupt) for
#     post-mortem inspection; pass --clean-copy to delete it instead (re-checks
#     the -COPY- marker immediately before the rm -rf, no matter how COPY_DIR
#     mutated during the run).
#
# RUNTIME CHARACTERISTICS (import mode, live 2026-07-16 finding): the
# ldb_snapshot_make() step is a hardlink of the immutable SSTs and is
# effectively instant — NOT the bottleneck. What follows it (streaming every
# Sapling/Sprout anchor through the fail-closed incremental-merkle-tree root
# re-check) is CPU-bound (one core pegged) and can run for MANY MINUTES with no
# progress output and no node.db writes yet — do not mistake that silence for a
# hang. --deadline (default 3600s) must stay generous enough to cover it
# end-to-end, including the post-import H* CLIMB poll.
#
# Usage:
#   tools/scripts/import-copy-prove.sh [--mode=import|bundle] [--dry-run] \
#     [--src=DIR]                  (datadir to copy from; default: $HOME/.zclassic-c23)
#     [--copy-dir=DIR]             (default: $HOME/.zclassic-c23-COPY-<ts>-<mode>;
#                                   must contain the "/.zclassic-c23-COPY-" marker)
#     [--expect-climb-past=H]      (import: optional — auto-parsed from the import
#                                   boundary= if omitted; bundle: REQUIRED)
#     [--deadline=SECS]            (default 3600)
#     [--rpcport=N] [--p2p-port=N] [--fs-port=N] [--https-port=N]
#     [--clean-copy]               (delete --copy-dir on exit; default keeps it)
#   import-mode only:
#     [--chainstate-src=DIR]       (default: $HOME/.zclassic/chainstate)
#     [--zclassicd-datadir=DIR]    (default: $HOME/.zclassic — READ ONLY)
#     [--zclassicd-rpcport=N]      (default 8232; read-only getblockhash/count)
#     [--skip-zclassicd-check]     (skip gate (c); marks verdict PASS-INCOMPLETE)
#     [--skip-header-refresh]      (skip the pre-phase-1 --importblockindex refresh)
#     [--tail-peer=HOST:PORT]      (boot with -addnode=HOST:PORT to fetch tail
#                                   block bodies past the copy's own stored
#                                   blocks/, e.g. the live zclassicd P2P port —
#                                   the "turnkey canonical-copy -> tip" boot;
#                                   default is a fully network-isolated boot)
#   bundle-mode only:
#     --bundle=PATH                (the exported consensus-state-bundle sqlite)
#     --receipt=PATH               (the independent consensus_state_replay_receipt)
#
# Exit codes: 0 PASS (or PASS-INCOMPLETE with import --skip-zclassicd-check),
#             1 FAIL, 2 usage/precondition error.
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"

MODE=import
SRC="$HOME/.zclassic-c23"
CHAINSTATE_SRC="$HOME/.zclassic/chainstate"
COPY_DIR=""
EXPECT_CLIMB_PAST=""
DEADLINE=3600
RPCPORT=18399
P2PPORT=19033
FSPORT=19034
HTTPSPORT=19035
ZD_DATADIR="$HOME/.zclassic"
ZD_RPCPORT=8232
SKIP_ZD_CHECK=0
SKIP_HEADER_REFRESH=0
TAIL_PEER=""
CLEAN_COPY=0
BUNDLE=""
RECEIPT=""
DRY_RUN=0

usage() {
    cat <<'USAGE'
import-copy-prove.sh — the one canonical copy-prove driver (--mode=import|bundle).

Common:
  --mode=import|bundle          default import
  --dry-run                     print the plan and touch nothing
  --src=DIR                     datadir to cp -a from (default: $HOME/.zclassic-c23)
  --copy-dir=DIR                throwaway target; must carry the /.zclassic-c23-COPY- marker
  --expect-climb-past=H         import: optional (auto-parsed from boundary=); bundle: REQUIRED
  --deadline=SECS               default 3600
  --rpcport/--p2p-port/--fs-port/--https-port=N
  --clean-copy                  delete --copy-dir on exit (default: keep for post-mortem)

import mode:
  --chainstate-src=DIR          default $HOME/.zclassic/chainstate
  --zclassicd-datadir=DIR       default $HOME/.zclassic (READ ONLY)
  --zclassicd-rpcport=N         default 8232
  --skip-zclassicd-check        skip gate (c) -> verdict PASS-INCOMPLETE
  --skip-header-refresh         skip the pre-phase-1 --importblockindex refresh
  --tail-peer=HOST:PORT         boot -addnode=HOST:PORT for tail bodies (default: isolated)

bundle mode:
  --bundle=PATH                 exported consensus-state bundle sqlite (REQUIRED)
  --receipt=PATH                independent replay receipt (REQUIRED)

Exit: 0 PASS (or import PASS-INCOMPLETE with --skip-zclassicd-check), 1 FAIL, 2 usage.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode=*)                 MODE="${1#--mode=}" ;;
        --dry-run)                DRY_RUN=1 ;;
        --src=*)                  SRC="${1#--src=}" ;;
        --chainstate-src=*)       CHAINSTATE_SRC="${1#--chainstate-src=}" ;;
        --copy-dir=*)             COPY_DIR="${1#--copy-dir=}" ;;
        --expect-climb-past=*)    EXPECT_CLIMB_PAST="${1#--expect-climb-past=}" ;;
        --deadline=*)             DEADLINE="${1#--deadline=}" ;;
        --rpcport=*)              RPCPORT="${1#--rpcport=}" ;;
        --p2p-port=*)             P2PPORT="${1#--p2p-port=}" ;;
        --fs-port=*)              FSPORT="${1#--fs-port=}" ;;
        --https-port=*)           HTTPSPORT="${1#--https-port=}" ;;
        --zclassicd-datadir=*)    ZD_DATADIR="${1#--zclassicd-datadir=}" ;;
        --zclassicd-rpcport=*)    ZD_RPCPORT="${1#--zclassicd-rpcport=}" ;;
        --skip-zclassicd-check)   SKIP_ZD_CHECK=1 ;;
        --skip-header-refresh)    SKIP_HEADER_REFRESH=1 ;;
        --tail-peer=*)            TAIL_PEER="${1#--tail-peer=}" ;;
        --clean-copy)             CLEAN_COPY=1 ;;
        --bundle=*)               BUNDLE="${1#--bundle=}" ;;
        --receipt=*)              RECEIPT="${1#--receipt=}" ;;
        -h|--help)                usage; exit 0 ;;
        *) echo "import-copy-prove: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ── validation ──────────────────────────────────────────────────────────

case "$MODE" in
    import|bundle) : ;;
    *) echo "import-copy-prove: --mode must be 'import' or 'bundle' (got '$MODE')" >&2; exit 2 ;;
esac

if [ -n "$EXPECT_CLIMB_PAST" ]; then
    case "$EXPECT_CLIMB_PAST" in
        ''|*[!0-9]*)
            echo "import-copy-prove: --expect-climb-past=H must be a non-negative integer" >&2
            exit 2 ;;
    esac
fi

if [ "$MODE" = "bundle" ]; then
    [ -n "$BUNDLE" ]  || { echo "import-copy-prove: --bundle=PATH is required in --mode=bundle" >&2; exit 2; }
    [ -n "$RECEIPT" ] || { echo "import-copy-prove: --receipt=PATH is required in --mode=bundle" >&2; exit 2; }
    if [ "$DRY_RUN" = "0" ]; then
        case "$EXPECT_CLIMB_PAST" in
            ""|*[!0-9]*)
                echo "import-copy-prove: --expect-climb-past=H (non-negative integer) is required in --mode=bundle unless --dry-run (there is no boundary= to auto-parse)" >&2
                exit 2 ;;
        esac
        [ -s "$BUNDLE" ]  || { echo "import-copy-prove: bundle not found or empty: $BUNDLE" >&2; exit 2; }
        [ -s "$RECEIPT" ] || { echo "import-copy-prove: receipt not found or empty: $RECEIPT" >&2; exit 2; }
    fi
fi

if [ -z "$COPY_DIR" ]; then
    COPY_DIR="$HOME/.zclassic-c23-COPY-$(date +%Y%m%d%H%M%S)-$MODE"
fi

# Safety invariant: never a live datadir, always the throwaway marker. Same
# rule as cognition/controllers/src/agent_copy_prove_controller.c cp_path_safety_ok().
case "$COPY_DIR" in
    *"/.zclassic-c23-COPY-"*) : ;;
    *) echo "import-copy-prove: REFUSED — --copy-dir must contain the '/.zclassic-c23-COPY-' marker: $COPY_DIR" >&2
       exit 2 ;;
esac
for live in "$HOME/.zclassic-c23" "$HOME/.zclassic-c23-dev" "$HOME/.zclassic-c23-soak" \
            "$HOME/.zclassic-c23-mint" "$HOME/.zclassic-c23-mint-receipt" "$HOME/.zclassic"; do
    if [ "$COPY_DIR" = "$live" ]; then
        echo "import-copy-prove: REFUSED — --copy-dir aliases a known live/protected datadir: $COPY_DIR" >&2
        exit 2
    fi
done
if [ -e "$COPY_DIR" ]; then
    echo "import-copy-prove: REFUSED — --copy-dir already exists, refusing to overwrite: $COPY_DIR" >&2
    exit 2
fi

if [ "$DRY_RUN" = "0" ]; then
    [ -d "$SRC" ] || { echo "import-copy-prove: source datadir not found: $SRC" >&2; exit 2; }
    [ -x "$NODE_BIN" ] || { echo "import-copy-prove: $NODE_BIN not built (run make build-only)" >&2; exit 2; }
    [ -x "$RPC_BIN" ]  || { echo "import-copy-prove: $RPC_BIN not built (run make zcl-rpc)" >&2; exit 2; }
    if [ "$MODE" = "import" ]; then
        [ -d "$CHAINSTATE_SRC" ] || { echo "import-copy-prove: chainstate source not found: $CHAINSTATE_SRC" >&2; exit 2; }
        if [ "$SKIP_ZD_CHECK" = "0" ]; then
            [ -d "$ZD_DATADIR" ] || { echo "import-copy-prove: --zclassicd-datadir not found: $ZD_DATADIR (or pass --skip-zclassicd-check)" >&2; exit 2; }
        fi
    fi
fi

# ── plan (always printed) ──────────────────────────────────────────────

echo "======================================================================"
echo "  import-copy-prove plan  (mode=$MODE)"
echo "  src (cp -a from):              $SRC"
echo "  copy_dir (must not pre-exist): $COPY_DIR"
echo "  expect_climb_past:             ${EXPECT_CLIMB_PAST:-$([ "$MODE" = "import" ] && echo '<auto-parsed from the import boundary=>' || echo '<none>')}"
echo "  deadline_secs:                 $DEADLINE"
echo "  node_bin:                      $NODE_BIN"
echo "  ports:                         rpc=$RPCPORT p2p=$P2PPORT fs=$FSPORT https=$HTTPSPORT"
echo "  cleanup:                       $([ "$CLEAN_COPY" = "1" ] && echo '--clean-copy: copy ALWAYS deleted on exit (pass, fail, or interrupt)' || echo 'copy LEFT on disk for inspection (pass --clean-copy to delete)')"
if [ "$MODE" = "import" ]; then
    echo "  chainstate_src (importer FNV-snapshots it): $CHAINSTATE_SRC"
    echo "  zclassicd cross-check:         $([ "$SKIP_ZD_CHECK" = "1" ] && echo 'SKIPPED (--skip-zclassicd-check; verdict PASS-INCOMPLETE at best)' || echo "datadir=$ZD_DATADIR rpcport=$ZD_RPCPORT (read-only RPC only)")"
    echo "  header refresh:                $([ "$SKIP_HEADER_REFRESH" = "1" ] && echo 'SKIPPED (--skip-header-refresh)' || echo 'ON (default) — fails the run on error, never proceeds with stale headers')"
    echo "  tail peer:                     $([ -n "$TAIL_PEER" ] && echo "-addnode=$TAIL_PEER (fetch tail bodies -> tip)" || echo 'none (fully network-isolated boot)')"
    echo "  steps:"
    echo "    1. cp -a \"\$SRC\" \"\$COPY_DIR\"  (throwaway wedged target datadir)"
    echo "    1b. header refresh (unless --skip-header-refresh):"
    echo "       \"\$NODE_BIN\" --importblockindex \"\$ZD_DATADIR\" \"\$COPY_DIR/node.db\""
    echo "    2. \"\$NODE_BIN\" -datadir=\"\$COPY_DIR\" -import-complete-shielded=\"\$ZD_DATADIR\""
    echo "       (terminal; require 'IMPORT COMPLETE (committed=' + exit 0; boundary= parsed for the gate)"
    echo "    3b. clear any stale \$COPY_DIR/auto_reindex_request before the proving boot"
    echo "    4. isolated boot$([ -n "$TAIL_PEER" ] && echo " (+ -addnode=$TAIL_PEER for tail bodies)")"
    echo "    5. GATE (a): H* climb past the wedge + both backfill-gap blockers absent"
    echo "    6. GATE (b): coins_applied_height == hstar + 1"
    echo "    7. GATE (c): getblockhash parity vs zclassicd at wedge / wedge+1 / final tip"
    echo "       (unless --skip-zclassicd-check)"
else
    echo "  bundle:                        $BUNDLE"
    echo "  receipt:                       $RECEIPT"
    echo "  steps:"
    echo "    1. cp -a \"\$SRC\" \"\$COPY_DIR\""
    echo "    2. cp \"\$RECEIPT\" \"\$COPY_DIR/consensus_state_replay_receipt.v1\" (read through the copy's own datadir_fd)"
    echo "    3. \"\$NODE_BIN\" -datadir=\"\$COPY_DIR\" -install-consensus-bundle=\"\$BUNDLE\""
    echo "       (terminal; require 'INSTALLED: -install-consensus-bundle:' + exit 0)"
    echo "    3b. clear any stale \$COPY_DIR/auto_reindex_request before the proving boot"
    echo "    4. isolated boot"
    echo "    5. G-SOV.1 H* climb past \$EXPECT_CLIMB_PAST"
    echo "    6. G-SOV.2 coins_applied_height == hstar + 1"
    echo "    7. G-SOV.3 coins_kv_migration_complete + coins_kv_self_folded present"
fi
echo "  does NOT do: set ZCL_DEPLOY_ALLOW_CANONICAL, restart/stop any systemd"
echo "  unit, write to --src beyond the read-only cp -a, or delete anything"
echo "  outside --copy-dir."
echo "======================================================================"

if [ "$DRY_RUN" = "1" ]; then
    echo "[import-copy-prove] --dry-run: no filesystem or process action taken."
    exit 0
fi

RUN_START_EPOCH=$(date +%s)

# ── step 1: copy the datadir ────────────────────────────────────────────

echo "[import-copy-prove] cp -a $SRC -> $COPY_DIR"
cp -a "$SRC" "$COPY_DIR"
rm -f "$COPY_DIR"/*.pid "$COPY_DIR"/.lock 2>/dev/null || true

cleanup() {
    if [ -n "${NODE_PID:-}" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -TERM "$NODE_PID" 2>/dev/null || true
        # A proven copy is the object an operator promotes.  Give it the same
        # five-minute WAL/checkpoint drain budget as the canonical service;
        # the old two-second grace always converted a green proof into a
        # forced-unclean artifact and made the next HDD boot repeat a full
        # integrity recovery.
        shutdown_wait=0
        while kill -0 "$NODE_PID" 2>/dev/null && [ "$shutdown_wait" -lt 300 ]; do
            sleep 1
            shutdown_wait=$((shutdown_wait + 1))
        done
        if kill -0 "$NODE_PID" 2>/dev/null; then
            echo "[import-copy-prove] cleanup: graceful shutdown exceeded 300s — forcing PID $NODE_PID" >&2
            kill -KILL "$NODE_PID" 2>/dev/null || true
        else
            echo "[import-copy-prove] cleanup: graceful node shutdown complete"
        fi
        wait "$NODE_PID" 2>/dev/null || true
    fi
    if [ "$CLEAN_COPY" = "1" ] && [ -e "$COPY_DIR" ]; then
        # Re-assert the safety invariant right before an rm -rf: never delete
        # anything that does not carry the throwaway marker, no matter how
        # COPY_DIR got mutated during the run.
        case "$COPY_DIR" in
            *"/.zclassic-c23-COPY-"*)
                echo "[import-copy-prove] cleanup: rm -rf $COPY_DIR (--clean-copy)"
                rm -rf "$COPY_DIR"
                ;;
            *)
                echo "[import-copy-prove] cleanup: REFUSING to rm -rf $COPY_DIR — lost the '-COPY-' marker, leaving it in place for manual review" >&2
                ;;
        esac
    fi
}
trap cleanup EXIT INT TERM

ISO_HOME="$COPY_DIR/.isolated-home"
mkdir -p "$ISO_HOME"
[ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

# The proving boot is fully isolated by default (-connect to a dead loopback
# port so nothing outbound resolves); import mode with --tail-peer instead
# adds that one outbound peer to fetch tail block bodies toward tip.
if [ "$MODE" = "import" ] && [ -n "$TAIL_PEER" ]; then
    BOOT_PEER_ARGS="-addnode=$TAIL_PEER"
else
    BOOT_PEER_ARGS="-connect=127.0.0.1:39999"
fi
# The canonical source datadir persists wallet_identity.operator_lane=canonical.
# A throwaway path is still the canonical lane's COPY; booting it as the argv
# default "unknown" makes wallet_identity_ensure() refuse before H* can be
# observed, which defeats the copy proof without protecting anything.  Keep
# the persisted identity stable while the -COPY- path/port guards provide the
# isolation boundary.
NODE_ISO_ARGS="-fsport=$FSPORT -httpsport=$HTTPSPORT $BOOT_PEER_ARGS -operator-lane=canonical -nolegacyimport -nofilesync"

# ── shared rpc helpers ──────────────────────────────────────────────────

rpc() { HOME="$ISO_HOME" ZCL_DATADIR="$COPY_DIR" ZCL_RPCPORT="$RPCPORT" "$RPC_BIN" "$@" 2>/dev/null || true; }
tip() {
    resp="$(rpc getblockcount)"
    printf '%s\n' "$resp" |
        sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1
}

# ── phase 1: the terminal install/import verb (mode-specific) ───────────

if [ "$MODE" = "import" ]; then
    # step 1b: header refresh (default ON, before phase 1). See the
    # HEADER-REFRESH STEP notice at the top of this script.
    if [ "$SKIP_HEADER_REFRESH" = "0" ]; then
        HEADER_REFRESH_LOG="$COPY_DIR/header_refresh.log"
        echo "[import-copy-prove] step 1b: header refresh — $NODE_BIN --importblockindex $ZD_DATADIR $COPY_DIR/node.db"
        href_rc=0
        HOME="$ISO_HOME" "$NODE_BIN" --importblockindex "$ZD_DATADIR" "$COPY_DIR/node.db" \
            > "$HEADER_REFRESH_LOG" 2>&1 || href_rc=$?
        if [ "$href_rc" != "0" ]; then
            echo "======================================================================"
            echo "  import-copy-prove VERDICT: FAIL"
            echo "  copy:    $COPY_DIR"
            echo "  reason:  header-refresh (--importblockindex) failed (exit=$href_rc)."
            echo "           Inspect $HEADER_REFRESH_LOG. Phase 1 (-import-complete-shielded)"
            echo "           was NOT run: proceeding with headers known to be stale risks"
            echo "           reproducing the 2026-07-16 tip-bind refusal"
            echo "           (hashFinalSaplingRoot=0000...0000) rather than exercising a"
            echo "           genuine anchor/nullifier gap. Pass --skip-header-refresh only"
            echo "           if the copy's headers are already known current by other means."
            echo "======================================================================"
            exit 1
        fi
        echo "[import-copy-prove] header refresh done — copy's headers now cover zclassicd's tip"
    else
        echo "[import-copy-prove] step 1b SKIPPED (--skip-header-refresh) — copy's headers are assumed already current"
    fi

    IMPORT_LOG="$COPY_DIR/import_shielded_history.log"
    echo "[import-copy-prove] phase 1: terminal -import-complete-shielded=$ZD_DATADIR (timeout ${DEADLINE}s)"
    install_rc=0
    if command -v timeout >/dev/null 2>&1; then
        HOME="$ISO_HOME" timeout "${DEADLINE}s" \
            "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
            $NODE_ISO_ARGS -import-complete-shielded="$ZD_DATADIR" \
            > "$IMPORT_LOG" 2>&1 || install_rc=$?
    else
        HOME="$ISO_HOME" \
            "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
            $NODE_ISO_ARGS -import-complete-shielded="$ZD_DATADIR" \
            > "$IMPORT_LOG" 2>&1 || install_rc=$?
    fi
    if [ "$install_rc" != "0" ] || ! grep -aq '^IMPORT COMPLETE (committed=' "$IMPORT_LOG"; then
        echo "======================================================================"
        echo "  import-copy-prove VERDICT: FAIL"
        echo "  copy:    $COPY_DIR"
        echo "  reason:  terminal -import-complete-shielded did not report IMPORT COMPLETE"
        echo "           (exit=$install_rc). Inspect $IMPORT_LOG. Nothing further was booted."
        echo "  NOTE:    if $IMPORT_LOG shows no mention of -import-complete-shielded at all,"
        echo "           the importer is not merged on this build. The argv loop silently"
        echo "           ignores unknown flags, so an unimplemented flag looks like a normal"
        echo "           (still-wedged) boot, not a crash — this is exactly why phase 1"
        echo "           requires the explicit banner instead of trusting a plain exit-0."
        echo "======================================================================"
        exit 1
    fi
    echo "[import-copy-prove] import reported IMPORT COMPLETE"

    # Auto-derive the pre-import wedge height from the import's own "boundary="
    # report unless the operator pinned one explicitly (never gate blind).
    if [ -z "$EXPECT_CLIMB_PAST" ]; then
        EXPECT_CLIMB_PAST="$(sed -n 's/.*boundary=\([0-9][0-9]*\).*/\1/p' "$IMPORT_LOG" | head -1)"
        if [ -z "$EXPECT_CLIMB_PAST" ]; then
            echo "======================================================================"
            echo "  import-copy-prove VERDICT: FAIL"
            echo "  copy:    $COPY_DIR"
            echo "  reason:  IMPORT COMPLETE banner present but no 'boundary=<height>' could"
            echo "           be parsed from $IMPORT_LOG, and no --expect-climb-past=H override"
            echo "           was given — refusing to gate blind. Pass --expect-climb-past=H"
            echo "           explicitly, or check that this build's importer still logs"
            echo "           boundary= (engine/services/src/shielded_history_import_service.c)."
            echo "======================================================================"
            exit 1
        fi
        echo "[import-copy-prove] auto-parsed pre-import wedge height: boundary=$EXPECT_CLIMB_PAST"
    else
        echo "[import-copy-prove] using operator-supplied --expect-climb-past=$EXPECT_CLIMB_PAST (override)"
    fi
    PHASE1_LOG="$IMPORT_LOG"
else
    # bundle mode: inject the replay receipt into the copy's own datadir_fd
    # path BEFORE the terminal install, then install the consensus-state bundle.
    echo "[import-copy-prove] installing replay receipt into the copy's own datadir_fd path"
    cp "$RECEIPT" "$COPY_DIR/consensus_state_replay_receipt.v1"

    INSTALL_LOG="$COPY_DIR/cure_install_bundle.log"
    echo "[import-copy-prove] phase 1: terminal -install-consensus-bundle=$BUNDLE (timeout ${DEADLINE}s)"
    install_rc=0
    if command -v timeout >/dev/null 2>&1; then
        HOME="$ISO_HOME" timeout "${DEADLINE}s" \
            "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
            $NODE_ISO_ARGS -install-consensus-bundle="$BUNDLE" \
            > "$INSTALL_LOG" 2>&1 || install_rc=$?
    else
        HOME="$ISO_HOME" \
            "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
            $NODE_ISO_ARGS -install-consensus-bundle="$BUNDLE" \
            > "$INSTALL_LOG" 2>&1 || install_rc=$?
    fi
    if [ "$install_rc" != "0" ] || ! grep -aq '^INSTALLED: -install-consensus-bundle:' "$INSTALL_LOG"; then
        echo "======================================================================"
        echo "  import-copy-prove VERDICT: FAIL"
        echo "  copy:    $COPY_DIR"
        echo "  reason:  terminal -install-consensus-bundle did not report INSTALLED"
        echo "           (exit=$install_rc). Inspect $INSTALL_LOG. Nothing further was booted."
        echo "======================================================================"
        exit 1
    fi
    echo "[import-copy-prove] install reported INSTALLED — booting normally to prove H* CLIMB"
    PHASE1_LOG="$INSTALL_LOG"
fi

# ── step 3b: clear any stale auto_reindex_request ──────────────────────
# The copy was cp -a'd from a datadir that may have armed a self-rebuild
# request (engine/composition/src/boot_crashonly.c, storage/boot_auto_reindex.h); the
# terminal argv paths above return before the normal boot sequence runs, so
# they never consume it — left in place, the very next normal boot (phase 2)
# would silently detour into -reindex-chainstate instead of exercising the
# state we just installed. Clear it unconditionally.
if [ -e "$COPY_DIR/auto_reindex_request" ]; then
    echo "[import-copy-prove] step 3b: stale auto_reindex_request found in the copy — clearing before boot"
    rm -f "$COPY_DIR/auto_reindex_request"
else
    echo "[import-copy-prove] step 3b: no stale auto_reindex_request present — nothing to clear"
fi

# ── step 4: normal isolated boot (phase 2) ─────────────────────────────

HOME="$ISO_HOME" ZCL_MIRROR_SYNC=0 \
"$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
    $NODE_ISO_ARGS \
    > "$COPY_DIR/prove_node.log" 2>&1 &
NODE_PID=$!

# ── step 5: poll for H* CLIMB (shared) ─────────────────────────────────

deadline_epoch=$(( $(date +%s) + DEADLINE ))
max_tip=-1
first_tip=-1
climbed_past=0
cookie="$COPY_DIR/.cookie"
while [ "$(date +%s)" -lt "$deadline_epoch" ]; do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "[import-copy-prove] node exited early (see $COPY_DIR/prove_node.log)"
        break
    fi
    if [ -f "$cookie" ]; then
        t="$(tip)"; t="${t:--1}"
        if [ "$t" -ge 0 ] 2>/dev/null; then
            [ "$first_tip" -lt 0 ] && first_tip="$t" && echo "[import-copy-prove] first tip: $t"
            [ "$t" -gt "$max_tip" ] && max_tip="$t"
            if [ "$t" -gt "$EXPECT_CLIMB_PAST" ] 2>/dev/null; then
                climbed_past=1
                echo "[import-copy-prove] H* CLIMBED to $t (> $EXPECT_CLIMB_PAST)"
                break
            fi
        fi
    fi
    sleep 5
done

# ── continuity (shared): coins_applied_height == hstar + 1 ─────────────
# The reducer can advance between the H* poll and this observation.  During
# that brief publish window coins_applied is legitimately one fact ahead of
# the durable H* cursor.  Require one coherent observation, but allow the
# moving pipeline a bounded interval to expose it; a persistent gap still
# fails closed.
continuity_ok=0
continuity_attempt=0
continuity_retries="${ZCL_COPY_PROVE_CONTINUITY_RETRIES:-15}"
coins_applied=""
hstar_now=""
while [ "$continuity_attempt" -lt "$continuity_retries" ]; do
    continuity_attempt=$((continuity_attempt + 1))
    frontier_json="$(rpc dumpstate '"reducer_frontier"')"
    coins_applied="$(printf '%s' "$frontier_json" | sed -n 's/.*"coins_applied_height":\([0-9-]*\).*/\1/p' | head -1)"
    hstar_now="$(printf '%s' "$frontier_json" | sed -n 's/.*"hstar":\([0-9-]*\).*/\1/p' | head -1)"
    if [ -n "${coins_applied:-}" ] && [ -n "${hstar_now:-}" ] && \
       [ "$coins_applied" = "$((hstar_now + 1))" ] 2>/dev/null; then
        continuity_ok=1
        break
    fi
    [ "$continuity_attempt" -lt "$continuity_retries" ] && sleep 1
done

DURATION_SECS=$(( $(date +%s) - RUN_START_EPOCH ))

# ── verdict (mode-specific gate set) ───────────────────────────────────

if [ "$MODE" = "import" ]; then
    # GATE (a) part 2: both backfill-gap blockers absent.
    blocker_json="$(rpc dumpstate '"blocker"')"
    anchor_gap_present=0
    nullifier_gap_present=0
    printf '%s' "$blocker_json" | grep -q '"id":"utxo_apply\.anchor_backfill_gap"' && anchor_gap_present=1
    printf '%s' "$blocker_json" | grep -q '"id":"utxo_apply\.nullifier_backfill_gap"' && nullifier_gap_present=1
    blockers_clear=0
    [ "$anchor_gap_present" = "0" ] && [ "$nullifier_gap_present" = "0" ] && blockers_clear=1
    gate_a_ok=0
    [ "$climbed_past" = "1" ] && [ "$blockers_clear" = "1" ] && gate_a_ok=1

    gate_b_ok="$continuity_ok"

    # GATE (c): exact same-height tip-hash parity vs zclassicd.
    copy_blockhash() {
        resp="$(rpc getblockhash "$1")"
        printf '%s\n' "$resp" |
            sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' | head -1
    }
    zd_rpc() { HOME="$ISO_HOME" ZCL_DATADIR="$ZD_DATADIR" ZCL_RPCPORT="$ZD_RPCPORT" "$RPC_BIN" "$@" 2>/dev/null || true; }
    zd_blockhash() {
        resp="$(zd_rpc getblockhash "$1")"
        printf '%s\n' "$resp" |
            sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' | head -1
    }
    zd_blockcount() {
        resp="$(zd_rpc getblockcount)"
        printf '%s\n' "$resp" |
            sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1
    }
    wedge_h="$EXPECT_CLIMB_PAST"
    wedge_plus1_h=$((EXPECT_CLIMB_PAST + 1))
    tip_h="$max_tip"
    gate_c_ok=0
    gate_c_note="skipped (--skip-zclassicd-check)"
    if [ "$SKIP_ZD_CHECK" = "0" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        zd_tip="$(zd_blockcount)"; zd_tip="${zd_tip:--1}"
        if [ "${zd_tip:-'-1'}" -ge 0 ] 2>/dev/null && [ "$tip_h" -ge 0 ] 2>/dev/null && \
           [ "$zd_tip" -ge "$tip_h" ] 2>/dev/null; then
            match_count=0
            checked_count=0
            for h in "$wedge_h" "$wedge_plus1_h" "$tip_h"; do
                [ "$h" -ge 0 ] 2>/dev/null || continue
                checked_count=$((checked_count + 1))
                copy_hash="$(copy_blockhash "$h")"
                zd_hash="$(zd_blockhash "$h")"
                if [ -n "$copy_hash" ] && [ -n "$zd_hash" ] && [ "$copy_hash" = "$zd_hash" ]; then
                    match_count=$((match_count + 1))
                    echo "[import-copy-prove] height $h: copy=$copy_hash zclassicd=$zd_hash MATCH"
                else
                    echo "[import-copy-prove] height $h: copy=${copy_hash:-<empty>} zclassicd=${zd_hash:-<empty>} MISMATCH"
                fi
            done
            if [ "$checked_count" -gt 0 ] && [ "$match_count" = "$checked_count" ]; then
                gate_c_ok=1
                gate_c_note="$match_count/$checked_count heights matched (wedge=$wedge_h wedge+1=$wedge_plus1_h tip=$tip_h)"
            else
                gate_c_note="$match_count/$checked_count heights matched — MISMATCH is the missing-anchor/nullifier signature"
            fi
        else
            gate_c_note="zclassicd unreachable or behind the copy's tip (zd_tip=${zd_tip:-<none>}, copy tip=$tip_h) — cannot cross-check"
        fi
    fi

    # best-effort sovereignty posture (never fails the verdict).
    sovereignty_json="$(rpc dumpstate '"sovereignty"')"
    if printf '%s' "$sovereignty_json" | grep -q '"trust_mode"'; then
        trust_mode="$(printf '%s' "$sovereignty_json" | sed -n 's/.*"trust_mode":"\([^"]*\)".*/\1/p' | head -1)"
        sovereignty_note="trust_mode=${trust_mode:-<unparsed>} (expected release_assisted after a real import)"
    else
        sovereignty_note="'sovereignty' dumpstate subsystem not registered on this build — informational only"
    fi

    echo "======================================================================"
    if [ "$gate_a_ok" = "1" ] && [ "$gate_b_ok" = "1" ] && [ "$gate_c_ok" = "1" ]; then
        verdict="PASS"; rc=0
    elif [ "$gate_a_ok" = "1" ] && [ "$gate_b_ok" = "1" ] && [ "$SKIP_ZD_CHECK" = "1" ]; then
        verdict="PASS-INCOMPLETE (gate c skipped — NOT sufficient for a live cutover decision)"; rc=0
    else
        verdict="FAIL"; rc=1
    fi
    echo "  import-copy-prove VERDICT: $verdict  (mode=import)"
    echo "  copy:                    $COPY_DIR $([ "$CLEAN_COPY" = "1" ] && echo '(will be deleted on exit)' || echo '(kept for inspection)')"
    echo "  first_tip:               $first_tip"
    echo "  max_tip:                 $max_tip"
    echo "  expect_climb_past:       $EXPECT_CLIMB_PAST"
    echo "  GATE (a) H* climb:       climbed_past=$climbed_past blockers_clear=$blockers_clear (anchor_gap_present=$anchor_gap_present nullifier_gap_present=$nullifier_gap_present) ok=$gate_a_ok"
    echo "  GATE (b) continuity:     coins_applied_height=$coins_applied hstar=$hstar_now (want coins_applied==hstar+1) ok=$gate_b_ok"
    echo "  GATE (c) hash parity:    $gate_c_note  ok=$gate_c_ok"
    echo "  sovereignty (info only): $sovereignty_note"
    echo "  duration_secs:           $DURATION_SECS"
    echo "  phase1_log:              $PHASE1_LOG"
    echo "  node_log:                $COPY_DIR/prove_node.log"
    if [ "$verdict" = "FAIL" ]; then
        echo "  NOTE: this is a false-green trap if you only look at climbed_past — the"
        echo "        gate requires (a) AND (b) AND (c). A partial import that flipped the"
        echo "        activation cursor while the historical set was incomplete shows up"
        echo "        EXACTLY as a GATE (c) mismatch (folds a different chain) or a GATE (a)"
        echo "        re-wedge — never a silent pass. Do not cut over on this result."
    fi
    echo "======================================================================"
    exit "$rc"
else
    # bundle mode: G-SOV.3 provenance markers. dbquery is SELECT-only,
    # auto-LIMIT'd; avoid a WHERE ... IN (...) literal to sidestep triple
    # quoting (shell -> JSON param -> SQL string) — read the small
    # progress_meta table and grep for both provenance markers.
    provenance_json="$(rpc dbquery '"SELECT key FROM progress_meta"' 50 2>/dev/null || true)"
    provenance_rows="$(printf '%s' "$provenance_json" | grep -o 'coins_kv_migration_complete\|coins_kv_self_folded' | sort -u | wc -l | tr -d ' ')"
    sov_provenance_ok=0
    [ "${provenance_rows:-0}" = "2" ] && sov_provenance_ok=1

    echo "======================================================================"
    if [ "$climbed_past" = "1" ] && [ "$continuity_ok" = "1" ] && [ "$sov_provenance_ok" = "1" ]; then
        verdict="PASS"; rc=0
    else
        verdict="FAIL"; rc=1
    fi
    echo "  import-copy-prove VERDICT: $verdict  (mode=bundle)"
    echo "  copy:                  $COPY_DIR $([ "$CLEAN_COPY" = "1" ] && echo '(will be deleted on exit)' || echo '(kept for inspection)')"
    echo "  first_tip:             $first_tip"
    echo "  max_tip:               $max_tip"
    echo "  expect_climb_past:     $EXPECT_CLIMB_PAST"
    echo "  G-SOV.1 climbed_past:  $climbed_past"
    echo "  G-SOV.2 coins_applied: $coins_applied (hstar=$hstar_now, want coins_applied==hstar+1) ok=$continuity_ok"
    echo "  G-SOV.3 provenance:    coins_kv_migration_complete + coins_kv_self_folded present: $sov_provenance_ok"
    echo "  duration_secs:         $DURATION_SECS"
    echo "  install_log:           $PHASE1_LOG"
    echo "  node_log:              $COPY_DIR/prove_node.log"
    if [ "$verdict" = "FAIL" ]; then
        echo "  NOTE: this is a false-green trap if you only look at climbed_past — G-SOV"
        echo "        requires ALL THREE items. Cross-check hash-agreement against"
        echo "        zclassicd/mirrors by hand (item 4 of the runbook's acceptance bar;"
        echo "        not automated here — --mode=import automates it as gate (c)) before"
        echo "        any live step."
    fi
    echo "======================================================================"
    exit "$rc"
fi
