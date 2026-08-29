#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# anchor-snapshot-copy-prove.sh — SYNC-STRENGTH Workflow-1 Lane-4 copy-prove
# harness for the fold-from-checkpoint cold-start/recovery seam
# (config/src/boot_refold_staged.c: boot_refold_from_anchor_reset,
# boot_refold_from_anchor_artifact_available). Mirrors the safety scaffolding
# and gate discipline of tools/scripts/import-copy-prove.sh (the canonical
# copy-prove driver for the shielded-state cure family) and the SKIP-when-
# fixture-absent convention of tools/scripts/cold_start_to_tip_probe.sh — this
# file adds neither a new safety model nor a new gate idiom, only the
# fold-from-checkpoint-specific proof.
#
# WHAT THIS PROVES: given a SOURCE datadir that already has an imported block
# index (headers + on-disk bodies, e.g. via the two-step --importblockindex
# recipe) and a verified <SRC>/utxo-anchor.snapshot artifact (produced by the
# offline -mint-anchor ceremony and matching the compiled SHA3 UTXO
# checkpoint), a throwaway COPY of that datadir:
#   (a) drives the terminal -refold-from-anchor reset ONCE, and the reset
#       banner ("anchor coin set RE-SEEDED + verified") is observed — never a
#       silent no-op fallback to the from-genesis path;
#   (b) then, on a normal isolated boot, folds FORWARD from the anchor over
#       the copy's own on-disk bodies: H* is observed CLIMBING, and at every
#       sampled point H* stays AT OR ABOVE the anchor height — the direct
#       discriminator between "fold from checkpoint" (this feature) and a
#       "genesis re-fold" (H* would sit near 0 for a long stretch first);
#   (c) reaches at least --target-height (default: the copy's own body tip,
#       auto-detected via getblockcount before the reset) within --deadline —
#       proving O(delta) forward progress, not a full-history replay.
#
# This is the harness for the ORCHESTRATOR to run END-TO-END once the real
# multi-GB -mint-anchor snapshot artifact exists on a lane/worker datadir; it
# is not a synthetic-fixture unit test (that lives in
# lib/test/src/test_refold_from_anchor_artifact_reachable.c and
# lib/test/src/test_refold_from_anchor_fatal.c, which prove the same
# predicates deterministically without a real snapshot or a live boot).
#
# SAFETY (identical invariants to import-copy-prove.sh):
#   - --copy-dir (or the generated default) MUST contain the literal
#     "/.zclassic-c23-COPY-" marker and MUST NOT equal a known live/protected
#     datadir path — refuses otherwise.
#   - --copy-dir must not already exist (never silently overwrites/reuses).
#   - --src is only ever READ (cp -a); this script never writes to it, never
#     stops/restarts any systemd unit, never touches a live/soaking datadir.
#   - the proving boot is fully network-isolated by default
#     (-connect=127.0.0.1:39999, isolated 39xxx-range ports) — it climbs over
#     the COPY's own on-disk bodies only, never dials a live peer, unless
#     --tail-peer=HOST:PORT is passed to fetch bodies past what the copy
#     already has on disk.
#   - process-group SIGKILL teardown on every exit (pass, fail, or interrupt).
#   - the copy is LEFT on disk on exit for post-mortem inspection; pass
#     --clean-copy to delete it instead.
#
# Usage:
#   tools/scripts/anchor-snapshot-copy-prove.sh [--dry-run] \
#     [--src=DIR]              (default: $HOME/.zclassic-c23; must already
#                                have an imported block index — headers AND
#                                bodies on disk, e.g. via the two-step
#                                --importblockindex recipe)
#     [--snapshot=PATH]        (a verified utxo-anchor.snapshot to stage into
#                                the copy at <copy>/utxo-anchor.snapshot
#                                before the reset boot; default: use
#                                <SRC>/utxo-anchor.snapshot if already present)
#     [--copy-dir=DIR]         (default: $HOME/.zclassic-c23-COPY-<ts>-anchor;
#                                must carry the "/.zclassic-c23-COPY-" marker)
#     [--target-height=H]      (default: auto-detected copy body tip before
#                                the reset — the O(delta) climb target)
#     [--deadline=SECS]        (default 1800 — this is a DELTA fold, not a
#                                full-history one; if the delta is large,
#                                raise this)
#     [--rpcport=N] [--p2p-port=N] [--fs-port=N] [--https-port=N]
#     [--tail-peer=HOST:PORT]  (fetch bodies past the copy's own blocks/ via
#                                this one outbound peer; default: fully
#                                isolated, copy's own bodies only)
#     [--clean-copy]           (delete --copy-dir on exit; default: keep)
#
# Exit: 0 PASS, 1 FAIL, 2 SKIP (fixture/binary prerequisites absent — this is
#       the expected result until a real -mint-anchor snapshot exists on the
#       chosen --src), 2 usage/precondition error.
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"

SRC="$HOME/.zclassic-c23"
SNAPSHOT=""
COPY_DIR=""
TARGET_HEIGHT=""
DEADLINE=1800
RPCPORT=18499
P2PPORT=19133
FSPORT=19134
HTTPSPORT=19135
TAIL_PEER=""
CLEAN_COPY=0
DRY_RUN=0

usage() {
    cat <<'USAGE'
anchor-snapshot-copy-prove.sh — copy-prove the fold-from-checkpoint seam
(boot_refold_from_anchor_reset) against a throwaway datadir COPY.

  --dry-run                 print the plan and touch nothing
  --src=DIR                 datadir to cp -a from (default: $HOME/.zclassic-c23);
                             must already have an imported block index
  --snapshot=PATH           verified utxo-anchor.snapshot to stage into the
                             copy (default: use <SRC>/utxo-anchor.snapshot)
  --copy-dir=DIR            throwaway target; must carry /.zclassic-c23-COPY-
  --target-height=H         climb target (default: auto-detected copy tip)
  --deadline=SECS           default 1800
  --rpcport/--p2p-port/--fs-port/--https-port=N
  --tail-peer=HOST:PORT     fetch bodies past the copy's own blocks/ (default: isolated)
  --clean-copy              delete --copy-dir on exit (default: keep for inspection)

Exit: 0 PASS, 1 FAIL, 2 SKIP (fixtures absent) / usage error.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)             DRY_RUN=1 ;;
        --src=*)                SRC="${1#--src=}" ;;
        --snapshot=*)            SNAPSHOT="${1#--snapshot=}" ;;
        --copy-dir=*)            COPY_DIR="${1#--copy-dir=}" ;;
        --target-height=*)       TARGET_HEIGHT="${1#--target-height=}" ;;
        --deadline=*)            DEADLINE="${1#--deadline=}" ;;
        --rpcport=*)             RPCPORT="${1#--rpcport=}" ;;
        --p2p-port=*)            P2PPORT="${1#--p2p-port=}" ;;
        --fs-port=*)             FSPORT="${1#--fs-port=}" ;;
        --https-port=*)          HTTPSPORT="${1#--https-port=}" ;;
        --tail-peer=*)           TAIL_PEER="${1#--tail-peer=}" ;;
        --clean-copy)            CLEAN_COPY=1 ;;
        -h|--help)               usage; exit 0 ;;
        *) echo "anchor-snapshot-copy-prove: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$COPY_DIR" ]; then
    COPY_DIR="$HOME/.zclassic-c23-COPY-$(date +%Y%m%d%H%M%S)-anchor"
fi

# ── safety invariant: never a live datadir, always the throwaway marker ────
case "$COPY_DIR" in
    *"/.zclassic-c23-COPY-"*) : ;;
    *) echo "anchor-snapshot-copy-prove: REFUSED — --copy-dir must contain the '/.zclassic-c23-COPY-' marker: $COPY_DIR" >&2
       exit 2 ;;
esac
for live in "$HOME/.zclassic-c23" "$HOME/.zclassic-c23-dev" "$HOME/.zclassic-c23-soak" \
            "$HOME/.zclassic-c23-mint" "$HOME/.zclassic-c23-mint-receipt" "$HOME/.zclassic"; do
    if [ "$COPY_DIR" = "$live" ]; then
        echo "anchor-snapshot-copy-prove: REFUSED — --copy-dir aliases a known live/protected datadir: $COPY_DIR" >&2
        exit 2
    fi
done
if [ -e "$COPY_DIR" ]; then
    echo "anchor-snapshot-copy-prove: REFUSED — --copy-dir already exists, refusing to overwrite: $COPY_DIR" >&2
    exit 2
fi

skip() { echo "anchor-snapshot-copy-prove: SKIP ($*)"; exit 2; }

echo "======================================================================"
echo "  anchor-snapshot-copy-prove plan"
echo "  src (cp -a from):              $SRC"
echo "  copy_dir (must not pre-exist): $COPY_DIR"
echo "  snapshot source:               ${SNAPSHOT:-<SRC>/utxo-anchor.snapshot if present}"
# An apostrophe inside ${var:-word} opens a single-quoted string even within
# double quotes, which swallowed the rest of this file: bash -n failed at EOF
# with "unexpected EOF while looking for matching '". Build the default
# outside the expansion instead of escaping inside it.
target_height_display="${TARGET_HEIGHT:-}"
[ -n "$target_height_display" ] || target_height_display="<auto: copy's own body tip>"
echo "  target_height:                 $target_height_display"
echo "  deadline_secs:                 $DEADLINE"
echo "  ports:                         rpc=$RPCPORT p2p=$P2PPORT fs=$FSPORT https=$HTTPSPORT"
echo "  tail peer:                     $([ -n "$TAIL_PEER" ] && echo "-addnode=$TAIL_PEER" || echo 'none (fully network-isolated boot)')"
echo "  cleanup:                       $([ "$CLEAN_COPY" = "1" ] && echo '--clean-copy: copy ALWAYS deleted on exit' || echo 'copy LEFT on disk for inspection')"
echo "  steps:"
echo "    1. cp -a \"\$SRC\" \"\$COPY_DIR\""
echo "    2. stage the verified snapshot at \$COPY_DIR/utxo-anchor.snapshot"
echo "    3. terminal boot: \"\$NODE_BIN\" -datadir=\$COPY_DIR -refold-from-anchor"
echo "       (require the 'anchor coin set RE-SEEDED + verified' banner; a"
echo "        FATAL here means the snapshot did NOT reproduce the compiled"
echo "        checkpoint — this is a REAL failure, not a fixture problem)"
echo "    4. normal isolated boot (the reset committed; this continues the fold)"
echo "    5. GATE (a): H* never dips below the anchor height at any sample"
echo "    6. GATE (b): H* CLIMBS to >= target_height within the deadline"
echo "  does NOT do: write to --src beyond the read-only cp -a, restart/stop"
echo "  any systemd unit, or touch anything outside --copy-dir."
echo "======================================================================"

if [ "$DRY_RUN" = "1" ]; then
    echo "[anchor-snapshot-copy-prove] --dry-run: no filesystem or process action taken."
    exit 0
fi

[ -x "$NODE_BIN" ] || skip "node binary absent: $NODE_BIN (run make build-only / make -j\$(nproc))"
[ -x "$RPC_BIN" ]  || skip "zcl-rpc absent: $RPC_BIN (run make zcl-rpc)"
[ -d "$SRC" ]       || skip "source datadir not found: $SRC"

if [ -z "$SNAPSHOT" ]; then
    if [ -f "$SRC/utxo-anchor.snapshot" ]; then
        SNAPSHOT="$SRC/utxo-anchor.snapshot"
    else
        skip "no --snapshot=PATH given and no $SRC/utxo-anchor.snapshot present — this harness needs a real verified anchor snapshot artifact (the offline -mint-anchor ceremony's output); see tools/seed_anchor_snapshot.sh to stage one, or lib/test/src/test_refold_from_anchor_artifact_reachable.c for the synthetic-fixture proof that does not need one"
    fi
fi
[ -s "$SNAPSHOT" ] || skip "snapshot not found or empty: $SNAPSHOT"

echo "[anchor-snapshot-copy-prove] cp -a $SRC -> $COPY_DIR"
cp -a "$SRC" "$COPY_DIR"
rm -f "$COPY_DIR"/*.pid "$COPY_DIR"/.lock 2>/dev/null || true

NODE_PID=""
cleanup() {
    if [ -n "${NODE_PID:-}" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -TERM -- "-$NODE_PID" 2>/dev/null || kill -TERM "$NODE_PID" 2>/dev/null || true
        sleep 2
        kill -KILL -- "-$NODE_PID" 2>/dev/null || kill -KILL "$NODE_PID" 2>/dev/null || true
    fi
    if [ "$CLEAN_COPY" = "1" ] && [ -e "$COPY_DIR" ]; then
        case "$COPY_DIR" in
            *"/.zclassic-c23-COPY-"*)
                echo "[anchor-snapshot-copy-prove] cleanup: rm -rf $COPY_DIR (--clean-copy)"
                rm -rf "$COPY_DIR"
                ;;
            *)
                echo "[anchor-snapshot-copy-prove] cleanup: REFUSING to rm -rf $COPY_DIR — lost the '-COPY-' marker, leaving it in place for manual review" >&2
                ;;
        esac
    fi
}
trap cleanup EXIT INT TERM

ISO_HOME="$COPY_DIR/.isolated-home"
mkdir -p "$ISO_HOME"
[ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

echo "[anchor-snapshot-copy-prove] staging snapshot: $SNAPSHOT -> $COPY_DIR/utxo-anchor.snapshot"
cp "$SNAPSHOT" "$COPY_DIR/utxo-anchor.snapshot"

if [ -e "$COPY_DIR/auto_reindex_request" ]; then
    echo "[anchor-snapshot-copy-prove] clearing stale auto_reindex_request in the copy before boot"
    rm -f "$COPY_DIR/auto_reindex_request"
fi

if [ -n "$TAIL_PEER" ]; then
    BOOT_PEER_ARGS="-addnode=$TAIL_PEER"
else
    BOOT_PEER_ARGS="-connect=127.0.0.1:39999"
fi
NODE_ISO_ARGS="-fsport=$FSPORT -httpsport=$HTTPSPORT $BOOT_PEER_ARGS -nolegacyimport -nofilesync -nobgvalidation"

rpc() { HOME="$ISO_HOME" ZCL_DATADIR="$COPY_DIR" ZCL_RPCPORT="$RPCPORT" "$RPC_BIN" "$@" 2>/dev/null || true; }
tip() {
    resp="$(rpc getblockcount)"
    printf '%s\n' "$resp" |
        sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1
}

# ── step 0: auto-detect the copy's own body tip (the O(delta) climb target)
# BEFORE the reset touches anything — a quick, isolated, throwaway probe boot
# with no reset flag, just enough to read getblockcount from the header/body
# chain already on disk. ──────────────────────────────────────────────────
if [ -z "$TARGET_HEIGHT" ]; then
    echo "[anchor-snapshot-copy-prove] auto-detecting the copy's own body tip (pre-reset probe boot)..."
    HOME="$ISO_HOME" \
    "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
        $NODE_ISO_ARGS \
        > "$COPY_DIR/probe_tip.log" 2>&1 &
    PROBE_PID=$!
    probe_deadline=$(( $(date +%s) + 60 ))
    probe_tip=-1
    while [ "$(date +%s)" -lt "$probe_deadline" ]; do
        if ! kill -0 "$PROBE_PID" 2>/dev/null; then break; fi
        t="$(tip)"; t="${t:--1}"
        if [ "$t" -ge 0 ] 2>/dev/null; then probe_tip="$t"; fi
        sleep 2
    done
    kill -TERM "$PROBE_PID" 2>/dev/null || true
    sleep 1
    kill -KILL "$PROBE_PID" 2>/dev/null || true
    wait "$PROBE_PID" 2>/dev/null || true
    if [ "$probe_tip" -lt 0 ] 2>/dev/null; then
        echo "======================================================================"
        echo "  anchor-snapshot-copy-prove VERDICT: FAIL"
        echo "  reason: could not auto-detect the copy's own body tip via a pre-reset"
        echo "          probe boot (getblockcount never answered within 60s). Pass"
        echo "          --target-height=H explicitly. See $COPY_DIR/probe_tip.log."
        echo "======================================================================"
        exit 1
    fi
    TARGET_HEIGHT="$probe_tip"
    echo "[anchor-snapshot-copy-prove] auto-detected target_height=$TARGET_HEIGHT"
fi

RUN_START_EPOCH=$(date +%s)

# ── step 1: terminal -refold-from-anchor boot (the reset) ─────────────────
RESET_LOG="$COPY_DIR/refold_from_anchor_reset.log"
echo "[anchor-snapshot-copy-prove] phase 1: terminal -refold-from-anchor (timeout ${DEADLINE}s)"
reset_rc=0
if command -v timeout >/dev/null 2>&1; then
    HOME="$ISO_HOME" timeout "${DEADLINE}s" \
        "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
        $NODE_ISO_ARGS -refold-from-anchor \
        > "$RESET_LOG" 2>&1 &
    RESET_PID=$!
else
    HOME="$ISO_HOME" \
        "$NODE_BIN" -datadir="$COPY_DIR" -rpcport="$RPCPORT" -port="$P2PPORT" \
        $NODE_ISO_ARGS -refold-from-anchor \
        > "$RESET_LOG" 2>&1 &
    RESET_PID=$!
fi

# The reset runs INSIDE the normal boot sequence (config/src/boot.c), not as a
# one-shot terminal verb — the process keeps running afterward as a normal
# node. Poll the log for the RE-SEEDED banner (success) or a FATAL banner
# (proven failure — the snapshot did not reproduce the compiled checkpoint),
# whichever comes first, for up to the deadline.
reset_seen=0
reset_fatal=0
reset_deadline=$(( $(date +%s) + DEADLINE ))
while [ "$(date +%s)" -lt "$reset_deadline" ]; do
    if grep -aqF "anchor coin set RE-SEEDED" "$RESET_LOG" 2>/dev/null; then
        reset_seen=1; break
    fi
    if grep -aqE "FATAL: -refold-from-anchor:" "$RESET_LOG" 2>/dev/null; then
        reset_fatal=1; break
    fi
    if ! kill -0 "$RESET_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done
NODE_PID="$RESET_PID"

if [ "$reset_fatal" = "1" ]; then
    echo "======================================================================"
    echo "  anchor-snapshot-copy-prove VERDICT: FAIL"
    echo "  reason: -refold-from-anchor FATALed — the staged snapshot did NOT"
    echo "          reproduce the compiled SHA3 UTXO checkpoint. This is a REAL"
    echo "          finding (a bad/wrong-height snapshot), not a harness bug."
    echo "          See $RESET_LOG."
    echo "======================================================================"
    exit 1
fi
if [ "$reset_seen" = "0" ]; then
    echo "======================================================================"
    echo "  anchor-snapshot-copy-prove VERDICT: FAIL"
    echo "  reason: neither the RE-SEEDED success banner nor a FATAL banner"
    echo "          appeared within ${DEADLINE}s. See $RESET_LOG."
    echo "======================================================================"
    exit 1
fi
echo "[anchor-snapshot-copy-prove] -refold-from-anchor RE-SEEDED the anchor coin set — the node is now running normally, folding forward"

# ── step 2 (implicit continuation): poll H* CLIMB from the anchor ─────────
# The same process from step 1 keeps running (the reset is inline in the
# normal boot, not a terminal exit) — no second boot needed.
ANCHOR_LOG_HEIGHT="$(sed -n 's/.*h=\([0-9][0-9]*\).*/\1/p' "$RESET_LOG" | tail -1)"
echo "[anchor-snapshot-copy-prove] parsed anchor height from reset log: ${ANCHOR_LOG_HEIGHT:-<unparsed>}"

deadline_epoch=$(( RUN_START_EPOCH + DEADLINE ))
first_hstar=-1
max_hstar=-1
below_anchor_sample=0
reached_target=0
while [ "$(date +%s)" -lt "$deadline_epoch" ]; do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "[anchor-snapshot-copy-prove] node exited (see $RESET_LOG)"
        break
    fi
    frontier_json="$(rpc dumpstate '"reducer_frontier"')"
    hstar="$(printf '%s' "$frontier_json" | sed -n 's/.*"hstar":\([0-9-]*\).*/\1/p' | head -1)"
    if [ -n "${hstar:-}" ] && [ "$hstar" -ge 0 ] 2>/dev/null; then
        [ "$first_hstar" -lt 0 ] && first_hstar="$hstar" && echo "[anchor-snapshot-copy-prove] first H*: $hstar"
        [ "$hstar" -gt "$max_hstar" ] && { max_hstar="$hstar"; echo "[anchor-snapshot-copy-prove] H*=$hstar"; }
        if [ -n "${ANCHOR_LOG_HEIGHT:-}" ] && [ "$hstar" -lt "$ANCHOR_LOG_HEIGHT" ] 2>/dev/null; then
            below_anchor_sample=1
            echo "[anchor-snapshot-copy-prove] WARNING: sampled H*=$hstar BELOW the anchor ($ANCHOR_LOG_HEIGHT) — looks like a genesis re-fold, not a fold-from-checkpoint"
        fi
        if [ "$hstar" -ge "$TARGET_HEIGHT" ] 2>/dev/null; then
            reached_target=1
            echo "[anchor-snapshot-copy-prove] REACHED target_height=$TARGET_HEIGHT (H*=$hstar)"
            break
        fi
    fi
    sleep 5
done

DURATION_SECS=$(( $(date +%s) - RUN_START_EPOCH ))

gate_a_ok=1
[ "$below_anchor_sample" = "1" ] && gate_a_ok=0
gate_b_ok="$reached_target"

echo "======================================================================"
if [ "$gate_a_ok" = "1" ] && [ "$gate_b_ok" = "1" ]; then
    verdict="PASS"; rc=0
else
    verdict="FAIL"; rc=1
fi
echo "  anchor-snapshot-copy-prove VERDICT: $verdict"
echo "  copy:                 $COPY_DIR $([ "$CLEAN_COPY" = "1" ] && echo '(will be deleted on exit)' || echo '(kept for inspection)')"
echo "  anchor_height:        ${ANCHOR_LOG_HEIGHT:-<unparsed>}"
echo "  target_height:        $TARGET_HEIGHT"
echo "  first_hstar:          $first_hstar"
echo "  max_hstar:            $max_hstar"
echo "  GATE (a) never below anchor: below_anchor_sample=$below_anchor_sample ok=$gate_a_ok"
echo "  GATE (b) climbed to target:  reached_target=$reached_target ok=$gate_b_ok"
echo "  duration_secs:        $DURATION_SECS"
echo "  reset_log:            $RESET_LOG"
if [ "$verdict" = "FAIL" ]; then
    echo "  NOTE: GATE (a) failing means H* was observed BELOW the anchor at some"
    echo "        point — that is the genesis-re-fold regression this harness"
    echo "        exists to catch, not a flaky timing artifact. GATE (b) failing"
    echo "        with GATE (a) still ok means the fold is progressing correctly"
    echo "        but the deadline was too short for this delta — raise --deadline"
    echo "        before treating it as a code regression."
fi
echo "======================================================================"
exit "$rc"
