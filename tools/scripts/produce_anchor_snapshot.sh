#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# produce_anchor_snapshot.sh — SYNC-STRENGTH Workflow-2 Lane-4 linchpin
# producer: mints the checkpoint-bound `utxo-anchor.snapshot` (UTXO set +
# Sapling frontier + anchor hash, all coherent at the baked SHA3 UTXO
# checkpoint height 3,056,758) and hard-verifies it against the compiled
# sha3_utxo_checkpoint + rom_state_checkpoint digests before the artifact is
# ever considered valid. Its presence unblocks fast cold-start, the recovery
# base, and the shielded frontier for every node.
#
# PRODUCTION PATH CHOSEN (see docs/work/self-verified-tip-plan.md +
# engine/composition/src/boot_mint_anchor.c): drive the node's own `-mint-anchor` offline
# reducer ceremony against a COPY of an already-synced-past-the-checkpoint
# archived datadir (default: ~/.zclassic-c23-serve1.archived). Reusing a
# datadir that already has every block BODY on disk means the
# genesis..checkpoint fold never needs P2P body-fetch (boot_mint_anchor_reset
# clears every reducer stage's LOG rows, not the blocks/*.dat bodies
# themselves, so body_fetch/body_persist re-confirm local files instead of
# fetching), while the state (UTXO set + Sapling frontier) is still fully
# RE-DERIVED from those bodies, never borrowed from a stamped coins_kv copy.
#
# OPTION-B FINDING (export at height 3,056,758 straight from an
# already-tip-synced node) — INVESTIGATED, NOT VIABLE: coins_kv is a mutable
# projection of the CURRENT tip only, with no per-height history.
# `-export-consensus-bundle` (engine/composition/src/boot_export_consensus_bundle.c)
# hardcodes `expected_height = cp->height` and its underlying
# consensus_state_snapshot_export requires the FROZEN coins_kv to already
# equal the state AT expected_height — see the doc comment on
# consensus_state_snapshot_export_from_progress_snapshot in
# engine/composition/include/config/consensus_state_snapshot_export.h: "a bundle can only
# be exported at the snapshot's frozen H*". A node synced past the checkpoint
# has a coins_kv reflecting ITS OWN tip (~3.18M), not h=3,056,758, so the
# transparent-coin SHA3 check would simply fail. There is no way to skip the
# genesis..checkpoint fold; the only real lever is avoiding the network
# body-fetch, which this script does by folding over an already-bodied copy.
#
# -mint-anchor-fast, NOT plain -mint-anchor: proven live against the real
# archived serve1 datadir (engine/composition/src/mint_anchor_progress.c
# mint_anchor_producer_lane_bind) — a datadir that already fully synced to
# tip carries "pre-lane" script_validate_log/proof_validate_log rows from
# BEFORE the producer-lane-profile tracking existed, with no recorded proof
# of their original crypto mode, and boot_mint_anchor_require_producer_lane
# refuses to promote that ambiguous legacy state to a "full" producer lane
# (it fails BEFORE the genesis reset, so no partial/wrong state is ever
# written). The documented, intended recourse is exactly what this script
# does: "-mint-anchor-fast" (the checkpoint_fold lane), which
# boot_mint_anchor_reset always accepts for pre-lane legacy state. This does
# NOT weaken the artifact's own verification: -fast only passes
# script_validate/proof_validate THROUGH during the offline state fold (the
# blocks are already a fully-validated canonical chain — that is precisely
# why the archived source is trustworthy to fold from); the UTXO-set
# derivation and BOTH hard-asserts (transparent SHA3+count vs
# sha3_utxo_checkpoint, shielded digest vs rom_state_checkpoint) are
# byte-for-byte identical to the full-crypto path and still unlink+_exit(1)
# on any mismatch. -fast only additionally skips the SEPARATE
# consensus-state-bundle export at the end (a different artifact this
# script does not produce), which is correctly marked non-canonical for a
# checkpoint_fold profile — the utxo-anchor.snapshot verification is
# unaffected either way.
#
# VERIFICATION: two independent passes.
#   (1) PRIMARY / authoritative — -mint-anchor's own internal hard-assert
#       (engine/composition/src/boot_mint_anchor.c:669-704 recomputes coins SHA3+count vs
#       the compiled sha3_utxo_checkpoint; boot_mint_anchor_rom_keystone.c
#       recomputes the shielded anchor/nullifier/Sprout-frontier digest vs
#       the compiled rom_state_checkpoint). Either mismatch UNLINKS the
#       artifact and _exit(1)s inside the mint process itself — a surviving
#       file with rc=0 IS the proof, never a self-report we merely trust.
#   (2) SECONDARY / independent corroboration (best-effort, non-authoritative)
#       — a SEPARATE process, in a throwaway offline scratch datadir, re-opens
#       the produced artifact through the SAME boot_load_verify_snapshot_eligible
#       probe a normal boot would use (`-load-verify-boot`), which independently
#       re-derives the transparent SHA3/count/supply straight from the artifact
#       bytes via uss_open() and compares against the compiled checkpoint. A
#       positive MISMATCH here escalates to FAIL; a timeout/inconclusive result
#       does not (the primary hard-assert is authoritative).
#
# SAFETY: NEVER touches a live/soaking datadir. Always operates on a COPY
# (ZCL_PAS_WORK_DATADIR) made from a read-only source (ZCL_PAS_SOURCE_DATADIR);
# refuses outright if either resolves to a name on the live-datadir denylist.
#
# IDEMPOTENT + RESUMABLE: the datadir copy happens once (a second run reuses
# the existing work datadir instead of re-copying); the mint ceremony itself
# resumes from its own durable progress marker
# (engine/composition/include/config/mint_anchor_progress.h) rather than re-folding from
# genesis after an interrupted run — so re-running this script, or a systemd
# Restart=on-failure, is always safe and never restarts the fold from height 0.
#
# USAGE:
#   tools/scripts/produce_anchor_snapshot.sh
#
# ENV (all optional):
#   ZCL_PAS_BINARY          path to the zclassic23 binary
#                           (default: /home/rhett/github/zclassic23/build/bin/zclassic23)
#   ZCL_PAS_SOURCE_DATADIR  read-only source datadir to copy from
#                           (default: $HOME/.zclassic-c23-serve1.archived)
#   ZCL_PAS_WORK_DATADIR    the isolated copy the mint runs against
#                           (default: $HOME/.zclassic-c23-anchor-producer)
#   ZCL_PAS_VERIFY_DATADIR  scratch datadir for the secondary verify pass
#                           (default: ${ZCL_PAS_WORK_DATADIR}-verify)
#   ZCL_PAS_VERDICT_LOG     PASS/FAIL verdict file
#                           (default: $ZCL_PAS_WORK_DATADIR/produce-anchor-snapshot-verdict.log)
#   ZCL_PAS_OPERATOR_LANE   operator lane to declare for the offline mint
#                           (default: unset — auto-adopted from the copy, see
#                           OPERATOR LANE below)
#
# OPERATOR LANE: wallet_identity_ensure (contexts/wallet/models/src/wallet_identity.c:107)
# FAILS the boot when the runtime lane does not equal the lane persisted in the
# datadir, and the copy inherits the SOURCE datadir's persisted lane. A mint
# driven with no -operator-lane therefore dies at db_open with
# "identity conflict: persisted lane=<X> does not match runtime lane=unknown"
# against every already-run source — which is every source this script is meant
# to use. So the lane is declared, not omitted: tools/repro_on_copy.sh solves the
# same problem by inheriting the source unit's ExecStart and stripping only
# network/port identity, and this is that same rule for a script that builds its
# own argv. Resolution order: $ZCL_PAS_OPERATOR_LANE, else an explicit
# -operator-lane already inside $ZCL_PAS_MINT_FLAGS, else adopt the persisted
# lane the failed boot itself names and retry once.
#
# Adopting the persisted lane is safe and is NOT a lane escalation: the mint is
# offline (it "skips frontend/P2P/runtime services"), binds no port, and runs
# against an isolated copy — never $HOME/.zclassic-c23. It grants the fold no
# authority the source datadir did not already carry, and the artifact's two
# hard-asserts against the compiled checkpoint are unchanged either way.
#
# On PASS, the verified artifact is at $ZCL_PAS_WORK_DATADIR/utxo-anchor.snapshot.
# Exit: 0 PASS · 1 FAIL (verdict log always names the reason either way).

set -u

BINARY="${ZCL_PAS_BINARY:-/home/rhett/github/zclassic23/build/bin/zclassic23}"
SRC_DATADIR="${ZCL_PAS_SOURCE_DATADIR:-$HOME/.zclassic-c23-serve1.archived}"
WORK_DATADIR="${ZCL_PAS_WORK_DATADIR:-$HOME/.zclassic-c23-anchor-producer}"
VERIFY_DATADIR="${ZCL_PAS_VERIFY_DATADIR:-${WORK_DATADIR}-verify}"
VERDICT_LOG="${ZCL_PAS_VERDICT_LOG:-$WORK_DATADIR/produce-anchor-snapshot-verdict.log}"
MINT_LOG="$WORK_DATADIR/produce-anchor-snapshot-mint.log"
VERIFY_LOG="$WORK_DATADIR/produce-anchor-snapshot-secondary-verify.log"
OUT_SNAPSHOT="$WORK_DATADIR/utxo-anchor.snapshot"
CHECKPOINT_HEIGHT=3056758
# -mint-anchor -mint-anchor-fast (the checkpoint_fold lane; -fast is honored
# ONLY together with -mint-anchor, per engine/entry/main.c) — see the PRODUCTION PATH
# comment above for why plain -mint-anchor alone refuses against pre-lane
# legacy state. Override only if you know the source datadir already carries
# a matching "full" producer-lane marker (a fresh, never-before-minted
# source) and want full crypto re-validation instead.
MINT_FLAGS="${ZCL_PAS_MINT_FLAGS:--mint-anchor -mint-anchor-fast}"
OPERATOR_LANE="${ZCL_PAS_OPERATOR_LANE:-}"

# True when $MINT_FLAGS already declares a lane, so an explicit caller choice is
# never overridden and the flag is never passed twice.
mint_flags_have_lane() {
    case " $MINT_FLAGS " in
        *" -operator-lane="*) return 0 ;;
        *) return 1 ;;
    esac
}

# The persisted lane named by a failed boot's own identity-conflict line, e.g.
# "identity conflict: persisted lane=canonical does not match runtime lane=test".
# Empty when this boot did not fail that way — the caller must then not retry.
mint_log_persisted_lane() {
    [ -f "$MINT_LOG" ] || return 0
    sed -n 's/.*identity conflict: persisted lane=\([A-Za-z0-9_-][A-Za-z0-9_-]*\).*/\1/p' \
        "$MINT_LOG" | tail -1
}

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[$(ts)] [produce-anchor-snapshot] $*"; }

verdict_fail() {
    mkdir -p "$(dirname "$VERDICT_LOG")" 2>/dev/null
    {
        echo "VERDICT: FAIL"
        echo "reason: $*"
        echo "checkpoint_height: $CHECKPOINT_HEIGHT"
        echo "timestamp: $(ts)"
    } >"$VERDICT_LOG"
    log "FAIL: $*"
    exit 1
}

# ── Live-datadir denylist — this script must NEVER copy into or mint against
# a datadir a live/soaking node might also be using. ────────────────────────
LIVE_DENYLIST=(
    "$HOME/.zclassic-c23"
    "$HOME/.zclassic-c23-dev"
    "$HOME/.zclassic-c23-work"
    "$HOME/.zclassic-c23-serve1"
    "$HOME/.zclassic"
)
for d in "${LIVE_DENYLIST[@]}"; do
    if [ "$WORK_DATADIR" = "$d" ] || [ "$VERIFY_DATADIR" = "$d" ]; then
        verdict_fail "refusing: target datadir '$d' is on the live-datadir denylist"
    fi
done

[ -x "$BINARY" ] || verdict_fail "binary not executable: $BINARY"
[ -d "$SRC_DATADIR" ] || verdict_fail "source datadir missing: $SRC_DATADIR"

# ── Disk-space sanity (soft) ─────────────────────────────────────────────────
AVAIL_KB=$(df -Pk "$HOME" 2>/dev/null | awk 'NR==2 {print $4}')
SRC_KB=$(du -sk "$SRC_DATADIR" 2>/dev/null | awk '{print $1}')
if [ -n "${AVAIL_KB:-}" ] && [ -n "${SRC_KB:-}" ]; then
    NEED_KB=$((SRC_KB * 2))
    if [ "$AVAIL_KB" -lt "$NEED_KB" ]; then
        verdict_fail "insufficient disk: need ~${NEED_KB}KB, have ${AVAIL_KB}KB free under $HOME"
    fi
fi

mkdir -p "$(dirname "$WORK_DATADIR")" 2>/dev/null

# ── Step 1: idempotent copy (source is NEVER modified) ──────────────────────
if [ -d "$WORK_DATADIR" ]; then
    log "work datadir already present at $WORK_DATADIR — resuming (no re-copy)"
else
    rm -rf "${WORK_DATADIR}".copying.* 2>/dev/null
    TMP_WORK="${WORK_DATADIR}.copying.$$"
    log "copying $SRC_DATADIR -> $TMP_WORK (one-time; source stays read-only)"
    if ! cp -a "$SRC_DATADIR" "$TMP_WORK"; then
        rm -rf "$TMP_WORK"
        verdict_fail "copy of source datadir failed"
    fi
    if ! mv -T "$TMP_WORK" "$WORK_DATADIR"; then
        rm -rf "$TMP_WORK"
        verdict_fail "atomic rename of copied datadir failed"
    fi
    log "copy complete: $WORK_DATADIR"
fi

# ── Step 2: drive the offline anchor mint (resumable via its own progress
# marker — engine/composition/include/config/mint_anchor_progress.h). Foreground: this
# script is meant to run under a durable systemd --user unit, so blocking for
# hours here is correct, not a bug. ─────────────────────────────────────────
if [ -n "$OPERATOR_LANE" ] && ! mint_flags_have_lane; then
    MINT_FLAGS="$MINT_FLAGS -operator-lane=$OPERATOR_LANE"
    log "declaring operator lane from ZCL_PAS_OPERATOR_LANE: $OPERATOR_LANE"
fi

log "driving $MINT_FLAGS against $WORK_DATADIR"
log "on-disk fold progress: $WORK_DATADIR/mint-progress.log ; full log: $MINT_LOG"
# shellcheck disable=SC2086
"$BINARY" -datadir="$WORK_DATADIR" $MINT_FLAGS >>"$MINT_LOG" 2>&1
MINT_RC=$?
log "$MINT_FLAGS exited rc=$MINT_RC"

# Undeclared lane + an identity conflict is the one failure this script can
# resolve without the operator knowing anything about the source datadir: the
# refusal names the lane it wanted. Adopt it and retry EXACTLY once, and only
# when no lane was declared — an explicit caller choice that conflicts is a real
# disagreement and must stay fatal. The mint is resumable via its own progress
# marker, so the retry never restarts the fold from height 0.
if [ "$MINT_RC" -ne 0 ] && ! mint_flags_have_lane; then
    PERSISTED_LANE="$(mint_log_persisted_lane)"
    if [ -n "$PERSISTED_LANE" ]; then
        log "identity conflict: the copy persists operator lane" \
            "'$PERSISTED_LANE' — adopting it and retrying the mint once"
        MINT_FLAGS="$MINT_FLAGS -operator-lane=$PERSISTED_LANE"
        # shellcheck disable=SC2086
        "$BINARY" -datadir="$WORK_DATADIR" $MINT_FLAGS >>"$MINT_LOG" 2>&1
        MINT_RC=$?
        log "$MINT_FLAGS exited rc=$MINT_RC"
    fi
fi

if [ "$MINT_RC" -ne 0 ]; then
    verdict_fail "mint-anchor exited non-zero ($MINT_RC) — see $MINT_LOG"
fi

if [ ! -s "$OUT_SNAPSHOT" ]; then
    verdict_fail "mint-anchor exited 0 but $OUT_SNAPSHOT is missing/empty"
fi

if ! grep -q "SUCCESS: minted a checkpoint-matching anchor UTXO set" "$MINT_LOG"; then
    verdict_fail "mint-anchor exited 0 but the internal hard-verify SUCCESS line is absent from $MINT_LOG — refusing to trust $OUT_SNAPSHOT"
fi

log "PRIMARY hard-verify PASSED — mint-anchor's own SHA3/count + ROM-keystone" \
    "(shielded) assert matched the compiled checkpoint. The mint process" \
    "unlinks the artifact and _exit(1)s on ANY mismatch, so the artifact" \
    "surviving with rc=0 plus this log line together ARE the proof."

# ── Step 3: independent secondary verify (best-effort, non-authoritative) ──
SECONDARY_STATUS="SKIPPED"
rm -rf "$VERIFY_DATADIR"
mkdir -p "$VERIFY_DATADIR"
if cp -f "$OUT_SNAPSHOT" "$VERIFY_DATADIR/utxo-anchor.snapshot"; then
    VERIFY_PORT=$(( (RANDOM % 5000) + 32000 ))
    "$BINARY" -datadir="$VERIFY_DATADIR" -load-verify-boot -nolegacyimport \
        -port="$VERIFY_PORT" -rpcport=$((VERIFY_PORT + 1)) \
        >"$VERIFY_LOG" 2>&1 &
    VERIFY_PID=$!
    SECONDARY_STATUS="TIMEOUT"
    for _ in $(seq 1 60); do
        if grep -q "verified baked anchor snapshot present" "$VERIFY_LOG" 2>/dev/null; then
            SECONDARY_STATUS="PASS"
            break
        fi
        if grep -qE "MISMATCH|does not match checkpoint" "$VERIFY_LOG" 2>/dev/null; then
            SECONDARY_STATUS="MISMATCH"
            break
        fi
        if ! kill -0 "$VERIFY_PID" 2>/dev/null; then
            SECONDARY_STATUS="PROCESS_EXITED"
            break
        fi
        sleep 1
    done
    kill "$VERIFY_PID" 2>/dev/null
    wait "$VERIFY_PID" 2>/dev/null
else
    log "secondary verify: could not stage a copy at $VERIFY_DATADIR — skipping (non-fatal)"
fi
rm -rf "$VERIFY_DATADIR"

log "SECONDARY independent verify status: $SECONDARY_STATUS (transcript before cleanup: $VERIFY_LOG)"
if [ "$SECONDARY_STATUS" = "MISMATCH" ]; then
    verdict_fail "SECONDARY independent verify (a separate process re-deriving the transparent SHA3/count/supply from the artifact bytes) reported a checkpoint MISMATCH — treating the primary PASS as untrustworthy"
fi

SNAPSHOT_SIZE=$(stat -c %s "$OUT_SNAPSHOT" 2>/dev/null || echo "?")
{
    echo "VERDICT: PASS"
    echo "artifact: $OUT_SNAPSHOT"
    echo "artifact_size_bytes: $SNAPSHOT_SIZE"
    echo "primary_hard_verify: PASS (mint-anchor internal SHA3/count + ROM-keystone assert; unlink+exit(1) on any mismatch)"
    echo "secondary_independent_verify: $SECONDARY_STATUS"
    echo "checkpoint_height: $CHECKPOINT_HEIGHT"
    echo "source_datadir: $SRC_DATADIR"
    echo "timestamp: $(ts)"
} >"$VERDICT_LOG"
log "PASS — verdict written to $VERDICT_LOG"
exit 0
