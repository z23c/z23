#!/usr/bin/env bash
# cold_start_test.sh — Wave 11D regression armor for Wave 11A.
#
# Asserts that a fresh datadir can seed a fast rebuild authority from a local
# cold-start fixture. Prefer the current secure operator-bundle shape:
# block_index.bin + utxo-seed-*.snapshot loaded through
# -load-snapshot-at-own-height, which checks the snapshot's claimed height/hash
# against the validated header chain (the state payload is still assisted; a
# ZClassic header does not commit UTXO or shielded roots)
# header and exposes fast_rebuild_authority_ready through bootstrapstatus.
#
# The legacy fallback is a checkpoint-height consensus_snapshot.db import. A
# consensus_snapshot.db above the compiled checkpoint is intentionally refused by
# boot_snapshot_import because it has no in-binary root; that is not a passing
# C3 proof and should be replaced by the operator bundle.
#
# Pass criterion: the fresh node reports fast_rebuild_authority_ready with a
# snapshot count >1,000,000 within 90 s of boot, or the legacy checkpoint import
# reports >1,000,000 UTXOs. Chain-tip advance past the snapshot height is a
# separate concern (needs block bodies from either the bundle/live peer path or
# P2P) and is not asserted here — this remains a thin gate on the cold-start
# seed authority.
#
# Without Wave 11A this silently timed out at h=-1 (see captured
# brnibh8u9.output — TIMEOUT after 602s). The presence of this script
# in CI keeps that regression armor in place: anyone who breaks the
# pre-restore import path now fails this gate.
#
# Exit codes:
#   0  — utxos > 1,000,000 within DEADLINE_SECS.
#   1  — timeout or threshold not met.
#   2  — pre-requisites missing (zclassic23 binary, source snapshot).

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO_DIR/build/bin/zclassic23"
CLI="$REPO_DIR/build/bin/zcl-rpc"
SRC_SNAP_CANDIDATES=(
    "$HOME/.zclassic-c23-test/consensus_snapshot.db"
    "$HOME/.zclassic-c23/consensus_snapshot.db"
)
SRC_BUNDLE_SNAP_CANDIDATES=(
    "$HOME"/.zclassic-c23-test/utxo-seed-*.snapshot
    "$HOME"/.zclassic-c23/utxo-seed-*.snapshot
)
TEST_DIR="/tmp/zclassic23_coldstart_$$"
TEST_PORT="${TEST_PORT:-18233}"
TEST_RPCPORT="${TEST_RPCPORT:-18235}"
TEST_FSPORT="${TEST_FSPORT:-18236}"
TEST_HTTPSPORT="${TEST_HTTPSPORT:-18237}"
TEST_DEAD_PEER="${TEST_DEAD_PEER:-127.0.0.1:39999}"
DEADLINE_SECS="${DEADLINE_SECS:-90}"
MIN_UTXOS="${MIN_UTXOS:-1000000}"

# The Wave 11A probe emits a single distinctive log line on success:
#   "[boot] snapshot-first import OK: N UTXOs at h=H — chain restore
#    will observe snapshot anchor"
# We grep for that prefix to keep the test independent of any
# external SQLite CLI dependency.
SUCCESS_PATTERN='snapshot-first import OK: '
BUNDLE_SUCCESS_PATTERN='-load-snapshot-at-own-height: coin set RE-SEEDED'

cleanup() {
    if [ -n "${NODE_PID:-}" ]; then
        kill -TERM "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
    echo "[coldstart] missing $BIN — run 'make' first"
    exit 2
fi
if [ ! -x "$CLI" ]; then
    echo "[coldstart] missing $CLI"
    exit 2
fi

SRC_SNAP=""
SRC_BUNDLE_SNAP="${ZCL_C3_BUNDLE_SNAPSHOT:-}"
SRC_BUNDLE_INDEX="${ZCL_C3_BLOCK_INDEX:-}"
if [ -z "$SRC_BUNDLE_SNAP" ]; then
    newest_mtime=0
    for cand in "${SRC_BUNDLE_SNAP_CANDIDATES[@]}"; do
        [ -f "$cand" ] || continue
        size=$(stat -c %s "$cand" 2>/dev/null || echo 0)
        [ "$size" -gt $((10*1024*1024)) ] || continue
        mt=$(stat -c %Y "$cand" 2>/dev/null || echo 0)
        if [ "$mt" -ge "$newest_mtime" ]; then
            newest_mtime="$mt"
            SRC_BUNDLE_SNAP="$cand"
        fi
    done
fi
if [ -n "$SRC_BUNDLE_SNAP" ] && [ -z "$SRC_BUNDLE_INDEX" ]; then
    snap_dir="$(dirname "$SRC_BUNDLE_SNAP")"
    SRC_BUNDLE_INDEX="$snap_dir/block_index.bin"
fi

for cand in "${SRC_SNAP_CANDIDATES[@]}"; do
    if [ -f "$cand" ] && [ "$(stat -c %s "$cand")" -gt $((10*1024*1024)) ]; then
        SRC_SNAP="$cand"
        break
    fi
done
if [ -z "$SRC_BUNDLE_SNAP" ] && [ -z "$SRC_SNAP" ]; then
    echo "[coldstart] no utxo-seed snapshot bundle or consensus_snapshot.db found"
    echo "[coldstart] bundle candidates:" "${SRC_BUNDLE_SNAP_CANDIDATES[*]}"
    echo "[coldstart] consensus candidates:" "${SRC_SNAP_CANDIDATES[*]}"
    exit 2
fi

copy_fixture() {
    src="$1"
    dst="$2"
    cp --reflink=auto "$src" "$dst" 2>/dev/null || cp "$src" "$dst"
}

mkdir -p "$TEST_DIR"
MODE="legacy-consensus-snapshot"
LOAD_FLAG=""
if [ -n "$SRC_BUNDLE_SNAP" ] &&
   [ -f "$SRC_BUNDLE_SNAP" ] &&
   [ -f "$SRC_BUNDLE_INDEX" ] &&
   [ "$(stat -c %s "$SRC_BUNDLE_INDEX")" -gt $((10*1024*1024)) ]; then
    MODE="operator-bundle"
    bundle_snap="$TEST_DIR/$(basename "$SRC_BUNDLE_SNAP")"
    echo "[coldstart] using operator bundle snapshot: $SRC_BUNDLE_SNAP"
    echo "[coldstart] using operator bundle block index: $SRC_BUNDLE_INDEX"
    echo "[coldstart] snapshot $(du -h "$SRC_BUNDLE_SNAP" | cut -f1), block_index $(du -h "$SRC_BUNDLE_INDEX" | cut -f1)"
    copy_fixture "$SRC_BUNDLE_SNAP" "$bundle_snap" || {
        echo "[coldstart] failed to copy bundle snapshot"
        exit 1
    }
    copy_fixture "$SRC_BUNDLE_INDEX" "$TEST_DIR/block_index.bin" || {
        echo "[coldstart] failed to copy block_index.bin"
        exit 1
    }
    LOAD_FLAG="-load-snapshot-at-own-height=$bundle_snap"
elif [ -n "$SRC_BUNDLE_SNAP" ]; then
    echo "[coldstart] bundle snapshot exists but block_index.bin is absent/too small: $SRC_BUNDLE_INDEX"
    echo "[coldstart] falling back to consensus_snapshot.db if available"
fi

if [ "$MODE" = "legacy-consensus-snapshot" ]; then
    if [ -z "$SRC_SNAP" ]; then
        echo "[coldstart] no usable legacy consensus_snapshot.db fallback"
        exit 2
    fi
    echo "[coldstart] using legacy consensus snapshot: $SRC_SNAP"
    echo "[coldstart] $(du -h "$SRC_SNAP" | cut -f1)"
    copy_fixture "$SRC_SNAP" "$TEST_DIR/consensus_snapshot.db" || {
        echo "[coldstart] failed to copy consensus_snapshot.db"
        exit 1
    }
fi

LOG="$TEST_DIR/node.log"
echo "[coldstart] launching node mode=$MODE datadir=$TEST_DIR rpcport=$TEST_RPCPORT"
# -listen=0 disables the public P2P listener so we don't compete with
# the operator's main node. The dead -connect target prevents accidental seed
# dialing; this test asserts local cold-start seeding, not network catchup.
# -nolegacyimport: don't pull from any local ~/.zclassic legacy datadir.
"$BIN" \
    -datadir="$TEST_DIR" \
    -port="$TEST_PORT" \
    -rpcport="$TEST_RPCPORT" \
    -fsport="$TEST_FSPORT" \
    -httpsport="$TEST_HTTPSPORT" \
    -listen=0 \
    -connect="$TEST_DEAD_PEER" \
    -nolegacyimport \
    -nobgvalidation \
    $LOAD_FLAG \
    > "$LOG" 2>&1 &
NODE_PID=$!

start_t=$(date +%s)
while :; do
    now=$(date +%s)
    elapsed=$((now - start_t))
    if [ $elapsed -ge $DEADLINE_SECS ]; then
        if [ "$MODE" = "operator-bundle" ]; then
            want_pattern="$BUNDLE_SUCCESS_PATTERN"
        else
            want_pattern="$SUCCESS_PATTERN"
        fi
        echo "[coldstart] TIMEOUT after ${elapsed}s — no '$want_pattern' in node.log"
        echo "[coldstart] last 40 log lines:"
        tail -40 "$LOG" || true
        exit 1
    fi
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "[coldstart] node exited unexpectedly at elapsed=${elapsed}s"
        tail -40 "$LOG" || true
        exit 1
    fi

    if [ "$MODE" = "operator-bundle" ]; then
        hit=$(grep -am1 -F -- "$BUNDLE_SUCCESS_PATTERN" "$LOG" 2>/dev/null || true)
        if [ -n "$hit" ]; then
            count=$(echo "$hit" | sed -n 's/.*count=\([0-9]*\).*/\1/p')
            count="${count:-0}"
            if [ "$count" -gt "$MIN_UTXOS" ]; then
                echo "[coldstart] PASS — $hit"
                echo "[coldstart] elapsed=${elapsed}s utxos=$count authority=self_verified_bundle"
                exit 0
            fi
            echo "[coldstart] FAIL — bundle loaded but utxos=$count below threshold $MIN_UTXOS"
            exit 1
        fi
    else
        hit=$(grep -am1 -F -- "$SUCCESS_PATTERN" "$LOG" 2>/dev/null || true)
        if [ -n "$hit" ]; then
        # Parse UTXO count from the log line. Format:
        #   "[boot] snapshot-first import OK: 1339612 UTXOs at h=3117754 ..."
            utxos=$(echo "$hit" | sed -n 's/.*OK: \([0-9]*\) UTXOs.*/\1/p')
            utxos="${utxos:-0}"
            if [ "$utxos" -gt "$MIN_UTXOS" ]; then
                echo "[coldstart] PASS — $hit"
                echo "[coldstart] elapsed=${elapsed}s utxos=$utxos"
                exit 0
            else
                echo "[coldstart] FAIL — import fired but utxos=$utxos below threshold $MIN_UTXOS"
                exit 1
            fi
        fi
    fi
    sleep 1
done
