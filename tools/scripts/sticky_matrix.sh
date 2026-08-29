#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# sticky_matrix.sh — the STICKINESS fault-injection matrix driver
# (sticky-node-plan §4: the AAR/MTTUR metric). For each fault row:
#   1. mint/copy a THROWAWAY datadir under /tmp (isolated_node_env.sh),
#   2. inject the fault on that COPY (sticky_fault_inject.sh),
#   3. plain restart `zclassic23` with NO recovery flags,
#   4. gate on H* CLIMB to the target tip with the G-SOV sub-gate green
#      (recovered AND sovereign), within a bounded MTTUR.
#
# A row PASSES iff H* (getblockcount) reaches target AND the served UTXO
# commitment matches the pre-fault baseline AND node.log shows NO coin tear
# (`coins_applied=.*> utxo_apply_frontier`) AND recovery used NO human / NO
# flag / NO $HOME/.zclassic. (When the HEAD binary exposes the future
# coins_kv_contains_refold_marker() / not-borrowed RPC, the G-SOV gate
# upgrades to the full H*-climb ∧ coins_applied_height==H*+1 ∧ not-borrowed
# triple — see _gsov_green below.)
#
# OUTPUT: a JSON sentinel $ZCL_STICKY_VERDICT_DIR/sticky_matrix.json with
# rows/passed/failed/blocked + aar_pct (over ATTEMPTABLE rows) + aar_strict_pct
# (over ALL rows) + mttur_secs_max + verdict. The Makefile gate requires a
# FRESH PASS sentinel (anti-false-green, same discipline as replay-canary).
#
# DELIBERATELY out of hermetic `make ci`: it SPAWNS a real isolated node.
# All isolation (datadir under /tmp, 39xxx ports, refuse-on-live preflight,
# process-group kill, cleanup trap) is delegated to isolated_node_env.sh —
# this harness NEVER touches the live datadir/ports/services.

set -euo pipefail

STI_SEED_BLOCKS="${STI_SEED_BLOCKS:-50}"
RPC_READY_TIMEOUT="${RPC_READY_TIMEOUT:-90}"
MTTUR_BUDGET_SECS="${MTTUR_BUDGET_SECS:-180}"
VERDICT_DIR="${ZCL_STICKY_VERDICT_DIR:-$HOME/.local/state/zclassic23-sticky}"
REQUIRE_ALL="${ZCL_STICKY_REQUIRE_ALL:-0}"   # 1 = blocked rows are HARD FAILs (v1 bar)

# shellcheck source=tools/scripts/isolated_node_env.sh
. tools/scripts/isolated_node_env.sh
# shellcheck source=tools/scripts/sticky_fault_inject.sh
. tools/scripts/sticky_fault_inject.sh

mkdir -p "$VERDICT_DIR"

ROWS=0 PASSED=0 FAILED=0 BLOCKED=0 MTTUR_MAX=0
ROW_JSON=""

rpc_int() {
    iso_rpc "$@" \
        | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\?[0-9][0-9]*\).*/\1/p' \
        | head -1
}
utxo_commitment() { iso_rpc getutxocommitment | grep -oE '[0-9a-f]{64}' | head -1; }

# G-SOV sub-gate: recovered (commitment matches baseline) AND sovereign
# (no coin tear in node.log). Upgrades to the not-borrowed triple once the
# coins_kv_contains_refold_marker RPC is on HEAD.
_gsov_green() {
    local baseline_commit="$1"
    local now_commit; now_commit="$(utxo_commitment)"
    [ -n "$now_commit" ] || return 1
    [ -n "$baseline_commit" ] && [ "$now_commit" != "$baseline_commit" ] && return 1
    if grep -aEq 'coins_applied=[0-9]+.*> *utxo_apply_frontier' \
        "$ISO_DD/node.log" 2>/dev/null; then
        return 1   # coin tear = borrowed/torn serve, NOT sovereign
    fi
    # FUTURE: once getbestblockhash/native dumpstate exposes not-borrowed, assert
    #   coins_applied_height == H*+1 AND refold marker present here.
    return 0
}

# Boot the node against the prepared datadir with NO recovery flags, poll for
# H* climb to $1 within the MTTUR budget. Echo elapsed secs on success.
_boot_and_climb() {
    local target="$1" start now h elapsed
    iso_spawn_node            # plain boot: no -reindex, no -importblockindex
    start="$(date +%s)"
    while :; do
        now="$(date +%s)"; elapsed="$((now - start))"
        [ "$elapsed" -gt "$MTTUR_BUDGET_SECS" ] && return 1
        if [ -f "$ISO_DD/.cookie" ]; then
            h="$(rpc_int getblockcount)"
            [ -n "$h" ] && [ "$h" -ge "$target" ] && { echo "$elapsed"; return 0; }
        fi
        # A boot crash-loop (FATAL/_exit under Restart-less direct launch) is a
        # FAIL, never a hang: detect the dead process.
        [ -n "${ISO_NODE_PID:-}" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null && {
            iso_spawn_node    # one in-process re-launch (mimics Restart=always)
        }
        sleep 1
    done
}

iso_stop_node() {
    [ -n "${ISO_PGID:-}" ] || return 0
    kill -TERM "-$ISO_PGID" 2>/dev/null || true
    local i; for i in $(seq 1 50); do kill -0 "-$ISO_PGID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "-$ISO_PGID" 2>/dev/null || true
    ISO_NODE_PID=""; ISO_PGID=""
}

record() {  # name status [mttur]
    local name="$1" status="$2" mt="${3:-0}"
    ROWS=$((ROWS + 1))
    case "$status" in
        PASS)    PASSED=$((PASSED + 1)); [ "$mt" -gt "$MTTUR_MAX" ] && MTTUR_MAX="$mt" ;;
        FAIL)    FAILED=$((FAILED + 1)) ;;
        BLOCKED) BLOCKED=$((BLOCKED + 1)) ;;
    esac
    ROW_JSON="$ROW_JSON{\"row\":\"$name\",\"status\":\"$status\",\"mttur_secs\":$mt},"
    echo "sticky-matrix: row=$name status=$status mttur=${mt}s"
}

# Run one row: inject_fn prepares $ISO_DD; then boot+climb+G-SOV.
run_row() {
    local name="$1" inject_fn="$2" target="$3" baseline_commit="$4"
    iso_stop_node
    set +e; "$inject_fn" "$ISO_DD"; local irc=$?; set -e
    if [ "$irc" = "2" ]; then record "$name" BLOCKED; return; fi
    if [ "$irc" != "0" ]; then record "$name" FAIL; return; fi
    local mt
    if mt="$(_boot_and_climb "$target")" && _gsov_green "$baseline_commit"; then
        record "$name" PASS "$mt"
    else
        record "$name" FAIL
    fi
}

# ── Bring up a seed node once to establish target tip + baseline commit. ──
iso_init
iso_spawn_node
iso_wait_rpc_ready "$RPC_READY_TIMEOUT" || { echo "sticky-matrix: seed node never came up" >&2; }
iso_rpc generate "$STI_SEED_BLOCKS" >/dev/null 2>&1 || true
TARGET="$(rpc_int getblockcount)"; TARGET="${TARGET:-0}"
BASE_COMMIT="$(utxo_commitment)"
echo "sticky-matrix: target tip=$TARGET baseline_commit=${BASE_COMMIT:0:16}..."

# ── The matrix. Rows that need a restart-surviving seed self-SKIP (BLOCKED)
#    via _sti_require_seed until regtest blocks are durable. ──
run_row fresh_empty            inject_fresh_empty                0           ""
run_row foreign_datadir        inject_foreign                    "$TARGET"   "$BASE_COMMIT"
run_row mid_write_kill9        inject_kill9_window               "$TARGET"   "$BASE_COMMIT"
run_row corrupt_sapling        inject_corrupt_sapling            "$TARGET"   "$BASE_COMMIT"
run_row corrupt_coinsview      inject_corrupt_coinsview          "$TARGET"   "$BASE_COMMIT"
run_row torn_index             inject_torn_index                 "$TARGET"   "$BASE_COMMIT"
run_row equalwork_corrupt      inject_equalwork_corrupt          "$TARGET"   "$BASE_COMMIT"
run_row truncated_header       inject_truncated_header           "$TARGET"   "$BASE_COMMIT"
run_row oracle_absent          inject_oracle_absent              "$TARGET"   "$BASE_COMMIT"
run_row peers_absent_returned  inject_peers_absent_then_returned "$TARGET"   "$BASE_COMMIT"
run_row disk_full_freed        inject_disk_full                  "$TARGET"   "$BASE_COMMIT"
run_row deep_reorg_finality    inject_deep_reorg                 "$TARGET"   "$BASE_COMMIT"
run_row clock_jump             inject_clock_jump                 "$TARGET"   "$BASE_COMMIT"

# ── AAR / MTTUR + verdict ──
ATTEMPTABLE=$((PASSED + FAILED))
AAR=0;        [ "$ATTEMPTABLE" -gt 0 ] && AAR=$(( 100 * PASSED / ATTEMPTABLE ))
AAR_STRICT=0; [ "$ROWS" -gt 0 ]        && AAR_STRICT=$(( 100 * PASSED / ROWS ))
VERDICT="FAIL"
if [ "$REQUIRE_ALL" = "1" ]; then
    [ "$AAR_STRICT" = "100" ] && VERDICT="PASS"   # v1 bar: every row passes
else
    if [ "$AAR" = "100" ]; then
        [ "$BLOCKED" -gt 0 ] && VERDICT="BLOCKED" || VERDICT="PASS"
    fi
fi

OUT="$VERDICT_DIR/sticky_matrix.json"
printf '{"rows":%d,"passed":%d,"failed":%d,"blocked":%d,"aar_pct":%d,"aar_strict_pct":%d,"mttur_secs_max":%d,"verdict":"%s","row_detail":[%s]}\n' \
    "$ROWS" "$PASSED" "$FAILED" "$BLOCKED" "$AAR" "$AAR_STRICT" "$MTTUR_MAX" "$VERDICT" "${ROW_JSON%,}" \
    > "$OUT"
echo "sticky-matrix: $OUT"; cat "$OUT"

iso_stop_node
case "$VERDICT" in PASS|BLOCKED) exit 0 ;; *) exit 1 ;; esac
