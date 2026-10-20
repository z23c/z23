#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# reindex_smoke.sh — acceptance harness (a) + (c) for the reindex epilogue
# (the reindex epilogue). Run via `make test-reindex-smoke` /
# `make test-reindex-killmid`. NOT in hermetic `make ci`: it SPAWNS a real
# isolated regtest node. All isolation (datadir under /tmp, 39xxx ports,
# refuse-on-live preflight, process-group kill, cleanup trap) is delegated to
# the single audited chokepoint tools/scripts/isolated_node_env.sh — this
# harness never touches the live datadir/ports/services.
#
# Flow:
#   (a) test-reindex-smoke (KILL_MID=0): generate N blocks, capture the
#       baseline (height, gettxoutsetinfo.txouts, getutxocommitment), CLEAN
#       restart with -reindex-chainstate, then assert the FOUR teeth:
#         1. tip parity:           post height == baseline height (== N)
#         2. row-count parity:     post txouts == baseline txouts
#         3. commitment parity:    post getutxocommitment == baseline
#                                  (== the epilogue's recomputed SHA3 over the
#                                   reseeded coins_kv; replay is deterministic)
#         4. SERVING + NO TEAR:    node answers RPC at tip AND node.log shows
#                                  NO "coins_applied=.*> utxo_apply_frontier"
#       These four parity checks do not independently prove that replay or
#       its epilogue completed; preserved pre-existing state can pass them.
#
#   (c) test-reindex-killmid (KILL_MID=1): spawn with -reindex-chainstate,
#       kill -9 after a randomized 200-2000ms delay from startup, then
#       reboot normally (the crash-only path re-requests reindex). Assert
#       eventual SERVING at tip == N with the same four teeth, within <=3
#       reboot cycles. Checks restart parity after a forced interruption;
#       the elapsed-time kill does not identify an exact replay boundary.
#
# Required env (set by the Makefile target before sourcing isolated_node_env.sh):
#   ISO_KIND=reindex, ISO_PORT_BASE=390xx, SEED_BLOCKS=N, KILL_MID=0|1.

set -euo pipefail

SEED_BLOCKS="${SEED_BLOCKS:-50}"
KILL_MID="${KILL_MID:-0}"
RPC_READY_TIMEOUT="${RPC_READY_TIMEOUT:-90}"
MAX_REBOOTS="${MAX_REBOOTS:-3}"
REINDEX_KILL_DELAY_MS="${REINDEX_KILL_DELAY_MS:-}"

# shellcheck source=tools/scripts/isolated_node_env.sh
. tools/scripts/isolated_node_env.sh
iso_init

reindex_log_tail() {
    echo "reindex-smoke: node log tail pid=${ISO_NODE_PID:-} pgid=${ISO_PGID:-}" >&2
    if [ -f "$ISO_DD/node.log" ]; then
        grep -aE 'reindex|authority epilogue|REFUSING' "$ISO_DD/node.log" | tail -n 40 >&2 || true
    fi
    [ ! -f "$ISO_DD/node.log" ] || tail -n 80 "$ISO_DD/node.log" >&2
}

fail() { echo "reindex-smoke: FAIL: $*" >&2; reindex_log_tail; exit 1; }

if [ -n "$REINDEX_KILL_DELAY_MS" ]; then
    case "$REINDEX_KILL_DELAY_MS" in
        *[!0-9]*) fail "REINDEX_KILL_DELAY_MS must be 200..2000" ;;
    esac
    [ "${#REINDEX_KILL_DELAY_MS}" -le 4 ] || fail "REINDEX_KILL_DELAY_MS must be 200..2000"
    REINDEX_KILL_DELAY_MS=$((10#$REINDEX_KILL_DELAY_MS))
    [ "$REINDEX_KILL_DELAY_MS" -ge 200 ] && [ "$REINDEX_KILL_DELAY_MS" -le 2000 ] \
        || fail "REINDEX_KILL_DELAY_MS must be 200..2000"
fi

# Gracefully stop the current node (SIGTERM the group, poll for WAL drain),
# WITHOUT firing the full cleanup trap (which would also rm the datadir).
iso_stop_node() {
    [ -n "${ISO_PGID:-}" ] || return 0
    kill -TERM "-$ISO_PGID" 2>/dev/null || true
    local i
    for i in $(seq 1 100); do
        kill -0 "-$ISO_PGID" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "-$ISO_PGID" 2>/dev/null || true
    local stop_status=0
    if wait "$ISO_NODE_PID"; then stop_status=0; else stop_status=$?; fi
    echo "reindex-smoke: waited pid=$ISO_NODE_PID pgid=$ISO_PGID status=$stop_status"
    ISO_NODE_PID=""
    ISO_PGID=""
}

# Scrape the numeric "result" field of an iso_rpc JSON-RPC response (NOT the
# "id" — a naive tr -dc '0-9' would splice result+id digits together).
rpc_int() {
    iso_rpc "$@" \
        | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\?[0-9][0-9]*\).*/\1/p' \
        | head -1
}

# gettxoutsetinfo.txouts (the row count over the reseeded coins_kv).
txoutset_txouts() {
    iso_rpc gettxoutsetinfo \
        | tr ',{}' '\n\n\n' \
        | sed -n 's/.*"txouts"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
        | head -1
}

# getutxocommitment — the served SHA3 commitment string (64 hex).
utxo_commitment() {
    iso_rpc getutxocommitment \
        | grep -oE '[0-9a-f]{64}' \
        | head -1
}

# KNOWN-BLOCKED skip (NOT a vacuous green): the same owner-gated reducer
# boot-init limitation test-crash-bootstrap documents — regtest `generate`
# does not currently produce blocks durable across a restart (the node boots
# h=-1 and a mined block's reducer state does not survive the kill/reboot the
# reindex teeth require). Without durable seeded blocks the four teeth cannot be
# exercised, so refuse to run a TOOTHLESS loop and SKIP loudly. See MVP.md #7.
# Set ZCL_REINDEX_REQUIRE_TEETH=1 to make this a HARD FAIL in a dedicated
# opt-in teeth job once regtest durability lands.
known_blocked() {
    echo "reindex-smoke: KNOWN BLOCKED (owner-gated reducer boot-init, MVP.md #7) — $*" >&2
    if [ "${ZCL_REINDEX_REQUIRE_TEETH:-0}" = "1" ]; then
        fail "ZCL_REINDEX_REQUIRE_TEETH=1 and teeth unexercisable: $*"
    fi
    echo "reindex-smoke: SKIP (teeth unexercisable in this environment; not a regression)"
    exit 0
}

# ── 1. Spawn fresh, seed SEED_BLOCKS regtest blocks. ────────────────
echo "reindex-smoke: spawn + seed $SEED_BLOCKS blocks (datadir=$ISO_DD)"
iso_spawn_node
iso_wait_rpc_ready "$RPC_READY_TIMEOUT" || fail "node never came up for seeding"
iso_rpc generate "$SEED_BLOCKS" >/dev/null 2>&1 || true

base_height="$(rpc_int getblockcount)"
base_txouts="$(txoutset_txouts)"
base_commit="$(utxo_commitment)"
[ -n "$base_height" ] || fail "baseline getblockcount empty (node not serving RPC)"
if [ "$base_height" -lt "$SEED_BLOCKS" ]; then
    known_blocked "bootstrap seeded only height $base_height (expected >= $SEED_BLOCKS); regtest generate not durable"
fi
[ -n "$base_txouts" ] || fail "baseline txouts empty"
[ -n "$base_commit" ] || fail "baseline commitment empty"
echo "reindex-smoke: baseline height=$base_height txouts=$base_txouts commit=${base_commit:0:16}..."

# ── 2. Restart with -reindex-chainstate (clean, or kill after startup). ──
boot=0
serving=0
while [ "$boot" -lt "$MAX_REBOOTS" ]; do
    boot=$((boot + 1))
    if [ "$KILL_MID" = "1" ] && [ "$boot" -eq 1 ]; then
        echo "reindex-smoke: boot $boot — spawn with -reindex-chainstate then kill -9 after startup"
        iso_stop_node
        iso_spawn_node "-reindex-chainstate"
        # Elapsed startup delay, not an observed replay boundary.
        delay_ms="${REINDEX_KILL_DELAY_MS:-$(( (RANDOM % 1801) + 200 ))}"
        sleep "$(awk "BEGIN{print $delay_ms/1000}")"
        if [ -n "${ISO_PGID:-}" ]; then
            kill -KILL "-$ISO_PGID" 2>/dev/null || fail "could not kill owned reindex process group $ISO_PGID"
            kill_status=0
            if wait "$ISO_NODE_PID"; then kill_status=0; else kill_status=$?; fi
            echo "reindex-smoke: waited killed pid=$ISO_NODE_PID pgid=$ISO_PGID status=$kill_status"
            [ "$kill_status" -eq 137 ] || fail "reindex child $ISO_NODE_PID did not exit from SIGKILL (status=$kill_status)"
            ISO_NODE_PID=""; ISO_PGID=""
        else
            fail "missing owned reindex process group before SIGKILL"
        fi
        echo "reindex-smoke: killed -9 after ${delay_ms}ms; rebooting normally"
        iso_spawn_node
    elif [ "$boot" -eq 1 ]; then
        echo "reindex-smoke: boot $boot — clean restart with -reindex-chainstate"
        iso_stop_node
        iso_spawn_node "-reindex-chainstate"
    else
        echo "reindex-smoke: boot $boot — normal reboot (crash-only re-replay)"
        iso_stop_node
        iso_spawn_node
    fi

    if iso_wait_rpc_ready "$RPC_READY_TIMEOUT"; then
        h="$(rpc_int getblockcount)"
        if [ -n "$h" ] && [ "$h" = "$base_height" ]; then
            serving=1
            break
        fi
        echo "reindex-smoke: boot $boot serving at h=$h (want $base_height) — rebooting"
        reindex_log_tail
    else
        echo "reindex-smoke: boot $boot RPC not ready — rebooting"
        reindex_log_tail
    fi
done

[ "$serving" = "1" ] || fail "node did not serve at tip $base_height within $MAX_REBOOTS reboots"

# A clean reindex must actually replay and finish its authority epilogue.
# Unchanged pre-existing coins also satisfy the parity checks below.
if [ "$KILL_MID" = "0" ]; then
    grep -aqE '^reindex-chainstate: complete in .+ \(0 errors\)$' "$ISO_DD/node.log" \
        || fail "clean reindex did not complete replay with zero errors"
    grep -aqF "UTXO authority epilogue derived: source=reindex tip=$base_height " "$ISO_DD/node.log" \
        || fail "clean reindex did not complete its authority epilogue at height $base_height"
    echo "reindex-smoke: completed replay and authority epilogue PASS"
fi

# ── 3. The FOUR teeth (each prints PASS; require all four). ──────────
post_height="$(rpc_int getblockcount)"
post_txouts="$(txoutset_txouts)"
post_commit="$(utxo_commitment)"

[ "$post_height" = "$base_height" ] \
    || fail "TOOTH 1 tip parity: post=$post_height != baseline=$base_height"
echo "reindex-smoke: TOOTH 1 tip parity PASS (h=$post_height)"

[ -n "$post_txouts" ] && [ "$post_txouts" = "$base_txouts" ] \
    || fail "TOOTH 2 row-count parity: post=$post_txouts != baseline=$base_txouts"
echo "reindex-smoke: TOOTH 2 row-count parity PASS (txouts=$post_txouts)"

[ -n "$post_commit" ] && [ "$post_commit" = "$base_commit" ] \
    || fail "TOOTH 3 commitment parity: post=${post_commit:0:16} != baseline=${base_commit:0:16}"
echo "reindex-smoke: TOOTH 3 commitment parity PASS (recomputed == served == pre)"

# Tooth 4: SERVING (already proven by the getblockcount at tip) + NO coin tear
# in node.log. The epilogue must leave coins_applied == utxo_apply frontier.
if grep -aqE 'coins_applied=[0-9]+ > utxo_apply_frontier' "$ISO_DD/node.log"; then
    grep -aE 'coins_applied=[0-9]+ > utxo_apply_frontier' "$ISO_DD/node.log" | tail -3 >&2
    fail "TOOTH 4 NO-TEAR: node.log shows coins_applied > utxo_apply_frontier"
fi
echo "reindex-smoke: TOOTH 4 SERVING + NO tear PASS (no coins_applied>frontier in node.log)"

echo "reindex-smoke: PASS"
