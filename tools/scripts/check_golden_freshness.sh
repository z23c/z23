#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Golden-table tip-coverage-lag check (item 2b of the golden immutable-
# history evidence wiring lane).
#
# test_golden_staleness_canary (tests/harness/src/test_golden_staleness_canary.c)
# already catches a REGRESSION that silently drops entries from the
# compiled SHA3 window table / UTXO root ladder — that runs hermetically in
# every `make ci` / `make test`. What it CANNOT catch is the golden tables
# simply never being re-minted again even though the real chain keeps
# growing: nothing "dropped", the tables are just increasingly stale. That
# decay only shows up by comparing the highest height the compiled tables
# actually corroborate against the REAL current chain tip — which needs a
# live node, so it belongs in the NIGHTLY sweep (`make simnet-nightly`),
# never in hermetic CI.
#
# Env-gated OFF by default (ZCL_GOLDEN_FRESHNESS=1 to run) so a plain `make
# simnet-nightly` on a dev box with no live node — or a CI runner — stays a
# clean SKIP, never a false FAIL. The systemd nightly timer
# (deploy/zclassic23-simnet-nightly.*) is the intended caller once the
# operator wants this to actually page.
#
# No new binary: parses the two generated golden-table .c files as text
# (they are simple, machine-generated `const ... = N;` declarations — see
# tools/gen_sha3_windows.c / tools/gen_utxo_root_ladder.c) and reads the
# current chain tip via the same zclassic-cli RPC convention every other
# operator script in tools/scripts/ uses (see tools/scripts/lane_health.sh).
set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "${ZCL_GOLDEN_FRESHNESS:-0}" != "1" ]; then
    echo "golden_freshness: SKIP (set ZCL_GOLDEN_FRESHNESS=1 to run — nightly-only, pages golden-table tip-coverage decay)"
    exit 0
fi

LAG_MAX="${ZCL_GOLDEN_FRESHNESS_LAG_MAX:-70000}"

SHA3_SRC=core/modules/chain/src/sha3_windows.c
SHA3_HDR=core/modules/chain/include/chain/sha3_windows.h
LADDER_SRC=core/modules/chain/src/utxo_root_ladder.c

# ── Highest height either golden table actually corroborates ──────────────
sha3_count=$(sed -n 's/.*g_sha3_windows_count = \([0-9][0-9]*\).*/\1/p' "$SHA3_SRC" | head -1)
sha3_window_size=$(sed -n 's/.*#define SHA3_WINDOW_SIZE \([0-9][0-9]*\).*/\1/p' "$SHA3_HDR" | head -1)
sha3_count="${sha3_count:-0}"
sha3_window_size="${sha3_window_size:-1000}"

sha3_max_covered=-1
if [ "$sha3_count" -gt 0 ]; then
    sha3_max_covered=$(( sha3_count * sha3_window_size - 1 ))
fi

ladder_max=-1
for h in $(grep -oE '^\s*\{ *[0-9]+' "$LADDER_SRC" | grep -oE '[0-9]+' || true); do
    if [ "$h" -gt "$ladder_max" ]; then ladder_max="$h"; fi
done
dense_h=$(sed -n 's/.*g_utxo_root_ladder_dense_height = \(-\{0,1\}[0-9][0-9]*\).*/\1/p' "$LADDER_SRC" | head -1)
dense_h="${dense_h:--1}"
if [ "$dense_h" -gt "$ladder_max" ]; then ladder_max="$dense_h"; fi

golden_max=$sha3_max_covered
if [ "$ladder_max" -gt "$golden_max" ]; then golden_max=$ladder_max; fi

if [ "$golden_max" -lt 0 ]; then
    echo "golden_freshness: SKIP (no golden coverage compiled in — placeholder tables, nothing to check yet)"
    exit 0
fi

# ── Current REAL chain tip (live node RPC; never fabricated) ──────────────
ZCL_CLI="${ZCL_CLI:-build/bin/zclassic-cli}"
DATADIR="${ZCL_GOLDEN_FRESHNESS_DATADIR:-$HOME/.zclassic-c23}"
RPCPORT="${ZCL_GOLDEN_FRESHNESS_RPCPORT:-18232}"

tip="${ZCL_GOLDEN_FRESHNESS_TIP:-}"
if [ -z "$tip" ] && [ -x "$ZCL_CLI" ]; then
    tip="$(timeout 5 "$ZCL_CLI" -datadir="$DATADIR" -rpcport="$RPCPORT" getblockcount 2>/dev/null || true)"
fi

if [ -z "$tip" ] || ! [[ "$tip" =~ ^[0-9]+$ ]]; then
    echo "golden_freshness: SKIP (no live node reachable at $DATADIR:$RPCPORT to read the current chain tip — set ZCL_GOLDEN_FRESHNESS_TIP=<height> to force a check without one)"
    exit 0
fi

lag=$(( tip - golden_max ))
echo "golden_freshness: tip=$tip golden_covered_max=$golden_max lag=$lag (fail-over=$LAG_MAX)"

if [ "$lag" -gt "$LAG_MAX" ]; then
    echo "==> golden_freshness FAILED (golden tables are $lag blocks behind the live tip, over the ${LAG_MAX}-block ceiling — re-mint tools/gen_sha3_windows and/or tools/gen_utxo_root_ladder)"
    exit 1
fi

echo "==> golden_freshness PASSED"
