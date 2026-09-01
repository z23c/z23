#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no NEW production caller of stage_repair_coin_backfill_try.
#
# The coin-backfill repair ladder is a borrowed-seed-era cure path that should
# shrink after the self-verified UTXO anchor rebuild cutover
# (-refold-from-anchor). Keep the runtime entry point owned by reducer_frontier
# only; new production callers widen the repair fabric and must fail review. A
# second call in the allowed file also fails so the allowed surface remains
# exact, not "anything from this file".
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# The self-test points this gate at a complete isolated fixture tree. Keeping
# that tree out of the tracked source directories prevents the gate proof from
# waking the long-lived development watcher and recursively launching CI.
ROOT="${ZCL_COIN_BACKFILL_ROOT_FOR_TEST:-${1:-$SCRIPT_ROOT}}"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source "$SCRIPT_ROOT/tools/lint/scan_exclusions.sh"

SYMBOL='stage_repair_coin_backfill_try('
DEF_FILE='engine/jobs/src/stage_repair_coin_backfill.c'
ALLOWED_FILE='engine/reducer/jobs/src/stage_repair_reducer_frontier_coin.c'

if [ ! -f "$DEF_FILE" ] || ! grep -qF "$SYMBOL" "$DEF_FILE"; then
    echo "check_no_new_coin_backfill_caller: FATAL — '$SYMBOL' no longer found in $DEF_FILE."
    echo "  - If the coin-backfill ladder was deleted, remove this gate and its Makefile wiring."
    echo "  - If it moved or was renamed, update DEF_FILE/SYMBOL so the ratchet keeps firing."
    exit 2
fi

bad=()
allowed_count=0
SCAN_ROOTS=(core engine contexts cognition platform tools)
while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$f" = "$DEF_FILE" ] && continue
    case "$f" in tests/harness/include/test/*) continue ;; esac

    count=$(grep -oF "$SYMBOL" "$f" | wc -l | tr -d ' ')
    if [ "$f" = "$ALLOWED_FILE" ]; then
        allowed_count=$((allowed_count + count))
    else
        bad+=("$f:$count")
    fi
done < <(grep -rlF --include='*.c' "$SYMBOL" "${SCAN_ROOTS[@]}" "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null | sort -u)

if [ "${#bad[@]}" = "0" ] && [ "$allowed_count" = "1" ]; then
    echo "check_no_new_coin_backfill_caller: clean — one allowed production caller"
    exit 0
fi

echo ""
if [ "$allowed_count" != "1" ]; then
    echo "check_no_new_coin_backfill_caller: expected exactly 1 call in $ALLOWED_FILE, found $allowed_count"
fi
if [ "${#bad[@]}" -gt 0 ]; then
    echo "check_no_new_coin_backfill_caller: NEW production caller(s) of $SYMBOL:"
    for v in "${bad[@]}"; do echo "  $v"; done
fi
echo ""
echo "Do NOT add another coin-backfill repair entry caller. Route reducer-frontier"
echo "repair evidence through the existing dispatcher, or delete/shrink this ladder"
echo "after the self-verified UTXO anchor rebuild cure (-refold-from-anchor)."
exit 1
