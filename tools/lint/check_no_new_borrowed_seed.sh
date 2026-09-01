#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no NEW caller of coins_kv_seed_from_node_db (the BORROWED seed).
#
# coins_kv_seed_from_node_db COPIES zclassicd's chainstate (node.db `utxos`
# mirror) into coins_kv — the borrowed UTXO trust root the sovereign cure
# (docs/work/self-verified-tip-plan.md Act 3) exists to DELETE in favour of a
# self-derived (from-anchor minted snapshot / from-genesis bodies) fold. While
# the cutover is in flight the borrow still has a few legitimate callers; this
# ratchet keeps that set SHRINK-ONLY so the borrow cannot proliferate into new
# code paths before it is removed.
#
# A caller is any .c file (outside the definition file + the test tree) with a
# paren-call `coins_kv_seed_from_node_db(`. Every caller MUST be listed in
# tools/lint/borrowed_seed_caller_baseline.txt. A NEW caller FAILS the gate.
# To clean up debt: delete a caller, remove its baseline line, re-run make lint.
#
# Hollow-gate guard: if the symbol no longer exists in the definition file
# (deleted or renamed) the gate exits 2 — a vacuous gate is a weakened gate.
set -euo pipefail

# Run from repo root regardless of invocation dir (mirrors the other gates that
# take a "." root arg; default to the script's grandparent).
ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

BASELINE=tools/lint/borrowed_seed_caller_baseline.txt
DEF_FILE=engine/modules/storage/src/coins_kv_boot_rebuild.c
SYMBOL='coins_kv_seed_from_node_db('

# Hollow-gate guard: the symbol must still be defined where we expect it.
if [ ! -f "$DEF_FILE" ] || ! grep -q "$SYMBOL" "$DEF_FILE"; then
    echo "check_no_new_borrowed_seed: FATAL — '$SYMBOL' no longer found in $DEF_FILE."
    echo "  - If the borrowed seed was DELETED (the sovereign cure landed), delete"
    echo "    this gate, its Makefile wiring, and $BASELINE."
    echo "  - If it was RENAMED/MOVED, update DEF_FILE/SYMBOL here so the ratchet"
    echo "    keeps firing. A gate that matches nothing is a hollow gate."
    exit 2
fi

declare -A baseline
baseline_count=0
gate_load_list_file "$BASELINE" baseline baseline_count

# All caller .c files (paren-call excludes the comment mentions, which use a
# space / a `)` after the name). Exclude the definition file and the test tree.
fail=0
new_callers=()
while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$f" = "$DEF_FILE" ] && continue
    case "$f" in tests/harness/include/test/*) continue ;; esac
    if [ -z "${baseline[$f]+x}" ]; then
        new_callers+=("$f")
        fail=1
    fi
done < <(grep -rl --include='*.c' "$SYMBOL" \
    core engine contexts cognition platform tools \
    "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null | sort -u)

# Also flag a STALE baseline entry (a listed caller that no longer calls it):
# keep the ratchet honest so deletions are reflected, not silently grandfathered.
stale=()
for b in "${!baseline[@]}"; do
    if [ ! -f "$b" ] || ! grep -q "$SYMBOL" "$b"; then
        stale+=("$b")
    fi
done

if [ "$fail" = "0" ] && [ "${#stale[@]}" = "0" ]; then
    echo "check_no_new_borrowed_seed: clean — ${baseline_count} grandfathered caller(s), no new ones"
    exit 0
fi

echo ""
if [ "${#new_callers[@]}" -gt 0 ]; then
    echo "check_no_new_borrowed_seed: ${#new_callers[@]} NEW caller(s) of the borrowed seed:"
    for v in "${new_callers[@]}"; do echo "  $v"; done
    echo ""
    echo "Do NOT add a new coins_kv_seed_from_node_db caller — the borrow is being"
    echo "DELETED (the self-verified-tip cure). Self-derive the coin set (from the"
    echo "minted anchor snapshot / a from-genesis fold) instead. If a caller is"
    echo "genuinely unavoidable for now, add its path to $BASELINE (last resort)."
fi
if [ "${#stale[@]}" -gt 0 ]; then
    echo "check_no_new_borrowed_seed: ${#stale[@]} STALE baseline entry(ies) (no longer call it):"
    for s in "${stale[@]}"; do echo "  $s"; done
    echo ""
    echo "A caller was removed — good. Delete its line from $BASELINE so the"
    echo "ratchet reflects the smaller set."
fi
exit 1
