#!/usr/bin/env bash
# Gate: HONEST WITNESS (Law 7 — "heal in the open, page when stuck").
#
# A Condition is (detect, remedy, witness). Law 7's hard rule: "a remedy
# that returns ok without moving the symptom is a LIE — forbidden." The
# witness is the post-condition that decides whether the symptom actually
# MOVED. If the witness only observes that the poison the remedy deleted is
# gone, or only re-reads an FSM state the remedy itself force-set, it can
# self-certify "cleared" on every tick while the tip stays frozen. That is
# the exact Law-7 lie W2 fixed for stale_validate_headers_repair /
# peer_floor_violated / sync_state_stuck. This gate stops it regressing.
#
# For each `static bool witness_<name>(...)` in engine/conditions/src/*.c the
# gate fails the witness if ANY of:
#   (1) TRIVIAL    — every return is a bare `return true;` / `return false;`
#                    (a constant post-condition observes nothing).
#   (2) PURE-INVERSE — the body is `return !detect_<x>();` (or `!= detect_`),
#                    i.e. it just re-runs detect. "The poison I named is gone"
#                    is a tautology, not forward progress.
#   (3) NO-OBSERVABLE — the body references NONE of the observable-progress
#                    tokens below. An honest witness must read OBSERVABLE
#                    progress (active_chain_height / block_map iteration / a
#                    durable SELECT / a bounded external-state read), not just
#                    poison-absence or FSM state.
#
# Per-witness escape hatch: add `// honest-witness-ok:<reason>` on a line
# inside the witness body for a documented, reviewed exception.
#
# Mode: WARN | RATCHET | FAIL (controlled by ZCL_LINT_MODE; default WARN).
#   WARN    — report violations, always exit 0 (Phase 0 measurement).
#   RATCHET — fail only on a witness NOT listed in
#             honest_witness_baseline.txt. Baselined witnesses are tolerated;
#             the baseline may only shrink. (E10 graduation mode.)
#   FAIL    — fail on ANY violation, baseline ignored.
#
# The exemplar honest witness is engine/conditions/src/block_failed_mask_at_tip.c
# (`current_tip_height(ms) > g_tip_at_detect` — the tip MOVED).
set -euo pipefail

MODE="${ZCL_LINT_MODE:-WARN}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASELINE="$SCRIPT_DIR/honest_witness_baseline.txt"
COND_DIR="engine/conditions/src"

cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

# Observable-progress tokens. An honest witness must reference at least one:
# real height/cursor advance, reducer-frontier H*, block_map iteration, a
# durable SELECT, or a bounded external-state read (peer height, inflight stats,
# mirror height).
# Deliberately NOT here: sync_get_state()/current_state() FSM reads and
# poison-flag reads (read_drift_flag, *_paused_height, snapsync *.failed) —
# those observe FSM/poison-absence, not that the symptom moved.
OBSERVABLE_RE='active_chain_height|active_chain_tip|current_tip_height|reducer_frontier_compute_hstar|reducer_frontier_provable_tip_cached|block_map_next|block_map_get|pindex_best_header|->nHeight|\.nHeight|connman_max_peer_height|connman_outbound_healthy_count|dl_get_stats|\.local_height|s\.local_height|stage_repair_body_fetch_observed|block_index_have_data_readable|any_utxo_above|target_has_readable_data|sync_monitor_active_next_child_exists|sqlite3_step|sqlite3_prepare|[[:space:]]SELECT[[:space:]]|offered_height|offered_utxos|staged_row_count|received_utxos|\brequested\b'

# Load baseline (set of witness names allowed to be dishonest, grandfathered).
declare -A BASELINED=()
gate_load_list_file "$BASELINE" BASELINED

scanned=0
violations=0
baselined_hits=0

if [[ -d "$COND_DIR" ]]; then
  while IFS= read -r file; do
    # Extract every witness function body: from the `static bool witness_`
    # opener through its closing `}` at column 0.
    while IFS= read -r witness_name; do
        [[ -z "$witness_name" ]] && continue
        scanned=$((scanned + 1))

        # The witness function body (opener line through column-0 `}`).
        body=$(awk -v fn="bool $witness_name(" '
            index($0, fn) { flag = 1 }
            flag { print }
            flag && /^}$/ { exit }
        ' "$file")

        # Documented per-witness exception.
        if grep -q '// honest-witness-ok:' <<< "$body"; then
            continue
        fi

        # Code lines only: strip // and block-comment * lines and the
        # (void)target_at_detect cast line.
        code=$(grep -v '^[[:space:]]*//' <<< "$body" \
             | grep -v '^[[:space:]]*\*' \
             | grep -v '(void)target_at_detect')

        reason=""

        # (1) TRIVIAL: there is at least one `return true/false;` and there
        # is NO return that is anything other than a bare true/false constant.
        bare_ret=$(grep -Ec '\breturn (true|false);' <<< "$code" || true)
        other_ret=$(grep -E '\breturn\b' <<< "$code" \
                  | grep -Evc '\breturn (true|false);' || true)
        if (( bare_ret > 0 && other_ret == 0 )); then
            reason="TRIVIAL (constant post-condition observes nothing)"
        fi

        # (2) PURE-INVERSE: body just re-runs detect (return !detect_x() or
        # a comparison against detect_x()).
        if [[ -z "$reason" ]] && \
           grep -Eq 'return[[:space:]]+!?[[:space:]]*detect_|[!=]=[[:space:]]*detect_' <<< "$code"; then
            reason="PURE-INVERSE (re-runs detect; tautology, not progress)"
        fi

        # (3) NO-OBSERVABLE: references no observable-progress token.
        if [[ -z "$reason" ]] && ! grep -Eq "$OBSERVABLE_RE" <<< "$code"; then
            reason="NO-OBSERVABLE (reads only FSM/poison-absence state)"
        fi

        [[ -z "$reason" ]] && continue

        if [[ "$MODE" == "RATCHET" && -n "${BASELINED[$witness_name]:-}" ]]; then
            baselined_hits=$((baselined_hits + 1))
            continue
        fi
        violations=$((violations + 1))
        echo "$file: $witness_name: $reason" >&2
    done < <(grep -oE '^static (inline )?bool +witness_[A-Za-z0-9_]+' "$file" \
             | grep -oE 'witness_[A-Za-z0-9_]+')
  done < <(find "$COND_DIR" -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}" | sort)
fi

# Fail-loud if the producer found NOTHING while condition sources exist. A
# silent "scanned 0 -> 0 violations -> clean" is the fail-silent hole this
# never-lie gate must not have: a witness-signature convention change (e.g.
# adding a qualifier the producer doesn't match) would otherwise skip every
# witness with CI green. (The producer now tolerates `static [inline] bool`.)
if [[ -d "$COND_DIR" ]] && compgen -G "$COND_DIR/*.c" >/dev/null && (( scanned == 0 )); then
    echo "[check_honest_witness] BROKEN — 0 witnesses found in $COND_DIR despite .c" >&2
    echo "  files present; the producer/anchor is likely stale (witness signature" >&2
    echo "  convention changed?). Refusing to report clean off an empty scan." >&2
    exit 2
fi

echo "[check_honest_witness] scanned $scanned witness(es) in $COND_DIR"
echo "[check_honest_witness] $violations violation(s) found (mode: $MODE)"
if (( baselined_hits > 0 )); then
    echo "[check_honest_witness] $baselined_hits baselined violation(s) ignored"
fi
echo "[check_honest_witness] an honest witness reads OBSERVABLE progress (tip/cursor/H*/block_map/SELECT), never poison-absence or FSM state"
echo "[check_honest_witness] document a reviewed exception with // honest-witness-ok:<reason>; baseline at tools/lint/honest_witness_baseline.txt (ratchet may only shrink)"

if (( violations > 0 )) && [[ "$MODE" == "FAIL" || "$MODE" == "RATCHET" ]]; then
    exit 1
fi
exit 0
