#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_model_column_drift.sh — a model must not hand-maintain the column
# indices of a multi-column row read (Makefile `check-model-column-drift`).
#
# ── The defect ─────────────────────────────────────────────────────────────
# A model that spells its row mapping out by hand carries the same column
# order in three places: a SQL column-name string, a read body with literal
# indices (AR_READ_BLOB(s, 0, ...) … AR_COL_INT(s, 14)), and a bind list with
# literal positions. Insert a column in the middle of the first and every
# index below it in the other two is wrong. There is no compiler error and no
# test failure unless a test happens to cover that exact field; the symptom is
# one field silently reading its neighbour's value, which looks like plausible
# data. This gate exists so a NEW model cannot reintroduce that shape.
#
# ── What is flagged ────────────────────────────────────────────────────────
# A model source file that reads TWO OR MORE DISTINCT literal column indices
# through AR_READ_BLOB / AR_READ_STR / AR_COL_INT / AR_COL_BYTES /
# AR_COL_TEXT / AR_COL_DOUBLE. Two distinct literal indices is the smallest
# thing that can drift relative to each other; a single-column scalar read
# (a COUNT, a SUM, one value column) cannot, and is not flagged.
#
# The fix is not to renumber carefully. It is to declare the model's fields
# once in app/models/include/models/def/<model>_fields.def and derive the
# column string, the read index and the bind position from that one list —
# see app/models/include/models/model_fields.h, and blog_post.c,
# market_download.c or tx_index.c for worked conversions. A converted model
# has no literal column index left to get wrong, so it leaves the baseline.
#
# Per-line exception: `// model-columns-ok: <reason>` on the offending line or
# the line above, for a read that genuinely cannot come from a field list
# (an owning heap blob, a computed column). State the reason.
#
# ── Mode ───────────────────────────────────────────────────────────────────
# WARN | RATCHET | FAIL (ZCL_LINT_MODE, default WARN). Wired RATCHET.
#   WARN    — report, always exit 0.
#   RATCHET — fail on a violation in a file NOT in
#             model_column_drift_baseline.txt. The baseline is the honest
#             count of models that predate the mechanism; it may only SHRINK.
#             A baselined file that no longer violates is ALSO a failure, so
#             the line gets deleted rather than left to rot.
#   FAIL    — fail on ANY violation, baseline ignored. The end state.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

# ── selftest ───────────────────────────────────────────────────────────────
# A gate nobody has seen fail is a gate nobody should trust. Each case plants
# ONE shape in a throwaway fixture and asserts the verdict, including the
# cases that must PASS, so an unconditionally-failing script cannot pose as a
# rail. Run: tools/lint/check_model_column_drift.sh --selftest
st_expect() {
    # st_expect <label> <want: pass|fail> <needle-or-empty> <root> <baseline>
    local label="$1" want="$2" needle="$3" root="$4" baseline="$5"
    local out rc=0
    out="$(ZCL_LINT_MODE=RATCHET ZCL_MODEL_DRIFT_ROOT="$root" \
           ZCL_MODEL_DRIFT_BASELINE="$baseline" \
           "$SCRIPT_DIR/check_model_column_drift.sh" 2>&1)" || rc=$?
    if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
        echo "SELFTEST FAIL: $label — expected a PASS, got exit $rc"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $label — expected a rejection, got a PASS"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF -- "$needle"; then
        echo "SELFTEST FAIL: $label — verdict never named '$needle'"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

run_selftest() {
    local d rc=0 i
    d="$(mktemp -d "${TMPDIR:-/tmp}/model-column-drift-selftest.XXXXXX")"
    mkdir -p "$d/src" "$d/none"
    # Inert files so the anti-hollow scan floor is met in every case.
    for i in $(seq 1 25); do printf '/* inert */\n' > "$d/src/inert_$i.c"; done
    : > "$d/empty.txt"

    echo "══ check-model-column-drift selftest ══"

    # A. two distinct literal indices IS the drift shape.
    printf 'AR_READ_BLOB(s, 0, out->a, 32);\nout->b = AR_COL_INT(s, 1);\n' \
        > "$d/src/drifty.c"
    st_expect "A: two hand-written column indices are caught" \
              fail "drifty.c" "$d/src" "$d/empty.txt" || rc=1

    # B. a single-column scalar read cannot drift and must NOT be flagged.
    rm -f "$d/src/drifty.c"
    printf 'int64_t total = AR_COL_INT(s, 0);\n' > "$d/src/scalar.c"
    st_expect "B: a single-column scalar read is not flagged" \
              pass "" "$d/src" "$d/empty.txt" || rc=1

    # C. derived index NAMES are not literals and must pass — otherwise the
    #    gate would punish the very fix it asks for.
    printf 'AR_READ_BLOB(s, IX_a, out->a, 32);\nout->b = AR_COL_INT(s, IX_b);\n' \
        > "$d/src/derived.c"
    st_expect "C: derived index names pass" \
              pass "" "$d/src" "$d/empty.txt" || rc=1

    # D. the documented per-line exception silences one read.
    printf 'AR_READ_BLOB(s, 0, out->a, 32); // model-columns-ok: owning heap blob\nout->b = AR_COL_INT(s, 1); // model-columns-ok: computed\n' \
        > "$d/src/excepted.c"
    st_expect "D: the // model-columns-ok: exception is honoured" \
              pass "" "$d/src" "$d/empty.txt" || rc=1
    rm -f "$d/src/excepted.c"

    # E. a baselined violator is tolerated…
    printf 'AR_READ_BLOB(s, 0, out->a, 32);\nout->b = AR_COL_INT(s, 1);\n' \
        > "$d/src/drifty.c"
    printf '%s/src/drifty.c\n' "$d" > "$d/baseline.txt"
    st_expect "E: a baselined violator is tolerated" \
              pass "" "$d/src" "$d/baseline.txt" || rc=1

    # …and a baseline line whose file stopped violating is a failure, which is
    # what makes the baseline shrink-only rather than a place to hide.
    rm -f "$d/src/drifty.c"
    st_expect "F: a stale baseline entry is caught (shrink-only)" \
              fail "NO LONGER violates" "$d/src" "$d/baseline.txt" || rc=1

    # G. an emptied scan set must fail LOUD, never report clean.
    st_expect "G: an empty scan set fails closed" \
              fail "FATAL" "$d/none" "$d/empty.txt" || rc=1

    rm -rf "$d"
    if [ "$rc" -eq 0 ]; then
        echo "══ selftest: PASS (7/7) ══"
    else
        echo "══ selftest: FAIL ══"
    fi
    return "$rc"
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
    exit $?
fi

MODE="${ZCL_LINT_MODE:-WARN}"
# ZCL_MODEL_DRIFT_ROOT overrides the scanned directory — selftest isolation
# only. Unset in production.
SCAN_ROOT="${ZCL_MODEL_DRIFT_ROOT:-app/models/src}"
BASELINE="${ZCL_MODEL_DRIFT_BASELINE:-$SCRIPT_DIR/model_column_drift_baseline.txt}"

READ_MACROS='AR_READ_BLOB|AR_READ_STR|AR_COL_INT|AR_COL_BYTES|AR_COL_TEXT|AR_COL_DOUBLE'

# Distinct literal column indices in one file. A literal index is the second
# argument of a read macro when that argument is a bare decimal number —
# `AR_COL_INT(s, 4)` counts, `AR_COL_INT(s, col)` and `AR_COL_INT(s, MD_IX_x)`
# do not, because those are derived and cannot silently disagree with a list.
distinct_literal_indices() {
    local f="$1"
    grep -vE '//[[:space:]]*model-columns-ok:' "$f" \
    | grep -oE "(${READ_MACROS})\([A-Za-z_][A-Za-z0-9_.>()-]*,[[:space:]]*[0-9]+" \
    | grep -oE '[0-9]+$' \
    | sort -u \
    | grep -c . || true
}

[ -d "$SCAN_ROOT" ] || {
    echo "check_model_column_drift: FATAL — $SCAN_ROOT is missing" >&2
    exit 2
}

declare -A BASELINED=()
baseline_count=0
gate_load_list_file "$BASELINE" BASELINED baseline_count

scanned=0
violations=0
stale=0
violating_files=()
for f in "$SCAN_ROOT"/*.c; do
    [ -f "$f" ] || continue
    scanned=$((scanned + 1))
    rel="${f#./}"
    n="$(distinct_literal_indices "$f")"
    if [ "$n" -ge 2 ]; then
        violating_files+=("$rel")
        if [ "$MODE" = "RATCHET" ] && [ -n "${BASELINED[$rel]:-}" ]; then
            continue
        fi
        violations=$((violations + 1))
        echo "$rel: $n distinct hand-written column indices in row reads" >&2
    fi
done

gate_require_scanned "$scanned" 20 check_model_column_drift \
    "app/models/src should hold dozens of model sources"

# Shrink-only: a baselined file that no longer violates must lose its line.
if [ "$MODE" = "RATCHET" ]; then
    for rel in "${!BASELINED[@]}"; do
        still=0
        for v in "${violating_files[@]:-}"; do
            [ "$v" = "$rel" ] && still=1 && break
        done
        if [ "$still" -eq 0 ]; then
            stale=$((stale + 1))
            echo "$rel: baselined but NO LONGER violates — delete its baseline line" >&2
        fi
    done
fi

echo "[check_model_column_drift] scanned $scanned model file(s), ${#violating_files[@]} with hand-written column indices, $violations unbaselined, $stale stale baseline entry(ies) (mode: $MODE)"
echo "[check_model_column_drift] fix: declare the fields once in app/models/include/models/def/<model>_fields.def and derive the mapping (models/model_fields.h)"
if [ "$MODE" = "RATCHET" ]; then
    echo "[check_model_column_drift] baseline: $BASELINE ($baseline_count entry(ies), may only SHRINK)"
fi

if [ "$MODE" = "FAIL" ] && [ "$violations" -gt 0 ]; then exit 1; fi
if [ "$MODE" = "RATCHET" ] && { [ "$violations" -gt 0 ] || [ "$stale" -gt 0 ]; }; then exit 1; fi
exit 0
