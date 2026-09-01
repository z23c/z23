#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no NEW repair rung without a write-time-invariant test.
#
# The ratchet for TENACITY invariant I3 ("don't grow the repair ladder;
# fix the writer"). The recurring anchor-collapse wedge is a coin tear
# written by an import path that skips verification; the correct fix is a
# WRITE-TIME correctness gate, never another downstream heal/reconcile/
# backfill rung that re-derives the wrong state. The measured repair ladder
# is already ~9,153 LOC across ~24 files — the accumulation IS the smell.
#
# This gate makes the ladder shrink-only: a NEW file in app/ whose name
# marks it as a repair rung (repair / reconcile / backfill, or `heal` but
# not `health`) must either
#   - be listed in tools/scripts/repair_rung_baseline.txt (the grandfathered
#     existing ladder — entries are REMOVED as rungs are deleted, never
#     added), OR
#   - carry a per-file marker `// repair-rung-ok:<cite>` whose <cite> names
#     the write-time-invariant test that makes the rung unnecessary-to-trust
#     (e.g. `// repair-rung-ok:test_utxo_recovery_refuses_torn_import`).
#
# Anything else is a NEW unjustified rung and fails the gate. To clean up
# debt: delete a rung, remove its baseline line, re-run `make lint`.
#
# "health" is explicitly NOT a repair rung (it is observability), so
# *health*.c files are not matched.
set -euo pipefail

# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/repo_shape.sh
source tools/lint/repo_shape.sh

BASELINE=tools/scripts/repair_rung_baseline.txt
[ -f "$BASELINE" ] || touch "$BASELINE"

declare -A baseline
baseline_count=0
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    baseline["$line"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

# Is a basename a repair-rung name? repair|reconcile|backfill always;
# `heal` only when it is NOT the substring of `health`. Pure bash — no
# basename/grep fork per file (the old is_repair_rung_name forked 2-3 times
# for every app/*.c file).
is_repair_rung_base() {
    local base="$1"
    case "$base" in
        *repair*|*reconcile*|*backfill*) return 0 ;;
    esac
    if [[ "$base" == *heal* && "$base" != *health* ]]; then
        return 0
    fi
    return 1
}

# First pass: filter every physical application room to just the
# repair-rung-named files using
# pure-bash name tests (no fork). Only that small candidate set (~two dozen)
# needs a content grep for the marker.
rung_files=()
while IFS= read -r f; do
    [ -f "$f" ] || continue
    is_repair_rung_base "${f##*/}" || continue
    rung_files+=("$f")
done < <(
    while IFS= read -r room; do
        find "$room" -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}"
    done < <(repo_shape_dirs app) | sort -u
)

# One batched `grep -lE` over the candidate set names every file that carries
# a `// repair-rung-ok:<cite>` marker, instead of a grep fork per candidate.
declare -A has_marker
if [ "${#rung_files[@]}" -gt 0 ]; then
    while IFS= read -r mf; do
        [ -n "$mf" ] && has_marker["$mf"]=1
    done < <(grep -lE '//[[:space:]]*repair-rung-ok:[A-Za-z][A-Za-z0-9_./-]*' \
                 "${rung_files[@]}" </dev/null 2>/dev/null || true)
fi

fail=0
new_violations=()
for f in "${rung_files[@]}"; do
    # Grandfathered existing rung? Pass.
    if [ -n "${baseline[$f]+x}" ]; then
        continue
    fi
    # Per-file marker citing the write-time-invariant test? Pass.
    if [ -n "${has_marker[$f]+x}" ]; then
        continue
    fi
    new_violations+=("$f")
    fail=1
done

if [ "$fail" = "0" ]; then
    echo "check_no_new_repair_rung: clean — ${baseline_count} grandfathered rung(s), no new ones"
    exit 0
fi

echo ""
echo "check_no_new_repair_rung: ${#new_violations[@]} NEW repair rung(s) with no justification"
echo ""
for v in "${new_violations[@]}"; do
    echo "  $v"
done
echo ""
echo "A new repair/reconcile/backfill/heal rung is almost always the WRONG"
echo "fix (TENACITY I3). Prefer fixing the WRITER so the bad state is never"
echo "produced. If a rung is genuinely required:"
echo "  1. Add a marker '// repair-rung-ok:<test_name>' citing the write-time-"
echo "     invariant test that proves the producing path now refuses to emit"
echo "     the state this rung repairs."
echo "  2. As a last resort (grandfathering an unavoidable existing rung),"
echo "     add the file path to $BASELINE."
exit 1
