#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# test-registry-report.sh — reconcile REGISTERED test groups against the groups
# a run actually EXECUTED, and name every group in the gap.
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# A full run reported "866 groups" and "groups_ran: 862". Nothing in the tree
# said which four were missing. A registered-but-never-executed group is a test
# that protects nothing: it compiles, it is counted in the headline number, and
# it never runs. Four of them had been invisible for as long as anyone looked.
#
# ── WHAT IS COMPARED, AND WHY IT IS EVIDENCE RATHER THAN A MODEL ──────────
# REGISTERED comes from the X-macro registry itself (tools/dev/test-group-list.sh
# parsing tests/harness/src/test_parallel.c) — the same table the compiler turns into
# g_groups[].
#
# EXECUTED comes from the runner's OWN artifact, .cache/test-timing/last-run.json,
# which write_test_timing_json() emits with one row per group that was not
# skipped. That matters: this report does not re-derive what "should" have run
# by re-implementing the runner's gating rules. Re-implementing them is exactly
# how a reconciliation drifts away from the thing it reconciles. The runner
# says what it ran; we diff that against the registry.
#
# The POLICY column is the only modelled part, and it is derived, not typed:
# `test-group-list.sh --params-gated` reads the names straight out of
# group_is_params_heavy() in the runner. It is used ONLY to explain a gap that
# the evidence already established — never to predict one.
#
# ── VERDICT ────────────────────────────────────────────────────────────────
# Exit 0 when every registered-but-not-executed group has a known reason.
# Exit 1 when any group is UNEXPLAINED, or when a name the runner executed is
# not in the registry (which would mean the parse is wrong, and every number
# above it is suspect).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO"
# shellcheck source=tools/scripts/sh_str.sh
. "$REPO/tools/scripts/sh_str.sh"  # str_contains — pipefail-safe, see F-note

T_LIST="$SCRIPT_DIR/test-group-list.sh"
ARTIFACT="${ZCL_TEST_TIMING_JSON:-.cache/test-timing/last-run.json}"

registered="$($T_LIST)"
reg_count="$(printf '%s\n' "$registered" | wc -l | tr -d ' ')"
gated="$($T_LIST --params-gated)"

echo "── test registry reconciliation ────────────────────────────────────"
echo "registry_source=tests/harness/src/test_parallel.c"
echo "registered_groups=$reg_count"

if [ ! -f "$ARTIFACT" ]; then
    # No evidence available. Say so plainly instead of printing a modelled
    # "executed" number that nothing measured — a report that invents its own
    # ground truth is worse than a report that admits it has none.
    echo "executed_groups=UNKNOWN"
    echo "run_artifact=MISSING ($ARTIFACT)"
    echo
    echo "No run artifact. EXECUTED cannot be established without one."
    echo "Produce it with a full run (make test-parallel), or point this at an"
    echo "existing one:  ZCL_TEST_TIMING_JSON=<path> make test-registry-report"
    echo
    echo "For reference, the policy that gates groups out of a default run"
    echo "(group_is_params_heavy(), tests/harness/src/test_parallel.c) currently names:"
    # shellcheck disable=SC2086  # deliberate word splitting: one name per line
    printf '  %s\n' $gated
    exit 0
fi

json_num() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\([0-9-][0-9]*\).*/\1/p" "$ARTIFACT" | head -1
}
json_str() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$ARTIFACT" | head -1
}

executed="$(grep -oE '"name":"[A-Za-z_0-9]+"' "$ARTIFACT" |
            sed 's/^"name":"//; s/"$//' | sort)"
exec_count="$(printf '%s\n' "$executed" | grep -c . || true)"

art_total="$(json_num group_count)"
art_ran="$(json_num groups_ran)"
art_cached="$(json_num groups_cached)"
art_skipped="$(json_num skipped_count)"

echo "executed_groups=$exec_count"
echo "run_artifact=$ARTIFACT"
echo "run_generated_at_utc=$(json_str generated_at_utc)"
echo "run_mode=$(json_str mode)"
echo "run_group_count=$art_total"
echo "run_groups_ran=$art_ran"
echo "run_groups_cached=$art_cached"
echo "run_skipped_count=$art_skipped"

status=0

# A run artifact from a different registry makes the by-name diff meaningless:
# the extra/missing names would be source drift, not gating. Refuse to present
# the diff as if it meant something.
if [ -n "$art_total" ] && [ "$art_total" != "$reg_count" ]; then
    echo
    echo "STALE ARTIFACT: the run recorded $art_total registered groups, this"
    echo "  source tree has $reg_count. The by-name difference below mixes"
    echo "  registry drift with gating and should not be read as gating."
    status=1
fi

registered_sorted="$(printf '%s\n' "$registered" | sort)"
missing="$(comm -23 <(printf '%s\n' "$registered_sorted") <(printf '%s\n' "$executed"))"
extra="$(comm -13 <(printf '%s\n' "$registered_sorted") <(printf '%s\n' "$executed"))"

echo
echo "── REGISTERED but NOT EXECUTED ─────────────────────────────────────"
if [ -z "$missing" ]; then
    echo "(none)"
else
    while IFS= read -r g; do
        [ -n "$g" ] || continue
        reason="UNEXPLAINED"
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            if [ "$g" = "$p" ]; then
                reason="params-heavy gate (group_is_params_heavy) — opt in with ZCL_PARAMS_TESTS=1 or --only=$g"
                break
            fi
        done <<<"$gated"
        printf '  %-42s %s\n' "$g" "$reason"
        if [ "$reason" = "UNEXPLAINED" ]; then status=1; fi
    done <<<"$missing"
fi

echo
echo "── EXECUTED but NOT REGISTERED ─────────────────────────────────────"
if [ -z "$extra" ]; then
    echo "(none)"
else
    # shellcheck disable=SC2086  # deliberate word splitting: one name per line
    printf '  %s\n' $extra
    echo "  ^ the registry parse disagrees with the runner; every count above is suspect"
    status=1
fi

echo
if [ "$status" -eq 0 ]; then
    echo "VERDICT: every registered group is accounted for."
else
    echo "VERDICT: unaccounted-for groups above — a registered group that never"
    echo "  runs is a test protecting nothing."
fi
exit "$status"
