#!/usr/bin/env bash
# Lint gate E8 — no-silent-ready: the block-connection authority must
# advance-the-tip OR name-a-typed-blocker; it may NEVER go silently "ready"
# while the active tip is below the most-work valid-header chain (HARD).
#
# Why this exists
# ----------------
# 2026-05-26 live witness: chain_activation_controller went to
# ACTIVATION_READY with reason "behind_peers" whenever tip_h + 100 < best_h
# and the tick could not advance. That is the silent-ready hole — the reducer
# reports "ready" while +950 behind, naming no actionable reason and reaching
# no operator sink, deadlocked against a 3-peer P2P quorum a personal stack
# can't form. The Prime Directive (FRAMEWORK.md) requires the reducer to
# advance-the-tip OR name-a-typed-blocker (blocker_set / a Condition) every
# tick. Going READY is only honest when local_tip == most-work header tip.
#
# The check
# ---------
# The single block-connection authority is
#   engine/services/src/chain_activation_service.c
# It owns the transition to ACTIVATION_READY. Any file that performs an
#   activation_set_state(..., ACTIVATION_READY, ...)
# on a non-progress path MUST also route a typed blocker through the blocker
# primitive (`blocker_set(` directly, or a helper such as
# `activation_set_behind_blocker(`) so the stall is always visible in
# `z23 dumpstate blocker` and reaches the supervisor escape / operator
# sink. A file that transitions to READY but never names a typed blocker is
# the silent-ready anti-pattern.
#
# This guards the *structure* — a future edit that removes the blocker
# registration but keeps the READY transition turns the build red.
#
# Override: a deliberate READY transition that provably cannot be a
# non-progress stall (e.g. a clean caught-up path) may carry a line-level
#   // no-silent-ready-ok:<tag>
# marker (no space after the colon, non-empty tag) on the offending
# activation_set_state(... ACTIVATION_READY ...) line.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# Files that own a transition into ACTIVATION_READY. Today this is the single
# block-connection authority; the glob keeps the gate honest if the authority
# is ever split or relocated within engine/services/.
mapfile -t files < <(grep -rlE 'activation_set_state[[:space:]]*\([^;]*ACTIVATION_READY' \
                        engine/services/src --include='*.c' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null | sort || true)

# FAIL-LOUD preflight (never report "clean" off an empty discovery). The
# producer finds the READY authority by grepping for the setter + the enum. If
# `activation_set_state` or `ACTIVATION_READY` is renamed (a plausible refactor
# that keeps the build green), the grep matches 0 files, the loop below runs
# zero times, and the gate would silently pass while the silent-ready hole is
# wide open. So: the discovery must be non-empty AND must still contain the
# known block-connection authority. A legitimate rename/split forces a
# deliberate update here (and a re-verify of the silent-ready boundary).
EXPECTED_AUTHORITY="engine/services/src/chain_activation_service.c"
if (( ${#files[@]} == 0 )); then
    echo "check_no_silent_ready: BROKEN — found 0 ACTIVATION_READY authorities." >&2
    echo "  The setter (activation_set_state) or enum (ACTIVATION_READY) was likely" >&2
    echo "  renamed; update the producer grep in this gate. Refusing to report clean." >&2
    exit 2
fi
if ! printf '%s\n' "${files[@]}" | grep -qxF "$EXPECTED_AUTHORITY"; then
    echo "check_no_silent_ready: BROKEN — the known authority ($EXPECTED_AUTHORITY)" >&2
    echo "  is not in the discovered set; the authority moved or the setter/enum was" >&2
    echo "  renamed. Update EXPECTED_AUTHORITY/producer in this gate deliberately." >&2
    exit 2
fi

fail=0
violations=()

for f in "${files[@]}"; do
    [ -n "$f" ] || continue

    # Count READY transitions that are NOT line-overridden.
    ready_unguarded=$(grep -nE 'activation_set_state[[:space:]]*\([^;]*ACTIVATION_READY' "$f" \
        | grep -vE '//[[:space:]]*no-silent-ready-ok:[A-Za-z][A-Za-z0-9_-]*' \
        | wc -l)
    [ "$ready_unguarded" -eq 0 ] && continue

    # The file transitions to READY on a real path — it MUST name a typed
    # blocker somewhere (blocker_set / blocker helper) so non-progress is
    # surfaced, never silent.
    if ! grep -qE 'blocker_set[[:space:]]*\(|_set_behind_blocker[[:space:]]*\(' "$f"; then
        violations+=("$f: transitions to ACTIVATION_READY but never names a typed blocker (blocker_set / *_set_behind_blocker) — the silent-ready hole: it can report 'ready' while behind the most-work header chain with no actionable reason and no operator sink")
        fail=1
    fi
done

if [ "$fail" = "0" ]; then
    echo "check_no_silent_ready: clean — every ACTIVATION_READY authority names a typed blocker on non-progress"
    exit 0
fi

echo ""
echo "check_no_silent_ready: ${#violations[@]} silent-ready violation(s)"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "The block-connection authority must advance-the-tip OR name-a-typed-blocker"
echo "every tick (FRAMEWORK.md Prime Directive). Going ACTIVATION_READY is only"
echo "honest when local_tip == most-work valid-header tip. On the behind path,"
echo "register a typed blocker (blocker_set / activation_set_behind_blocker) that"
echo "names WHY, the height, and the escape action, then transition to READY."
exit 1
