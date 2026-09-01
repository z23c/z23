#!/usr/bin/env bash
# Lint gate E9 — operator-needed events must reach a sink (HARD).
#
# THE silent-halt class of bug: code emits EV_OPERATOR_NEEDED (the
# loudest "auto-healing gave up, a human must act" signal) but NOTHING
# subscribes to it, so it pages nobody. On 2026-05-25 the live tip could
# halt while EV_OPERATOR_NEEDED reached no consumer. This gate makes that
# regression impossible: every emit must be paired with a registered
# subscriber for the same event id.
#
# Concrete pairing rule (modeled on check_lag_slo_observable.sh):
#   1. At least one `event_emitf(EV_OPERATOR_NEEDED` / `event_emit(EV_OPERATOR_NEEDED`
#      exists in production code (app/, lib/, config/) — proves the loud
#      signal is wired to fire.
#   2. engine/modules/event/src/alerts.c registers a subscriber for it: an alert rule
#      with `.trigger = EV_OPERATOR_NEEDED` AND an `event_observe(` call
#      that routes the trigger to the alert observer.
# If a refactor drops the emit or the subscriber, the signal goes silent
# and this gate fails CI before it ships.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

EVENT=EV_OPERATOR_NEEDED
ALERTS_FILE="engine/modules/event/src/alerts.c"

# 1. Production emit present? (exclude lib/test fixtures)
emit_hits=$(grep -rln --include='*.c' \
    -E "event_emitf?\s*\(\s*${EVENT}\b" \
    core engine contexts cognition platform "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
    | grep -v '/test/' \
    || true)

if [ -z "${emit_hits//[[:space:]]/}" ]; then
    echo "FAIL: no production emit of ${EVENT} found"
    echo "      The condition engine / watchdogs must emit ${EVENT} when"
    echo "      auto-healing is exhausted, or operators are never paged."
    exit 1
fi

# 2. Subscriber registered in alerts.c?
if [ ! -f "$ALERTS_FILE" ]; then
    echo "FAIL: $ALERTS_FILE not found (the ${EVENT} sink)"
    exit 1
fi

if ! grep -qE "\.trigger\s*=\s*${EVENT}\b" "$ALERTS_FILE"; then
    echo "$ALERTS_FILE: missing alert rule with .trigger = ${EVENT}"
    echo ""
    echo "FAIL: ${EVENT} is emitted but has no registered subscriber."
    echo "      Add a seed alert rule (.trigger = ${EVENT}) in alerts.c so"
    echo "      the signal reaches the health surface / sd_notify / webhook"
    echo "      sinks instead of being silently observed."
    exit 1
fi

if ! grep -qE 'event_observe(_async)?\s*\(' "$ALERTS_FILE"; then
    echo "$ALERTS_FILE: alert rule for ${EVENT} present but no event_observe() registration"
    echo ""
    echo "FAIL: the alert rule must be wired to the event bus via"
    echo "      event_observe(rule->trigger, alert_observer, ...). Without it"
    echo "      the rule never fires and ${EVENT} reaches no sink."
    exit 1
fi

echo "  OK: ${EVENT} emit paired with registered alerts.c subscriber"
