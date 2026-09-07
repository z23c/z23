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
exec "$(dirname "$0")/../../build/bin/z23-lint" check-operator-needed-sink "$@"
