#!/usr/bin/env bash
# Lag-SLO observability: the mirror service writes lag-related atomics
# that gate the severity ladder + sd_notify heartbeat. Every read of
# those atomics that could influence severity MUST be paired with an
# EV_LAG_SLO_BREACH emit in the same file, so downstream consumers
# (Prometheus, node_health, native diagnostics) can react to the state change instead
# of silently observing it.
#
# Concrete rule for this gate: legacy_mirror_sync_service.c must contain
# at least one EV_LAG_SLO_BREACH emission. If a refactor removes it,
# lag-SLO breaches fall back to "silent failure" and this gate is what
# prevents that regression from shipping unnoticed.
#
# NOTE: EV_MIRROR_CONCURRENT_CATCHUP is no longer required here. Post-B8
# the mirror is monitor-only — it observes lag but never applies blocks —
# so "redundancy engaged via concurrent catchup" no longer occurs and the
# stage pipeline is the sole writer. Requiring that emit would force dead
# code that lies ("redundancy engaged" when nothing was applied).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-lag-slo-observable "$@"
