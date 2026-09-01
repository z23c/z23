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

set -euo pipefail

cd "$(dirname "$0")/../.."

LMS_FILE="engine/services/src/legacy_mirror_sync_service.c"

if [ ! -f "$LMS_FILE" ]; then
    echo "FAIL: $LMS_FILE not found"
    exit 1
fi

if ! grep -q "EV_LAG_SLO_BREACH" "$LMS_FILE"; then
    echo "$LMS_FILE: missing EV_LAG_SLO_BREACH emission"
    echo ""
    echo "FAIL: legacy_mirror_sync_service.c must emit EV_LAG_SLO_BREACH"
    echo "      so node_health, sd_notify, and Prometheus can react to"
    echo "      lag SLO breaches. Add a paired emit when crossing the"
    echo "      breach_blocks / critical_blocks thresholds."
    exit 1
fi

# The block source policy must honor the mirror_lag_sla_breach_blocks field.
# If a refactor drops the field from cac_plan_input or removes the
# concurrent-redundancy override, this gate fails.
POLICY_FILE="engine/services/src/block_source_policy.c"
if [ ! -f "$POLICY_FILE" ]; then
    echo "FAIL: $POLICY_FILE not found"
    exit 1
fi

if ! grep -q "mirror_lag_sla_breach_blocks" "$POLICY_FILE"; then
    echo "$POLICY_FILE: missing mirror_lag_sla_breach_blocks check"
    echo ""
    echo "FAIL: block_source_policy must honor"
    echo "      in->mirror_lag_sla_breach_blocks in mirror_fallback_allowed()."
    echo "      Without it, the mirror is gated strictly behind local"
    echo "      retries — exactly the bug we shipped this gate to prevent."
    exit 1
fi

echo "  OK: lag SLO emit + concurrent-redundancy override present"
