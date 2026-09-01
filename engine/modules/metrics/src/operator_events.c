/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Operator-class event allow-list. See metrics/operator_events.h. */

#include "metrics/operator_events.h"

#include <string.h>

/* These strings are event_type_name() outputs (engine/modules/event/src/event.c): the
 * named operator signals plus the loudest integrity alarms. Add a string here
 * to make a new event class operator-visible. */
static const char *const k_operator_events[] = {
    "condition.operator_needed",   /* EV_OPERATOR_NEEDED */
    "condition.detected",          /* EV_CONDITION_DETECTED */
    "oracle.chain_halted",         /* EV_CHAIN_HALTED */
    "oracle.fork_suspected",       /* EV_FORK_SUSPECTED */
    "oracle.anchor_panic",         /* EV_ANCHOR_PANIC */
    "oracle.disagree",             /* EV_ORACLE_DISAGREE */
    "mirror.lag_slo_breach",       /* EV_LAG_SLO_BREACH */
    "peer.floor_breach",           /* EV_PEER_FLOOR_BREACH */
    "boot.validation_failed",      /* EV_BOOT_VALIDATION_FAILED */
    "disk.critical",               /* EV_DISK_CRITICAL */
    "chain.utxo_drift_detected",   /* EV_UTXO_DRIFT_DETECTED */
    "chain.coins_flush_fail",      /* EV_COINS_FLUSH_FAILED */
    "sys.crash",                   /* EV_CRASH */
};

bool metrics_is_operator_event(const char *event_type)
{
    if (!event_type) return false;
    for (size_t i = 0; i < sizeof(k_operator_events) /
                           sizeof(k_operator_events[0]); i++)
        if (strcmp(event_type, k_operator_events[i]) == 0)
            return true;
    return false;
}
