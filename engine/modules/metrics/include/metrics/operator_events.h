/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Operator-class event allow-list.  A small, stable set of event_type_name()
 * strings (engine/modules/event/src/event.c) that demand operator attention: a suspected
 * fork, a violated anchor, a halted chain, a lag-SLO breach, a needed operator
 * action, a failed boot validation, a critical disk, a UTXO drift, a
 * coins-flush failure, an oracle disagreement, a crash, and a detected
 * condition.  The metrics threshold-alert rule table
 * (engine/modules/metrics/src/prometheus_metrics.c) uses "condition.detected" as the
 * generic operator-alert vehicle, so its membership here is load-bearing. */

#ifndef ZCL_METRICS_OPERATOR_EVENTS_H
#define ZCL_METRICS_OPERATOR_EVENTS_H

#include <stdbool.h>

/* True when `event_type` names an operator-class event (a member of the
 * allow-list). NULL and unknown types return false. */
bool metrics_is_operator_event(const char *event_type);

#endif
