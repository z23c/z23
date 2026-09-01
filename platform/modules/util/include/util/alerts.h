/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Forwarding header — alert routing moved to engine/modules/event. It observes the
 * event bus and dispatches matching events, so it belongs on the bus side
 * of the boundary; platform/modules/util no longer references engine/modules/event at all.
 * New code should include "event/alerts.h" directly. */

#ifndef ZCL_UTIL_ALERTS_FORWARD_H
#define ZCL_UTIL_ALERTS_FORWARD_H

#include "event/alerts.h"

#endif /* ZCL_UTIL_ALERTS_FORWARD_H */
