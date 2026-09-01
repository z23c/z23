/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal bounded readiness policy for scheduler-owned onion dials. */

#ifndef ZCL_NET_CONNMAN_ONION_DIAL_POLICY_H
#define ZCL_NET_CONNMAN_ONION_DIAL_POLICY_H

#include "net/netbase.h"

#include <stdint.h>

/* True when svc may consume the remaining shared onion circuit budget.
 * False names either budget exhaustion or local Tor readiness and never
 * charges peer backoff for a local bootstrap wait. */
bool connman_onion_dial_policy_allows(const struct net_service *svc,
                                      int64_t remaining_budget_ms);

#endif
