/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grades the plugin-swarm row G5 of `fleet.goals` from this host's
 *          binary slot directory alone: every slot's installed binary is
 *          rehashed and compared with its install record (read-only). */

#ifndef ZCL_NATIVE_FLEET_GOALS_SLOTS_H
#define ZCL_NATIVE_FLEET_GOALS_SLOTS_H

#include "command/native_fleet_goals.h"

#include <stdbool.h>
#include <stddef.h>

struct zcl_goals_slots_in {
    const char *slots_root;  /* slot root; NULL = this user's binary slot root */
    size_t admitted_hosts;   /* admitted roster size, supplied by the wiring */
    bool skip;               /* true: no directory read, row is unmeasured */
};

/* Grades G5 from the local slot directory. FAIL on any mismatch, unsafe or
 * writable slot; PARTIAL when at least one slot verifies and none is bad.
 * Never PASS: peer-fetch provenance is not recorded anywhere. */
struct zcl_goal_result zcl_goals_slots_measure(
    const struct zcl_goals_slots_in *in);

#endif /* ZCL_NATIVE_FLEET_GOALS_SLOTS_H */
