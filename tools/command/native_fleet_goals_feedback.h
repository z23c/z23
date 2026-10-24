/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grades fleet goal D6, delivery-to-verdict time, from the landing
 *          outcomes ledger (native_fleet_goals_feedback.c). */

#ifndef ZCL_NATIVE_FLEET_GOALS_FEEDBACK_H
#define ZCL_NATIVE_FLEET_GOALS_FEEDBACK_H

#include "command/native_fleet_goals.h"

/* Grades D6 from the usable landed rows of the last 7 days: the p95 of
 * landed_at minus ts. PARTIAL when the p95 is within the 180 s bar, FAIL
 * above it, UNMEASURED with the reason when no row is usable. Never PASS:
 * the warm-lane clause is not measured. */
struct zcl_goal_result zcl_goals_feedback_d6(
    const struct zcl_goals_options *options);

#endif /* ZCL_NATIVE_FLEET_GOALS_FEEDBACK_H */
