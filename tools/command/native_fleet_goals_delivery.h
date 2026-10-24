/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Delivery-accounting readers for the fleet goals D1, D2 and D4.
 *          Each takes explicit paths and a clock, reads the experiment
 *          ledger (rows.tsv), the land outcomes and the agent-to-lane index,
 *          and grades honestly: an unreadable or empty input is
 *          unmeasured, an unmet bar is fail, and a met bar is at best
 *          partial because the ledger records no review verdicts and no
 *          roster host names. */

#ifndef ZCL_NATIVE_FLEET_GOALS_DELIVERY_H
#define ZCL_NATIVE_FLEET_GOALS_DELIVERY_H

#include "native_fleet_goals.h"
#include "native_fleet_objectives.h"

#include <stddef.h>
#include <stdint.h>

/* 2026-10-23T18:05:00Z: rows.tsv `turns` counts API messages only from here
 * on (SCHEMA.md next to rows.tsv; objectives.def tokens_per_landed_commit);
 * earlier rows over-count tokens 3-4.5x, so D1 and D2 ignore them. */
#define ZCL_GOALS_DELIVERY_FIX_EPOCH INT64_C(1792778700)
#define ZCL_GOALS_DELIVERY_WINDOW_S (INT64_C(7) * 86400)
#define ZCL_GOALS_DELIVERY_D2_MAX_REQUESTS 18
#define ZCL_GOALS_DELIVERY_D4_SAMPLE 100u
#define ZCL_GOALS_DELIVERY_D4_MIN_FIRST_TIME 60u

struct zcl_goals_delivery_in {
    const char *rows_tsv;  /* experiment ledger, 22 tab columns */
    const char *outcomes;  /* land outcomes.jsonl (D2) */
    int64_t now;           /* unix seconds */
    size_t admitted_hosts; /* roster size; 0 when unknown */
    const struct zcl_agent_index *index; /* prebuilt, or NULL to build one */
};

/* D1: finished runs recording requests, input and output tokens. */
struct zcl_goal_result zcl_goals_delivery_d1(
    const struct zcl_goals_delivery_in *in);
/* D2: median provider requests per accepted change. */
struct zcl_goal_result zcl_goals_delivery_d2(
    const struct zcl_goals_delivery_in *in);
/* D4: share of the newest 100 deliveries without a repair round. */
struct zcl_goal_result zcl_goals_delivery_d4(
    const struct zcl_goals_delivery_in *in);

#endif /* ZCL_NATIVE_FLEET_GOALS_DELIVERY_H */
