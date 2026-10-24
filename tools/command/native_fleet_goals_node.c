/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grades the node row G10 of `fleet goals` from the served tip lag
 *          of the node this machine can ask, read through the objectives
 *          node producers so the status brief is fetched once per run.
 *
 * The grade is at most partial: one node says nothing about the other
 * canonical nodes, log advance or receiver health, so pass is never given.
 * The lag target is the objectives catalog's own node_tip_lag_blocks target;
 * no threshold lives here. */

#include "native_fleet_goals_node.h"

#include "native_fleet_objectives.h"

#include <stdio.h>
#include <string.h>

#define GN_LAG_ID "node_tip_lag_blocks"
#define GN_RSS_NOTE_MAX 48u
#define GN_NEXT_UNMEASURED                                                    \
    "make the node answer z23 status (served tip and rss), then "             \
    "z23-dev fleet goals"
#define GN_NEXT_PARTIAL                                                       \
    "probe the other canonical nodes for log advance and receiver health"
#define GN_NEXT_FAIL                                                          \
    "let the node catch up to the best known height, then z23-dev fleet goals"

/* The tip-lag target from the objectives catalog. False when the catalog
 * names no such row. */
static bool gn_lag_target(int64_t *target)
{
    const struct zcl_objective_row *rows = NULL;
    size_t n = zcl_objectives_catalog(&rows);
    for (size_t i = 0; rows && i < n; i++) {
        if (strcmp(rows[i].id, GN_LAG_ID) == 0) {
            *target = rows[i].target;
            return true;
        }
    }
    return false;
}

static void gn_rss_note(const struct zcl_objective_value *rss, char *out,
                        size_t cap)
{
    if (rss->measured)
        (void)snprintf(out, cap, "rss %lld MB", (long long)rss->value);
    else
        (void)snprintf(out, cap, "rss unmeasured");
}

/* Grades the measured lag. Never pass: at most partial, with the evidence
 * naming this node only and what was not probed. */
static struct zcl_goal_result gn_grade_lag(const struct zcl_objective_value *lag,
                                           const struct zcl_objective_value *rss)
{
    char rss_note[GN_RSS_NOTE_MAX];
    int64_t target = 0;
    if (!lag->measured)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, GN_NEXT_UNMEASURED, "%s",
                             lag->reason);
    if (!gn_lag_target(&target))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, GN_NEXT_UNMEASURED, "%s",
                             "the objectives catalog names no node tip lag target");
    gn_rss_note(rss, rss_note, sizeof(rss_note));
    if (lag->value > target)
        return zcl_goal_make(ZCL_GOAL_FAIL, GN_NEXT_FAIL,
                             "served tip trails by %lld blocks, above the "
                             "%lld-block target; this node only; %s",
                             (long long)lag->value, (long long)target,
                             rss_note);
    return zcl_goal_make(ZCL_GOAL_PARTIAL, GN_NEXT_PARTIAL,
                         "this node only; other canonical nodes, log advance "
                         "and receivers not probed. served tip trails by %lld "
                         "blocks (target %lld); %s",
                         (long long)lag->value, (long long)target, rss_note);
}

struct zcl_goal_result zcl_goals_node_measure(const struct zcl_goals_node_in *in)
{
    struct zcl_objectives_node_cache cache;
    struct zcl_objectives_options o;
    struct zcl_objective_value lag, rss;
    struct zcl_goal_result r;
    if (!in)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, GN_NEXT_UNMEASURED,
                             "no node inputs were given");
    if (in->skip)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, GN_NEXT_UNMEASURED,
                             "skipped: this run does not ask the node");
    memset(&cache, 0, sizeof(cache));
    memset(&o, 0, sizeof(o));
    o.brief = in->brief_path;
    o.datadir = in->datadir;
    o.node_budget_ms = in->node_budget_ms;
    o.node_cache = &cache;
    lag = zcl_objectives_node_tip_lag_blocks(&o);
    rss = zcl_objectives_node_rss_mb(&o);
    r = gn_grade_lag(&lag, &rss);
    zcl_objectives_node_cache_free(&cache);
    return r;
}
