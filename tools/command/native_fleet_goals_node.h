/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The node row G10 of `fleet goals`, graded from the objectives
 *          node producers (native_fleet_objectives_node.c). */

#ifndef ZCL_NATIVE_FLEET_GOALS_NODE_H
#define ZCL_NATIVE_FLEET_GOALS_NODE_H

#include "native_fleet_goals.h"

#include <stdbool.h>
#include <stdint.h>

/* Inputs of the G10 reader. Every field is optional; zero or NULL selects
 * this machine's own default. */
struct zcl_goals_node_in {
    const char *brief_path;  /* a status-brief fixture read in place of the
                              * node; NULL asks the node */
    const char *datadir;     /* the datadir the node rows read; NULL = default */
    int64_t node_budget_ms;  /* the longest wait on the node; 0 = its deadline */
    bool skip;               /* tests: do not ask the node at all */
};

/* Grades G10 from the served tip lag of this node. Never grades pass: a
 * fixture or a single node cannot show every canonical node alive. */
struct zcl_goal_result zcl_goals_node_measure(const struct zcl_goals_node_in *in);

#endif /* ZCL_NATIVE_FLEET_GOALS_NODE_H */
