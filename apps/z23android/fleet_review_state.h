/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_FLEET_REVIEW_STATE_H
#define ZAPP_FLEET_REVIEW_STATE_H
#include <stdbool.h>

enum zapp_fleet_node_state { ZAPP_FLEET_NODE_READY, ZAPP_FLEET_NODE_START, ZAPP_FLEET_NODE_WAIT };
static inline enum zapp_fleet_node_state zapp_fleet_node_state(bool machine, bool running, bool stopping, bool busy)
{
    if (machine || (running && !stopping)) return ZAPP_FLEET_NODE_READY;
    return stopping || busy ? ZAPP_FLEET_NODE_WAIT : ZAPP_FLEET_NODE_START;
}
static inline void zapp_fleet_review_select(bool *joined, bool *started, bool join)
{
    *joined = join;
    *started = !join;
}
static inline const char *zapp_fleet_review_message(bool joined, bool started, const char *join_result, const char *start_result)
{
    return joined ? join_result : started ? start_result : "";
}
#endif
