/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: Shared verified inputs for StoryGraph native read projections. */
#ifndef ZCL_COMMAND_NATIVE_STORY_INTERNAL_H
#define ZCL_COMMAND_NATIVE_STORY_INTERNAL_H

#include "command/native_command.h"
#include "ontology/story_graph.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>

#define ZCL_STORY_GOAL_MAX 4096u

struct story_loaded_work {
    struct zcl_story_event_v1 events[7];
    struct zcl_story_graph_v1 graph;
    struct zcl_story_show_v1 show;
    char work_id[32];
    char goal[ZCL_STORY_GOAL_MAX + 1u];
    char state[32];
    char stage[64];
    char next_action[512];
    char next_safe_command[128];
    char task_root[65];
    char source_root[65];
    char goal_root[65];
    char agent_context_root[65];
    bool agent_context_ambiguous;
};

enum story_context_status {
    STORY_CONTEXT_UNKNOWN = 0,
    STORY_CONTEXT_PROVED,
    STORY_CONTEXT_AMBIGUOUS,
    STORY_CONTEXT_UNAVAILABLE,
};

enum { STORY_JOURNEY_STAGE_COUNT = 9 };

struct story_journey_stage {
    const char *stage;
    const char *role;
    enum zcl_ontology_status status;
    const char *evidence_event;
    const char *reason;
    const char *next_command;
    bool actionable;
};

void story_journey_build(
    const struct story_loaded_work *loaded,
    struct story_journey_stage out[STORY_JOURNEY_STAGE_COUNT]);
const struct story_journey_stage *story_journey_next(
    const struct story_journey_stage stages[STORY_JOURNEY_STAGE_COUNT]);

bool story_load_work(const struct zcl_command_request *request,
                     const char *workspace, const char *work,
                     const char *datadir, struct story_loaded_work *loaded,
                     struct zcl_command_reply *reply);

bool story_load_task(const char *workspace,
                     const struct story_loaded_work *loaded,
                     struct vcs_zcode_task_v1 *task);

enum story_context_status story_load_agent_context(
    const char *workspace, const struct story_loaded_work *loaded,
    struct vcs_zcode_agent_context_v1 *context);

bool story_workspace_source_root(const char *workspace, uint8_t out[32]);

#endif /* ZCL_COMMAND_NATIVE_STORY_INTERNAL_H */
