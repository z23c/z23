/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read-only StoryGraph projection over canonical ZCODE work facts. */
#ifndef ZCL_COMMAND_NATIVE_STORY_COMMAND_H
#define ZCL_COMMAND_NATIVE_STORY_COMMAND_H

#include "ontology/story_graph.h"

#include <stdbool.h>

/* Borrowed strings from one already-reverified zcode.work.status result.
 * This struct is an input boundary, not storage and not a second authority. */
struct zcl_story_work_facts_v1 {
    const char *state;
    const char *build_result;
    const char *test_result;
    const char *task_root;
    const char *source_root;
    const char *goal_root;
    const char *agent_context_root;
    bool agent_context_ambiguous;
    const char *candidate_root;
    const char *candidate_source_root;
    const char *patch_root;
    const char *action_root;
    const char *work_receipt_root;
    const char *output_root;
    const char *lane_receipt_root;
    const char *proof_set_root;
};

bool zcl_story_graph_from_work_facts(
    const struct zcl_story_work_facts_v1 *facts,
    struct zcl_story_event_v1 events[7],
    struct zcl_story_graph_v1 *graph);

#endif /* ZCL_COMMAND_NATIVE_STORY_COMMAND_H */
