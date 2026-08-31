/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Born-red contracts for bounded rooted development stories. */
#include "test/test_core.h"
#include "ontology/story_graph.h"
#include "command/native_story_command.h"

#include <string.h>

static void sg_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void sg_event(struct zcl_story_event_v1 *event, uint8_t kind,
                     uint8_t status, uint8_t identity, uint8_t cause)
{
    memset(event, 0, sizeof(*event));
    event->schema_version = ZCL_STORY_GRAPH_VERSION;
    event->kind = kind;
    event->status = status;
    sg_root(event->universe_root, 1);
    sg_root(event->context_root, 2);
    sg_root(event->scene_root, (uint8_t)(20u + kind));
    sg_root(event->entity_root, 3);
    sg_root(event->action_root, (uint8_t)(40u + kind));
    sg_root(event->event_root, identity);
    sg_root(event->evidence_root, (uint8_t)(60u + kind));
    if (cause != 0) sg_root(event->cause_event_root, cause);
}

static void sg_complete(struct zcl_story_event_v1 events[7])
{
    for (uint8_t i = 0; i < 7; i++)
        sg_event(&events[i], (uint8_t)(i + 1u), ZCL_ONTOLOGY_PROVED,
                 (uint8_t)(80u + i), i == 0 ? 0 : (uint8_t)(79u + i));
}

static int sg_complete_story(void)
{
    int failures = 0;
    TEST("story graph: complete development story is rooted and shown") {
        struct zcl_story_event_v1 events[7];
        sg_complete(events);
        struct zcl_story_graph_v1 graph = {
            .schema_version = ZCL_STORY_GRAPH_VERSION,
            .event_count = 7,
            .events = events,
        };
        uint8_t root_a[32], root_b[32];
        ASSERT(zcl_story_graph_v1_validate(&graph));
        ASSERT(zcl_story_graph_v1_root(&graph, root_a));
        ASSERT(zcl_story_graph_v1_root(&graph, root_b));
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        struct zcl_story_show_v1 show;
        ASSERT(zcl_story_show_v1_build(&graph, &show));
        ASSERT(show.status == ZCL_ONTOLOGY_PROVED);
        ASSERT(show.complete);
        ASSERT(show.observed_mask == ZCL_STORY_DEVELOPMENT_ALL);
        ASSERT(show.missing_mask == 0);
        ASSERT(show.unknown_mask == 0);
        ASSERT(show.incomplete_mask == 0);
        ASSERT(show.event_count == 7);
        ASSERT(memcmp(show.story_root, root_a, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_unknown_and_incomplete(void)
{
    int failures = 0;
    TEST("story graph: unknown and missing relations remain visible") {
        struct zcl_story_event_v1 events[7];
        sg_complete(events);
        events[5].status = ZCL_ONTOLOGY_UNKNOWN;
        struct zcl_story_graph_v1 graph = {
            .schema_version = ZCL_STORY_GRAPH_VERSION,
            .event_count = 7,
            .events = events,
        };
        struct zcl_story_show_v1 show;
        ASSERT(zcl_story_show_v1_build(&graph, &show));
        ASSERT(show.status == ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(!show.complete);
        ASSERT(show.unknown_mask == ZCL_STORY_STEP_APP_RUNS);

        graph.event_count = 6;
        ASSERT(zcl_story_show_v1_build(&graph, &show));
        ASSERT(show.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(!show.complete);
        ASSERT(show.missing_mask == ZCL_STORY_STEP_USER_ACCEPTS);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_why_chain(void)
{
    int failures = 0;
    TEST("story graph: why returns the exact causal event chain") {
        struct zcl_story_event_v1 events[7];
        sg_complete(events);
        struct zcl_story_graph_v1 graph = {
            .schema_version = ZCL_STORY_GRAPH_VERSION,
            .event_count = 7,
            .events = events,
        };
        struct zcl_story_why_v1 why;
        ASSERT(zcl_story_why_v1_build(&graph, events[6].event_root, &why));
        ASSERT(why.status == ZCL_ONTOLOGY_PROVED);
        ASSERT(why.complete);
        ASSERT(why.cause_count == 7);
        ASSERT(memcmp(why.cause_event_roots[0], events[0].event_root, 32) == 0);
        ASSERT(memcmp(why.cause_event_roots[6], events[6].event_root, 32) == 0);

        sg_root(events[4].cause_event_root, 250);
        ASSERT(zcl_story_why_v1_build(&graph, events[6].event_root, &why));
        ASSERT(why.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(!why.complete);
        ASSERT(why.missing_cause);
        ASSERT(memcmp(why.missing_cause_root, events[4].cause_event_root, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_diff(void)
{
    int failures = 0;
    TEST("story graph: diff names added and status-changed event roots") {
        struct zcl_story_event_v1 before_events[7], after_events[7];
        sg_complete(before_events);
        sg_complete(after_events);
        before_events[5].status = ZCL_ONTOLOGY_UNKNOWN;
        struct zcl_story_graph_v1 before = {
            .schema_version = ZCL_STORY_GRAPH_VERSION,
            .event_count = 6,
            .events = before_events,
        };
        struct zcl_story_graph_v1 after = {
            .schema_version = ZCL_STORY_GRAPH_VERSION,
            .event_count = 7,
            .events = after_events,
        };
        struct zcl_story_diff_v1 diff;
        ASSERT(zcl_story_diff_v1_build(&before, &after, &diff));
        ASSERT(diff.status == ZCL_ONTOLOGY_PROVED);
        ASSERT(diff.added_count == 1);
        ASSERT(diff.removed_count == 0);
        ASSERT(diff.changed_count == 1);
        ASSERT(memcmp(diff.added_event_roots[0],
                      after_events[6].event_root, 32) == 0);
        ASSERT(memcmp(diff.changed_event_roots[0],
                      after_events[5].event_root, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_refusals(void)
{
    int failures = 0;
    TEST("story graph: evidence, identity, kind, and duplicate roots fail closed") {
        struct zcl_story_event_v1 events[7];
        sg_complete(events);
        struct zcl_story_graph_v1 graph = {
            .schema_version = ZCL_STORY_GRAPH_VERSION,
            .event_count = 7,
            .events = events,
        };
        memset(events[3].evidence_root, 0, 32);
        ASSERT(!zcl_story_graph_v1_validate(&graph));
        sg_complete(events);
        memset(events[2].event_root, 0, 32);
        ASSERT(!zcl_story_graph_v1_validate(&graph));
        sg_complete(events);
        events[1].kind = 99;
        ASSERT(!zcl_story_graph_v1_validate(&graph));
        sg_complete(events);
        memcpy(events[2].event_root, events[1].event_root, 32);
        ASSERT(!zcl_story_graph_v1_validate(&graph));
        PASS();
    } _test_next:;
    return failures;
}

static const char *sg_hex(uint8_t value)
{
    static char roots[16][65];
    static size_t next;
    char *out = roots[next++ % 16u];
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; i++)
        out[i] = digits[(value + (uint8_t)i) & 15u];
    out[64] = '\0';
    return out;
}

static int sg_canonical_work_projection(void)
{
    int failures = 0;
    TEST("story graph: canonical work projection never invents app execution") {
        struct zcl_story_work_facts_v1 facts = {
            .state = "PROVEN",
            .build_result = "passed",
            .test_result = "passed_declared_tests",
            .task_root = sg_hex(1),
            .source_root = sg_hex(2),
            .goal_root = sg_hex(3),
            .agent_context_root = sg_hex(4),
            .candidate_root = sg_hex(5),
            .candidate_source_root = sg_hex(6),
            .patch_root = sg_hex(7),
            .action_root = sg_hex(8),
            .work_receipt_root = sg_hex(9),
            .output_root = sg_hex(10),
            .lane_receipt_root = sg_hex(11),
            .proof_set_root = sg_hex(12),
        };
        struct zcl_story_event_v1 events[7];
        struct zcl_story_graph_v1 graph;
        struct zcl_story_show_v1 show;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT(zcl_story_show_v1_build(&graph, &show));
        ASSERT(graph.event_count == 7);
        ASSERT(events[0].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(events[1].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(events[2].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(events[3].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(events[4].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(events[5].status == ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(events[6].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(show.status == ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(show.unknown_mask == ZCL_STORY_STEP_APP_RUNS);

        struct zcl_story_event_v1 changed_events[7];
        struct zcl_story_graph_v1 changed_graph;
        facts.build_result = "failed";
        ASSERT(zcl_story_graph_from_work_facts(
            &facts, changed_events, &changed_graph));
        struct zcl_story_diff_v1 diff;
        ASSERT(zcl_story_diff_v1_build(&graph, &changed_graph, &diff));
        ASSERT(diff.added_count == 0);
        ASSERT(diff.removed_count == 0);
        ASSERT(diff.changed_count == 1);
        ASSERT(memcmp(diff.changed_event_roots[0],
                      events[3].event_root, 32) == 0);

        facts.build_result = "passed_without_canonical_contract";
        ASSERT(zcl_story_graph_from_work_facts(
            &facts, changed_events, &changed_graph));
        ASSERT(changed_events[3].status == ZCL_ONTOLOGY_INCOMPLETE);

        facts.agent_context_root = "";
        facts.agent_context_ambiguous = true;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT(events[1].status == ZCL_ONTOLOGY_INCOMPLETE);
        PASS();
    } _test_next:;
    return failures;
}

int test_story_graph(void)
{
    int failures = 0;
    failures += sg_complete_story();
    failures += sg_unknown_and_incomplete();
    failures += sg_why_chain();
    failures += sg_diff();
    failures += sg_refusals();
    failures += sg_canonical_work_projection();
    return failures;
}
