/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Born-red contracts for bounded rooted development stories. */
#include "test/test_core.h"
#include "test/accepted_work_fixture.h"
#include "base/hex.h"
#include "ontology/story_graph.h"
#include "ontology/work_map.h"
#include "command/native_story_command.h"
#include "command/native_story_internal.h"
#include "command/native_zcode_work_map.h"
#include "command/native_command.h"
#include "vcs/vcs_object.h"
#include "sha3/sha3.h"
#include "vcs/zcode_app_run_observation.h"
#include "vcs/zcode_dev.h"

#include <limits.h>
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

static int sg_journey_branches(void)
{
    int failures = 0;
    TEST("story journey: proof, inspection, and acceptance branches stay explicit") {
        struct zcl_story_event_v1 events[7];
        sg_complete(events);
        struct story_loaded_work loaded = {0};
        memcpy(loaded.events, events, sizeof(events));
        struct story_journey_stage stages[STORY_JOURNEY_STAGE_COUNT];

        story_journey_build(&loaded, stages);
        ASSERT_EQ(stages[2].status, ZCL_ONTOLOGY_UNKNOWN);
        ASSERT_EQ(stages[5].status, ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(stages[6].status, ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(!stages[2].actionable);
        ASSERT(!stages[6].actionable);
        ASSERT(!stages[8].actionable);
        ASSERT(story_journey_next(stages) == NULL);

        loaded.events[3].status = ZCL_ONTOLOGY_UNKNOWN;
        story_journey_build(&loaded, stages);
        ASSERT_EQ(stages[5].status, ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(strcmp(story_journey_next(stages)->next_command,
                      "zcode.package.dev.evidence") == 0);

        loaded.events[3].status = ZCL_ONTOLOGY_DISPROVED;
        story_journey_build(&loaded, stages);
        ASSERT_EQ(stages[5].status, ZCL_ONTOLOGY_DISPROVED);
        ASSERT(strcmp(story_journey_next(stages)->stage, "proof") == 0);

        loaded.events[3].status = ZCL_ONTOLOGY_BOTH;
        story_journey_build(&loaded, stages);
        ASSERT_EQ(stages[5].status, ZCL_ONTOLOGY_INCOMPLETE);

        loaded.events[3].status = ZCL_ONTOLOGY_PROVED;
        loaded.events[6].status = ZCL_ONTOLOGY_UNKNOWN;
        story_journey_build(&loaded, stages);
        ASSERT_EQ(stages[7].status, ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(strcmp(stages[7].next_command, "zcode.work.accept") == 0);
        ASSERT(strcmp(story_journey_next(stages)->stage, "accept") == 0);
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
    static char roots[64][65];
    static size_t next;
    char *out = roots[next++ % 64u];
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; i++)
        out[i] = digits[(value + (uint8_t)i) & 15u];
    out[64] = '\0';
    return out;
}

static int sg_context_load_states(void)
{
    int failures = 0;
    TEST("story focus: missing, ambiguous, and unavailable context fail closed") {
        struct story_loaded_work loaded = {0};
        struct vcs_zcode_agent_context_v1 context;
        vcs_zcode_agent_context_init(&context);
        ASSERT_EQ(story_load_agent_context(".", &loaded, &context),
                  STORY_CONTEXT_UNKNOWN);

        loaded.agent_context_ambiguous = true;
        ASSERT_EQ(story_load_agent_context(".", &loaded, &context),
                  STORY_CONTEXT_AMBIGUOUS);

        loaded.agent_context_ambiguous = false;
        (void)snprintf(loaded.task_root, sizeof(loaded.task_root), "%s",
                       sg_hex(1));
        (void)snprintf(loaded.source_root, sizeof(loaded.source_root), "%s",
                       sg_hex(2));
        (void)snprintf(loaded.goal_root, sizeof(loaded.goal_root), "%s",
                       sg_hex(3));
        (void)snprintf(loaded.agent_context_root,
                       sizeof(loaded.agent_context_root), "%s", sg_hex(4));
        ASSERT_EQ(story_load_agent_context(
                      "test-tmp/story-context-absent", &loaded, &context),
                  STORY_CONTEXT_UNAVAILABLE);
        ASSERT_EQ(context.file_count, 0);
        vcs_zcode_agent_context_free(&context);
        PASS();
    } _test_next:;
    return failures;
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
            .proof_action_root = sg_hex(13),
            .build_output_root = sg_hex(14),
        };
        facts.accepted_work_root = facts.lane_receipt_root;
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
        uint8_t expected[32];
        ASSERT(zcl_hex_decode_lower(facts.build_output_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(events[3].scene_root, expected, 32) == 0);
        ASSERT(memcmp(events[4].scene_root, expected, 32) == 0);
        ASSERT(zcl_hex_decode_lower(facts.proof_action_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(events[3].action_root, expected, 32) == 0);
        ASSERT(memcmp(events[4].action_root, expected, 32) == 0);
        ASSERT(zcl_hex_decode_lower(facts.proof_set_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(events[3].evidence_root, expected, 32) == 0);
        ASSERT(memcmp(events[4].evidence_root, expected, 32) == 0);
        ASSERT(show.status == ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(show.unknown_mask == ZCL_STORY_STEP_APP_RUNS);

        struct zcl_story_event_v1 changed_events[7];
        struct zcl_story_graph_v1 changed_graph;
        struct zcl_story_work_facts_v1 awaiting = {
            .state = "AWAITING_CANDIDATE",
            .build_result = "not_started",
            .test_result = "unknown",
            .task_root = sg_hex(1),
            .source_root = sg_hex(2),
            .goal_root = sg_hex(3),
            .agent_context_root = sg_hex(4),
        };
        ASSERT(zcl_story_graph_from_work_facts(
            &awaiting, changed_events, &changed_graph));
        ASSERT_EQ(changed_events[1].status, ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(changed_events[2].status, ZCL_ONTOLOGY_UNKNOWN);
        ASSERT_EQ(changed_events[3].status, ZCL_ONTOLOGY_UNKNOWN);
        ASSERT_EQ(changed_events[6].status, ZCL_ONTOLOGY_UNKNOWN);

        facts.accepted_work_root = sg_hex(15);
        ASSERT(zcl_story_graph_from_work_facts(
            &facts, changed_events, &changed_graph));
        ASSERT(changed_events[6].status == ZCL_ONTOLOGY_INCOMPLETE);
        facts.accepted_work_root = facts.lane_receipt_root;

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

        facts.build_result = "passed";
        facts.build_output_root = "";
        ASSERT(zcl_story_graph_from_work_facts(
            &facts, changed_events, &changed_graph));
        ASSERT(changed_events[3].status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(changed_events[4].status == ZCL_ONTOLOGY_PROVED);
        ASSERT(zcl_hex_decode_lower(facts.candidate_source_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(changed_events[4].scene_root, expected, 32) == 0);

        facts.agent_context_root = "";
        facts.agent_context_ambiguous = true;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT(events[1].status == ZCL_ONTOLOGY_INCOMPLETE);
        PASS();
    } _test_next:;
    return failures;
}

static void sg_app_run_fill(struct vcs_zcode_app_run_observation_v1 *observation)
{
    memset(observation, 0, sizeof(*observation));
    observation->schema_version = VCS_ZCODE_APP_RUN_OBSERVATION_VERSION;
    observation->flags = VCS_ZCODE_APP_RUN_PROVED_FLAGS;
    observation->exit_status = 0;
    observation->started_unix = 1000;
    observation->finished_unix = 1001;
    sg_root(observation->task_root, 1);
    sg_root(observation->candidate_root, 2);
    sg_root(observation->build_receipt_root, 3);
    sg_root(observation->artifact_root, 4);
    sg_root(observation->invocation_root, 5);
    sg_root(observation->stdout_root, 6);
    sg_root(observation->stderr_root, 7);
    sg_root(observation->confinement_root, 8);
}

static size_t sg_app_run_root_ptrs(
    struct vcs_zcode_app_run_observation_v1 *observation, uint8_t *out[8])
{
    out[0] = observation->task_root;
    out[1] = observation->candidate_root;
    out[2] = observation->build_receipt_root;
    out[3] = observation->artifact_root;
    out[4] = observation->invocation_root;
    out[5] = observation->stdout_root;
    out[6] = observation->stderr_root;
    out[7] = observation->confinement_root;
    return 8;
}

static int sg_app_run_observation_codec(void)
{
    int failures = 0;
    TEST("story graph: app-run observation is exact evidence, not authority") {
        struct vcs_zcode_app_run_observation_v1 observation;
        sg_app_run_fill(&observation);
        uint8_t wire[VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES];
        uint8_t root_a[32], root_b[32];
        struct vcs_zcode_app_run_observation_v1 parsed;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_serialize(
                      &observation, wire), VCS_ZCODE_APP_RUN_OK);
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_parse(
                      wire, sizeof(wire), &parsed), VCS_ZCODE_APP_RUN_OK);
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_root(
                      &observation, root_a), VCS_ZCODE_APP_RUN_OK);
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_root(
                      &parsed, root_b), VCS_ZCODE_APP_RUN_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        ASSERT(vcs_zcode_app_run_observation_v1_proves_success(&parsed));
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_parse(
                      wire, sizeof(wire) - 1u, &parsed),
                  VCS_ZCODE_APP_RUN_ERR_WIRE_SIZE);
        struct vcs_zcode_app_run_observation_v1 partial = observation;
        partial.flags = VCS_ZCODE_APP_RUN_ATTEMPTED;
        partial.exit_status = INT32_MIN;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&partial),
                  VCS_ZCODE_APP_RUN_OK);
        ASSERT(!vcs_zcode_app_run_observation_v1_proves_success(&partial));
        partial.flags |= UINT16_C(0x8000);
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&partial),
                  VCS_ZCODE_APP_RUN_ERR_FLAGS);
        observation.artifact_root[0] = 0;
        memset(observation.artifact_root, 0,
               sizeof(observation.artifact_root));
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&observation),
                  VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_app_run_observation_refusals(void)
{
    int failures = 0;
    TEST("story graph: app-run validation names every public refusal") {
        static const struct {
            enum vcs_zcode_app_run_observation_error code;
            const char *spelling;
        } spellings[] = {
            { VCS_ZCODE_APP_RUN_OK, "ok" },
            { VCS_ZCODE_APP_RUN_ERR_NULL, "null-argument" },
            { VCS_ZCODE_APP_RUN_ERR_VERSION, "schema-version" },
            { VCS_ZCODE_APP_RUN_ERR_WIRE_SIZE, "wire-size" },
            { VCS_ZCODE_APP_RUN_ERR_WIRE_MAGIC, "wire-magic" },
            { VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO, "root-zero" },
            { VCS_ZCODE_APP_RUN_ERR_FLAGS, "flags-invalid" },
            { VCS_ZCODE_APP_RUN_ERR_EXIT_STATUS, "exit-status-invalid" },
            { VCS_ZCODE_APP_RUN_ERR_TIME_ORDER, "time-order-invalid" },
            { VCS_ZCODE_APP_RUN_ERR_RESERVED, "reserved-nonzero" },
        };
        for (size_t i = 0; i < sizeof(spellings) / sizeof(spellings[0]); i++) {
            const char *got = vcs_zcode_app_run_observation_error_string(
                spellings[i].code);
            ASSERT(got != NULL);
            ASSERT_STR_EQ(got, spellings[i].spelling);
        }
        {
            const char *unknown = vcs_zcode_app_run_observation_error_string(
                (enum vcs_zcode_app_run_observation_error)255);
            ASSERT(unknown != NULL);
            ASSERT_STR_EQ(unknown, "unknown");
        }

        struct vcs_zcode_app_run_observation_v1 valid;
        sg_app_run_fill(&valid);
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(NULL),
                  VCS_ZCODE_APP_RUN_ERR_NULL);
        ASSERT_STR_EQ(vcs_zcode_app_run_observation_error_string(
                          vcs_zcode_app_run_observation_v1_validate(NULL)),
                      "null-argument");
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_serialize(NULL, NULL),
                  VCS_ZCODE_APP_RUN_ERR_NULL);
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_parse(NULL, 0, NULL),
                  VCS_ZCODE_APP_RUN_ERR_NULL);

        struct vcs_zcode_app_run_observation_v1 version = valid;
        version.schema_version = 0;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&version),
                  VCS_ZCODE_APP_RUN_ERR_VERSION);
        version.schema_version = VCS_ZCODE_APP_RUN_OBSERVATION_VERSION + 1u;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&version),
                  VCS_ZCODE_APP_RUN_ERR_VERSION);
        ASSERT_STR_EQ(vcs_zcode_app_run_observation_error_string(
                          vcs_zcode_app_run_observation_v1_validate(&version)),
                      "schema-version");

        struct vcs_zcode_app_run_observation_v1 first = valid;
        memset(first.task_root, 0, sizeof(first.task_root));
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&first),
                  VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO);
        uint8_t *roots[8];
        for (size_t i = 0; i < 8; i++) {
            struct vcs_zcode_app_run_observation_v1 zeroed = valid;
            ASSERT_EQ(sg_app_run_root_ptrs(&zeroed, roots), (size_t)8);
            memset(roots[i], 0, 32);
            ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&zeroed),
                      VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO);
        }

        struct vcs_zcode_app_run_observation_v1 last_byte = valid;
        ASSERT_EQ(sg_app_run_root_ptrs(&last_byte, roots), (size_t)8);
        for (size_t i = 0; i < 8; i++) {
            memset(roots[i], 0, 32);
            roots[i][31] = (uint8_t)(0xa0u + i);
            ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&last_byte),
                      VCS_ZCODE_APP_RUN_OK);
        }

        struct vcs_zcode_app_run_observation_v1 timed = valid;
        timed.started_unix = 0;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&timed),
                  VCS_ZCODE_APP_RUN_ERR_TIME_ORDER);
        timed = valid;
        timed.finished_unix = timed.started_unix - 1;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&timed),
                  VCS_ZCODE_APP_RUN_ERR_TIME_ORDER);

        struct vcs_zcode_app_run_observation_v1 exited = valid;
        exited.exit_status = 256;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&exited),
                  VCS_ZCODE_APP_RUN_ERR_EXIT_STATUS);
        exited.flags = VCS_ZCODE_APP_RUN_ATTEMPTED;
        exited.exit_status = 0;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&exited),
                  VCS_ZCODE_APP_RUN_ERR_EXIT_STATUS);

        struct vcs_zcode_app_run_observation_v1 reserved = valid;
        reserved.reserved[0] = 1;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_validate(&reserved),
                  VCS_ZCODE_APP_RUN_ERR_RESERVED);

        uint8_t wire[VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES];
        struct vcs_zcode_app_run_observation_v1 parsed;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_serialize(&valid, wire),
                  VCS_ZCODE_APP_RUN_OK);
        wire[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_app_run_observation_v1_parse(
                      wire, sizeof(wire), &parsed),
                  VCS_ZCODE_APP_RUN_ERR_WIRE_MAGIC);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_app_run_projection(void)
{
    int failures = 0;
    TEST("story graph: only a complete validated app-run receipt proves run") {
        struct zcl_story_work_facts_v1 facts = {
            .state = "PROVEN",
            .build_result = "passed",
            .test_result = "passed_declared_tests",
            .task_root = sg_hex(1), .source_root = sg_hex(2),
            .goal_root = sg_hex(3), .agent_context_root = sg_hex(4),
            .candidate_root = sg_hex(5),
            .candidate_source_root = sg_hex(6), .patch_root = sg_hex(7),
            .action_root = sg_hex(8), .work_receipt_root = sg_hex(9),
            .output_root = sg_hex(10), .lane_receipt_root = sg_hex(11),
            .proof_set_root = sg_hex(12),
            .lane_created_unix = 101,
        };
        facts.accepted_work_root = facts.lane_receipt_root;
        struct zcl_story_event_v1 events[7];
        struct zcl_story_graph_v1 graph;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT_EQ(events[5].status, ZCL_ONTOLOGY_UNKNOWN);

        facts.app_run_receipt_count = 1;
        facts.app_run_receipt_root = sg_hex(13);
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT_EQ(events[5].status, ZCL_ONTOLOGY_INCOMPLETE);

        facts.valid_app_run_receipt_count = 1;
        facts.app_run_observation_root = sg_hex(14);
        facts.app_run_artifact_root = sg_hex(15);
        facts.app_run_invocation_root = sg_hex(1);
        facts.app_run_action_root = sg_hex(2);
        facts.app_run_flags = VCS_ZCODE_APP_RUN_PROVED_FLAGS;
        facts.app_run_status = VCS_ZCODE_WORK_PASS;
        facts.app_run_exit_status = 0;
        facts.app_run_finished_unix = 100;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT_EQ(events[5].status, ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(events[6].status, ZCL_ONTOLOGY_PROVED);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode_lower(facts.app_run_artifact_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(events[5].scene_root, expected, 32) == 0);
        ASSERT(zcl_hex_decode_lower(facts.app_run_invocation_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(events[5].action_root, expected, 32) == 0);
        ASSERT(zcl_hex_decode_lower(facts.app_run_observation_root,
                                    expected, sizeof(expected)));
        ASSERT(memcmp(events[5].evidence_root, expected, 32) == 0);

        /* A later observation cannot be projected as the cause of an
         * earlier human acceptance, even though both receipts are valid
         * facts independently. */
        facts.app_run_finished_unix = 102;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT_EQ(events[5].status, ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(events[6].status, ZCL_ONTOLOGY_INCOMPLETE);
        facts.app_run_finished_unix = 100;

        facts.app_run_status = VCS_ZCODE_WORK_FAIL;
        facts.app_run_exit_status = 1;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT_EQ(events[5].status, ZCL_ONTOLOGY_DISPROVED);
        facts.valid_app_run_receipt_count = 2;
        ASSERT(zcl_story_graph_from_work_facts(&facts, events, &graph));
        ASSERT_EQ(events[5].status, ZCL_ONTOLOGY_INCOMPLETE);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_hierarchy(void)
{
    int failures = 0;
    TEST("work map: exact task hierarchy rejects duplicates and completion cycles") {
        struct zcl_work_map_node nodes[4] = {0};
        for (size_t i = 0; i < 4; i++) {
            sg_root(nodes[i].task_root, (uint8_t)(i + 1));
            nodes[i].kind = i < 2 ? (uint16_t)(i + 1) : ZCL_WORK_MAP_LOOP;
            nodes[i].parent = i == 0 ? ZCL_WORK_MAP_NO_PARENT : i == 1 ? 0 : 1;
        }
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_OK);
        nodes[3].dependency_count = 1;
        nodes[3].dependencies[0] = 2;
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_OK);
        nodes[2].dependency_count = 1;
        nodes[2].dependencies[0] = 3;
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_CYCLE);
        nodes[2].dependencies[0] = 0;
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_CYCLE);
        nodes[2].dependency_count = 0;
        nodes[3].dependencies[0] = 4;
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_DEPENDENCY);
        nodes[3].dependency_count = 0;
        nodes[3].parent = 0;
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_HIERARCHY);
        nodes[3].parent = 1;
        memcpy(nodes[3].task_root, nodes[2].task_root, 32);
        ASSERT_EQ(zcl_work_map_validate(nodes, 4), ZCL_WORK_MAP_IDENTITY);
        ASSERT_EQ(zcl_work_map_validate(NULL, 4), ZCL_WORK_MAP_BOUNDS);
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES + 1),
                  ZCL_WORK_MAP_BOUNDS);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_bounds(void)
{
    int failures = 0;
    TEST("work map: full capacity and dependency boundaries are enforced") {
        struct zcl_work_map_node nodes[ZCL_WORK_MAP_MAX_NODES] = {0};
        for (size_t i = 0; i < ZCL_WORK_MAP_MAX_NODES; i++) {
            sg_root(nodes[i].task_root, (uint8_t)(i + 1));
            nodes[i].kind = i < 2 ? (uint16_t)(i + 1) : ZCL_WORK_MAP_LOOP;
            nodes[i].parent = i == 0 ? ZCL_WORK_MAP_NO_PARENT : i == 1 ? 0 : 1;
            if (i >= 2 && i + 1 < ZCL_WORK_MAP_MAX_NODES) {
                nodes[i].dependency_count = 1;
                nodes[i].dependencies[0] = (uint16_t)(i + 1);
            }
        }
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES),
                  ZCL_WORK_MAP_OK);
        nodes[2].dependency_count = ZCL_WORK_MAP_MAX_DEPENDENCIES;
        for (size_t d = 0; d < ZCL_WORK_MAP_MAX_DEPENDENCIES; d++)
            nodes[2].dependencies[d] = (uint16_t)(d + 3);
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES),
                  ZCL_WORK_MAP_OK);
        nodes[2].dependency_count++;
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES),
                  ZCL_WORK_MAP_DEPENDENCY);
        nodes[2].dependency_count = 2;
        nodes[2].dependencies[1] = nodes[2].dependencies[0];
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES),
                  ZCL_WORK_MAP_DEPENDENCY);
        nodes[2].dependency_count = 1;
        nodes[2].dependencies[0] = 2;
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES),
                  ZCL_WORK_MAP_DEPENDENCY);
        nodes[2].dependency_count = 0;
        memset(nodes[2].task_root, 0, 32);
        ASSERT_EQ(zcl_work_map_validate(nodes, ZCL_WORK_MAP_MAX_NODES),
                  ZCL_WORK_MAP_IDENTITY);
        ASSERT_EQ(zcl_work_map_validate(nodes, 0), ZCL_WORK_MAP_BOUNDS);
        ASSERT_EQ(zcl_work_map_validate(nodes, 2), ZCL_WORK_MAP_HIERARCHY);
        ASSERT_EQ(zcl_work_map_validate(nodes, 1), ZCL_WORK_MAP_HIERARCHY);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_wire(void)
{
    int failures = 0;
    TEST("work map: bounded wire preserves hierarchy and refuses incomplete bytes") {
        struct zcl_work_map_node nodes[3] = {0}, decoded[3] = {0};
        for (size_t i = 0; i < 3; i++) {
            sg_root(nodes[i].task_root, (uint8_t)(i + 1));
            nodes[i].kind = (uint16_t)(i + 1);
            nodes[i].parent = i == 0 ? ZCL_WORK_MAP_NO_PARENT : (uint16_t)(i - 1);
        }
        uint8_t wire[256], again[256];
        size_t written = 0, count = 0, repeated = 0;
        ASSERT_EQ(zcl_work_map_serialize(nodes, 3, wire, sizeof(wire),
                                         &written), ZCL_WORK_MAP_OK);
        ASSERT_EQ(zcl_work_map_parse(wire, written, decoded, 3, &count),
                   ZCL_WORK_MAP_OK);
        ASSERT_EQ(count, 3);
        ASSERT(memcmp(nodes, decoded, sizeof(nodes)) == 0);
        ASSERT_EQ(zcl_work_map_serialize(decoded, count, again, sizeof(again),
                                         &repeated), ZCL_WORK_MAP_OK);
        ASSERT_EQ(written, repeated);
        ASSERT(memcmp(wire, again, written) == 0);
        ASSERT(zcl_work_map_parse(wire, written - 1, decoded, 3, &count) !=
               ZCL_WORK_MAP_OK);
        ASSERT_EQ(count, 0);
        wire[written] = 0;
        ASSERT(zcl_work_map_parse(wire, written + 1, decoded, 3, &count) !=
               ZCL_WORK_MAP_OK);
        ASSERT_EQ(count, 0);
        ASSERT(zcl_work_map_parse(wire, written, decoded, 2, &count) !=
               ZCL_WORK_MAP_OK);
        ASSERT_EQ(count, 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Independent byte fixture: milestone, feature, two loops; last loop needs
 * the first. Designated bytes expose endian and record offsets explicitly. */
static const uint8_t sg_map_golden[166] = {
    [0]='Z', [1]='2', [2]='3', [3]='W', [4]='M', [5]='A', [6]='P', [7]='\n',
    [8]=1, [10]=4,
    [12]=1, [44]=1, [46]=255, [47]=255,
    [50]=2, [82]=2,
    [88]=3, [120]=3, [122]=1,
    [126]=4, [158]=3, [160]=1, [162]=1, [164]=2,
};

static int sg_work_map_golden(void)
{
    int failures = 0;
    TEST("work map: independent wire bytes and exact output capacity") {
        struct zcl_work_map_node nodes[4] = {0};
        for (size_t i = 0; i < 4; i++) {
            nodes[i].task_root[0] = (uint8_t)(i + 1);
            nodes[i].kind = i < 2 ? (uint16_t)(i + 1) : ZCL_WORK_MAP_LOOP;
            nodes[i].parent = i == 0 ? ZCL_WORK_MAP_NO_PARENT : i == 1 ? 0 : 1;
        }
        nodes[3].dependency_count = 1;
        nodes[3].dependencies[0] = 2;
        uint8_t wire[sizeof(sg_map_golden)];
        size_t written = 999;
        ASSERT_EQ(zcl_work_map_serialize(nodes, 4, wire, sizeof(wire), &written),
                   ZCL_WORK_MAP_OK);
        ASSERT_EQ(written, sizeof(sg_map_golden));
        ASSERT(memcmp(wire, sg_map_golden, written) == 0);
        nodes[0].dependencies[15] = UINT16_MAX;
        ASSERT_EQ(zcl_work_map_serialize(nodes, 4, wire, sizeof(wire), &written),
                   ZCL_WORK_MAP_OK);
        ASSERT(memcmp(wire, sg_map_golden, written) == 0);
        ASSERT_EQ(zcl_work_map_serialize(nodes, 4, wire, sizeof(wire) - 1,
                                         &written), ZCL_WORK_MAP_BOUNDS);
        ASSERT_EQ(written, 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool sg_map_refusal_atomic(const uint8_t *wire, size_t length)
{
    struct zcl_work_map_node nodes[4], before[4];
    memset(nodes, 0xa5, sizeof(nodes));
    memcpy(before, nodes, sizeof(nodes));
    size_t count = 999;
    enum zcl_work_map_result result = zcl_work_map_parse(
        wire, length, nodes, 4, &count);
    return result != ZCL_WORK_MAP_OK && count == 0 &&
           memcmp(nodes, before, sizeof(nodes)) == 0;
}

static int sg_work_map_wire_refusals(void)
{
    int failures = 0;
    TEST("work map: wire refusals never expose partial decoded nodes") {
        for (size_t length = 0; length < sizeof(sg_map_golden); length++)
            ASSERT(sg_map_refusal_atomic(sg_map_golden, length));
        static const struct { size_t offset; uint8_t value; } mutations[] = {
            {0, 0}, {8, 2}, {10, 0}, {10, 205}, {11, 1}, {162, 17},
            {120, 2}, {122, 0}, {88, 2}, {164, 0}, {164, 4}, {164, 3},
        };
        uint8_t wire[sizeof(sg_map_golden) + 1];
        for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
            memcpy(wire, sg_map_golden, sizeof(sg_map_golden));
            wire[mutations[i].offset] = mutations[i].value;
            ASSERT(sg_map_refusal_atomic(wire, sizeof(sg_map_golden)));
        }
        memcpy(wire, sg_map_golden, sizeof(sg_map_golden));
        wire[sizeof(sg_map_golden)] = 0;
        ASSERT(sg_map_refusal_atomic(wire, sizeof(wire)));
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_wire_full(void)
{
    int failures = 0;
    TEST("work map: all 204 nodes and 16 dependency indices round trip") {
        struct zcl_work_map_node nodes[ZCL_WORK_MAP_MAX_NODES] = {0};
        struct zcl_work_map_node decoded[ZCL_WORK_MAP_MAX_NODES] = {0};
        for (size_t i = 0; i < ZCL_WORK_MAP_MAX_NODES; i++) {
            sg_root(nodes[i].task_root, (uint8_t)(i + 1));
            nodes[i].kind = i < 2 ? (uint16_t)(i + 1) : ZCL_WORK_MAP_LOOP;
            nodes[i].parent = i == 0 ? ZCL_WORK_MAP_NO_PARENT : i == 1 ? 0 : 1;
            if (i >= 18) {
                nodes[i].dependency_count = ZCL_WORK_MAP_MAX_DEPENDENCIES;
                for (size_t d = 0; d < ZCL_WORK_MAP_MAX_DEPENDENCIES; d++)
                    nodes[i].dependencies[d] = (uint16_t)(d + 2);
            }
        }
        uint8_t wire[ZCL_WORK_MAP_WIRE_MAX];
        size_t written = 0, count = 0;
        ASSERT_EQ(zcl_work_map_serialize(nodes, ZCL_WORK_MAP_MAX_NODES,
                                         wire, sizeof(wire), &written),
                   ZCL_WORK_MAP_OK);
        ASSERT_EQ(zcl_work_map_parse(wire, written, decoded,
                                     ZCL_WORK_MAP_MAX_NODES, &count),
                   ZCL_WORK_MAP_OK);
        ASSERT_EQ(count, ZCL_WORK_MAP_MAX_NODES);
        ASSERT(memcmp(nodes, decoded, sizeof(nodes)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_command_pages(void)
{
    int failures = 0;
    TEST("work map: complete 204-node coverage paginates without omissions") {
        struct zcl_work_map_node nodes[ZCL_WORK_MAP_MAX_NODES] = {0};
        for (size_t i = 0; i < ZCL_WORK_MAP_MAX_NODES; i++) {
            sg_root(nodes[i].task_root, (uint8_t)(i + 1));
            nodes[i].kind = i < 2 ? (uint16_t)(i + 1) : ZCL_WORK_MAP_LOOP;
            nodes[i].parent = i == 0 ? ZCL_WORK_MAP_NO_PARENT : i == 1 ? 0 : 1;
        }
        uint8_t wire[ZCL_WORK_MAP_WIRE_MAX], root[32];
        size_t written = 0;
        ASSERT_EQ(zcl_work_map_serialize(nodes, ZCL_WORK_MAP_MAX_NODES,
                  wire, sizeof(wire), &written), ZCL_WORK_MAP_OK);
        char dir[256], hex[65];
        test_make_tmpdir(dir, sizeof(dir), "work_map", "pages");
        ASSERT(vcs_object_store_init(dir));
        sha3_256(wire, written, root);
        zcl_hex_encode(root, 32, hex);
        ASSERT(vcs_object_put_addressed(dir, root, wire, written));
        for (size_t offset = 0; offset < ZCL_WORK_MAP_MAX_NODES; offset += 4) {
            struct json_value input;
            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "workspace", dir));
            ASSERT(json_push_kv_str(&input, "map_root", hex));
            ASSERT(json_push_kv_int(&input, "offset", (int64_t)offset));
            struct zcl_command_request request = { .input = &input };
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.zcode_work_map.v1");
            zcl_native_handle_zcode_work_map(&request, &reply);
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
            ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), 204);
            ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 4);
            ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")),
                      offset + 4 == 204 ? -1 : (int64_t)(offset + 4));
            const struct json_value *rows = json_get(&reply.data, "nodes");
            ASSERT_EQ(json_size(rows), 4);
            for (size_t i = 0; i < 4; i++) {
                char expected[65];
                zcl_hex_encode(nodes[offset + i].task_root, 32, expected);
                const struct json_value *row = json_at(rows, i);
                ASSERT_EQ(json_get_int(json_get(row, "index")), (int64_t)(offset + i));
                ASSERT_STR_EQ(json_get_str(json_get(row, "task_root")), expected);
            }
            ASSERT(json_write(&reply.data, NULL, 0) < 4096);
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_command_offpage(void)
{
    int failures = 0;
    TEST("work map: corruption outside requested page refuses the complete map") {
        char dir[256], hex[65];
        test_make_tmpdir(dir, sizeof(dir), "work_map", "offpage");
        ASSERT(vcs_object_store_init(dir));
        uint8_t wire[sizeof(sg_map_golden)], root[32];
        memcpy(wire, sg_map_golden, sizeof(wire));
        wire[126] = 0; /* Fourth node has a zero task root, outside page zero. */
        sha3_256(wire, sizeof(wire), root);
        zcl_hex_encode(root, 32, hex);
        ASSERT(vcs_object_put_addressed(dir, root, wire, sizeof(wire)));
        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", dir));
        ASSERT(json_push_kv_str(&input, "map_root", hex));
        ASSERT(json_push_kv_int(&input, "limit", 1));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_work_map.v1");
        zcl_native_handle_zcode_work_map(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "WORK_MAP_UNAVAILABLE");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "map_refusal")), ZCL_WORK_MAP_IDENTITY);
        ASSERT(json_get(&reply.data, "nodes") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_command_inputs(void)
{
    int failures = 0;
    TEST("work map: malformed command inputs refuse explicitly") {
        static const char *const invalid[] = {
            "{}", "{\"map_root\":\"bad\"}", "{\"workspace\":1}",
            "{\"offset\":-1}", "{\"offset\":205}", "{\"offset\":\"0\"}",
            "{\"limit\":0}", "{\"limit\":5}", "{\"limit\":true}",
            "{\"proof_datadir\":1}",
        };
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            struct json_value input;
            json_init(&input);
            ASSERT(json_read(&input, invalid[i], strlen(invalid[i])));
            if (i >= 2)
                ASSERT(json_push_kv_str(&input, "map_root",
                    "0101010101010101010101010101010101010101010101010101010101010101"));
            struct zcl_command_request request = { .input = &input };
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.zcode_work_map.v1");
            zcl_native_handle_zcode_work_map(&request, &reply);
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
            ASSERT_STR_EQ(reply.error.code, "WORK_MAP_INPUT");
            ASSERT(json_get(&reply.data, "nodes") == NULL);
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_command(void)
{
    int failures = 0;
    TEST("work map: native page exposes hierarchy without inventing acceptance") {
        char dir[256], hex[65];
        test_make_tmpdir(dir, sizeof(dir), "work_map", "command");
        ASSERT(vcs_object_store_init(dir));
        struct test_accepted_work_fixture fixture;
        uint8_t source[32];
        sg_root(source, 0x71);
        ASSERT(test_accepted_work_fixture_create(dir, source, 1500, 0x72, &fixture));
        uint8_t wire[sizeof(sg_map_golden)], task_root[32];
        memcpy(wire, sg_map_golden, sizeof(wire));
        ASSERT_EQ(vcs_zcode_task_root(&fixture.accepted.task, task_root), VCS_ZCODE_DEV_OK);
        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_task_serialize(&fixture.accepted.task, task_wire), VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(dir, wire + 126, task_wire, sizeof(task_wire)));
        memcpy(wire + 88, task_root, 32);
        uint8_t root[32];
        sha3_256(wire, sizeof(wire), root);
        zcl_hex_encode(root, sizeof(root), hex);
        ASSERT(vcs_object_put_addressed(dir, root, wire, sizeof(wire)));
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", dir));
        ASSERT(json_push_kv_str(&input, "map_root", hex));
        ASSERT(json_push_kv_int(&input, "offset", 2));
        ASSERT(json_push_kv_int(&input, "limit", 1));
        ASSERT(json_push_kv_str(&input, "proof_datadir", dir));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_work_map.v1");
        zcl_native_handle_zcode_work_map(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), 4);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")), 3);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "map_root")), hex);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "acceptance_coverage")),
                      "unobserved");
        const struct json_value *row = json_at(json_get(&reply.data, "nodes"), 0);
        ASSERT(row != NULL);
        ASSERT_EQ(json_get_int(json_get(row, "index")), 2);
        ASSERT_EQ(json_get_int(json_get(row, "parent")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(row, "kind")), "loop");
        ASSERT_STR_EQ(json_get_str(json_get(row, "status")), "UNKNOWN");
        ASSERT_STR_EQ(json_get_str(json_get(row, "reason")), "acceptance_not_observed");
        ASSERT_STR_EQ(json_get_str(json_get(row, "task_resolution")), "verified");
        ASSERT(json_get_bool(json_get(row, "task_expired")));
        ASSERT_STR_EQ(json_get_str(json_get(row, "candidate_resolution")), "unobserved");
        ASSERT_EQ(json_get_int(json_get(row, "candidate_ledger_status")),
                  ZCL_NODE_DB_RO_ABSENT);
        ASSERT(json_get(row, "candidate_roots") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "review_resolution")), "unobserved");
        char acceptance[65];
        zcl_hex_encode(fixture.accepted.task.acceptance_tests_root, 32, acceptance);
        ASSERT_STR_EQ(json_get_str(json_get(row, "acceptance_tests_root")), acceptance);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "task_resolution_scope")), "requested_page");
        ASSERT(json_get_int(json_get(&reply.data, "observed_unix")) > 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", dir));
        ASSERT(json_push_kv_str(&input, "map_root", hex));
        ASSERT(json_push_kv_int(&input, "offset", 3));
        ASSERT(json_push_kv_int(&input, "limit", 1));
        zcl_command_reply_init(&reply, "zcl.zcode_work_map.v1");
        zcl_native_handle_zcode_work_map(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        row = json_at(json_get(&reply.data, "nodes"), 0);
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "task_resolution")), "unobserved");
        ASSERT_STR_EQ(json_get_str(json_get(row, "status")), "UNKNOWN");
        ASSERT(json_get(row, "acceptance_tests_root") == NULL);
        ASSERT(json_get(row, "source_root") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_cas_refusals(void)
{
    int failures = 0;
    TEST("work map: addressed malformed and oversized CAS objects refuse atomically") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "work_map", "cas_refusals");
        ASSERT(vcs_object_store_init(dir));
        uint8_t wire[ZCL_WORK_MAP_WIRE_MAX + 1] = {0}, root[32];
        struct zcl_work_map_node nodes[4], before[4];
        memset(nodes, 0xa5, sizeof(nodes));
        memcpy(before, nodes, sizeof(nodes));
        size_t count = 999;
        sha3_256(wire, sizeof(wire), root);
        ASSERT(vcs_object_put_addressed(dir, root, wire, sizeof(wire)));
        ASSERT_EQ(zcl_native_work_map_load(dir, root, nodes, 4, &count),
                  ZCL_WORK_MAP_BOUNDS);
        ASSERT_EQ(count, 0);
        ASSERT(memcmp(nodes, before, sizeof(nodes)) == 0);
        memcpy(wire, sg_map_golden, sizeof(sg_map_golden));
        wire[0] ^= 1;
        sha3_256(wire, sizeof(sg_map_golden), root);
        ASSERT(vcs_object_put_addressed(dir, root, wire, sizeof(sg_map_golden)));
        count = 999;
        ASSERT_EQ(zcl_native_work_map_load(dir, root, nodes, 4, &count),
                  ZCL_WORK_MAP_WIRE);
        ASSERT_EQ(count, 0);
        ASSERT(memcmp(nodes, before, sizeof(nodes)) == 0);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int sg_work_map_cas(void)
{
    int failures = 0;
    TEST("work map: CAS loading verifies exact bounded bytes before exposing nodes") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "work_map", "cas");
        uint8_t root[32], wrong[32];
        sha3_256(sg_map_golden, sizeof(sg_map_golden), root);
        memcpy(wrong, root, sizeof(wrong));
        wrong[0] ^= 1;
        struct zcl_work_map_node nodes[4], before[4];
        memset(nodes, 0xa5, sizeof(nodes));
        memcpy(before, nodes, sizeof(nodes));
        size_t count = 999;
        ASSERT_EQ(zcl_native_work_map_load(dir, root, nodes, 4, &count),
                  ZCL_WORK_MAP_OBJECT);
        ASSERT_EQ(count, 0);
        ASSERT(memcmp(nodes, before, sizeof(nodes)) == 0);
        ASSERT(!vcs_object_store_initialized(dir));
        ASSERT(vcs_object_store_init(dir));
        ASSERT(vcs_object_put_addressed(dir, wrong, sg_map_golden,
                                        sizeof(sg_map_golden)));
        ASSERT_EQ(zcl_native_work_map_load(dir, wrong, nodes, 4, &count),
                  ZCL_WORK_MAP_IDENTITY);
        ASSERT_EQ(count, 0);
        ASSERT(memcmp(nodes, before, sizeof(nodes)) == 0);
        ASSERT(vcs_object_put_addressed(dir, root, sg_map_golden,
                                        sizeof(sg_map_golden)));
        ASSERT_EQ(zcl_native_work_map_load(dir, root, nodes, 3, &count),
                  ZCL_WORK_MAP_BOUNDS);
        ASSERT_EQ(count, 0);
        ASSERT(memcmp(nodes, before, sizeof(nodes)) == 0);
        ASSERT_EQ(zcl_native_work_map_load(dir, root, nodes, 4, &count),
                   ZCL_WORK_MAP_OK);
        ASSERT_EQ(count, 4);
        ASSERT_EQ(nodes[3].dependencies[0], 2);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_story_graph(void)
{
    int failures = 0;
    failures += sg_work_map_cas_refusals();
    failures += sg_work_map_command();
    failures += sg_work_map_command_inputs();
    failures += sg_work_map_command_pages();
    failures += sg_work_map_command_offpage();
    failures += sg_work_map_hierarchy();
    failures += sg_work_map_bounds();
    failures += sg_work_map_wire();
    failures += sg_work_map_golden();
    failures += sg_work_map_wire_refusals();
    failures += sg_work_map_wire_full();
    failures += sg_work_map_cas();
    failures += sg_complete_story();
    failures += sg_unknown_and_incomplete();
    failures += sg_journey_branches();
    failures += sg_why_chain();
    failures += sg_diff();
    failures += sg_refusals();
    failures += sg_context_load_states();
    failures += sg_canonical_work_projection();
    failures += sg_app_run_observation_codec();
    failures += sg_app_run_observation_refusals();
    failures += sg_app_run_projection();
    return failures;
}
