/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded causal views over exact ontology-adjacent evidence roots. */
#ifndef ZCL_ONTOLOGY_STORY_GRAPH_H
#define ZCL_ONTOLOGY_STORY_GRAPH_H

#include "ontology/ontology.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    ZCL_STORY_GRAPH_VERSION = 1,
    ZCL_STORY_MAX_EVENTS = 16,
};

enum zcl_story_event_kind {
    ZCL_STORY_EVENT_USER_ASKS = 1,
    ZCL_STORY_EVENT_AGENT_FINDS_CODE = 2,
    ZCL_STORY_EVENT_AGENT_EDITS = 3,
    ZCL_STORY_EVENT_BUILD_COMPLETES = 4,
    ZCL_STORY_EVENT_TEST_COMPLETES = 5,
    ZCL_STORY_EVENT_APP_RUNS = 6,
    ZCL_STORY_EVENT_USER_ACCEPTS = 7,
};

enum zcl_story_development_step {
    ZCL_STORY_STEP_USER_ASKS = 1u << 0,
    ZCL_STORY_STEP_AGENT_FINDS_CODE = 1u << 1,
    ZCL_STORY_STEP_AGENT_EDITS = 1u << 2,
    ZCL_STORY_STEP_BUILD_COMPLETES = 1u << 3,
    ZCL_STORY_STEP_TEST_COMPLETES = 1u << 4,
    ZCL_STORY_STEP_APP_RUNS = 1u << 5,
    ZCL_STORY_STEP_USER_ACCEPTS = 1u << 6,
    ZCL_STORY_DEVELOPMENT_ALL = (1u << 7) - 1u,
};

/* A story event is a read-only causal projection, never a new authority.
 * universe/context/scene identify what existed and the bounded assumptions;
 * entity/action/event identify who or what changed; evidence identifies the
 * canonical object or receipt that supports this exact projection. UNKNOWN
 * and INCOMPLETE events still carry all of those roots: absence of proof is
 * represented explicitly rather than by an empty identity. event_root is the
 * stable identity of this relation within the context (so diff can distinguish
 * identity from changed evidence), while this object's canonical root binds
 * its current status, scene, evidence, and cause. */
struct zcl_story_event_v1 {
    uint16_t schema_version;
    uint8_t kind;
    uint8_t status;
    uint32_t reserved;
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t scene_root[32];
    uint8_t entity_root[32];
    uint8_t action_root[32];
    uint8_t event_root[32];
    uint8_t evidence_root[32];
    uint8_t cause_event_root[32];
};

struct zcl_story_graph_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    size_t event_count;
    const struct zcl_story_event_v1 *events;
};

struct zcl_story_show_v1 {
    enum zcl_ontology_status status;
    bool complete;
    size_t event_count;
    uint32_t observed_mask;
    uint32_t proved_mask;
    uint32_t disproved_mask;
    uint32_t both_mask;
    uint32_t unknown_mask;
    uint32_t incomplete_mask;
    uint32_t missing_mask;
    uint8_t story_root[32];
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t scene_root[32];
};

struct zcl_story_why_v1 {
    enum zcl_ontology_status status;
    bool complete;
    bool target_unknown;
    bool missing_cause;
    bool cycle_detected;
    size_t cause_count;
    uint8_t story_root[32];
    uint8_t target_event_root[32];
    uint8_t missing_cause_root[32];
    uint8_t cause_event_roots[ZCL_STORY_MAX_EVENTS][32];
};

struct zcl_story_diff_v1 {
    enum zcl_ontology_status status;
    bool complete;
    size_t added_count;
    size_t removed_count;
    size_t changed_count;
    uint8_t before_story_root[32];
    uint8_t after_story_root[32];
    uint8_t added_event_roots[ZCL_STORY_MAX_EVENTS][32];
    uint8_t removed_event_roots[ZCL_STORY_MAX_EVENTS][32];
    uint8_t changed_event_roots[ZCL_STORY_MAX_EVENTS][32];
};

bool zcl_story_event_v1_root(
    const struct zcl_story_event_v1 *event, uint8_t out[32]);
bool zcl_story_graph_v1_validate(const struct zcl_story_graph_v1 *graph);
bool zcl_story_graph_v1_root(
    const struct zcl_story_graph_v1 *graph, uint8_t out[32]);
bool zcl_story_show_v1_build(
    const struct zcl_story_graph_v1 *graph, struct zcl_story_show_v1 *out);
bool zcl_story_why_v1_build(
    const struct zcl_story_graph_v1 *graph, const uint8_t target_event_root[32],
    struct zcl_story_why_v1 *out);
bool zcl_story_diff_v1_build(
    const struct zcl_story_graph_v1 *before,
    const struct zcl_story_graph_v1 *after,
    struct zcl_story_diff_v1 *out);

const char *zcl_story_event_kind_name(enum zcl_story_event_kind kind);

#endif /* ZCL_ONTOLOGY_STORY_GRAPH_H */
