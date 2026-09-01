/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Root and query bounded causal views without creating new truth. */
#include "ontology/story_graph.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

static bool story_nonzero(const uint8_t root[32])
{
    return root && zcl_bytes_any_set(root, 32);
}

static bool story_status_valid(uint8_t status)
{
    return status >= ZCL_ONTOLOGY_PROVED &&
           status <= ZCL_ONTOLOGY_INCOMPLETE;
}

static uint32_t story_kind_bit(uint8_t kind)
{
    return kind >= ZCL_STORY_EVENT_USER_ASKS &&
           kind <= ZCL_STORY_EVENT_USER_ACCEPTS
        ? 1u << (kind - 1u) : 0;
}

static void story_hash_start(struct sha3_256_ctx *sha, const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1u);
}

static void story_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t wire[2];
    zcl_write_u16_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void story_hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t wire[4];
    zcl_write_u32_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void story_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t wire[8];
    zcl_write_u64_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

bool zcl_story_event_v1_root(
    const struct zcl_story_event_v1 *event, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!event || !out ||
        event->schema_version != ZCL_STORY_GRAPH_VERSION ||
        story_kind_bit(event->kind) == 0 ||
        !story_status_valid(event->status) || event->reserved != 0)
        return false;
    const uint8_t *required[] = {
        event->universe_root, event->context_root, event->scene_root,
        event->entity_root, event->action_root, event->event_root,
        event->evidence_root,
    };
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++)
        if (!story_nonzero(required[i])) return false;
    bool first = event->kind == ZCL_STORY_EVENT_USER_ASKS;
    if (first == story_nonzero(event->cause_event_root) ||
        memcmp(event->event_root, event->cause_event_root, 32) == 0)
        return false;
    struct sha3_256_ctx sha;
    story_hash_start(&sha, "zcl.story_event.v1");
    story_hash_u16(&sha, event->schema_version);
    sha3_256_write(&sha, &event->kind, 1);
    sha3_256_write(&sha, &event->status, 1);
    story_hash_u32(&sha, event->reserved);
    sha3_256_write(&sha, event->universe_root, 32);
    sha3_256_write(&sha, event->context_root, 32);
    sha3_256_write(&sha, event->scene_root, 32);
    sha3_256_write(&sha, event->entity_root, 32);
    sha3_256_write(&sha, event->action_root, 32);
    sha3_256_write(&sha, event->event_root, 32);
    sha3_256_write(&sha, event->evidence_root, 32);
    sha3_256_write(&sha, event->cause_event_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

bool zcl_story_graph_v1_validate(const struct zcl_story_graph_v1 *graph)
{
    if (!graph || graph->schema_version != ZCL_STORY_GRAPH_VERSION ||
        graph->reserved != 0 || graph->event_count == 0 ||
        graph->event_count > ZCL_STORY_MAX_EVENTS || !graph->events)
        return false;
    for (size_t i = 0; i < graph->event_count; i++) {
        uint8_t ignored[32];
        const struct zcl_story_event_v1 *event = &graph->events[i];
        if (!zcl_story_event_v1_root(event, ignored) ||
            (i != 0 && event->kind <= graph->events[i - 1u].kind) ||
            memcmp(event->universe_root,
                   graph->events[0].universe_root, 32) != 0 ||
            memcmp(event->context_root,
                   graph->events[0].context_root, 32) != 0)
            return false;
        for (size_t j = 0; j < i; j++)
            if (memcmp(event->event_root,
                       graph->events[j].event_root, 32) == 0)
                return false;
    }
    return true;
}

bool zcl_story_graph_v1_root(
    const struct zcl_story_graph_v1 *graph, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out || !zcl_story_graph_v1_validate(graph)) return false;
    struct sha3_256_ctx sha;
    story_hash_start(&sha, "zcl.story_graph.v1");
    story_hash_u16(&sha, graph->schema_version);
    story_hash_u16(&sha, graph->reserved);
    story_hash_u64(&sha, graph->event_count);
    for (size_t i = 0; i < graph->event_count; i++) {
        uint8_t event_root[32];
        if (!zcl_story_event_v1_root(&graph->events[i], event_root))
            return false;
        sha3_256_write(&sha, event_root, 32);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

static enum zcl_ontology_status story_status(
    uint32_t missing, uint32_t incomplete, uint32_t unknown,
    uint32_t both, uint32_t disproved)
{
    if (missing || incomplete) return ZCL_ONTOLOGY_INCOMPLETE;
    if (unknown) return ZCL_ONTOLOGY_UNKNOWN;
    if (both) return ZCL_ONTOLOGY_BOTH;
    if (disproved) return ZCL_ONTOLOGY_DISPROVED;
    return ZCL_ONTOLOGY_PROVED;
}

bool zcl_story_show_v1_build(
    const struct zcl_story_graph_v1 *graph, struct zcl_story_show_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!zcl_story_graph_v1_root(graph, out->story_root)) return false;
    out->event_count = graph->event_count;
    memcpy(out->universe_root, graph->events[0].universe_root, 32);
    memcpy(out->context_root, graph->events[0].context_root, 32);
    memcpy(out->scene_root,
           graph->events[graph->event_count - 1u].scene_root, 32);
    for (size_t i = 0; i < graph->event_count; i++) {
        uint32_t bit = story_kind_bit(graph->events[i].kind);
        out->observed_mask |= bit;
        switch (graph->events[i].status) {
        case ZCL_ONTOLOGY_PROVED: out->proved_mask |= bit; break;
        case ZCL_ONTOLOGY_DISPROVED: out->disproved_mask |= bit; break;
        case ZCL_ONTOLOGY_BOTH: out->both_mask |= bit; break;
        case ZCL_ONTOLOGY_UNKNOWN: out->unknown_mask |= bit; break;
        case ZCL_ONTOLOGY_INCOMPLETE: out->incomplete_mask |= bit; break;
        default: return false;
        }
    }
    out->missing_mask = ZCL_STORY_DEVELOPMENT_ALL & ~out->observed_mask;
    out->status = story_status(out->missing_mask, out->incomplete_mask,
                               out->unknown_mask, out->both_mask,
                               out->disproved_mask);
    out->complete = out->missing_mask == 0 && out->incomplete_mask == 0 &&
                    out->unknown_mask == 0;
    return true;
}

static size_t story_find_event(const struct zcl_story_graph_v1 *graph,
                               const uint8_t event_root[32])
{
    for (size_t i = 0; i < graph->event_count; i++)
        if (memcmp(graph->events[i].event_root, event_root, 32) == 0)
            return i;
    return SIZE_MAX;
}

bool zcl_story_why_v1_build(
    const struct zcl_story_graph_v1 *graph, const uint8_t target_event_root[32],
    struct zcl_story_why_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!story_nonzero(target_event_root) ||
        !zcl_story_graph_v1_root(graph, out->story_root))
        return false;
    memcpy(out->target_event_root, target_event_root, 32);
    size_t at = story_find_event(graph, target_event_root);
    if (at == SIZE_MAX) {
        out->status = ZCL_ONTOLOGY_UNKNOWN;
        out->target_unknown = true;
        return true;
    }
    uint8_t reverse[ZCL_STORY_MAX_EVENTS][32];
    uint32_t incomplete = 0, unknown = 0, both = 0, disproved = 0;
    while (true) {
        const struct zcl_story_event_v1 *event = &graph->events[at];
        if (out->cause_count >= ZCL_STORY_MAX_EVENTS) {
            out->cycle_detected = true;
            break;
        }
        for (size_t i = 0; i < out->cause_count; i++)
            if (memcmp(reverse[i], event->event_root, 32) == 0) {
                out->cycle_detected = true;
                break;
            }
        if (out->cycle_detected) break;
        memcpy(reverse[out->cause_count++], event->event_root, 32);
        uint32_t bit = story_kind_bit(event->kind);
        if (event->status == ZCL_ONTOLOGY_INCOMPLETE) incomplete |= bit;
        else if (event->status == ZCL_ONTOLOGY_UNKNOWN) unknown |= bit;
        else if (event->status == ZCL_ONTOLOGY_BOTH) both |= bit;
        else if (event->status == ZCL_ONTOLOGY_DISPROVED) disproved |= bit;
        if (!story_nonzero(event->cause_event_root)) break;
        size_t cause = story_find_event(graph, event->cause_event_root);
        if (cause == SIZE_MAX) {
            out->missing_cause = true;
            memcpy(out->missing_cause_root, event->cause_event_root, 32);
            break;
        }
        at = cause;
    }
    for (size_t i = 0; i < out->cause_count; i++)
        memcpy(out->cause_event_roots[i],
               reverse[out->cause_count - i - 1u], 32);
    uint32_t structural = (out->missing_cause || out->cycle_detected) ? 1u : 0;
    out->status = story_status(structural, incomplete, unknown, both,
                               disproved);
    out->complete = !structural && incomplete == 0 && unknown == 0;
    return true;
}

bool zcl_story_diff_v1_build(
    const struct zcl_story_graph_v1 *before,
    const struct zcl_story_graph_v1 *after,
    struct zcl_story_diff_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!zcl_story_graph_v1_root(before, out->before_story_root) ||
        !zcl_story_graph_v1_root(after, out->after_story_root))
        return false;
    for (size_t i = 0; i < before->event_count; i++) {
        size_t match = story_find_event(after, before->events[i].event_root);
        if (match == SIZE_MAX) {
            memcpy(out->removed_event_roots[out->removed_count++],
                   before->events[i].event_root, 32);
            continue;
        }
        uint8_t left[32], right[32];
        if (!zcl_story_event_v1_root(&before->events[i], left) ||
            !zcl_story_event_v1_root(&after->events[match], right))
            return false;
        if (memcmp(left, right, 32) != 0)
            memcpy(out->changed_event_roots[out->changed_count++],
                   before->events[i].event_root, 32);
    }
    for (size_t i = 0; i < after->event_count; i++)
        if (story_find_event(before, after->events[i].event_root) == SIZE_MAX)
            memcpy(out->added_event_roots[out->added_count++],
                   after->events[i].event_root, 32);
    out->status = ZCL_ONTOLOGY_PROVED;
    out->complete = true;
    return true;
}

const char *zcl_story_event_kind_name(enum zcl_story_event_kind kind)
{
    switch (kind) {
    case ZCL_STORY_EVENT_USER_ASKS: return "user_asks";
    case ZCL_STORY_EVENT_AGENT_FINDS_CODE: return "agent_finds_code";
    case ZCL_STORY_EVENT_AGENT_EDITS: return "agent_edits";
    case ZCL_STORY_EVENT_BUILD_COMPLETES: return "builds";
    case ZCL_STORY_EVENT_TEST_COMPLETES: return "tests";
    case ZCL_STORY_EVENT_APP_RUNS: return "app_runs";
    case ZCL_STORY_EVENT_USER_ACCEPTS: return "user_accepts";
    default: return "unknown";
    }
}
