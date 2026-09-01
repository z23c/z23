/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded CAS-backed heuristic lifecycle state-machine projection. */
#include "vcs/zcode_heuristic_lifecycle.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_science.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct hl_node {
    struct vcs_zcode_science_statement_v1 statement;
    uint8_t predecessor_root[32];
    size_t predecessor;
    size_t child;
    uint8_t child_count;
    uint8_t relation_type;
    uint16_t relation_count;
};

static bool hl_root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32u; i++) any |= root[i];
    return any != 0;
}

static bool hl_memory_overlaps(const void *left, size_t left_size,
                               const void *right, size_t right_size)
{
    uintptr_t l = (uintptr_t)left;
    uintptr_t r = (uintptr_t)right;
    if (l > UINTPTR_MAX - left_size || r > UINTPTR_MAX - right_size)
        return true;
    return l < r + right_size && r < l + left_size;
}

static enum vcs_zcode_attention_error hl_snapshot_validate(
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot)
{
    if (!snapshot) return VCS_ZCODE_ATTENTION_NULL;
    if (snapshot->schema_version !=
        VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_VERSION)
        return VCS_ZCODE_ATTENTION_VERSION;
    if (snapshot->statement_count >
        VCS_ZCODE_HEURISTIC_LIFECYCLE_MAX_STATEMENTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (!hl_root_nonzero(snapshot->local_policy_root) ||
        !hl_root_nonzero(snapshot->expected_signer) ||
        !hl_root_nonzero(snapshot->heuristic_root))
        return VCS_ZCODE_ATTENTION_ROOT;

    bool anchor_found = false;
    for (size_t i = 0;
         i < VCS_ZCODE_HEURISTIC_LIFECYCLE_MAX_STATEMENTS; i++) {
        bool active = i < snapshot->statement_count;
        bool nonzero = hl_root_nonzero(snapshot->statement_roots[i]);
        if (active != nonzero) return VCS_ZCODE_ATTENTION_ROOT;
        if (!active) continue;
        if (i != 0 && memcmp(snapshot->statement_roots[i - 1u],
                             snapshot->statement_roots[i], 32) >= 0)
            return VCS_ZCODE_ATTENTION_ORDER;
        if (memcmp(snapshot->statement_roots[i],
                   snapshot->anchor_statement_root, 32) == 0)
            anchor_found = true;
    }
    if (snapshot->statement_count == 0)
        return hl_root_nonzero(snapshot->anchor_statement_root)
            ? VCS_ZCODE_ATTENTION_BINDING : VCS_ZCODE_ATTENTION_OK;
    if (!hl_root_nonzero(snapshot->anchor_statement_root) || !anchor_found)
        return VCS_ZCODE_ATTENTION_BINDING;
    return VCS_ZCODE_ATTENTION_OK;
}

static void hl_snapshot_root(
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    uint8_t out[32])
{
    static const char domain[] =
        VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_DOMAIN;
    uint8_t count_le[2];
    zcl_write_u16_le(count_le, snapshot->statement_count);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, snapshot->local_policy_root, 32);
    sha3_256_write(&sha, snapshot->expected_signer, 32);
    sha3_256_write(&sha, snapshot->heuristic_root, 32);
    sha3_256_write(&sha, snapshot->anchor_statement_root, 32);
    sha3_256_write(&sha, count_le, sizeof(count_le));
    for (size_t i = 0; i < snapshot->statement_count; i++)
        sha3_256_write(&sha, snapshot->statement_roots[i], 32);
    sha3_256_finalize(&sha, out);
}

static bool hl_statement_load(
    const char *workspace, const uint8_t expected_root[32],
    const uint8_t expected_signer[32], const uint8_t heuristic_root[32],
    struct vcs_zcode_science_statement_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t checked_root[32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, expected_root,
            VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        wire_len == VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES &&
        vcs_zcode_science_statement_parse(wire, wire_len, out) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(out, checked_root) ==
            VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked_root, expected_root, 32) == 0 &&
        vcs_zcode_science_statement_verify(out, expected_signer) ==
            VCS_ZCODE_SCIENCE_OK &&
        memcmp(out->subject_root, heuristic_root, 32) == 0;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static bool hl_relations_load(
    const char *workspace,
    const struct vcs_zcode_science_statement_v1 *statement,
    struct vcs_zcode_science_relation_set_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t checked_root[32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, statement->relations_root,
            VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_science_relation_set_parse(wire, wire_len, out) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_relation_set_root(out, checked_root) ==
            VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked_root, statement->relations_root, 32) == 0 &&
        vcs_zcode_science_statement_validate_relations(statement, out) ==
            VCS_ZCODE_SCIENCE_OK;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static size_t hl_find_root(
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    const uint8_t root[32])
{
    size_t low = 0, high = snapshot->statement_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        int cmp = memcmp(snapshot->statement_roots[middle], root, 32);
        if (cmp < 0) low = middle + 1u;
        else high = middle;
    }
    return low < snapshot->statement_count &&
           memcmp(snapshot->statement_roots[low], root, 32) == 0
        ? low : SIZE_MAX;
}

static uint8_t hl_relation_for_profile(uint8_t profile)
{
    switch (profile) {
    case VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION:
        return VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION;
    case VCS_ZCODE_SCIENCE_PROFILE_RETRACTION:
        return VCS_ZCODE_SCIENCE_RELATION_RETRACTION;
    default:
        return 0;
    }
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_lifecycle_fold(
    const char *workspace,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    struct vcs_zcode_heuristic_lifecycle_report *report)
{
    if (!workspace || !snapshot || !report)
        return VCS_ZCODE_ATTENTION_NULL;
    size_t workspace_bytes = strlen(workspace) + 1u;
    if (hl_memory_overlaps(report, sizeof(*report), workspace,
                           workspace_bytes) ||
        hl_memory_overlaps(report, sizeof(*report), snapshot,
                           sizeof(*snapshot)))
        return VCS_ZCODE_ATTENTION_ALIAS;
    enum vcs_zcode_attention_error error = hl_snapshot_validate(snapshot);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    struct vcs_zcode_heuristic_lifecycle_report result = {0};
    result.status = VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED;
    hl_snapshot_root(snapshot, result.snapshot_root);
    if (snapshot->statement_count == 0) {
        result.complete = true;
        result.reason = VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_EMPTY;
        *report = result;
        return VCS_ZCODE_ATTENTION_OK;
    }

    struct hl_node *nodes = zcl_calloc(
        snapshot->statement_count, sizeof(*nodes), "heuristic_lifecycle");
    if (!nodes) return VCS_ZCODE_ATTENTION_CAS;
    size_t anchor = hl_find_root(snapshot, snapshot->anchor_statement_root);
    bool valid = anchor != SIZE_MAX;
    for (size_t i = 0; valid && i < snapshot->statement_count; i++) {
        valid = hl_statement_load(
            workspace, snapshot->statement_roots[i],
            snapshot->expected_signer, snapshot->heuristic_root,
            &nodes[i].statement);
        if (!valid) break;
        struct vcs_zcode_science_relation_set_v1 relations;
        valid = hl_relations_load(workspace, &nodes[i].statement, &relations);
        if (!valid) break;
        nodes[i].predecessor = SIZE_MAX;
        nodes[i].child = SIZE_MAX;
        nodes[i].relation_count = relations.row_count;
        if (relations.row_count != 0) {
            nodes[i].relation_type = relations.rows[0].type;
            memcpy(nodes[i].predecessor_root,
                   relations.rows[0].statement_root, 32);
        }
    }
    if (!valid) {
        free(nodes);
        return VCS_ZCODE_ATTENTION_EVIDENCE;
    }

    valid = nodes[anchor].statement.profile ==
            VCS_ZCODE_SCIENCE_PROFILE_RESULT &&
        nodes[anchor].relation_count == 0;
    for (size_t i = 0; valid && i < snapshot->statement_count; i++) {
        if (i == anchor) continue;
        uint8_t expected_relation =
            hl_relation_for_profile(nodes[i].statement.profile);
        valid = expected_relation != 0 && nodes[i].relation_count == 1 &&
            nodes[i].relation_type == expected_relation &&
            memcmp(nodes[i].statement.predicate_body_root,
                   nodes[anchor].statement.predicate_body_root, 32) == 0 &&
            memcmp(nodes[i].statement.input_root,
                   nodes[anchor].statement.input_root, 32) == 0 &&
            memcmp(nodes[i].statement.activity_root,
                   nodes[anchor].statement.activity_root, 32) == 0;
        if (!valid) break;
        nodes[i].predecessor = hl_find_root(
            snapshot, nodes[i].predecessor_root);
        valid = nodes[i].predecessor != SIZE_MAX;
    }
    if (!valid) {
        free(nodes);
        return VCS_ZCODE_ATTENTION_EVIDENCE;
    }

    bool ambiguous = false;
    for (size_t i = 0; i < snapshot->statement_count; i++) {
        if (i == anchor) continue;
        size_t predecessor = nodes[i].predecessor;
        nodes[predecessor].child_count++;
        if (nodes[predecessor].child_count == 1u)
            nodes[predecessor].child = i;
        else
            ambiguous = true;
    }
    bool visited[VCS_ZCODE_HEURISTIC_LIFECYCLE_MAX_STATEMENTS] = {false};
    size_t current = anchor, visited_count = 0;
    while (!ambiguous && current != SIZE_MAX && !visited[current]) {
        visited[current] = true;
        visited_count++;
        current = nodes[current].child;
    }
    if (current != SIZE_MAX || visited_count != snapshot->statement_count)
        ambiguous = true;

    result.validated_count = snapshot->statement_count;
    result.complete = true;
    if (ambiguous) {
        result.reason = VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_AMBIGUOUS;
    } else {
        size_t head = anchor;
        while (nodes[head].child != SIZE_MAX) head = nodes[head].child;
        memcpy(result.head_statement_root,
               snapshot->statement_roots[head], 32);
        switch (nodes[head].statement.profile) {
        case VCS_ZCODE_SCIENCE_PROFILE_RESULT:
        case VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION:
            result.status = VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED;
            break;
        case VCS_ZCODE_SCIENCE_PROFILE_RETRACTION:
            result.status = VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED;
            break;
        default:
            break;
        }
    }
    free(nodes);
    *report = result;
    return VCS_ZCODE_ATTENTION_OK;
}
