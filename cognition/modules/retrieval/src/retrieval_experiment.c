/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, relevance-free retrieval experiment projection. */
#include "retrieval/retrieval_experiment.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

static void rx_u64le(uint8_t out[8], uint64_t value)
{
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value & 0xffu);
        value >>= 8;
    }
}

static bool rx_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool rx_memory_overlaps(const void *left, size_t left_size,
                               const void *right, size_t right_size)
{
    uintptr_t left_address = (uintptr_t)left;
    uintptr_t right_address = (uintptr_t)right;
    if (left_address > UINTPTR_MAX - left_size ||
        right_address > UINTPTR_MAX - right_size)
        return true;
    return left_address < right_address + right_size &&
           right_address < left_address + left_size;
}

static bool rx_bounded_text(const char *text, size_t maximum,
                            size_t *length_out)
{
    if (!text || !length_out) return false;
    size_t length = 0;
    while (length <= maximum && text[length]) length++;
    if (length == 0 || length > maximum) return false;
    *length_out = length;
    return true;
}

void zcl_retrieval_profile_init(struct zcl_retrieval_profile_v1 *profile)
{
    if (!profile) return;
    memset(profile, 0, sizeof(*profile));
    profile->schema_version = ZCL_RETRIEVAL_PROFILE_VERSION;
}

enum zcl_retrieval_experiment_error zcl_retrieval_profile_validate(
    const struct zcl_retrieval_profile_v1 *profile)
{
    if (!profile) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (profile->schema_version != ZCL_RETRIEVAL_PROFILE_VERSION)
        return ZCL_RETRIEVAL_EXPERIMENT_VERSION;
    if (profile->feature_mask == 0 ||
        (profile->feature_mask & ~ZCL_RETRIEVAL_FEATURE_MASK_ALL) != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_PARAMETER;
    for (size_t i = 0; i < ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT; i++) {
        bool active = (profile->feature_mask &
                       ZCL_RETRIEVAL_FEATURE_BIT(i)) != 0;
        if (active != (profile->weight_bp[i] != 0) ||
            profile->weight_bp[i] > ZCL_RETRIEVAL_PROFILE_WEIGHT_MAX)
            return ZCL_RETRIEVAL_EXPERIMENT_PARAMETER;
    }
    bool rarity = (profile->feature_mask & ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY)) != 0;
    bool graph = (profile->feature_mask & ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY)) != 0;
    bool context = (profile->feature_mask & ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES)) != 0;
    if ((rarity && (profile->identifier_df_max == 0 ||
                    profile->identifier_df_max >
                        ZCL_RETRIEVAL_EVAL_RANK_MAX)) ||
        (!rarity && profile->identifier_df_max != 0) ||
        (graph && (profile->graph_depth == 0 ||
                   profile->graph_depth >
                       ZCL_RETRIEVAL_PROFILE_GRAPH_DEPTH_MAX)) ||
        (!graph && profile->graph_depth != 0) ||
        (context != (profile->context_byte_scale != 0)) ||
        profile->rerank_window == 0 ||
        profile->rerank_window > ZCL_RETRIEVAL_PROFILE_WINDOW_MAX ||
        profile->top_k == 0 || profile->top_k > ZCL_RETRIEVAL_EXPERIMENT_TOP ||
        profile->top_k > profile->rerank_window)
        return ZCL_RETRIEVAL_EXPERIMENT_PARAMETER;
    if (profile->reserved != 0 || profile->reserved_tail != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_RESERVED;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error zcl_retrieval_profile_serialize(
    const struct zcl_retrieval_profile_v1 *profile,
    uint8_t out[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES])
{
    static const uint8_t magic[8] = {'Z','C','R','P','R','O','1','\n'};
    if (!profile || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rx_memory_overlaps(profile, sizeof(*profile), out,
                           ZCL_RETRIEVAL_PROFILE_WIRE_BYTES))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_validate(profile);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    uint8_t wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES] = {0};
    memcpy(wire, magic, sizeof(magic));
    zcl_write_u16_le(wire + 8u, profile->schema_version);
    zcl_write_u16_le(wire + 10u, profile->feature_mask);
    for (size_t i = 0; i < ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT; i++)
        zcl_write_u16_le(wire + 12u + i * 2u, profile->weight_bp[i]);
    zcl_write_u16_le(wire + 40u, profile->identifier_df_max);
    wire[42] = profile->graph_depth;
    wire[43] = profile->rerank_window;
    wire[44] = profile->top_k;
    wire[45] = profile->reserved;
    zcl_write_u16_le(wire + 46u, profile->reserved_tail);
    zcl_write_u64_le(wire + 48u, profile->context_byte_scale);
    memcpy(out, wire, sizeof(wire));
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error zcl_retrieval_profile_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_profile_v1 *out)
{
    static const uint8_t magic[8] = {'Z','C','R','P','R','O','1','\n'};
    if (!wire || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rx_memory_overlaps(wire, wire_len, out, sizeof(*out)))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    if (wire_len != ZCL_RETRIEVAL_PROFILE_WIRE_BYTES) {
        memset(out, 0, sizeof(*out));
        return ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE;
    }
    struct zcl_retrieval_profile_v1 profile = {0};
    if (memcmp(wire, magic, sizeof(magic)) != 0) {
        memset(out, 0, sizeof(*out));
        return ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE;
    }
    profile.schema_version = zcl_read_u16_le(wire + 8u);
    profile.feature_mask = zcl_read_u16_le(wire + 10u);
    for (size_t i = 0; i < ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT; i++)
        profile.weight_bp[i] = zcl_read_u16_le(wire + 12u + i * 2u);
    profile.identifier_df_max = zcl_read_u16_le(wire + 40u);
    profile.graph_depth = wire[42];
    profile.rerank_window = wire[43];
    profile.top_k = wire[44];
    profile.reserved = wire[45];
    profile.reserved_tail = zcl_read_u16_le(wire + 46u);
    profile.context_byte_scale = zcl_read_u64_le(wire + 48u);
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_validate(&profile);
    if (error == ZCL_RETRIEVAL_EXPERIMENT_OK) *out = profile;
    else memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_retrieval_experiment_error zcl_retrieval_profile_root(
    const struct zcl_retrieval_profile_v1 *profile, uint8_t out[32])
{
    if (!profile || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rx_memory_overlaps(profile, sizeof(*profile), out, 32u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    uint8_t wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_serialize(profile, wire);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = ZCL_RETRIEVAL_PROFILE_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rx_sum_top(const struct zcl_retrieval_ranked_file *rows,
                       size_t count, uint64_t *out)
{
    uint64_t total = 0;
    size_t top = count < ZCL_RETRIEVAL_EXPERIMENT_TOP
        ? count : ZCL_RETRIEVAL_EXPERIMENT_TOP;
    for (size_t i = 0; i < top; i++) {
        if (UINT64_MAX - total < rows[i].context_bytes) return false;
        total += rows[i].context_bytes;
    }
    *out = total;
    return true;
}

static size_t rx_find(const struct zcl_retrieval_ranked_file *rows,
                      size_t count, const char *path)
{
    for (size_t i = 0; i < count; i++)
        if (rows[i].path && path && strcmp(rows[i].path, path) == 0) return i;
    return count;
}

static enum zcl_retrieval_experiment_error rx_validate_pair(
    const struct zcl_retrieval_ranked_file *bm25, size_t bm25_count,
    bool bm25_complete,
    const struct zcl_retrieval_ranked_file *parent, size_t parent_count,
    bool parent_complete)
{
    if (bm25_count != parent_count || bm25_complete != parent_complete ||
        bm25_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    for (size_t i = 0; i < bm25_count; i++) {
        if (!bm25[i].path || !bm25[i].path[0] ||
            rx_find(bm25, i, bm25[i].path) != i ||
            !parent[i].path || !parent[i].path[0] ||
            rx_find(parent, i, parent[i].path) != i)
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        size_t peer = rx_find(parent, parent_count, bm25[i].path);
        if (peer == parent_count ||
            parent[peer].context_bytes != bm25[i].context_bytes)
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    }
    size_t top = bm25_count < ZCL_RETRIEVAL_EXPERIMENT_WINDOW
        ? bm25_count : ZCL_RETRIEVAL_EXPERIMENT_WINDOW;
    for (size_t i = 0; i < top; i++)
        if (rx_find(parent, top, bm25[i].path) == top)
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error zcl_retrieval_experiment_project(
    const struct zcl_retrieval_ranked_file *bm25, size_t bm25_count,
    bool bm25_complete,
    const struct zcl_retrieval_ranked_file *parent, size_t parent_count,
    bool parent_complete, uint8_t bm25_prefix,
    struct zcl_retrieval_ranked_file *out, size_t out_capacity,
    struct zcl_retrieval_experiment_report *report)
{
    if ((!bm25 && bm25_count) || (!parent && parent_count) || !out || !report)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (bm25_prefix > ZCL_RETRIEVAL_EXPERIMENT_TOP)
        return ZCL_RETRIEVAL_EXPERIMENT_PARAMETER;
    if (bm25_count > ZCL_RETRIEVAL_EVAL_RANK_MAX ||
        parent_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (bm25_count != parent_count || bm25_complete != parent_complete)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (out_capacity < bm25_count)
        return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
    size_t row_bytes = bm25_count * sizeof(*out);
    if ((bm25_count &&
         (rx_memory_overlaps(out, row_bytes, bm25, row_bytes) ||
          rx_memory_overlaps(out, row_bytes, parent, row_bytes) ||
          rx_memory_overlaps(report, sizeof(*report), bm25, row_bytes) ||
          rx_memory_overlaps(report, sizeof(*report), parent, row_bytes))) ||
        rx_memory_overlaps(report, sizeof(*report), out, row_bytes))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    memset(report, 0, sizeof(*report));
    enum zcl_retrieval_experiment_error error = rx_validate_pair(
        bm25, bm25_count, bm25_complete, parent, parent_count,
        parent_complete);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;

    uint64_t ceiling = 0;
    if (!rx_sum_top(bm25, bm25_count, &ceiling))
        return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
    const size_t target = bm25_count < ZCL_RETRIEVAL_EXPERIMENT_TOP
        ? bm25_count : ZCL_RETRIEVAL_EXPERIMENT_TOP;
    const size_t prefix = bm25_prefix < target ? bm25_prefix : target;
    bool selected[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {false};
    size_t used = 0;
    uint64_t bytes = 0;

    if (bm25_prefix == 0) {
        for (size_t i = 0; i < bm25_count; i++) out[i] = parent[i];
        if (!rx_sum_top(out, bm25_count, &bytes))
            return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
        used = bm25_count;
        if (bytes > ceiling) {
            for (size_t i = 0; i < bm25_count; i++) out[i] = bm25[i];
            bytes = ceiling;
            report->used_bm25_fallback = true;
        }
    } else {
        for (size_t i = 0; i < prefix; i++) {
            if (UINT64_MAX - bytes < bm25[i].context_bytes)
                return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
            out[used++] = bm25[i];
            selected[i] = true;
            bytes += bm25[i].context_bytes;
        }
        size_t window = parent_count < ZCL_RETRIEVAL_EXPERIMENT_WINDOW
            ? parent_count : ZCL_RETRIEVAL_EXPERIMENT_WINDOW;
        for (size_t i = 0; i < window && used < target; i++) {
            size_t original = rx_find(bm25, bm25_count, parent[i].path);
            if (selected[original] ||
                UINT64_MAX - bytes < parent[i].context_bytes ||
                bytes + parent[i].context_bytes > ceiling)
                continue;
            out[used++] = parent[i];
            selected[original] = true;
            bytes += parent[i].context_bytes;
        }
        if (used != target) {
            for (size_t i = 0; i < bm25_count; i++) out[i] = bm25[i];
            used = bm25_count;
            bytes = ceiling;
            report->used_bm25_fallback = true;
        } else {
            for (size_t i = 0; i < parent_count; i++) {
                size_t original = rx_find(bm25, bm25_count, parent[i].path);
                if (!selected[original]) out[used++] = parent[i];
            }
        }
    }
    for (size_t i = 0; i < used; i++) {
        out[i].in_scope = false;
        out[i].in_scope_available = false;
    }
    report->ranked_count = used;
    report->bm25_context_bytes_at_5 = ceiling;
    report->candidate_context_bytes_at_5 = bytes;
    report->top20_membership_preserved = true;
    for (size_t i = 0; i < target; i++)
        if (strcmp(out[i].path, parent[i].path) != 0)
            report->changed_positions_at_5++;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error zcl_retrieval_experiment_evaluate(
    const struct zcl_retrieval_experiment_eval_task *tasks,
    size_t task_count, uint8_t bm25_prefix,
    struct zcl_retrieval_experiment_eval_report *report)
{
    if (!tasks || !report) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (task_count == 0 || task_count > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (bm25_prefix > ZCL_RETRIEVAL_EXPERIMENT_TOP)
        return ZCL_RETRIEVAL_EXPERIMENT_PARAMETER;
    if (rx_memory_overlaps(report, sizeof(*report), tasks,
                           task_count * sizeof(*tasks)))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    for (size_t i = 0; i < task_count; i++) {
        if (tasks[i].relevant_count == 0 ||
            tasks[i].relevant_count >
                ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX ||
            tasks[i].bm25_count > ZCL_RETRIEVAL_EVAL_RANK_MAX ||
            tasks[i].parent_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
            return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
        if ((tasks[i].bm25_count && rx_memory_overlaps(
                report, sizeof(*report), tasks[i].bm25,
                tasks[i].bm25_count * sizeof(*tasks[i].bm25))) ||
            (tasks[i].parent_count && rx_memory_overlaps(
                report, sizeof(*report), tasks[i].parent,
                tasks[i].parent_count * sizeof(*tasks[i].parent))) ||
            (tasks[i].relevant_paths && rx_memory_overlaps(
                report, sizeof(*report), tasks[i].relevant_paths,
                tasks[i].relevant_count * sizeof(*tasks[i].relevant_paths))))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    }
    struct zcl_retrieval_experiment_eval_report result = {
        .top20_membership_preserved = true,
        .full_retained_set_preserved = true,
        .context_ceiling_preserved = true,
    };
    struct zcl_retrieval_ranked_file (*candidate)
        [ZCL_RETRIEVAL_EVAL_RANK_MAX] = zcl_calloc(
            task_count, sizeof(*candidate), "retrieval experiment candidates");
    if (!candidate) {
        memset(report, 0, sizeof(*report));
        return ZCL_RETRIEVAL_EXPERIMENT_ALLOCATION;
    }
    struct zcl_retrieval_gold_task
        evaluated[ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX] = {0};
    for (size_t i = 0; i < task_count; i++) {
        struct zcl_retrieval_experiment_report projected;
        enum zcl_retrieval_experiment_error error =
            zcl_retrieval_experiment_project(
                tasks[i].bm25, tasks[i].bm25_count,
                tasks[i].bm25_complete, tasks[i].parent,
                tasks[i].parent_count, tasks[i].parent_complete,
                bm25_prefix, candidate[i], ZCL_RETRIEVAL_EVAL_RANK_MAX,
                &projected);
        if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) {
            free(candidate);
            memset(report, 0, sizeof(*report));
            return error;
        }
        if (SIZE_MAX - result.changed_positions_at_5 <
            projected.changed_positions_at_5) {
            free(candidate);
            memset(report, 0, sizeof(*report));
            return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
        }
        result.changed_positions_at_5 += projected.changed_positions_at_5;
        if (projected.used_bm25_fallback) result.fallback_tasks++;
        result.top20_membership_preserved =
            result.top20_membership_preserved &&
            projected.top20_membership_preserved;
        result.context_ceiling_preserved =
            result.context_ceiling_preserved &&
            projected.candidate_context_bytes_at_5 <=
                projected.bm25_context_bytes_at_5;
        evaluated[i] = (struct zcl_retrieval_gold_task){
            .task_id = tasks[i].task_id,
            .query = tasks[i].query,
            .relevant_paths = tasks[i].relevant_paths,
            .relevant_count = tasks[i].relevant_count,
            .ranked = candidate[i],
            .ranked_count = projected.ranked_count,
            .ranking_complete = tasks[i].bm25_complete,
        };
    }
    if (!zcl_retrieval_evaluate(evaluated, task_count, &result.metrics)) {
        free(candidate);
        memset(report, 0, sizeof(*report));
        return ZCL_RETRIEVAL_EXPERIMENT_EVALUATION;
    }
    free(candidate);
    *report = result;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

bool zcl_retrieval_ranked_files_root(
    const struct zcl_retrieval_ranked_file *ranked, size_t ranked_count,
    bool ranking_complete, uint8_t out[32])
{
    static const char domain[] = "zcl.retrieval_ranked_files.v1";
    if (!out) return false;
    if ((!ranked && ranked_count) ||
        ranked_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    uint8_t complete = ranking_complete ? 1u : 0u;
    sha3_256_write(&sha, &complete, 1u);
    uint8_t encoded[8];
    rx_u64le(encoded, (uint64_t)ranked_count);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    for (size_t i = 0; i < ranked_count; i++) {
        if (!ranked[i].path || !ranked[i].path[0]) return false;
        sha3_256_write(&sha, (const uint8_t *)ranked[i].path,
                       strlen(ranked[i].path) + 1u);
        rx_u64le(encoded, ranked[i].context_bytes);
        sha3_256_write(&sha, encoded, sizeof(encoded));
    }
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return true;
}

static void rx_write_text(struct sha3_256_ctx *sha, const char *text,
                          size_t length)
{
    uint8_t encoded[8];
    rx_u64le(encoded, (uint64_t)length);
    sha3_256_write(sha, encoded, sizeof(encoded));
    sha3_256_write(sha, (const uint8_t *)text, length);
}

bool zcl_retrieval_experiment_proposal_input_root(
    const uint8_t source_root[32],
    const uint8_t retrieval_projection_root[32],
    const char *task_id, const char *query,
    const uint8_t bm25_ranking_root[32],
    const uint8_t parent_ranking_root[32], uint8_t bm25_prefix,
    const uint8_t study_root[32], const uint8_t preregistration_root[32],
    const uint8_t evaluator_root[32], uint8_t out[32])
{
    static const char domain[] = "zcl.retrieval_experiment_proposal_input.v2";
    if (!out) return false;
    size_t task_id_length = 0, query_length = 0;
    if (!source_root || !retrieval_projection_root || !task_id ||
        !task_id[0] ||
        !query || !query[0] || !bm25_ranking_root || !parent_ranking_root ||
        bm25_prefix > ZCL_RETRIEVAL_EXPERIMENT_TOP || !study_root ||
        !preregistration_root || !evaluator_root ||
        !rx_root_any(source_root) ||
        !rx_root_any(retrieval_projection_root) ||
        !rx_root_any(bm25_ranking_root) ||
        !rx_root_any(parent_ranking_root) || !rx_root_any(study_root) ||
        !rx_root_any(preregistration_root) || !rx_root_any(evaluator_root) ||
        !rx_bounded_text(task_id, 128u, &task_id_length) ||
        !rx_bounded_text(query, 4096u, &query_length))
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, source_root, 32u);
    sha3_256_write(&sha, retrieval_projection_root, 32u);
    rx_write_text(&sha, task_id, task_id_length);
    rx_write_text(&sha, query, query_length);
    sha3_256_write(&sha, bm25_ranking_root, 32u);
    sha3_256_write(&sha, parent_ranking_root, 32u);
    sha3_256_write(&sha, &bm25_prefix, 1u);
    sha3_256_write(&sha, study_root, 32u);
    sha3_256_write(&sha, preregistration_root, 32u);
    sha3_256_write(&sha, evaluator_root, 32u);
    rx_write_text(&sha, ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM,
                  strlen(ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return true;
}

bool zcl_retrieval_profile_proposal_input_root(
    const uint8_t source_root[32],
    const uint8_t codeindex_source_root[32],
    const uint8_t retrieval_projection_root[32],
    const char *task_id, const char *query,
    const uint8_t baseline_ranking_root[32],
    const uint8_t profile_root[32],
    const uint8_t feature_snapshot_root[32],
    const uint8_t candidate_ranking_root[32],
    const uint8_t study_root[32], const uint8_t preregistration_root[32],
    const uint8_t evaluator_root[32], uint8_t out[32])
{
    static const char domain[] =
        "zcl.retrieval_profile_proposal_input.v1";
    if (!out) return false;
    size_t task_id_length = 0, query_length = 0;
    if (!source_root || !codeindex_source_root ||
        !retrieval_projection_root || !task_id || !query ||
        !baseline_ranking_root || !profile_root || !feature_snapshot_root ||
        !candidate_ranking_root || !study_root || !preregistration_root ||
        !evaluator_root || !rx_root_any(source_root) ||
        !rx_root_any(codeindex_source_root) ||
        !rx_root_any(retrieval_projection_root) ||
        !rx_root_any(baseline_ranking_root) || !rx_root_any(profile_root) ||
        !rx_root_any(feature_snapshot_root) ||
        !rx_root_any(candidate_ranking_root) || !rx_root_any(study_root) ||
        !rx_root_any(preregistration_root) || !rx_root_any(evaluator_root) ||
        !rx_bounded_text(task_id, 128u, &task_id_length) ||
        !rx_bounded_text(query, 4096u, &query_length))
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, source_root, 32u);
    sha3_256_write(&sha, codeindex_source_root, 32u);
    sha3_256_write(&sha, retrieval_projection_root, 32u);
    rx_write_text(&sha, task_id, task_id_length);
    rx_write_text(&sha, query, query_length);
    sha3_256_write(&sha, baseline_ranking_root, 32u);
    sha3_256_write(&sha, profile_root, 32u);
    sha3_256_write(&sha, feature_snapshot_root, 32u);
    sha3_256_write(&sha, candidate_ranking_root, 32u);
    sha3_256_write(&sha, study_root, 32u);
    sha3_256_write(&sha, preregistration_root, 32u);
    sha3_256_write(&sha, evaluator_root, 32u);
    rx_write_text(&sha, ZCL_RETRIEVAL_PROFILE_ALGORITHM,
                  strlen(ZCL_RETRIEVAL_PROFILE_ALGORITHM));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return true;
}

const char *zcl_retrieval_experiment_error_string(
    enum zcl_retrieval_experiment_error error)
{
    switch (error) {
    case ZCL_RETRIEVAL_EXPERIMENT_OK: return "ok";
    case ZCL_RETRIEVAL_EXPERIMENT_NULL: return "null argument";
    case ZCL_RETRIEVAL_EXPERIMENT_PARAMETER: return "parameter out of range";
    case ZCL_RETRIEVAL_EXPERIMENT_CAPACITY: return "output capacity too small";
    case ZCL_RETRIEVAL_EXPERIMENT_SHAPE: return "ranking shape mismatch";
    case ZCL_RETRIEVAL_EXPERIMENT_BINDING: return "ranking binding mismatch";
    case ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW: return "context byte overflow";
    case ZCL_RETRIEVAL_EXPERIMENT_ALIAS: return "input/output alias";
    case ZCL_RETRIEVAL_EXPERIMENT_EVALUATION:
        return "maintained evaluator refused projected tasks";
    case ZCL_RETRIEVAL_EXPERIMENT_ALLOCATION:
        return "candidate workspace allocation failed";
    case ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE:
        return "profile wire size or magic mismatch";
    case ZCL_RETRIEVAL_EXPERIMENT_VERSION:
        return "profile or feature snapshot version mismatch";
    case ZCL_RETRIEVAL_EXPERIMENT_RESERVED:
        return "reserved profile field is nonzero";
    case ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE:
        return "required feature evidence is unavailable or saturated";
    }
    return "unknown retrieval experiment error";
}
