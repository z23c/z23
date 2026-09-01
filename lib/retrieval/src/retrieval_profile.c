/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic integer retrieval profile projection. */
#include "retrieval/retrieval_experiment.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

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

static bool rx_canonical_path(const char *path, size_t *length_out)
{
    if (!path || !length_out) return false;
    size_t length = 0;
    while (length <= 255u && path[length]) length++;
    if (length == 0 || length > 255u || path[0] == '/' ||
        path[length - 1u] == '/' || strchr(path, '\\') || strstr(path, "//"))
        return false;
    const char *part = path;
    while (part && *part) {
        const char *slash = strchr(part, '/');
        size_t part_length = slash ? (size_t)(slash - part) : strlen(part);
        if ((part_length == 1u && part[0] == '.') ||
            (part_length == 2u && part[0] == '.' && part[1] == '.'))
            return false;
        part = slash ? slash + 1u : NULL;
    }
    *length_out = length;
    return true;
}

static enum zcl_retrieval_experiment_error rx_snapshot_validate(
    const struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 *rows)
{
    if (!snapshot || !rows) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (snapshot->schema_version != ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION)
        return ZCL_RETRIEVAL_EXPERIMENT_VERSION;
    if (snapshot->row_count == 0 ||
        snapshot->row_count > ZCL_RETRIEVAL_EVAL_RANK_MAX ||
        (snapshot->available_features & ~ZCL_RETRIEVAL_FEATURE_MASK_ALL) != 0 ||
        (snapshot->saturated_features & ~ZCL_RETRIEVAL_FEATURE_MASK_ALL) != 0 ||
        (snapshot->available_features & snapshot->saturated_features) != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    uint16_t scoped = snapshot->available_features |
        snapshot->saturated_features;
    bool rarity = (scoped & ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY)) != 0;
    bool graph = (scoped & ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY)) != 0;
    if ((rarity && (snapshot->identifier_df_max == 0 ||
                    snapshot->identifier_df_max >
                        ZCL_RETRIEVAL_EVAL_RANK_MAX)) ||
        (!rarity && snapshot->identifier_df_max != 0) ||
        (graph && (snapshot->graph_depth == 0 ||
                   snapshot->graph_depth >
                       ZCL_RETRIEVAL_PROFILE_GRAPH_DEPTH_MAX)) ||
        (!graph && snapshot->graph_depth != 0) || snapshot->reserved != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    const uint8_t *const roots[] = {
        snapshot->source_root, snapshot->codeindex_root, snapshot->query_root,
        snapshot->baseline_ranking_root, snapshot->extractor_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!rx_root_any(roots[i])) return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    uint16_t common = ZCL_RETRIEVAL_FEATURE_MASK_ALL;
    struct zcl_retrieval_ranked_file baseline[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    for (size_t i = 0; i < snapshot->row_count; i++) {
        size_t path_length = 0;
        if (!rx_canonical_path(rows[i].path, &path_length) ||
            rows[i].original_bm25_rank != i + 1u ||
            (rows[i].observed_features &
             ~ZCL_RETRIEVAL_FEATURE_MASK_ALL) != 0)
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        (void)path_length;
        for (size_t prior = 0; prior < i; prior++)
            if (strcmp(rows[prior].path, rows[i].path) == 0)
                return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        for (size_t feature = 0;
             feature < ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT; feature++) {
            bool observed = (rows[i].observed_features &
                ZCL_RETRIEVAL_FEATURE_BIT(feature)) != 0;
            if ((!observed && rows[i].feature_bp[feature] != 0) ||
                rows[i].feature_bp[feature] >
                    ZCL_RETRIEVAL_PROFILE_WEIGHT_MAX ||
                (feature == ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES &&
                 rows[i].feature_bp[feature] != 0))
                return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        }
        common &= rows[i].observed_features;
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = rows[i].path,
            .context_bytes = rows[i].context_bytes,
            .in_scope = false,
            .in_scope_available = false,
        };
    }
    if (common != snapshot->available_features)
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    uint8_t baseline_root[32];
    if (!zcl_retrieval_ranked_files_root(
            baseline, snapshot->row_count, snapshot->ranking_complete,
            baseline_root) ||
        memcmp(baseline_root, snapshot->baseline_ranking_root, 32) != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error zcl_retrieval_feature_snapshot_root(
    const struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 *rows, uint8_t out[32])
{
    if (!snapshot || !rows || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    size_t rows_bytes = snapshot->row_count * sizeof(*rows);
    if (rx_memory_overlaps(out, 32u, snapshot, sizeof(*snapshot)) ||
        rx_memory_overlaps(out, 32u, rows, rows_bytes))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    enum zcl_retrieval_experiment_error error =
        rx_snapshot_validate(snapshot, rows);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = ZCL_RETRIEVAL_FEATURE_SNAPSHOT_DOMAIN;
    uint8_t encoded[8];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    zcl_write_u16_le(encoded, snapshot->schema_version);
    sha3_256_write(&sha, encoded, 2u);
    zcl_write_u16_le(encoded, snapshot->row_count);
    sha3_256_write(&sha, encoded, 2u);
    encoded[0] = snapshot->ranking_complete ? 1u : 0u;
    sha3_256_write(&sha, encoded, 1u);
    zcl_write_u16_le(encoded, snapshot->available_features);
    sha3_256_write(&sha, encoded, 2u);
    zcl_write_u16_le(encoded, snapshot->saturated_features);
    sha3_256_write(&sha, encoded, 2u);
    zcl_write_u16_le(encoded, snapshot->identifier_df_max);
    sha3_256_write(&sha, encoded, 2u);
    encoded[0] = snapshot->graph_depth;
    encoded[1] = snapshot->reserved;
    sha3_256_write(&sha, encoded, 2u);
    sha3_256_write(&sha, snapshot->source_root, 32u);
    sha3_256_write(&sha, snapshot->codeindex_root, 32u);
    sha3_256_write(&sha, snapshot->query_root, 32u);
    sha3_256_write(&sha, snapshot->baseline_ranking_root, 32u);
    sha3_256_write(&sha, snapshot->extractor_root, 32u);
    for (size_t i = 0; i < snapshot->row_count; i++) {
        size_t path_length = strlen(rows[i].path);
        if (rx_memory_overlaps(out, 32u, rows[i].path, path_length + 1u))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
        zcl_write_u16_le(encoded, (uint16_t)path_length);
        sha3_256_write(&sha, encoded, 2u);
        sha3_256_write(&sha, (const uint8_t *)rows[i].path, path_length);
        zcl_write_u64_le(encoded, rows[i].context_bytes);
        sha3_256_write(&sha, encoded, 8u);
        zcl_write_u16_le(encoded, rows[i].original_bm25_rank);
        sha3_256_write(&sha, encoded, 2u);
        zcl_write_u16_le(encoded, rows[i].observed_features);
        sha3_256_write(&sha, encoded, 2u);
        for (size_t feature = 0;
             feature < ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT; feature++) {
            zcl_write_u16_le(encoded, rows[i].feature_bp[feature]);
            sha3_256_write(&sha, encoded, 2u);
        }
    }
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

struct rx_profile_candidate {
    size_t index;
    int64_t utility;
};

static bool rx_profile_score(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_feature_row_v1 *row, int64_t *out)
{
    int64_t score = 0;
    for (size_t feature = 0;
         feature < ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT; feature++) {
        if ((profile->feature_mask & ZCL_RETRIEVAL_FEATURE_BIT(feature)) == 0)
            continue;
        uint64_t contribution;
        if (feature == ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES) {
            uint64_t units = row->context_bytes / profile->context_byte_scale;
            if (row->context_bytes % profile->context_byte_scale != 0) units++;
            if (units > (uint64_t)INT64_MAX / profile->weight_bp[feature])
                return false;
            contribution = units * profile->weight_bp[feature];
            if (contribution > (uint64_t)INT64_MAX ||
                score < INT64_MIN + (int64_t)contribution)
                return false;
            score -= (int64_t)contribution;
        } else {
            contribution = (uint64_t)row->feature_bp[feature] *
                profile->weight_bp[feature];
            if (contribution > (uint64_t)INT64_MAX) return false;
            int64_t benefit = (int64_t)contribution;
            if (score > INT64_MAX - benefit) return false;
            score += benefit;
        }
    }
    *out = score;
    return true;
}

static bool rx_profile_better(
    const struct rx_profile_candidate *left,
    const struct rx_profile_candidate *right,
    const struct zcl_retrieval_feature_row_v1 *rows)
{
    if (left->utility != right->utility)
        return left->utility > right->utility;
    if (rows[left->index].original_bm25_rank !=
        rows[right->index].original_bm25_rank)
        return rows[left->index].original_bm25_rank <
            rows[right->index].original_bm25_rank;
    return strcmp(rows[left->index].path, rows[right->index].path) < 0;
}

enum zcl_retrieval_experiment_error zcl_retrieval_profile_project(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 *rows,
    size_t *out_indices, size_t out_capacity,
    struct zcl_retrieval_profile_report *report)
{
    if (!profile || !snapshot || !rows || !out_indices || !report)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    size_t row_count = snapshot->row_count;
    size_t row_bytes = row_count * sizeof(*rows);
    size_t index_bytes = row_count * sizeof(*out_indices);
    if (out_capacity < row_count) return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
    if (rx_memory_overlaps(out_indices, index_bytes, profile,
                           sizeof(*profile)) ||
        rx_memory_overlaps(out_indices, index_bytes, snapshot,
                           sizeof(*snapshot)) ||
        rx_memory_overlaps(out_indices, index_bytes, rows, row_bytes) ||
        rx_memory_overlaps(report, sizeof(*report), profile,
                           sizeof(*profile)) ||
        rx_memory_overlaps(report, sizeof(*report), snapshot,
                           sizeof(*snapshot)) ||
        rx_memory_overlaps(report, sizeof(*report), rows, row_bytes) ||
        rx_memory_overlaps(report, sizeof(*report), out_indices, index_bytes))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_validate(profile);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    error = rx_snapshot_validate(snapshot, rows);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    for (size_t i = 0; i < row_count; i++) {
        size_t path_length = strlen(rows[i].path) + 1u;
        if (rx_memory_overlaps(out_indices, index_bytes,
                               rows[i].path, path_length) ||
            rx_memory_overlaps(report, sizeof(*report),
                               rows[i].path, path_length))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    }
    if ((profile->feature_mask & snapshot->available_features) !=
            profile->feature_mask ||
        (profile->feature_mask & snapshot->saturated_features) != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE;
    if (((profile->feature_mask & ZCL_RETRIEVAL_FEATURE_BIT(
              ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY)) != 0 &&
         profile->identifier_df_max != snapshot->identifier_df_max) ||
        ((profile->feature_mask & ZCL_RETRIEVAL_FEATURE_BIT(
              ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY)) != 0 &&
         profile->graph_depth != snapshot->graph_depth))
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    for (size_t i = 0; i < row_count; i++)
        if ((profile->feature_mask & rows[i].observed_features) !=
            profile->feature_mask)
            return ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE;

    size_t window = profile->rerank_window < row_count
        ? profile->rerank_window : row_count;
    size_t top = profile->top_k < row_count ? profile->top_k : row_count;
    struct rx_profile_candidate sorted[ZCL_RETRIEVAL_PROFILE_WINDOW_MAX];
    for (size_t i = 0; i < window; i++) {
        sorted[i].index = i;
        if (!rx_profile_score(profile, &rows[i], &sorted[i].utility))
            return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
        size_t at = i;
        while (at != 0 && rx_profile_better(
                &sorted[at], &sorted[at - 1u], rows)) {
            struct rx_profile_candidate swap = sorted[at - 1u];
            sorted[at - 1u] = sorted[at];
            sorted[at] = swap;
            at--;
        }
    }
    uint64_t ceiling = 0;
    for (size_t i = 0; i < top; i++) {
        if (UINT64_MAX - ceiling < rows[i].context_bytes)
            return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
        ceiling += rows[i].context_bytes;
    }
    size_t projected[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    bool selected[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {false};
    size_t used = 0;
    uint64_t selected_bytes = 0;
    for (size_t i = 0; i < window && used < top; i++) {
        size_t candidate = sorted[i].index;
        if (UINT64_MAX - selected_bytes < rows[candidate].context_bytes ||
            selected_bytes + rows[candidate].context_bytes > ceiling)
            continue;
        projected[used++] = candidate;
        selected[candidate] = true;
        selected_bytes += rows[candidate].context_bytes;
    }
    struct zcl_retrieval_profile_report result = {
        .ranked_count = row_count,
        .baseline_context_bytes_at_top = ceiling,
        .candidate_context_bytes_at_top = selected_bytes,
        .retained_set_preserved = true,
    };
    if (used != top) {
        for (size_t i = 0; i < row_count; i++) projected[i] = i;
        used = row_count;
        result.candidate_context_bytes_at_top = ceiling;
        result.used_baseline_fallback = true;
    } else {
        for (size_t i = 0; i < window; i++) {
            size_t candidate = sorted[i].index;
            if (!selected[candidate]) projected[used++] = candidate;
        }
        for (size_t i = window; i < row_count; i++) projected[used++] = i;
    }
    for (size_t i = 0; i < top; i++)
        if (projected[i] != i) result.changed_positions_at_top++;
    error = zcl_retrieval_profile_root(profile, result.profile_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    error = zcl_retrieval_feature_snapshot_root(
        snapshot, rows, result.feature_snapshot_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    struct zcl_retrieval_ranked_file ranking[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    for (size_t i = 0; i < row_count; i++)
        ranking[i] = (struct zcl_retrieval_ranked_file){
            .path = rows[projected[i]].path,
            .context_bytes = rows[projected[i]].context_bytes,
            .in_scope = false,
            .in_scope_available = false,
        };
    if (!zcl_retrieval_ranked_files_root(
            ranking, row_count, snapshot->ranking_complete,
            result.candidate_ranking_root))
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    memcpy(out_indices, projected, index_bytes);
    *report = result;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}
