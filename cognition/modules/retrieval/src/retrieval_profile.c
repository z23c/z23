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

enum zcl_retrieval_experiment_error zcl_retrieval_query_root(
    const char *query, uint8_t out[32])
{
    if (!query || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    size_t query_length = 0;
    while (query_length <= 4096u && query[query_length]) query_length++;
    if (query_length == 0 || query_length > 4096u)
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    if (rx_memory_overlaps(out, 32u, query, query_length + 1u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    struct sha3_256_ctx sha;
    static const char query_domain[] = "zcl.retrieval_query.v1";
    uint8_t encoded[8], root[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)query_domain,
                   sizeof(query_domain));
    zcl_write_u64_le(encoded, query_length);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_write(&sha, (const uint8_t *)query, query_length);
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
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

enum zcl_retrieval_experiment_error
zcl_retrieval_context_feature_snapshot(
    const uint8_t codeindex_source_root[32],
    const uint8_t retrieval_projection_root[32], const char *query,
    const struct zcl_retrieval_ranked_file *baseline, size_t baseline_count,
    bool baseline_complete,
    struct zcl_retrieval_feature_snapshot_v1 *snapshot_out,
    struct zcl_retrieval_feature_row_v1 *rows_out, size_t rows_capacity)
{
    if (!codeindex_source_root || !retrieval_projection_root || !query ||
        !baseline || !snapshot_out || !rows_out)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (baseline_count == 0 ||
        baseline_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (rows_capacity < baseline_count)
        return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
    size_t query_length = 0;
    while (query_length <= 4096u && query[query_length]) query_length++;
    if (query_length == 0 || query_length > 4096u ||
        !rx_root_any(codeindex_source_root) ||
        !rx_root_any(retrieval_projection_root))
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    size_t rows_bytes = baseline_count * sizeof(*rows_out);
    size_t baseline_bytes = baseline_count * sizeof(*baseline);
    if (rx_memory_overlaps(snapshot_out, sizeof(*snapshot_out), baseline,
                           baseline_bytes) ||
        rx_memory_overlaps(rows_out, rows_bytes, baseline, baseline_bytes) ||
        rx_memory_overlaps(snapshot_out, sizeof(*snapshot_out), rows_out,
                           rows_bytes) ||
        rx_memory_overlaps(snapshot_out, sizeof(*snapshot_out),
                           codeindex_source_root, 32u) ||
        rx_memory_overlaps(rows_out, rows_bytes, codeindex_source_root, 32u) ||
        rx_memory_overlaps(snapshot_out, sizeof(*snapshot_out),
                           retrieval_projection_root, 32u) ||
        rx_memory_overlaps(rows_out, rows_bytes,
                           retrieval_projection_root, 32u) ||
        rx_memory_overlaps(snapshot_out, sizeof(*snapshot_out), query,
                           query_length + 1u) ||
        rx_memory_overlaps(rows_out, rows_bytes, query,
                           query_length + 1u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    size_t path_lengths[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    for (size_t i = 0; i < baseline_count; i++) {
        if (!rx_canonical_path(baseline[i].path, &path_lengths[i]))
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        if (rx_memory_overlaps(snapshot_out, sizeof(*snapshot_out),
                               baseline[i].path, path_lengths[i] + 1u) ||
            rx_memory_overlaps(rows_out, rows_bytes, baseline[i].path,
                               path_lengths[i] + 1u))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    }

    struct zcl_retrieval_feature_snapshot_v1 snapshot = {
        .schema_version = ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION,
        .row_count = (uint16_t)baseline_count,
        .ranking_complete = baseline_complete,
        .available_features = ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES),
    };
    struct zcl_retrieval_feature_row_v1
        rows[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {{0}};
    memcpy(snapshot.source_root, codeindex_source_root, 32u);
    memcpy(snapshot.codeindex_root, retrieval_projection_root, 32u);
    if (!zcl_retrieval_ranked_files_root(
            baseline, baseline_count, baseline_complete,
            snapshot.baseline_ranking_root))
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    if (zcl_retrieval_query_root(query, snapshot.query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    struct sha3_256_ctx sha;
    static const char extractor_domain[] =
        "zcl.retrieval_context_feature_extractor.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)extractor_domain,
                   sizeof(extractor_domain));
    sha3_256_finalize(&sha, snapshot.extractor_root);
    for (size_t i = 0; i < baseline_count; i++) {
        rows[i].path = baseline[i].path;
        rows[i].context_bytes = baseline[i].context_bytes;
        rows[i].original_bm25_rank = (uint16_t)(i + 1u);
        rows[i].observed_features = ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    }
    uint8_t snapshot_root[32];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_feature_snapshot_root(
            &snapshot, rows, snapshot_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    *snapshot_out = snapshot;
    memcpy(rows_out, rows, baseline_count * sizeof(*rows));
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

static enum zcl_retrieval_experiment_error rx_profile_project_core(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_feature_row_v1 *rows, size_t row_count,
    bool ranking_complete, size_t *out_indices,
    struct zcl_retrieval_profile_report *report)
{
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
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_root(profile, result.profile_root);
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
            ranking, row_count, ranking_complete,
            result.candidate_ranking_root))
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    memcpy(out_indices, projected, row_count * sizeof(*out_indices));
    *report = result;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
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

    uint8_t snapshot_root[32];
    error = zcl_retrieval_feature_snapshot_root(
        snapshot, rows, snapshot_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    struct zcl_retrieval_profile_report result;
    error = rx_profile_project_core(
        profile, rows, row_count, snapshot->ranking_complete,
        out_indices, &result);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    memcpy(result.feature_snapshot_root, snapshot_root, 32u);
    *report = result;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rx_replay_task_id(const char *task_id, size_t *length_out)
{
    if (!task_id || !length_out) return false;
    size_t length = 0;
    while (length <= 128u && task_id[length]) length++;
    if (length == 0 || length > 128u) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)task_id[i];
        if (!((c >= (unsigned char)'a' && c <= (unsigned char)'z') ||
              (c >= (unsigned char)'0' && c <= (unsigned char)'9') ||
              c == (unsigned char)'_'))
            return false;
    }
    if (task_id[0] == '_') return false;
    *length_out = length;
    return true;
}

static bool rx_replay_query(const char *query, size_t *length_out)
{
    if (!query || !length_out) return false;
    size_t length = 0;
    while (length <= 768u && query[length]) length++;
    if (length == 0 || length > 768u) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)query[i];
        if (c < 0x20u || c > 0x7eu) return false;
    }
    *length_out = length;
    return true;
}

static void rx_replay_hash_text(struct sha3_256_ctx *sha, const char *text,
                                size_t length)
{
    uint8_t encoded[2];
    zcl_write_u16_le(encoded, (uint16_t)length);
    sha3_256_write(sha, encoded, sizeof(encoded));
    sha3_256_write(sha, (const uint8_t *)text, length);
}

enum zcl_retrieval_experiment_error zcl_retrieval_profile_replay_project(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_profile_replay_task_v1 *tasks,
    size_t task_count,
    struct zcl_retrieval_profile_replay_candidate_v1 *candidates,
    size_t candidate_capacity,
    struct zcl_retrieval_profile_replay_report_v1 *report)
{
    if (!profile || !tasks || !candidates || !report)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (task_count == 0 ||
        task_count > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (candidate_capacity < task_count)
        return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
    size_t tasks_bytes = task_count * sizeof(*tasks);
    size_t candidates_bytes = task_count * sizeof(*candidates);
    if (rx_memory_overlaps(candidates, candidates_bytes,
                           profile, sizeof(*profile)) ||
        rx_memory_overlaps(candidates, candidates_bytes,
                           tasks, tasks_bytes) ||
        rx_memory_overlaps(candidates, candidates_bytes,
                           report, sizeof(*report)) ||
        rx_memory_overlaps(report, sizeof(*report), profile,
                           sizeof(*profile)) ||
        rx_memory_overlaps(report, sizeof(*report), tasks, tasks_bytes))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_validate(profile);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    const uint16_t context_only = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    if (profile->feature_mask != context_only)
        return ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE;
    if (profile->top_k != ZCL_RETRIEVAL_EXPERIMENT_TOP)
        return ZCL_RETRIEVAL_EXPERIMENT_PARAMETER;

    size_t projected_indices[ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX]
                            [ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_profile_report
        task_reports[ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX];
    struct zcl_retrieval_profile_replay_report_v1 result = {
        .schema_version = ZCL_RETRIEVAL_PROFILE_REPLAY_VERSION,
        .task_count = task_count,
        .top20_membership_preserved = true,
        .full_retained_set_preserved = true,
        .context_ceiling_preserved = true,
    };
    error = zcl_retrieval_profile_root(profile, result.profile_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    struct sha3_256_ctx hypothesis_sha, candidates_sha;
    static const char hypothesis_domain[] =
        ZCL_RETRIEVAL_PROFILE_REPLAY_HYPOTHESIS_DOMAIN;
    static const char candidates_domain[] =
        ZCL_RETRIEVAL_PROFILE_REPLAY_CANDIDATES_DOMAIN;
    uint8_t encoded[8];
    sha3_256_init(&hypothesis_sha);
    sha3_256_write(&hypothesis_sha, (const uint8_t *)hypothesis_domain,
                   sizeof(hypothesis_domain));
    zcl_write_u16_le(encoded, ZCL_RETRIEVAL_PROFILE_REPLAY_VERSION);
    sha3_256_write(&hypothesis_sha, encoded, 2u);
    uint8_t profile_wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES];
    error = zcl_retrieval_profile_serialize(profile, profile_wire);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    sha3_256_write(&hypothesis_sha, profile_wire, sizeof(profile_wire));
    zcl_write_u64_le(encoded, task_count);
    sha3_256_write(&hypothesis_sha, encoded, sizeof(encoded));
    sha3_256_init(&candidates_sha);
    sha3_256_write(&candidates_sha, (const uint8_t *)candidates_domain,
                   sizeof(candidates_domain));
    zcl_write_u16_le(encoded, ZCL_RETRIEVAL_PROFILE_REPLAY_VERSION);
    sha3_256_write(&candidates_sha, encoded, 2u);
    zcl_write_u64_le(encoded, task_count);
    sha3_256_write(&candidates_sha, encoded, sizeof(encoded));

    for (size_t t = 0; t < task_count; t++) {
        const struct zcl_retrieval_profile_replay_task_v1 *task = &tasks[t];
        size_t id_length = 0, query_length = 0;
        if (!rx_replay_task_id(task->task_id, &id_length) ||
            !rx_replay_query(task->query, &query_length) ||
            !task->baseline ||
            task->baseline_count < ZCL_RETRIEVAL_EXPERIMENT_TOP ||
            task->baseline_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
            return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
        for (size_t prior = 0; prior < t; prior++)
            if (strcmp(tasks[prior].task_id, task->task_id) == 0)
                return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        size_t baseline_bytes = task->baseline_count *
            sizeof(*task->baseline);
        if (rx_memory_overlaps(candidates, candidates_bytes,
                               task->baseline, baseline_bytes) ||
            rx_memory_overlaps(report, sizeof(*report),
                               task->baseline, baseline_bytes) ||
            rx_memory_overlaps(candidates, candidates_bytes,
                               task->task_id, id_length + 1u) ||
            rx_memory_overlaps(report, sizeof(*report),
                               task->task_id, id_length + 1u) ||
            rx_memory_overlaps(candidates, candidates_bytes,
                               task->query, query_length + 1u) ||
            rx_memory_overlaps(report, sizeof(*report),
                               task->query, query_length + 1u))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
        struct zcl_retrieval_feature_row_v1
            rows[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {{0}};
        for (size_t i = 0; i < task->baseline_count; i++) {
            size_t path_length = 0;
            if (!rx_canonical_path(task->baseline[i].path, &path_length))
                return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
            if (rx_memory_overlaps(candidates, candidates_bytes,
                                   task->baseline[i].path,
                                   path_length + 1u) ||
                rx_memory_overlaps(report, sizeof(*report),
                                   task->baseline[i].path,
                                   path_length + 1u))
                return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
            for (size_t prior = 0; prior < i; prior++)
                if (strcmp(task->baseline[prior].path,
                           task->baseline[i].path) == 0)
                    return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
            rows[i].path = task->baseline[i].path;
            rows[i].context_bytes = task->baseline[i].context_bytes;
            rows[i].original_bm25_rank = (uint16_t)(i + 1u);
            rows[i].observed_features = context_only;
        }
        uint8_t baseline_root[32];
        if (!zcl_retrieval_ranked_files_root(
                task->baseline, task->baseline_count,
                task->baseline_complete, baseline_root))
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
        error = rx_profile_project_core(
            profile, rows, task->baseline_count, task->baseline_complete,
            projected_indices[t], &task_reports[t]);
        if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
        if (SIZE_MAX - result.changed_positions_at_5 <
                task_reports[t].changed_positions_at_top)
            return ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW;
        result.changed_positions_at_5 +=
            task_reports[t].changed_positions_at_top;
        if (task_reports[t].used_baseline_fallback) result.fallback_tasks++;
        result.full_retained_set_preserved =
            result.full_retained_set_preserved &&
            task_reports[t].retained_set_preserved;
        result.context_ceiling_preserved =
            result.context_ceiling_preserved &&
            task_reports[t].candidate_context_bytes_at_top <=
                task_reports[t].baseline_context_bytes_at_top;

        rx_replay_hash_text(&hypothesis_sha, task->task_id, id_length);
        rx_replay_hash_text(&hypothesis_sha, task->query, query_length);
        encoded[0] = task->baseline_complete ? 1u : 0u;
        sha3_256_write(&hypothesis_sha, encoded, 1u);
        zcl_write_u64_le(encoded, task->baseline_count);
        sha3_256_write(&hypothesis_sha, encoded, sizeof(encoded));
        sha3_256_write(&hypothesis_sha, baseline_root, 32u);
        sha3_256_write(&hypothesis_sha,
                       task_reports[t].candidate_ranking_root, 32u);

        rx_replay_hash_text(&candidates_sha, task->task_id, id_length);
        encoded[0] = task->baseline_complete ? 1u : 0u;
        sha3_256_write(&candidates_sha, encoded, 1u);
        zcl_write_u64_le(encoded, task->baseline_count);
        sha3_256_write(&candidates_sha, encoded, sizeof(encoded));
        sha3_256_write(&candidates_sha,
                       task_reports[t].candidate_ranking_root, 32u);
    }
    sha3_256_finalize(&hypothesis_sha, result.replay_hypothesis_root);
    sha3_256_finalize(&candidates_sha, result.candidate_batch_root);
    for (size_t t = 0; t < task_count; t++) {
        candidates[t].ranked_count = tasks[t].baseline_count;
        candidates[t].ranking_complete = tasks[t].baseline_complete;
        memcpy(candidates[t].ranking_root,
               task_reports[t].candidate_ranking_root, 32u);
        for (size_t i = 0; i < tasks[t].baseline_count; i++) {
            size_t index = projected_indices[t][i];
            candidates[t].ranked[i] =
                (struct zcl_retrieval_ranked_file){
                    .path = tasks[t].baseline[index].path,
                    .context_bytes = tasks[t].baseline[index].context_bytes,
                    .in_scope = false,
                    .in_scope_available = false,
                };
        }
    }
    *report = result;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}
