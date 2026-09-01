/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "retrieval/retrieval_experiment.h"

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
    const uint8_t source_root[32], const uint8_t codeindex_root[32],
    const char *task_id, const char *query,
    const uint8_t bm25_ranking_root[32],
    const uint8_t parent_ranking_root[32], uint8_t bm25_prefix,
    const uint8_t study_root[32], const uint8_t preregistration_root[32],
    const uint8_t evaluator_root[32], uint8_t out[32])
{
    static const char domain[] = "zcl.retrieval_experiment_proposal_input.v1";
    if (!out) return false;
    size_t task_id_length = 0, query_length = 0;
    if (!source_root || !codeindex_root || !task_id || !task_id[0] ||
        !query || !query[0] || !bm25_ranking_root || !parent_ranking_root ||
        bm25_prefix > ZCL_RETRIEVAL_EXPERIMENT_TOP || !study_root ||
        !preregistration_root || !evaluator_root ||
        !rx_root_any(source_root) || !rx_root_any(codeindex_root) ||
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
    sha3_256_write(&sha, codeindex_root, 32u);
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
    }
    return "unknown retrieval experiment error";
}
