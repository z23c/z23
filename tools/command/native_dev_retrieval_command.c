/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: source-bound observational retrieval benchmark for dev builds. */

#include "command/native_command.h"
#include "command/native_dev_retrieval_stream.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "retrieval/retrieval.h"
#include "services/zcode_goal_context_service.h"
#include "sha3/sha3.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RB_TAG "native.dev.retrieval"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

enum {
    RB_DISPLAY_ROWS = 20,
    RB_RETAIN_ROWS = ZCL_RETRIEVAL_EVAL_RANK_MAX,
    RB_STREAM_MAX_BYTES = 2 * 1024 * 1024,
};

struct rb_rank {
    struct zcl_retrieval_ranked_file rows[RB_RETAIN_ROWS];
    char paths[RB_RETAIN_ROWS][256];
    size_t count;
    bool complete;
};

/* One source-bound computation owns every byte needed to render any page.
 * In particular, rank row pointers refer only to the adjacent owned path
 * arrays, never to the manifest or code index after they are closed. */
struct rb_computation {
    char workspace[PATH_MAX];
    char task_id[129];
    char query[4097];
    char expected_hex[65];
    char pre_hex[65];
    char post_hex[65];
    char codeindex_hex[65];
    size_t corpus_files;
    struct rb_rank literal;
    struct rb_rank bm25;
};

static void rb_fail(struct zcl_command_reply *reply, const char *code,
                    const char *phase, const char *message,
                    const char *evidence)
{
    LOG_ERROR(RB_TAG, "%s: %s (%s)", code, message,
              evidence ? evidence : "");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool rb_canonical_repo_path(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || strchr(path, '\\') ||
        strstr(path, "//") || path[strlen(path) - 1] == '/')
        return false;
    const char *part = path;
    while (part && *part) {
        const char *slash = strchr(part, '/');
        size_t len = slash ? (size_t)(slash - part) : strlen(part);
        if ((len == 1 && part[0] == '.') ||
            (len == 2 && part[0] == '.' && part[1] == '.'))
            return false;
        part = slash ? slash + 1 : NULL;
    }
    return true;
}

static const struct vcs_entry *rb_manifest_entry(
    const struct vcs_manifest *manifest, const char *path)
{
    size_t lo = 0, hi = manifest ? manifest->count : 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(manifest->entries[mid].path, path);
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    if (!manifest || lo >= manifest->count ||
        strcmp(manifest->entries[lo].path, path) != 0)
        return NULL;
    return &manifest->entries[lo];
}

static bool rb_rank_add(struct rb_rank *rank, const char *path,
                        const struct vcs_manifest *manifest)
{
    if (!path || !path[0]) return true;
    if (!rb_canonical_repo_path(path)) {
        LOG_ERROR(RB_TAG, "ranker emitted non-canonical repo path: %s", path);
        return false;
    }
    for (size_t i = 0; i < rank->count; i++)
        if (strcmp(rank->paths[i], path) == 0) return true;
    if (rank->count >= RB_RETAIN_ROWS) {
        rank->complete = false;
        return true;
    }
    const struct vcs_entry *entry = rb_manifest_entry(manifest, path);
    if (!entry) {
        LOG_ERROR(RB_TAG, "ranked path absent from bound manifest: %s", path);
        return false;
    }
    if (entry->size > INT64_MAX) {
        LOG_ERROR(RB_TAG, "ranked file size exceeds JSON integer range: %s",
                  path);
        return false;
    }
    int n = snprintf(rank->paths[rank->count], sizeof(rank->paths[0]), "%s",
                     path);
    if (n < 0 || (size_t)n >= sizeof(rank->paths[0])) {
        LOG_ERROR(RB_TAG, "ranked path exceeds output bound: %s", path);
        return false;
    }
    rank->rows[rank->count].path = rank->paths[rank->count];
    rank->rows[rank->count].context_bytes = entry->size;
    rank->rows[rank->count].in_scope = false;
    rank->count++;
    return true;
}

static bool rb_literal_rank(struct codeindex *index, const char *query,
                            const struct vcs_manifest *manifest,
                            struct rb_rank *rank)
{
    struct zcode_goal_selection selected;
    struct zcl_result result = zcode_goal_context_select_literal_indexed(
        index, query, &selected);
    if (!result.ok) {
        LOG_ERROR(RB_TAG, "production selector failed: %s", result.message);
        return false;
    }
    rank->complete = !selected.budget_exhausted;
    for (size_t i = 0; i < selected.candidate_count; i++) {
        if (!rb_rank_add(rank, selected.candidates[i].symbol.def_path,
                         manifest) ||
            !rb_rank_add(rank, selected.candidates[i].symbol.decl_path,
                         manifest))
            return false;
    }
    return true;
}

static bool rb_bm25_rank(struct codeindex *ci, const char *query,
                         const struct vcs_manifest *manifest,
                         struct rb_rank *rank, size_t *corpus_files)
{
    struct ci_story_hit hits[RB_RETAIN_ROWS];
    bool truncated = false;
    int n = codeindex_search_story(ci, query, hits, RB_RETAIN_ROWS,
                                   corpus_files, &truncated);
    if (n < 0) return false;
    rank->complete = !truncated;
    for (int i = 0; i < n; i++)
        if (!rb_manifest_entry(manifest, hits[i].path) ||
            !rb_rank_add(rank, hits[i].path, manifest))
            return false;
    return true;
}

static void rb_u64le(uint8_t out[8], uint64_t value)
{
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value & 0xffu);
        value >>= 8;
    }
}

static void rb_rank_root(const struct rb_rank *rank, char out[65])
{
    static const char domain[] = "zcl.retrieval_ranked_files.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    const uint8_t complete = rank->complete ? 1u : 0u;
    sha3_256_write(&sha, &complete, 1);
    uint8_t encoded[8];
    rb_u64le(encoded, (uint64_t)rank->count);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    for (size_t i = 0; i < rank->count; i++) {
        sha3_256_write(&sha, (const uint8_t *)rank->rows[i].path,
                       strlen(rank->rows[i].path) + 1u);
        rb_u64le(encoded, rank->rows[i].context_bytes);
        sha3_256_write(&sha, encoded, sizeof(encoded));
    }
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    zcl_hex_encode(root, sizeof(root), out);
}

static bool rb_push_rank(struct json_value *object, const struct rb_rank *rank,
                         size_t offset, size_t page_limit)
{
    uint64_t bytes_at_5 = 0;
    for (size_t i = 0; i < rank->count && i < 5; i++) {
        if (UINT64_MAX - bytes_at_5 < rank->rows[i].context_bytes) {
            LOG_ERROR(RB_TAG, "top-five context byte sum overflow");
            return false;
        }
        bytes_at_5 += rank->rows[i].context_bytes;
    }
    if (bytes_at_5 > INT64_MAX || bytes_at_5 > UINT64_MAX - 3u) {
        LOG_ERROR(RB_TAG, "top-five context cost exceeds output range");
        return false;
    }
    size_t displayed = rank->count > offset ? rank->count - offset : 0;
    if (displayed > page_limit) displayed = page_limit;
    char ranking_root[65];
    rb_rank_root(rank, ranking_root);
    bool ok = json_push_kv_bool(object, "ranking_complete", rank->complete) &&
        json_push_kv_int(object, "ranked_files", (int64_t)rank->count) &&
        json_push_kv_int(object, "display_offset", (int64_t)offset) &&
        json_push_kv_int(object, "displayed_files", (int64_t)displayed) &&
        json_push_kv_str(object, "ranking_root_sha3", ranking_root) &&
        json_push_kv_int(object, "context_bytes_at_5", (int64_t)bytes_at_5) &&
        json_push_kv_int(object, "approximate_tokens_at_5",
                         (int64_t)((bytes_at_5 + 3u) / 4u));
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = offset; i < rank->count &&
         i < offset + page_limit && ok; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        ok = json_push_kv_int(&row, "rank", (int64_t)i + 1) &&
            json_push_kv_str(&row, "path", rank->rows[i].path) &&
            json_push_kv_int(&row, "context_bytes",
                             (int64_t)rank->rows[i].context_bytes) &&
            json_push_back(&rows, &row);
        json_free(&row);
    }
    if (ok) ok = json_push_kv(object, "ranking", &rows);
    json_free(&rows);
    if (!ok) LOG_ERROR(RB_TAG, "rank JSON allocation failed");
    return ok;
}

static bool rb_manifest_capture(const char *workspace, struct vcs_index *index,
                                struct vcs_manifest *manifest,
                                uint8_t root[32])
{
    if (!vcs_manifest_build(workspace, index, manifest)) {
        LOG_ERROR(RB_TAG, "manifest build failed for %s", workspace);
        return false;
    }
    if (!vcs_manifest_tree_hash(manifest, root)) {
        vcs_manifest_free(manifest);
        LOG_ERROR(RB_TAG, "manifest root derivation failed for %s", workspace);
        return false;
    }
    return true;
}

static struct vcs_index *rb_index_open(const char *workspace)
{
    char cache_dir[PATH_MAX];
    int n = snprintf(cache_dir, sizeof(cache_dir), "%s/.zvcs", workspace);
    if (n <= 0 || (size_t)n >= sizeof(cache_dir)) {
        LOG_ERROR(RB_TAG, "ZVCS cache path is too long for %s", workspace);
        return NULL;
    }
    if (!platform_private_directory_ensure(cache_dir)) {
        LOG_ERROR(RB_TAG, "could not establish private ZVCS cache at %s",
                  cache_dir);
        return NULL;
    }
    return vcs_index_open(workspace);
}

static bool rb_workspace(const struct json_value *input, char out[PATH_MAX])
{
    const char *value = json_get_str(json_get(input, "workspace"));
    return value && value[0] == '/' &&
        platform_directory_canonical_real(value, out, PATH_MAX) &&
        strcmp(value, out) == 0;
}

static bool rb_cursor(const struct zcl_command_request *request, size_t *out)
{
    const char *value = request->cursor;
    *out = 0;
    if (!value || !value[0]) return true;
    if (strspn(value, "0123456789") != strlen(value)) return false;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (!end || *end != '\0' || parsed >= RB_RETAIN_ROWS)
        return false;
    *out = (size_t)parsed;
    return true;
}

static bool rb_render_data(
    struct zcl_command_reply *reply, const char *task_id, const char *query,
    const char *expected_hex, const char *pre_hex, const char *post_hex,
    const char *codeindex_hex, size_t rank_offset, size_t corpus_files,
    const struct rb_rank *literal, const struct rb_rank *bm25,
    size_t page_limit)
{
    size_t max_count = literal->count > bm25->count
        ? literal->count : bm25->count;
    size_t page_span = max_count > rank_offset ? max_count - rank_offset : 0;
    if (page_span > page_limit) page_span = page_limit;
    bool has_more = rank_offset + page_span < max_count;
    json_set_object(&reply->data);
    bool ok = corpus_files <= INT64_MAX &&
        json_push_kv_str(&reply->data, "schema",
                         "zcl.dev_retrieval_benchmark.v1") &&
        json_push_kv_bool(&reply->data, "observational", true) &&
        json_push_kv_bool(&reply->data, "production_ordering_changed", true) &&
        json_push_kv_bool(&reply->data, "promotion_authorized", false) &&
        json_push_kv_bool(&reply->data, "native_execution", true) &&
        json_push_kv_bool(&reply->data, "ready_to_benchmark", true) &&
        json_push_kv_str(&reply->data, "task_id", task_id) &&
        json_push_kv_str(&reply->data, "query", query) &&
        json_push_kv_str(&reply->data, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(&reply->data, "observed_vcs_root_pre", pre_hex) &&
        json_push_kv_str(&reply->data, "observed_vcs_root_post", post_hex) &&
        json_push_kv_str(&reply->data, "shared_codeindex_source_root_sha3",
                         codeindex_hex) &&
        json_push_kv_int(&reply->data, "rank_offset",
                         (int64_t)rank_offset) &&
        json_push_kv_int(&reply->data, "page_limit", (int64_t)page_limit) &&
        json_push_kv_int(&reply->data, "page_span", (int64_t)page_span) &&
        json_push_kv_bool(&reply->data, "has_more", has_more) &&
        json_push_kv_int(&reply->data, "next_offset",
                         has_more ? (int64_t)(rank_offset + page_span) : 0) &&
        json_push_kv_int(&reply->data, "corpus_files", (int64_t)corpus_files) &&
        json_push_kv_str(
            &reply->data, "document_profile",
            "path+group+purpose+symbol_name+signature+doc+guard") &&
        json_push_kv_str(&reply->data, "context_basis", "full_file_bytes") &&
        json_push_kv_str(&reply->data, "context_cost_kind",
                         "projected_not_read") &&
        json_push_kv_str(&reply->data, "token_basis",
                         "ceil(context_bytes/4)") &&
        json_push_kv_str(&reply->data, "literal_selector_basis",
                         "frozen_pre_story_token_order_v1") &&
        json_push_kv_str(&reply->data, "production_selector_basis",
                         "hybrid_literal_bm25_story_v1") &&
        json_push_kv_str(&reply->data, "gold_basis",
                         "not_supplied_rank_only") &&
        json_push_kv_str(&reply->data, "scope_basis", "unavailable");
    struct json_value literal_json, bm25_json;
    json_init(&literal_json);
    json_set_object(&literal_json);
    json_init(&bm25_json);
    json_set_object(&bm25_json);
    ok = ok && rb_push_rank(&literal_json, literal, rank_offset, page_limit) &&
        rb_push_rank(&bm25_json, bm25, rank_offset, page_limit) &&
        json_push_kv(&reply->data, "literal", &literal_json) &&
        json_push_kv(&reply->data, "bm25", &bm25_json);
    json_free(&literal_json);
    json_free(&bm25_json);
    return ok;
}

static bool rb_compute(const struct json_value *input, const char *workspace,
                       struct rb_computation *computed,
                       struct zcl_command_reply *reply)
{
    const char *expected_hex = json_get_str(json_get(input,
                                                     "expected_vcs_root"));
    const char *task_id = json_get_str(json_get(input, "task_id"));
    const char *query = json_get_str(json_get(input, "query"));
    if (!task_id || !task_id[0] || strlen(task_id) > 128 || !query ||
        !query[0] || strlen(query) > 4096) {
        rb_fail(reply, "INVALID_TASK", "input",
                "task_id and bounded non-empty query are required", "task");
        return false;
    }
    if (!expected_hex || !expected_hex[0]) {
        rb_fail(reply, "EXPECTED_VCS_ROOT_REQUIRED", "bind",
                "expected_vcs_root is required for observational ranking",
                "expected_vcs_root");
        return false;
    }
    uint8_t expected[32];
    if (!zcl_hex_decode_lower(expected_hex, expected, sizeof(expected))) {
        rb_fail(reply, "INVALID_VCS_ROOT", "bind",
                "expected_vcs_root must be exactly 64 lowercase hex characters",
                "expected_vcs_root");
        return false;
    }

    memset(computed, 0, sizeof(*computed));
    (void)snprintf(computed->workspace, sizeof(computed->workspace), "%s",
                   workspace);
    (void)snprintf(computed->task_id, sizeof(computed->task_id), "%s",
                   task_id);
    (void)snprintf(computed->query, sizeof(computed->query), "%s", query);
    (void)snprintf(computed->expected_hex, sizeof(computed->expected_hex),
                   "%s", expected_hex);

    struct vcs_manifest pre = {0};
    uint8_t pre_root[32];
    struct vcs_index *index = rb_index_open(workspace);
    if (!index) {
        rb_fail(reply, "SOURCE_CAPTURE_FAILED", "capture",
                "could not open the ZVCS stat cache", workspace);
        return false;
    }
    if (!rb_manifest_capture(workspace, index, &pre, pre_root)) {
        vcs_index_close(index);
        rb_fail(reply, "SOURCE_CAPTURE_FAILED", "capture",
                "could not build the pre-run ZVCS manifest", workspace);
        return false;
    }
    zcl_hex_encode(pre_root, sizeof(pre_root), computed->pre_hex);
    if (memcmp(expected, pre_root, sizeof(expected)) != 0) {
        vcs_manifest_free(&pre);
        vcs_index_close(index);
        rb_fail(reply, "SOURCE_ROOT_MISMATCH", "bind",
                "expected source root does not match the pre-run manifest",
                computed->pre_hex);
        return false;
    }

    struct codeindex *ci = codeindex_open_source_view(workspace);
    uint8_t codeindex_root[32];
    bool ranked = ci && codeindex_source_root_sha3(ci, codeindex_root) &&
        rb_literal_rank(ci, query, &pre, &computed->literal) &&
        rb_bm25_rank(ci, query, &pre, &computed->bm25,
                     &computed->corpus_files);
    codeindex_close(ci);
    if (!ranked) {
        vcs_manifest_free(&pre);
        vcs_index_close(index);
        rb_fail(reply, "RANKING_FAILED", "rank",
                "literal or BM25 ranking could not be sealed", workspace);
        return false;
    }

    struct vcs_manifest post = {0};
    uint8_t post_root[32];
    if (!rb_manifest_capture(workspace, index, &post, post_root) ||
        memcmp(pre_root, post_root, sizeof(pre_root)) != 0) {
        vcs_manifest_free(&pre);
        vcs_manifest_free(&post);
        vcs_index_close(index);
        rb_fail(reply, "SOURCE_CHANGED_DURING_BENCHMARK", "bind",
                "the ZVCS manifest changed while rankings were computed",
                workspace);
        return false;
    }
    vcs_manifest_free(&post);
    vcs_manifest_free(&pre);
    vcs_index_close(index);
    zcl_hex_encode(post_root, sizeof(post_root), computed->post_hex);
    zcl_hex_encode(codeindex_root, sizeof(codeindex_root),
                   computed->codeindex_hex);
    return true;
}

static bool rb_render_fitted(struct zcl_command_reply *reply,
                             const struct rb_computation *computed,
                             size_t rank_offset, size_t contract,
                             size_t *page_limit_out)
{
    size_t data_cap = contract > 768u ? contract - 768u : 0;
    size_t page_limit = RB_DISPLAY_ROWS;
    bool output_ok = false;
    while (page_limit > 0) {
        output_ok = rb_render_data(
            reply, computed->task_id, computed->query, computed->expected_hex,
            computed->pre_hex, computed->post_hex, computed->codeindex_hex,
            rank_offset, computed->corpus_files, &computed->literal,
            &computed->bm25, page_limit);
        if (!output_ok || json_write(&reply->data, NULL, 0) <= data_cap)
            break;
        page_limit--;
    }
    if (!output_ok || page_limit == 0 ||
        json_write(&reply->data, NULL, 0) > data_cap) {
        rb_fail(reply, "OUTPUT_ALLOCATION_FAILED", "render",
                "benchmark result could not be rendered completely",
                computed->task_id);
        return false;
    }
    if (page_limit_out) *page_limit_out = page_limit;
    return true;
}

struct rb_stream_buffer {
    char *bytes;
    size_t used;
    size_t cap;
};

static bool rb_stream_append(struct rb_stream_buffer *buffer,
                             const char *bytes, size_t count)
{
    if (!buffer || !bytes || count > RB_STREAM_MAX_BYTES ||
        buffer->used > RB_STREAM_MAX_BYTES - count) {
        LOG_ERROR(RB_TAG, "stream output exceeded its %d-byte bound",
                  RB_STREAM_MAX_BYTES);
        return false;
    }
    size_t need = buffer->used + count;
    if (need > buffer->cap) {
        size_t cap = buffer->cap ? buffer->cap : 16384u;
        while (cap < need && cap <= RB_STREAM_MAX_BYTES / 2u) cap *= 2u;
        if (cap < need) cap = RB_STREAM_MAX_BYTES;
        char *grown = zcl_realloc(buffer->bytes, cap,
                                  "retrieval benchmark stream");
        if (!grown) {
            LOG_ERROR(RB_TAG, "stream output allocation failed at %zu bytes",
                      cap);
            return false;
        }
        buffer->bytes = grown;
        buffer->cap = cap;
    }
    memcpy(buffer->bytes + buffer->used, bytes, count);
    buffer->used += count;
    return true;
}

static void rb_stream_error(char *code, size_t code_cap,
                            char *message, size_t message_cap,
                            const char *error_code, const char *error_message)
{
    if (code && code_cap)
        (void)snprintf(code, code_cap, "%s",
                       error_code ? error_code : "STREAM_FAILED");
    if (message && message_cap)
        (void)snprintf(message, message_cap, "%s",
                       error_message ? error_message
                                     : "retrieval stream failed");
}

static bool rb_stream_cursor_zero(const struct json_value *input)
{
    const struct json_value *cursor = json_get(input, "cursor");
    if (!cursor) return true;
    if (cursor->type == JSON_INT) return json_get_int(cursor) == 0;
    if (cursor->type == JSON_STR) {
        const char *value = json_get_str(cursor);
        return value && strcmp(value, "0") == 0;
    }
    return false;
}

int zcl_native_dev_retrieval_stream_jsonl(
    const struct json_value *input, size_t contract_bytes, FILE *out,
    char *error_code, size_t error_code_cap,
    char *error_message, size_t error_message_cap)
{
    if (error_code && error_code_cap) error_code[0] = '\0';
    if (error_message && error_message_cap) error_message[0] = '\0';
    if (!input || input->type != JSON_OBJ || !out) {
        rb_stream_error(error_code, error_code_cap, error_message,
                        error_message_cap, "INVALID_INPUT",
                        "stream input must be one JSON object");
        return ZCL_COMMAND_EXIT_INVALID;
    }
    if (!rb_stream_cursor_zero(input)) {
        rb_stream_error(error_code, error_code_cap, error_message,
                        error_message_cap, "INVALID_CURSOR",
                        "stream cursor must be absent or zero");
        return ZCL_COMMAND_EXIT_INVALID;
    }
    char workspace[PATH_MAX];
    if (!rb_workspace(input, workspace)) {
        rb_stream_error(error_code, error_code_cap, error_message,
                        error_message_cap, "WORKSPACE_NOT_CANONICAL",
                        "workspace must be a canonical absolute directory");
        return ZCL_COMMAND_EXIT_INVALID;
    }
    if (contract_bytes < 512u || contract_bytes > ZCL_COMMAND_LIST_BUDGET)
        contract_bytes = ZCL_COMMAND_LIST_BUDGET;

    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_benchmark.v1");
    struct rb_computation computed;
    int64_t started_us = platform_time_monotonic_us();
    if (!rb_compute(input, workspace, &computed, &reply)) {
        rb_stream_error(error_code, error_code_cap, error_message,
                        error_message_cap, reply.error.code,
                        reply.error.message);
        int rc = reply.exit_code;
        zcl_command_reply_free(&reply);
        return rc;
    }
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
    if (elapsed_us < 0) elapsed_us = 0;
    const int64_t budget_ms = ZCL_COMMAND_LATENCY_BUDGET_PERSISTENT_MS;
    const bool budget_exceeded = elapsed_us > budget_ms * 1000;
    size_t max_count = computed.literal.count > computed.bm25.count
        ? computed.literal.count : computed.bm25.count;
    size_t offset = 0, page_index = 0;
    struct rb_stream_buffer stream = {0};
    bool ok = true;
    do {
        json_free(&reply.data);
        json_init(&reply.data);
        size_t page_limit = 0;
        if (!rb_render_fitted(&reply, &computed, offset, contract_bytes,
                              &page_limit)) {
            ok = false;
            break;
        }
        size_t page_span = max_count > offset ? max_count - offset : 0;
        if (page_span > page_limit) page_span = page_limit;
        bool has_more = offset + page_span < max_count;

        struct json_value line;
        json_init(&line);
        json_set_object(&line);
        ok = page_index <= INT64_MAX &&
            json_push_kv_str(
                &line, "schema",
                "zcl.dev_retrieval_benchmark_stream_page.v2") &&
            json_push_kv_str(&line, "command", "dev.retrieval.benchmark") &&
            json_push_kv_int(&line, "page_index", (int64_t)page_index) &&
            json_push_kv_bool(&line, "shared_computation", true) &&
            json_push_kv_int(&line, "ranking_computations", 1) &&
            json_push_kv_int(&line, "ranking_elapsed_us", elapsed_us) &&
            json_push_kv_int(&line, "ranking_elapsed_ms", elapsed_us / 1000) &&
            json_push_kv_int(&line, "ranking_budget_ms", budget_ms) &&
            json_push_kv_bool(&line, "ranking_budget_exceeded",
                              budget_exceeded) &&
            json_push_kv_str(&line, "data_schema",
                             "zcl.dev_retrieval_benchmark.v1") &&
            json_push_kv(&line, "data", &reply.data);
        char encoded[ZCL_COMMAND_LIST_BUDGET + 1];
        size_t encoded_len = ok
            ? json_write(&line, encoded, sizeof(encoded)) : 0;
        json_free(&line);
        if (!encoded_len || encoded_len >= sizeof(encoded) ||
            !rb_stream_append(&stream, encoded, encoded_len) ||
            !rb_stream_append(&stream, "\n", 1u)) {
            ok = false;
            break;
        }
        page_index++;
        if (!has_more) break;
        if (page_span == 0 || offset > RB_RETAIN_ROWS - page_span) {
            ok = false;
            break;
        }
        offset += page_span;
    } while (page_index <= RB_RETAIN_ROWS);

    int rc = ZCL_COMMAND_EXIT_OK;
    if (!ok || page_index == 0 || page_index > RB_RETAIN_ROWS) {
        const char *code = reply.error.code[0]
            ? reply.error.code : "STREAM_RENDER_FAILED";
        const char *message = reply.error.message[0]
            ? reply.error.message
            : "all retrieval pages could not be buffered";
        rb_stream_error(error_code, error_code_cap, error_message,
                        error_message_cap, code, message);
        rc = reply.exit_code == ZCL_COMMAND_EXIT_OK
            ? ZCL_COMMAND_EXIT_INTERNAL : reply.exit_code;
    } else if (fwrite(stream.bytes, 1, stream.used, out) != stream.used ||
               fflush(out) != 0) {
        rb_stream_error(error_code, error_code_cap, error_message,
                        error_message_cap, "STREAM_WRITE_FAILED",
                        "buffered retrieval pages could not be written");
        rc = ZCL_COMMAND_EXIT_INTERNAL;
    }
    free(stream.bytes);
    zcl_command_reply_free(&reply);
    return rc;
}

static void rb_run(const struct zcl_command_request *request,
                   struct zcl_command_reply *reply)
{
    if (!request->input || request->input->type != JSON_OBJ) {
        rb_fail(reply, "INVALID_INPUT", "input",
                "benchmark input must be one JSON object", "input");
        return;
    }
    char workspace[PATH_MAX];
    if (!rb_workspace(request->input, workspace)) {
        rb_fail(reply, "WORKSPACE_NOT_CANONICAL", "input",
                "workspace must be a canonical absolute directory path",
                "workspace");
        return;
    }
    size_t rank_offset = 0;
    if (!rb_cursor(request, &rank_offset)) {
        rb_fail(reply, "INVALID_CURSOR", "input",
                "cursor must be a decimal rank offset from 0 through 127",
                "cursor");
        return;
    }
    struct rb_computation computed;
    if (!rb_compute(request->input, workspace, &computed, reply)) return;
    size_t contract = request->spec && request->spec->budget_bytes
        ? (size_t)request->spec->budget_bytes
        : (size_t)ZCL_COMMAND_LIST_BUDGET;
    if (request->budget_bytes && request->budget_bytes < contract)
        contract = request->budget_bytes;
    (void)rb_render_fitted(reply, &computed, rank_offset, contract, NULL);
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

void zcl_native_handle_dev_retrieval_benchmark(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    if (!request || !reply) {
        LOG_ERROR(RB_TAG, "INVALID_REQUEST: request or reply is null");
        return;
    }
    rb_run(request, reply);
#else
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "retrieval benchmarking requires the dev binary", "make dev-bin");
#endif
}
