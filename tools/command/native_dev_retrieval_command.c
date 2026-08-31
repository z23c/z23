/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: source-bound observational retrieval benchmark for dev builds. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "retrieval/retrieval.h"
#include "services/zcode_goal_context_service.h"
#include "vcs/vcs_manifest.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RB_TAG "native.dev.retrieval"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

enum {
    RB_MAX_ROWS = 20,
    RB_QUERY_ROWS = RB_MAX_ROWS + 1,
    RB_INITIAL_ROWS = 64,
    RB_MAX_INDEX_ROWS = 65536,
};

struct rb_rank {
    struct zcl_retrieval_ranked_file rows[RB_MAX_ROWS];
    char paths[RB_MAX_ROWS][256];
    size_t count;
    bool complete;
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

static bool rb_add_size(size_t *total, size_t add)
{
    if (!total || SIZE_MAX - *total < add) {
        LOG_ERROR(RB_TAG, "document size overflow");
        return false;
    }
    *total += add;
    return true;
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

static bool rb_load_groups(struct codeindex *ci, struct ci_group **out,
                           size_t *count)
{
    int cap = RB_INITIAL_ROWS;
    struct ci_group *rows = NULL;
    for (;;) {
        struct ci_group *grown = zcl_realloc(
            rows, (size_t)cap * sizeof(*rows), "retrieval benchmark groups");
        if (!grown) {
            free(rows);
            LOG_ERROR(RB_TAG, "group allocation failed at cap=%d", cap);
            return false;
        }
        rows = grown;
        int n = codeindex_groups(ci, rows, cap);
        if (n < 0) {
            free(rows);
            LOG_ERROR(RB_TAG, "codeindex group enumeration failed");
            return false;
        }
        if (n < cap) {
            *out = rows;
            *count = (size_t)n;
            return true;
        }
        if (cap >= RB_MAX_INDEX_ROWS) {
            free(rows);
            LOG_ERROR(RB_TAG, "group enumeration exceeded %d rows", cap);
            return false;
        }
        cap *= 2;
    }
}

static bool rb_load_group_files(struct codeindex *ci, const char *group,
                                struct ci_file **out, size_t *count)
{
    int cap = RB_INITIAL_ROWS;
    struct ci_file *rows = NULL;
    for (;;) {
        struct ci_file *grown = zcl_realloc(
            rows, (size_t)cap * sizeof(*rows), "retrieval benchmark files");
        if (!grown) {
            free(rows);
            LOG_ERROR(RB_TAG, "file allocation failed for group=%s", group);
            return false;
        }
        rows = grown;
        int n = codeindex_files_in_group(ci, group, rows, cap);
        if (n < 0) {
            free(rows);
            LOG_ERROR(RB_TAG, "file enumeration failed for group=%s", group);
            return false;
        }
        if (n < cap) {
            *out = rows;
            *count = (size_t)n;
            return true;
        }
        if (cap >= RB_MAX_INDEX_ROWS) {
            free(rows);
            LOG_ERROR(RB_TAG, "file enumeration exceeded %d rows", cap);
            return false;
        }
        cap *= 2;
    }
}

static bool rb_load_symbols(struct codeindex *ci, const char *path,
                            struct ci_symbol **out, size_t *count)
{
    int cap = RB_INITIAL_ROWS;
    struct ci_symbol *rows = NULL;
    for (;;) {
        struct ci_symbol *grown = zcl_realloc(
            rows, (size_t)cap * sizeof(*rows), "retrieval benchmark symbols");
        if (!grown) {
            free(rows);
            LOG_ERROR(RB_TAG, "symbol allocation failed for path=%s", path);
            return false;
        }
        rows = grown;
        int n = codeindex_symbols_in_file(ci, path, rows, cap);
        if (n < 0) {
            free(rows);
            LOG_ERROR(RB_TAG, "symbol enumeration failed for path=%s", path);
            return false;
        }
        if (n < cap) {
            *out = rows;
            *count = (size_t)n;
            return true;
        }
        if (cap >= RB_MAX_INDEX_ROWS) {
            free(rows);
            LOG_ERROR(RB_TAG, "symbol enumeration exceeded %d rows", cap);
            return false;
        }
        cap *= 2;
    }
}

static int rb_file_cmp(const void *a, const void *b)
{
    const struct ci_file *left = a;
    const struct ci_file *right = b;
    return strcmp(left->path, right->path);
}

static bool rb_collect_files(struct codeindex *ci, struct ci_file **out,
                             size_t *count)
{
    struct ci_group *groups = NULL;
    size_t group_count = 0, used = 0, cap = 0;
    struct ci_file *all = NULL;
    if (!rb_load_groups(ci, &groups, &group_count)) return false;
    for (size_t g = 0; g < group_count; g++) {
        struct ci_file *files = NULL;
        size_t file_count = 0;
        if (!rb_load_group_files(ci, groups[g].path, &files, &file_count)) {
            free(groups);
            free(all);
            return false;
        }
        if (file_count > SIZE_MAX - used) {
            free(files);
            free(groups);
            free(all);
            LOG_ERROR(RB_TAG, "indexed file count overflow");
            return false;
        }
        size_t want = used + file_count;
        if (want > cap) {
            size_t next = cap ? cap : RB_INITIAL_ROWS;
            while (next < want && next <= SIZE_MAX / 2) next *= 2;
            if (next < want || next > RB_MAX_INDEX_ROWS) {
                free(files);
                free(groups);
                free(all);
                LOG_ERROR(RB_TAG, "indexed file corpus exceeds bound");
                return false;
            }
            struct ci_file *grown = zcl_realloc(
                all, next * sizeof(*all), "retrieval benchmark file corpus");
            if (!grown) {
                free(files);
                free(groups);
                free(all);
                LOG_ERROR(RB_TAG, "file corpus allocation failed");
                return false;
            }
            all = grown;
            cap = next;
        }
        memcpy(all + used, files, file_count * sizeof(*files));
        used += file_count;
        free(files);
    }
    free(groups);
    qsort(all, used, sizeof(*all), rb_file_cmp);
    for (size_t i = 1; i < used; i++) {
        if (strcmp(all[i - 1].path, all[i].path) == 0) {
            LOG_ERROR(RB_TAG, "indexed file belongs to multiple groups: %s",
                      all[i].path);
            free(all);
            return false;
        }
    }
    *out = all;
    *count = used;
    return true;
}

static bool rb_append(char *out, size_t cap, size_t *used, const char *field)
{
    size_t len = strlen(field);
    if (*used > cap || len > cap - *used || cap - *used - len < 1) {
        LOG_ERROR(RB_TAG, "retrieval document assembly exceeded allocation");
        return false;
    }
    memcpy(out + *used, field, len);
    *used += len;
    out[(*used)++] = '\n';
    return true;
}

static char *rb_document(const struct ci_file *file,
                         const struct ci_symbol *symbols, size_t symbol_count)
{
    size_t need = 1;
    const char *base[] = { file->path, file->group, file->purpose };
    for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); i++)
        if (!rb_add_size(&need, strlen(base[i]) + 1)) return NULL;
    for (size_t i = 0; i < symbol_count; i++) {
        const char *fields[] = { symbols[i].name, symbols[i].signature,
                                 symbols[i].doc, symbols[i].guard };
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); j++)
            if (!rb_add_size(&need, strlen(fields[j]) + 1)) return NULL;
    }
    char *out = zcl_malloc(need, "retrieval benchmark document");
    if (!out) {
        LOG_ERROR(RB_TAG, "retrieval document allocation failed");
        return NULL;
    }
    size_t used = 0;
    for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); i++)
        if (!rb_append(out, need, &used, base[i])) {
            free(out);
            return NULL;
        }
    for (size_t i = 0; i < symbol_count; i++) {
        const char *fields[] = { symbols[i].name, symbols[i].signature,
                                 symbols[i].doc, symbols[i].guard };
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); j++)
            if (!rb_append(out, need, &used, fields[j])) {
                free(out);
                return NULL;
            }
    }
    out[used] = '\0';
    return out;
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
    if (rank->count >= RB_MAX_ROWS) {
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

static bool rb_literal_rank(const char *workspace, const char *query,
                            const struct vcs_manifest *manifest,
                            struct rb_rank *rank)
{
    struct zcode_goal_selection selected;
    struct zcl_result result = zcode_goal_context_select(
        workspace, query, NULL, &selected);
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
    struct ci_file *files = NULL;
    size_t file_count = 0;
    if (!rb_collect_files(ci, &files, &file_count) || file_count == 0) {
        free(files);
        LOG_ERROR(RB_TAG, "indexed file corpus is unavailable or empty");
        return false;
    }
    struct zcl_retrieval *retrieval = zcl_retrieval_create();
    if (!retrieval) {
        free(files);
        LOG_ERROR(RB_TAG, "BM25 index allocation failed");
        return false;
    }
    bool ok = true;
    for (size_t i = 0; i < file_count && ok; i++) {
        if (!rb_manifest_entry(manifest, files[i].path)) {
            LOG_ERROR(RB_TAG, "indexed file absent from manifest: %s",
                      files[i].path);
            ok = false;
            break;
        }
        struct ci_symbol *symbols = NULL;
        size_t symbol_count = 0;
        if (!rb_load_symbols(ci, files[i].path, &symbols, &symbol_count)) {
            ok = false;
            break;
        }
        char *document = rb_document(&files[i], symbols, symbol_count);
        free(symbols);
        if (!document || zcl_retrieval_add(
                retrieval, files[i].path, document) == 0) {
            free(document);
            LOG_ERROR(RB_TAG, "BM25 document insertion failed: %s",
                      files[i].path);
            ok = false;
            break;
        }
        free(document);
    }
    if (ok) {
        struct zcl_retrieval_hit hits[RB_QUERY_ROWS];
        size_t n = 0;
        if (!zcl_retrieval_query_checked(retrieval, query, hits,
                                         RB_QUERY_ROWS, &n)) {
            LOG_ERROR(RB_TAG, "checked BM25 query failed");
            ok = false;
        } else {
            rank->complete = n <= RB_MAX_ROWS;
            for (size_t i = 0; i < n && i < RB_MAX_ROWS && ok; i++)
                ok = rb_rank_add(rank,
                    zcl_retrieval_name(retrieval, hits[i].doc), manifest);
        }
    }
    *corpus_files = file_count;
    zcl_retrieval_destroy(retrieval);
    free(files);
    return ok;
}

static bool rb_push_rank(struct json_value *object, const struct rb_rank *rank)
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
    bool ok = json_push_kv_bool(object, "ranking_complete", rank->complete) &&
        json_push_kv_int(object, "ranked_files", (int64_t)rank->count) &&
        json_push_kv_int(object, "context_bytes_at_5", (int64_t)bytes_at_5) &&
        json_push_kv_int(object, "approximate_tokens_at_5",
                         (int64_t)((bytes_at_5 + 3u) / 4u));
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < rank->count && ok; i++) {
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

static bool rb_manifest_capture(const char *workspace,
                                struct vcs_manifest *manifest,
                                uint8_t root[32])
{
    if (!vcs_manifest_build(workspace, NULL, manifest)) {
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

static void rb_run(const struct zcl_command_request *request,
                   struct zcl_command_reply *reply)
{
    if (!request->input || request->input->type != JSON_OBJ) {
        rb_fail(reply, "INVALID_INPUT", "input",
                "benchmark input must be one JSON object", "input");
        return;
    }
    const char *workspace_input = json_get_str(json_get(request->input,
                                                        "workspace"));
    const char *expected_hex = json_get_str(json_get(request->input,
                                                     "expected_vcs_root"));
    const char *task_id = json_get_str(json_get(request->input, "task_id"));
    const char *query = json_get_str(json_get(request->input, "query"));
    char workspace[PATH_MAX];
    if (!workspace_input || workspace_input[0] != '/' ||
        !platform_directory_canonical_real(workspace_input, workspace,
                                           sizeof(workspace)) ||
        strcmp(workspace_input, workspace) != 0) {
        rb_fail(reply, "WORKSPACE_NOT_CANONICAL", "input",
                "workspace must be a canonical absolute directory path",
                workspace_input ? workspace_input : "missing");
        return;
    }
    if (!task_id || !task_id[0] || strlen(task_id) > 128 || !query ||
        !query[0] || strlen(query) > 4096) {
        rb_fail(reply, "INVALID_TASK", "input",
                "task_id and bounded non-empty query are required", "task");
        return;
    }
    if (!expected_hex || !expected_hex[0]) {
        rb_fail(reply, "EXPECTED_VCS_ROOT_REQUIRED", "bind",
                "expected_vcs_root is required for observational ranking",
                "expected_vcs_root");
        return;
    }
    uint8_t expected[32];
    if (!zcl_hex_decode_lower(expected_hex, expected, sizeof(expected))) {
        rb_fail(reply, "INVALID_VCS_ROOT", "bind",
                "expected_vcs_root must be exactly 64 lowercase hex characters",
                "expected_vcs_root");
        return;
    }

    struct vcs_manifest pre;
    uint8_t pre_root[32];
    if (!rb_manifest_capture(workspace, &pre, pre_root)) {
        rb_fail(reply, "SOURCE_CAPTURE_FAILED", "capture",
                "could not build the pre-run ZVCS manifest", workspace);
        return;
    }
    char pre_hex[65];
    zcl_hex_encode(pre_root, sizeof(pre_root), pre_hex);
    if (memcmp(expected, pre_root, sizeof(expected)) != 0) {
        vcs_manifest_free(&pre);
        rb_fail(reply, "SOURCE_ROOT_MISMATCH", "bind",
                "expected source root does not match the pre-run manifest",
                pre_hex);
        return;
    }

    struct codeindex *ci = codeindex_open_source_view(workspace);
    uint8_t codeindex_root[32];
    struct rb_rank literal = {0}, bm25 = {0};
    size_t corpus_files = 0;
    bool ranked = ci && codeindex_source_root_sha3(ci, codeindex_root) &&
        rb_literal_rank(workspace, query, &pre, &literal) &&
        rb_bm25_rank(ci, query, &pre, &bm25, &corpus_files);
    codeindex_close(ci);
    if (!ranked) {
        vcs_manifest_free(&pre);
        rb_fail(reply, "RANKING_FAILED", "rank",
                "literal or BM25 ranking could not be sealed", workspace);
        return;
    }

    struct vcs_manifest post;
    uint8_t post_root[32];
    if (!rb_manifest_capture(workspace, &post, post_root) ||
        memcmp(pre_root, post_root, sizeof(pre_root)) != 0) {
        vcs_manifest_free(&pre);
        vcs_manifest_free(&post);
        rb_fail(reply, "SOURCE_CHANGED_DURING_BENCHMARK", "bind",
                "the ZVCS manifest changed while rankings were computed",
                workspace);
        return;
    }
    vcs_manifest_free(&post);

    char post_hex[65], codeindex_hex[65];
    zcl_hex_encode(post_root, sizeof(post_root), post_hex);
    zcl_hex_encode(codeindex_root, sizeof(codeindex_root), codeindex_hex);
    bool output_ok = corpus_files <= INT64_MAX &&
        json_push_kv_str(&reply->data, "schema",
                         "zcl.dev_retrieval_benchmark.v1") &&
        json_push_kv_bool(&reply->data, "observational", true) &&
        json_push_kv_bool(&reply->data, "production_ordering_changed", false) &&
        json_push_kv_bool(&reply->data, "promotion_authorized", false) &&
        json_push_kv_bool(&reply->data, "native_execution", true) &&
        json_push_kv_bool(&reply->data, "ready_to_benchmark", true) &&
        json_push_kv_str(&reply->data, "task_id", task_id) &&
        json_push_kv_str(&reply->data, "query", query) &&
        json_push_kv_str(&reply->data, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(&reply->data, "observed_vcs_root_pre", pre_hex) &&
        json_push_kv_str(&reply->data, "observed_vcs_root_post", post_hex) &&
        json_push_kv_str(&reply->data, "bm25_codeindex_source_root_sha3",
                         codeindex_hex) &&
        json_push_kv_int(&reply->data, "corpus_files", (int64_t)corpus_files) &&
        json_push_kv_str(
            &reply->data, "document_profile",
            "path+group+purpose+symbol_name+signature+doc+guard") &&
        json_push_kv_str(&reply->data, "context_basis", "full_file_bytes") &&
        json_push_kv_str(&reply->data, "context_cost_kind",
                         "projected_not_read") &&
        json_push_kv_str(&reply->data, "token_basis",
                         "ceil(context_bytes/4)") &&
        json_push_kv_str(&reply->data, "literal_source_generation_basis",
                         "unobserved_internal_selector") &&
        json_push_kv_str(&reply->data, "gold_basis",
                         "not_supplied_rank_only") &&
        json_push_kv_str(&reply->data, "scope_basis", "unavailable");
    struct json_value literal_json, bm25_json;
    json_init(&literal_json);
    json_set_object(&literal_json);
    json_init(&bm25_json);
    json_set_object(&bm25_json);
    output_ok = output_ok && rb_push_rank(&literal_json, &literal) &&
        rb_push_rank(&bm25_json, &bm25) &&
        json_push_kv(&reply->data, "literal", &literal_json) &&
        json_push_kv(&reply->data, "bm25", &bm25_json);
    json_free(&literal_json);
    json_free(&bm25_json);
    vcs_manifest_free(&pre);
    if (!output_ok)
        rb_fail(reply, "OUTPUT_ALLOCATION_FAILED", "render",
                "benchmark result could not be rendered completely", task_id);
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
