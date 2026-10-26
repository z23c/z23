/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Render the generated bounded-context map and its violations. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_context.h"
#include "json/json.h"
#include "sha3/sha3.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CONTEXT_VIOLATION_CAP = 8,
    CONTEXT_SHAPE_CAP = 48,
    CONTEXT_FILE_PAGE_CAP = 256,
    CONTEXT_INCLUDE_PAGE_CAP = 256,
    CONTEXT_COUPLING_CAP = 8,
};

struct context_count {
    char name[CI_CONTEXT_SHAPE_MAX];
    int count;
};

struct context_pair {
    int from;
    int to;
    int64_t count;
};

static void context_push_string(struct json_value *array, const char *value)
{
    struct json_value item;
    json_init(&item); json_set_str(&item, value);
    (void)json_push_back(array, &item);
    json_free(&item);
}

static void context_push_object(struct json_value *array,
                                struct json_value *object)
{
    (void)json_push_back(array, object);
    json_free(object);
}

static int context_index(const char *name, const char *const *contexts,
                         size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(contexts[i], name) == 0) return (int)i;
    return -1;
}

static int shape_index(struct context_count *shapes, int *count,
                       const char *name)
{
    for (int i = 0; i < *count; i++)
        if (strcmp(shapes[i].name, name) == 0) return i;
    if (*count >= CONTEXT_SHAPE_CAP) return -1;
    int i = (*count)++;
    (void)snprintf(shapes[i].name, sizeof(shapes[i].name), "%s", name);
    return i;
}

static int pair_cmp(const void *a, const void *b)
{
    const struct context_pair *pa = a;
    const struct context_pair *pb = b;
    if (pa->count != pb->count) return pa->count < pb->count ? 1 : -1;
    if (pa->from != pb->from) return pa->from - pb->from;
    return pa->to - pb->to;
}

static bool context_digest_row(
    struct sha3_256_ctx *digest, const char *path,
    const struct ci_context_assignment *assignment)
{
    uint8_t row[32];
    if (!codeindex_context_assignment_digest(path, assignment, row))
        return false;
    sha3_256_write(digest, row, sizeof(row));
    return true;
}

/* Warm reads reuse the last derived map while it was derived from the index
 * generation just opened. codeindex_open() has already refreshed the store
 * against the live sources and depfiles, so the store's own source and
 * depfile content roots name exactly what the map would be derived from.
 * A file count cannot: a depfile-only edit or a rename across contexts keeps
 * it. The first dispatch still walks every production file and include edge;
 * the latency contract is the second. */
static struct {
    char root[1024];
    uint8_t generation[64];
    struct json_value data;
    bool valid;
} g_map_warm;

static bool context_map_generation(struct codeindex *index,
                                   uint8_t generation[64])
{
    return codeindex_source_root_sha3(index, generation) &&
           codeindex_dep_root_sha3(index, generation + 32);
}

static bool context_map_warm_hit(const char *root,
                                 const uint8_t generation[64])
{
    return g_map_warm.valid && strlen(root) < sizeof g_map_warm.root &&
           strcmp(g_map_warm.root, root) == 0 &&
           memcmp(g_map_warm.generation, generation, 64) == 0;
}

struct context_map_acc {
    int counts[10];
    int64_t coupling[10][10];
    struct context_count shapes[CONTEXT_SHAPE_CAP];
    int shape_count;
    int production;
    int classified;
    int orphans;
    int overlaps;
    int64_t observed_edges;
    int64_t cross_edges;
    bool shape_overflow;
    bool coupling_query_failed;
    bool digest_failed;
    bool page_failed;
    int listed_total;
    struct sha3_256_ctx digest;
    struct json_value orphan_files;
    struct json_value overlap_files;
    int64_t include_edge_count;
};

static void context_map_note_overlap(
    const struct ci_context_assignment *assignment,
    struct context_map_acc *acc, const char *path)
{
    if (!assignment->overlap)
        return;
    acc->overlaps++;
    if (acc->overlaps <= CONTEXT_VIOLATION_CAP) {
        struct json_value item, matches;
        json_init(&item); json_set_object(&item);
        json_init(&matches); json_set_array(&matches);
        (void)json_push_kv_str(&item, "path", path);
        (void)json_push_kv_str(&item, "assigned", assignment->context);
        for (size_t m = 0; m < assignment->match_count; m++)
            context_push_string(&matches, assignment->matches[m]);
        (void)json_push_kv(&item, "matches", &matches);
        json_free(&matches);
        context_push_object(&acc->overlap_files, &item);
    }
}

static void context_map_tally_include_page(
    char (*includes)[256], int ni, int from,
    const char *const *contexts, size_t context_count,
    struct context_map_acc *acc)
{
    for (int j = 0; j < ni; j++) {
        struct ci_context_assignment dependency;
        if (!codeindex_context_classify(includes[j], &dependency) ||
            !dependency.production || dependency.orphan)
            continue;
        int to = context_index(dependency.context, contexts, context_count);
        if (to < 0) continue;
        acc->observed_edges++;
        if (from != to) {
            acc->coupling[from][to]++;
            acc->cross_edges++;
        }
    }
}

static void context_map_tally_includes(
    struct codeindex *index, const char *path, int from,
    char (*includes)[256], const char *const *contexts, size_t context_count,
    struct context_map_acc *acc)
{
    if (!codeindex_path_is_translation_unit(path))
        return;
    int include_offset = 0;
    for (;;) {
        int ni = codeindex_includes_of_file_page(
            index, path, include_offset, includes, CONTEXT_INCLUDE_PAGE_CAP);
        if (ni < 0) {
            acc->coupling_query_failed = true;
            break;
        }
        context_map_tally_include_page(includes, ni, from, contexts,
                                       context_count, acc);
        if (ni < CONTEXT_INCLUDE_PAGE_CAP) break;
        if (include_offset > INT_MAX - ni) {
            acc->coupling_query_failed = true;
            break;
        }
        include_offset += ni;
    }
}

static void context_map_scan_production_file(
    struct codeindex *index, const char *path, char (*includes)[256],
    const char *const *contexts, size_t context_count,
    struct context_map_acc *acc)
{
    struct ci_context_assignment assignment;
    if (!codeindex_context_classify(path, &assignment) ||
        !assignment.production)
        return;
    acc->production++;
    if (!context_digest_row(&acc->digest, path, &assignment)) {
        acc->digest_failed = true;
        return;
    }
    int shape = shape_index(acc->shapes, &acc->shape_count, assignment.shape);
    if (shape < 0) {
        acc->shape_overflow = true;
        return;
    }
    acc->shapes[shape].count++;
    int from = context_index(assignment.context, contexts, context_count);
    if (assignment.orphan || from < 0) {
        acc->orphans++;
        if (acc->orphans <= CONTEXT_VIOLATION_CAP)
            context_push_string(&acc->orphan_files, path);
        return;
    }
    acc->classified++;
    acc->counts[from]++;
    context_map_note_overlap(&assignment, acc, path);
    context_map_tally_includes(index, path, from, includes, contexts,
                               context_count, acc);
}

static void context_map_scan_pages(
    struct codeindex *index, int total, struct ci_file *files,
    char (*includes)[256], const char *const *contexts, size_t context_count,
    struct context_map_acc *acc)
{
    for (int offset = 0; offset < total && !acc->shape_overflow &&
                         !acc->coupling_query_failed && !acc->digest_failed;) {
        int listed = codeindex_files_page(index, offset, files,
                                           CONTEXT_FILE_PAGE_CAP);
        if (listed <= 0) {
            acc->page_failed = true;
            break;
        }
        acc->listed_total += listed;
        for (int i = 0; i < listed; i++) {
            context_map_scan_production_file(index, files[i].path, includes,
                                             contexts, context_count, acc);
            if (acc->digest_failed || acc->shape_overflow ||
                acc->coupling_query_failed)
                break;
        }
        offset += listed;
    }
}

static void context_map_read_include_edges(
    struct codeindex *index, int total, struct context_map_acc *acc)
{
    acc->include_edge_count = -1;
    if (!acc->shape_overflow && !acc->coupling_query_failed &&
        !acc->digest_failed && !acc->page_failed &&
        acc->listed_total == total) {
        acc->include_edge_count = codeindex_include_edge_count(index);
        if (acc->include_edge_count < 0) acc->coupling_query_failed = true;
    }
}

static void context_map_select_failure(
    const struct context_map_acc *acc, int total,
    const char **code, const char **message)
{
    *code = NULL;
    *message = NULL;
    if (acc->shape_overflow) {
        *code = "SHAPE_TAXONOMY_OVERFLOW";
        *message = "the architectural shape taxonomy exceeded its bound";
    } else if (acc->coupling_query_failed) {
        *code = "COUPLING_QUERY_FAILED";
        *message = "an indexed include query failed";
    } else if (acc->digest_failed) {
        *code = "MAP_DIGEST_FAILED";
        *message = "a context assignment could not be digested";
    } else if (acc->page_failed || acc->listed_total != total) {
        *code = "MAP_INCOMPLETE";
        *message = "the paged code index file listing was incomplete";
    }
}

static int context_map_collect_pairs(
    const int64_t coupling[10][10], size_t context_count,
    struct context_pair *pairs)
{
    int pair_count = 0;
    for (size_t from = 0; from < context_count; from++)
        for (size_t to = 0; to < context_count; to++)
            if (from != to && coupling[from][to] > 0) {
                pairs[pair_count].from = (int)from;
                pairs[pair_count].to = (int)to;
                pairs[pair_count].count = coupling[from][to];
                pair_count++;
            }
    qsort(pairs, (size_t)pair_count, sizeof(pairs[0]), pair_cmp);
    return pair_count;
}

static void context_map_store_warm(
    const char *root, bool have_generation, const uint8_t generation[64],
    const struct json_value *data)
{
    if (have_generation && strlen(root) < sizeof g_map_warm.root) {
        if (g_map_warm.valid)
            json_free(&g_map_warm.data);
        json_init(&g_map_warm.data);
        json_copy(&g_map_warm.data, data);
        (void)snprintf(g_map_warm.root, sizeof g_map_warm.root, "%s", root);
        memcpy(g_map_warm.generation, generation, sizeof g_map_warm.generation);
        g_map_warm.valid = true;
    }
}

static void context_map_emit_reply(
    struct zcl_command_reply *reply, const char *root, int total,
    bool have_generation, const uint8_t generation[64],
    const char *const *contexts, size_t context_count,
    struct context_map_acc *acc, struct ci_file *files,
    char (*includes)[256], struct codeindex *index)
{
    uint8_t root_bytes[32];
    char root_hex[65];
    sha3_256_finalize(&acc->digest, root_bytes);
    zcl_hex_encode(root_bytes, sizeof(root_bytes), root_hex);

    struct json_value taxonomy, context_rows, shape_rows;
    json_init(&taxonomy); json_set_array(&taxonomy);
    json_init(&context_rows); json_set_array(&context_rows);
    json_init(&shape_rows); json_set_array(&shape_rows);
    for (size_t i = 0; i < context_count; i++) {
        context_push_string(&taxonomy, contexts[i]);
        struct json_value row;
        json_init(&row); json_set_object(&row);
        (void)json_push_kv_str(&row, "context", contexts[i]);
        (void)json_push_kv_int(&row, "file_count", acc->counts[i]);
        context_push_object(&context_rows, &row);
    }
    for (int i = 0; i < acc->shape_count; i++) {
        struct json_value row;
        json_init(&row); json_set_object(&row);
        (void)json_push_kv_str(&row, "shape", acc->shapes[i].name);
        (void)json_push_kv_int(&row, "file_count", acc->shapes[i].count);
        context_push_object(&shape_rows, &row);
    }

    struct context_pair pairs[100];
    int pair_count = context_map_collect_pairs(acc->coupling, context_count,
                                                pairs);
    struct json_value coupling_rows;
    json_init(&coupling_rows); json_set_array(&coupling_rows);
    int pair_shown = pair_count < CONTEXT_COUPLING_CAP
                         ? pair_count : CONTEXT_COUPLING_CAP;
    for (int i = 0; i < pair_shown; i++) {
        struct json_value row;
        json_init(&row); json_set_object(&row);
        (void)json_push_kv_str(&row, "from", contexts[pairs[i].from]);
        (void)json_push_kv_str(&row, "to", contexts[pairs[i].to]);
        (void)json_push_kv_int(&row, "edge_count", pairs[i].count);
        context_push_object(&coupling_rows, &row);
    }

    (void)json_push_kv(&reply->data, "taxonomy", &taxonomy);
    (void)json_push_kv_int(&reply->data, "indexed_files", total);
    (void)json_push_kv_int(&reply->data, "production_files", acc->production);
    (void)json_push_kv_int(&reply->data, "classified_files", acc->classified);
    (void)json_push_kv_str(&reply->data, "map_sha3", root_hex);
    (void)json_push_kv_str(
        &reply->data, "map_digest_scope",
        "ordered production path + full context assignment v1");
    (void)json_push_kv(&reply->data, "contexts", &context_rows);
    (void)json_push_kv(&reply->data, "shapes", &shape_rows);
    (void)json_push_kv_bool(&reply->data, "shapes_complete", true);
    (void)json_push_kv_int(&reply->data, "orphan_count", acc->orphans);
    (void)json_push_kv(&reply->data, "orphan_files", &acc->orphan_files);
    (void)json_push_kv_bool(&reply->data, "orphan_files_truncated",
                            acc->orphans > CONTEXT_VIOLATION_CAP);
    (void)json_push_kv_int(&reply->data, "overlap_count", acc->overlaps);
    (void)json_push_kv(&reply->data, "overlap_files", &acc->overlap_files);
    (void)json_push_kv_bool(&reply->data, "overlap_files_truncated",
                            acc->overlaps > CONTEXT_VIOLATION_CAP);
    (void)json_push_kv_str(&reply->data, "coupling_scope",
                           "observed compiler-depfile include edges");
    (void)json_push_kv_int(&reply->data, "observed_include_edges",
                           acc->observed_edges);
    (void)json_push_kv_int(&reply->data, "cross_context_include_edges",
                           acc->cross_edges);
    (void)json_push_kv_bool(&reply->data, "coupling_available",
                            acc->include_edge_count > 0);
    (void)json_push_kv_bool(&reply->data, "coupling_input_truncated",
                            false);
    (void)json_push_kv_int(&reply->data, "coupling_pair_count", pair_count);
    (void)json_push_kv_bool(&reply->data, "top_couplings_truncated",
                            pair_count > CONTEXT_COUPLING_CAP);
    (void)json_push_kv_bool(&reply->data, "coupling_truncated",
                            pair_count > CONTEXT_COUPLING_CAP);
    (void)json_push_kv(&reply->data, "top_couplings", &coupling_rows);
    char summary[256];
    (void)snprintf(summary, sizeof(summary),
                   "%d/%d production files classified into %zu contexts; "
                   "%d orphan(s), %d overlap(s), %" PRId64 " observed cross-context "
                   "include edge(s)", acc->classified, acc->production,
                   context_count, acc->orphans, acc->overlaps,
                   acc->cross_edges);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    context_map_store_warm(root, have_generation, generation, &reply->data);

    json_free(&taxonomy); json_free(&context_rows); json_free(&shape_rows);
    json_free(&acc->orphan_files); json_free(&acc->overlap_files);
    json_free(&coupling_rows);
    free(files); free(includes); codeindex_close(index);
}

static void context_map_derive(
    struct codeindex *index, const char *root, int total,
    struct zcl_command_reply *reply, bool have_generation,
    const uint8_t generation[64])
{
    struct ci_file *files = zcl_calloc(CONTEXT_FILE_PAGE_CAP, sizeof(*files),
                                       "code.context_map.files");
    char (*includes)[256] = zcl_calloc(CONTEXT_INCLUDE_PAGE_CAP,
                                       sizeof(*includes),
                                       "code.context_map.includes");
    if (!files || !includes) {
        free(files); free(includes); codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC_FAILED",
                               "derive", false, false,
                               "could not allocate the bounded context map",
                               root);
        return;
    }
    size_t context_count = 0;
    const char *const *contexts = codeindex_context_names(&context_count);
    if (context_count != 10) {
        free(files); free(includes); codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "CONTEXT_TAXONOMY_INVALID", "derive", false,
                               false, "the bounded-context taxonomy changed",
                               root);
        return;
    }
    struct context_map_acc acc = {0};
    sha3_256_init(&acc.digest);
    static const char map_domain[] = "zcl.code_context_map.v1";
    sha3_256_write(&acc.digest, (const unsigned char *)map_domain,
                   sizeof(map_domain));
    json_init(&acc.orphan_files); json_set_array(&acc.orphan_files);
    json_init(&acc.overlap_files); json_set_array(&acc.overlap_files);

    context_map_scan_pages(index, total, files, includes, contexts,
                           context_count, &acc);
    context_map_read_include_edges(index, total, &acc);

    const char *failure_code = NULL;
    const char *failure_message = NULL;
    context_map_select_failure(&acc, total, &failure_code, &failure_message);
    if (failure_code) {
        json_free(&acc.orphan_files); json_free(&acc.overlap_files);
        free(files); free(includes); codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, failure_code,
                               "derive", false, false, failure_message, root);
        return;
    }
    context_map_emit_reply(reply, root, total, have_generation, generation,
                           contexts, context_count, &acc, files, includes,
                           index);
}

void zcl_native_handle_code_context_map(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *root = request && request->context &&
                               request->context->source_root &&
                               request->context->source_root[0]
                           ? request->context->source_root : ".";
    struct codeindex *index = codeindex_open(root);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index", root);
        return;
    }

    int total = codeindex_file_count(index);
    if (total <= 0) {
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "EMPTY_CODE_MAP",
                               "derive", false, false,
                               "the code index contains no source files", root);
        return;
    }
    uint8_t generation[64];
    bool have_generation = context_map_generation(index, generation);
    if (have_generation && context_map_warm_hit(root, generation)) {
        json_copy(&reply->data, &g_map_warm.data);
        codeindex_close(index);
        return;
    }
    context_map_derive(index, root, total, reply, have_generation, generation);
}
