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
    int counts[10] = {0};
    int64_t coupling[10][10] = {{0}};
    struct context_count shapes[CONTEXT_SHAPE_CAP] = {0};
    int shape_count = 0;
    int production = 0, classified = 0, orphans = 0, overlaps = 0;
    int64_t observed_edges = 0, cross_edges = 0;
    bool shape_overflow = false, coupling_query_failed = false;
    bool digest_failed = false, page_failed = false;
    int listed_total = 0;
    struct sha3_256_ctx digest;
    sha3_256_init(&digest);
    static const char map_domain[] = "zcl.code_context_map.v1";
    sha3_256_write(&digest, (const unsigned char *)map_domain,
                   sizeof(map_domain));

    struct json_value orphan_files, overlap_files;
    json_init(&orphan_files); json_set_array(&orphan_files);
    json_init(&overlap_files); json_set_array(&overlap_files);

    for (int offset = 0; offset < total && !shape_overflow &&
                         !coupling_query_failed && !digest_failed;) {
        int listed = codeindex_files_page(index, offset, files,
                                           CONTEXT_FILE_PAGE_CAP);
        if (listed <= 0) {
            page_failed = true;
            break;
        }
        listed_total += listed;
        for (int i = 0; i < listed; i++) {
            struct ci_context_assignment assignment;
            if (!codeindex_context_classify(files[i].path, &assignment) ||
                !assignment.production)
                continue;
            production++;
            if (!context_digest_row(&digest, files[i].path, &assignment)) {
                digest_failed = true;
                break;
            }
            int shape = shape_index(shapes, &shape_count, assignment.shape);
            if (shape < 0) {
                shape_overflow = true;
                break;
            }
            shapes[shape].count++;
            int from = context_index(assignment.context, contexts,
                                     context_count);
            if (assignment.orphan || from < 0) {
                orphans++;
                if (orphans <= CONTEXT_VIOLATION_CAP)
                    context_push_string(&orphan_files, files[i].path);
                continue;
            }
            classified++;
            counts[from]++;
            if (assignment.overlap) {
                overlaps++;
                if (overlaps <= CONTEXT_VIOLATION_CAP) {
                    struct json_value item, matches;
                    json_init(&item); json_set_object(&item);
                    json_init(&matches); json_set_array(&matches);
                    (void)json_push_kv_str(&item, "path", files[i].path);
                    (void)json_push_kv_str(&item, "assigned",
                                           assignment.context);
                    for (size_t m = 0; m < assignment.match_count; m++)
                        context_push_string(&matches, assignment.matches[m]);
                    (void)json_push_kv(&item, "matches", &matches);
                    json_free(&matches);
                    context_push_object(&overlap_files, &item);
                }
            }

            if (codeindex_path_is_translation_unit(files[i].path)) {
                int include_offset = 0;
                for (;;) {
                    int ni = codeindex_includes_of_file_page(
                        index, files[i].path, include_offset, includes,
                        CONTEXT_INCLUDE_PAGE_CAP);
                    if (ni < 0) {
                        coupling_query_failed = true;
                        break;
                    }
                    for (int j = 0; j < ni; j++) {
                        struct ci_context_assignment dependency;
                        if (!codeindex_context_classify(
                                includes[j], &dependency) ||
                            !dependency.production || dependency.orphan)
                            continue;
                        int to = context_index(dependency.context, contexts,
                                               context_count);
                        if (to < 0) continue;
                        observed_edges++;
                        if (from != to) {
                            coupling[from][to]++;
                            cross_edges++;
                        }
                    }
                    if (ni < CONTEXT_INCLUDE_PAGE_CAP) break;
                    if (include_offset > INT_MAX - ni) {
                        coupling_query_failed = true;
                        break;
                    }
                    include_offset += ni;
                }
                if (coupling_query_failed) break;
            }
        }
        offset += listed;
    }

    int64_t include_edge_count = -1;
    if (!shape_overflow && !coupling_query_failed && !digest_failed &&
        !page_failed && listed_total == total) {
        include_edge_count = codeindex_include_edge_count(index);
        if (include_edge_count < 0) coupling_query_failed = true;
    }

    const char *failure_code = NULL;
    const char *failure_message = NULL;
    if (shape_overflow) {
        failure_code = "SHAPE_TAXONOMY_OVERFLOW";
        failure_message = "the architectural shape taxonomy exceeded its bound";
    } else if (coupling_query_failed) {
        failure_code = "COUPLING_QUERY_FAILED";
        failure_message = "an indexed include query failed";
    } else if (digest_failed) {
        failure_code = "MAP_DIGEST_FAILED";
        failure_message = "a context assignment could not be digested";
    } else if (page_failed || listed_total != total) {
        failure_code = "MAP_INCOMPLETE";
        failure_message = "the paged code index file listing was incomplete";
    }
    if (failure_code) {
        json_free(&orphan_files); json_free(&overlap_files);
        free(files); free(includes); codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, failure_code,
                               "derive", false, false, failure_message, root);
        return;
    }

    uint8_t root_bytes[32];
    char root_hex[65];
    sha3_256_finalize(&digest, root_bytes);
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
        (void)json_push_kv_int(&row, "file_count", counts[i]);
        context_push_object(&context_rows, &row);
    }
    for (int i = 0; i < shape_count; i++) {
        struct json_value row;
        json_init(&row); json_set_object(&row);
        (void)json_push_kv_str(&row, "shape", shapes[i].name);
        (void)json_push_kv_int(&row, "file_count", shapes[i].count);
        context_push_object(&shape_rows, &row);
    }

    struct context_pair pairs[100];
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
    (void)json_push_kv_int(&reply->data, "production_files", production);
    (void)json_push_kv_int(&reply->data, "classified_files", classified);
    (void)json_push_kv_str(&reply->data, "map_sha3", root_hex);
    (void)json_push_kv_str(
        &reply->data, "map_digest_scope",
        "ordered production path + full context assignment v1");
    (void)json_push_kv(&reply->data, "contexts", &context_rows);
    (void)json_push_kv(&reply->data, "shapes", &shape_rows);
    (void)json_push_kv_bool(&reply->data, "shapes_complete", true);
    (void)json_push_kv_int(&reply->data, "orphan_count", orphans);
    (void)json_push_kv(&reply->data, "orphan_files", &orphan_files);
    (void)json_push_kv_bool(&reply->data, "orphan_files_truncated",
                            orphans > CONTEXT_VIOLATION_CAP);
    (void)json_push_kv_int(&reply->data, "overlap_count", overlaps);
    (void)json_push_kv(&reply->data, "overlap_files", &overlap_files);
    (void)json_push_kv_bool(&reply->data, "overlap_files_truncated",
                            overlaps > CONTEXT_VIOLATION_CAP);
    (void)json_push_kv_str(&reply->data, "coupling_scope",
                           "observed compiler-depfile include edges");
    (void)json_push_kv_int(&reply->data, "observed_include_edges",
                           observed_edges);
    (void)json_push_kv_int(&reply->data, "cross_context_include_edges",
                           cross_edges);
    (void)json_push_kv_bool(&reply->data, "coupling_available",
                            include_edge_count > 0);
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
                   "include edge(s)", classified, production, context_count,
                   orphans, overlaps, cross_edges);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&taxonomy); json_free(&context_rows); json_free(&shape_rows);
    json_free(&orphan_files); json_free(&overlap_files);
    json_free(&coupling_rows);
    free(files); free(includes); codeindex_close(index);
}
