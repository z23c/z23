/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Reconcile Git-tracked maintained source with one verified code-index generation. */

#include "command/native_command.h"
#include "command/native_dev_fleet_internal.h"

#include "codeindex/codeindex.h"
#include "json/json.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CODE_COVERAGE_CAPTURE_INITIAL = 1024 * 1024,
    CODE_COVERAGE_CAPTURE_MAX = 256 * 1024 * 1024,
    CODE_COVERAGE_MISSING_CAP = 16,
};

static const char *coverage_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

static bool coverage_has_suffix(const char *path, const char *suffix)
{
    size_t path_length = strlen(path);
    size_t suffix_length = strlen(suffix);
    return path_length >= suffix_length &&
           strcmp(path + path_length - suffix_length, suffix) == 0;
}

static bool coverage_is_source(const char *path)
{
    return coverage_has_suffix(path, ".c") ||
           coverage_has_suffix(path, ".h") ||
           coverage_has_suffix(path, ".def");
}

static bool coverage_is_maintained(const char *path)
{
    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        size_t length = strlen(roots[i]);
        if (strncmp(path, roots[i], length) == 0 && path[length] == '/')
            return true;
    }
    return false;
}

/* Capture the Git index, growing until the helper proves it did not truncate.
 * Newline-delimited output is intentional: tracked paths containing a newline
 * remain Git-quoted and therefore surface as an unindexed path instead of
 * silently changing the manifest boundary. */
static char *coverage_git_manifest(const char *root, size_t *capacity,
                                   char *why, size_t why_size)
{
    const char *const args[] = {"ls-files", NULL};
    size_t cap = CODE_COVERAGE_CAPTURE_INITIAL;
    while (cap <= CODE_COVERAGE_CAPTURE_MAX) {
        char *output = zcl_malloc(cap, "code_coverage_git_manifest");
        if (!output) {
            (void)snprintf(why, why_size,
                           "could not allocate the bounded Git manifest");
            return NULL;
        }
        bool truncated = false;
        int rc = zcl_dev_fleet_git_capture(root, args, output, cap,
                                           &truncated);
        if (rc == 0 && !truncated) {
            *capacity = cap;
            return output;
        }
        free(output);
        if (rc != 0) {
            (void)snprintf(why, why_size,
                           "git ls-files failed while reading tracked source");
            return NULL;
        }
        if (cap > CODE_COVERAGE_CAPTURE_MAX / 2) break;
        cap *= 2;
    }
    (void)snprintf(why, why_size,
                   "tracked manifest exceeds the 256 MiB observation bound");
    return NULL;
}

static void coverage_push_missing(struct json_value *missing,
                                  const char *path)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, path);
    (void)json_push_back(missing, &item);
    json_free(&item);
}

void zcl_native_handle_code_coverage(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *root = coverage_source_root(request);
    struct codeindex *index = codeindex_open_source_view(root);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "measure", true, false,
                               "could not open or rebuild the source index",
                               root);
        return;
    }

    char why[160] = {0};
    size_t manifest_capacity = 0;
    char *manifest = coverage_git_manifest(root, &manifest_capacity,
                                           why, sizeof(why));
    if (!manifest) {
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "GIT_MANIFEST_UNAVAILABLE", "measure",
                               true, false, why, root);
        return;
    }

    int indexed_total = codeindex_file_count(index);
    if (indexed_total < 0) {
        free(manifest);
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_COUNT",
                               "measure", false, false,
                               "could not count indexed source nodes", "");
        return;
    }

    int tracked_total = 0;
    int indexed_tracked = 0;
    int missing_total = 0;
    struct json_value missing;
    json_init(&missing);
    json_set_array(&missing);

    char *cursor = manifest;
    char *end = manifest + strnlen(manifest, manifest_capacity);
    while (cursor < end) {
        char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        char *next = newline ? newline + 1 : end;
        if (newline) *newline = '\0';
        if (cursor[0] && coverage_is_maintained(cursor) &&
            coverage_is_source(cursor)) {
            tracked_total++;
            struct ci_file row;
            bool found = false;
            if (!codeindex_file(index, cursor, &row, &found)) {
                (void)snprintf(why, sizeof(why), "%s", cursor);
                json_free(&missing);
                free(manifest);
                codeindex_close(index);
                zcl_command_reply_fail(
                    reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_INTERNAL, "INDEX_LOOKUP", "measure",
                    false, false, "could not reconcile an indexed path",
                    why);
                return;
            }
            if (found) {
                indexed_tracked++;
            } else {
                if (missing_total < CODE_COVERAGE_MISSING_CAP)
                    coverage_push_missing(&missing, cursor);
                missing_total++;
            }
        }
        cursor = next;
    }

    const char *verdict = missing_total == 0 ? "GREEN" : "RED";
    int percent = tracked_total == 0
        ? 100 : (int)(((long long)indexed_tracked * 100LL) / tracked_total);
    char ratio[64];
    (void)snprintf(ratio, sizeof(ratio), "%d/%d (%d%%)",
                   indexed_tracked, tracked_total, percent);
    char summary[224];
    (void)snprintf(summary, sizeof(summary),
                   "%s indexed/tracked=%s; missing=%d%s",
                   verdict, ratio, missing_total,
                   missing_total > CODE_COVERAGE_MISSING_CAP
                       ? " (missing_paths truncated)" : "");

    (void)json_push_kv_str(&reply->data, "verdict", verdict);
    (void)json_push_kv_str(&reply->data, "scope",
                           "Git-tracked maintained .c/.h/.def");
    (void)json_push_kv_int(&reply->data, "indexed_files", indexed_total);
    (void)json_push_kv_int(&reply->data, "tracked_files", tracked_total);
    (void)json_push_kv_int(&reply->data, "indexed_tracked_files",
                           indexed_tracked);
    (void)json_push_kv_int(&reply->data, "missing_files", missing_total);
    (void)json_push_kv_int(&reply->data, "coverage_percent", percent);
    (void)json_push_kv_str(&reply->data, "indexed_over_tracked", ratio);
    (void)json_push_kv(&reply->data, "missing_paths", &missing);
    (void)json_push_kv_bool(&reply->data, "missing_paths_truncated",
                            missing_total > CODE_COVERAGE_MISSING_CAP);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&missing);
    free(manifest);
    codeindex_close(index);
}
