/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: List what changed under one path since a commit, newest first. */

#include "command/native_command.h"
#include "command/native_dev_fleet_internal.h"

#include "json/json.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CODE_RECENT_CAPTURE_INITIAL = 1024 * 1024,
    CODE_RECENT_CAPTURE_MAX = 256 * 1024 * 1024,
    CODE_RECENT_COMMIT_CAP = 32,
    CODE_RECENT_SINCE_MAX = 128,
};

static const char *recent_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

static const char *recent_str(const struct zcl_command_request *request,
                              const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

/* Capture `git log`, growing until the helper proves it did not truncate.
 * Rows are unit-separator delimited (%H%x1f%ad%x1f%s), one commit per line. */
static char *recent_git_log(const char *root, const char *range,
                            const char *path, size_t *capacity,
                            char *why, size_t why_size)
{
    const char *const args[] = {
        "log", "--no-color", "--format=%H%x1f%ad%x1f%s", "--date=short",
        range, "--", path, NULL,
    };
    size_t cap = CODE_RECENT_CAPTURE_INITIAL;
    while (cap <= CODE_RECENT_CAPTURE_MAX) {
        char *output = zcl_malloc(cap, "code_recent_git_log");
        if (!output) {
            (void)snprintf(why, why_size,
                           "could not allocate the bounded git log capture");
            return NULL;
        }
        bool truncated = false;
        int rc = zcl_dev_fleet_git_capture(root, args, output, cap,
                                           &truncated);
        if (rc == 0 && !truncated) {
            *capacity = cap;
            return output;
        }
        if (rc != 0) {
            /* The bounded capture seam discards the child's stderr, so the
             * exit status is all of what git said that survives. */
            (void)snprintf(why, why_size,
                           "git log %s -- %s exited %d (bad ref or not a git "
                           "work tree); stderr is not captured by the bounded "
                           "git seam", range, path, rc);
            free(output);
            return NULL;
        }
        free(output);
        if (cap > CODE_RECENT_CAPTURE_MAX / 2) break;
        cap *= 2;
    }
    (void)snprintf(why, why_size,
                   "git log output exceeds the 256 MiB observation bound");
    return NULL;
}

void zcl_native_handle_code_recent(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *path = recent_str(request, "path");
    if (!path) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code recent requires a repo-relative path", "");
        return;
    }
    const char *since = recent_str(request, "since");
    if (!since) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SINCE",
                               "normalize", false, false,
                               "code recent requires a `since` commit-ish", "");
        return;
    }
    if (strlen(since) > CODE_RECENT_SINCE_MAX) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "SINCE_TOO_LONG",
                               "normalize", false, false,
                               "since exceeds the 128-byte commit-ish bound",
                               since);
        return;
    }

    char range[CODE_RECENT_SINCE_MAX + 16];
    (void)snprintf(range, sizeof(range), "%s..HEAD", since);

    const char *root = recent_source_root(request);
    char why[256] = {0};
    size_t capacity = 0;
    char *log = recent_git_log(root, range, path, &capacity,
                               why, sizeof(why));
    if (!log) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "GIT_LOG_FAILED",
                               "measure", false, false, why, root);
        return;
    }

    struct json_value commits;
    json_init(&commits);
    json_set_array(&commits);

    size_t total = 0;
    char *cursor = log;
    char *end = log + strnlen(log, capacity);
    while (cursor < end) {
        char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        char *next = newline ? newline + 1 : end;
        if (newline) *newline = '\0';
        if (cursor[0]) {
            char *first = strchr(cursor, '\x1f');
            char *second = first ? strchr(first + 1, '\x1f') : NULL;
            total++;
            if (second && total <= (size_t)CODE_RECENT_COMMIT_CAP) {
                *first = '\0';
                *second = '\0';
                struct json_value row;
                json_init(&row);
                json_set_object(&row);
                (void)json_push_kv_str(&row, "commit", cursor);
                (void)json_push_kv_str(&row, "date", first + 1);
                (void)json_push_kv_str(&row, "summary", second + 1);
                (void)json_push_back(&commits, &row);
                json_free(&row);
            }
        }
        cursor = next;
    }
    free(log);

    size_t shown = total < CODE_RECENT_COMMIT_CAP
                       ? total : (size_t)CODE_RECENT_COMMIT_CAP;
    bool truncated = total > CODE_RECENT_COMMIT_CAP;

    char summary[224];
    (void)snprintf(summary, sizeof(summary),
                   "%zu commit%s since %s touching %s%s",
                   total, total == 1 ? "" : "s", since, path,
                   truncated ? " (showing newest 32)" : "");

    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_str(&reply->data, "since", since);
    (void)json_push_kv(&reply->data, "commits", &commits);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)shown);
    (void)json_push_kv_int(&reply->data, "total", (int64_t)total);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&commits);
}
