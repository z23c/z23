/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: Resolve a module's exact committed tree without trusting the live overlay. */
#include "native_code_pages.h"
#include "command/native_command.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_pages.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "util/spawn.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_INPUT_MAX = 1024 * 1024, PAGE_COUNT_MAX = 256, PAGE_QUERY_MAX = 16 };

static bool page_oid(const char *s, size_t n)
{
    if (n != 40 && n != 64) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool page_component(const char *s, size_t n)
{
    return n && !(n == 1 && s[0] == '.') &&
           !(n == 2 && s[0] == '.' && s[1] == '.');
}

static bool page_path_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static bool page_directory(const char *s)
{
    if (!s || !s[0] || strlen(s) > 512 || s[0] == '/') return false;
    const char *component = s;
    for (const char *p = s;; p++) {
        char c = *p;
        if (c == '/' || c == '\0') {
            size_t n = (size_t)(p - component);
            if (!page_component(component, n)) return false;
            if (!c) return true;
            component = p + 1;
        } else if (!page_path_char(c)) {
            return false;
        }
    }
}

static bool page_tree_output(const char *out, size_t n, size_t oid_len,
                             const char *directory, char tree[65])
{
    size_t prefix = sizeof("040000 tree ") - 1, path_len = strlen(directory);
    if (n != prefix + oid_len + 1 + path_len + 1 ||
        memcmp(out, "040000 tree ", prefix) || !page_oid(out + prefix, oid_len) ||
        out[prefix + oid_len] != '\t' ||
        memcmp(out + prefix + oid_len + 1, directory, path_len) || out[n - 1] != '\0')
        return false;
    memcpy(tree, out + prefix, oid_len);
    tree[oid_len] = '\0';
    return true;
}

static bool page_capture(const char *const argv[], char *out, size_t cap, size_t *len)
{
    struct zcl_spawn_binary_observation observation = {0};
    struct zcl_result result = zcl_spawn_capture_binary(argv, out, cap, 10000, &observation);
    if (!result.ok) return false;
    *len = observation.output_len;
    return true;
}

bool zcl_code_pages_subject(const char *repo, const char *commit,
                            const char *directory, char tree[65])
{
    if (tree) tree[0] = '\0';
    if (!repo || !repo[0] || !commit || !tree || !page_directory(directory)) return false;
    size_t oid_len = strlen(commit);
    if (!page_oid(commit, oid_len)) return false;
    const char *type_argv[] = {"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
        "GIT_ALLOW_PROTOCOL=", "GIT_OPTIONAL_LOCKS=0", "git", "--no-replace-objects",
        "-c", "protocol.allow=never", "-C", repo, "cat-file", "-t", commit, NULL};
    char out[768];
    size_t n = 0;
    if (!page_capture(type_argv, out, sizeof(out), &n) || n != 7 || memcmp(out, "commit\n", 7))
        return false;
    const char *tree_argv[] = {"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
        "GIT_ALLOW_PROTOCOL=", "GIT_OPTIONAL_LOCKS=0", "git", "--no-replace-objects",
        "-c", "protocol.allow=never", "-C", repo, "ls-tree", "--full-tree", "-z",
        commit, "--", directory, NULL};
    return page_capture(tree_argv, out, sizeof(out), &n) &&
           page_tree_output(out, n, oid_len, directory, tree);
}

static void pages_refuse(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                           code, "execute", false, false, why, "code.pages");
}

static const char *pages_arg(const struct zcl_command_request *request, const char *key)
{
    return request && request->input ? json_get_str(json_get(request->input, key)) : NULL;
}

static uint8_t *pages_read_artifact(const char *path, size_t *length)
{
    if (!path || !path[0] || !length) return NULL;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    uint64_t size = 0;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_is_current_user_only(&file) &&
              platform_positioned_file_snapshot(&file, &before) &&
              platform_positioned_file_size(&file, &size) && size > 0 && size <= PAGE_INPUT_MAX;
    uint8_t *bytes = ok ? zcl_malloc((size_t)size, "code pages input") : NULL;
    if (ok) ok = bytes && platform_positioned_file_read(&file, bytes, (size_t)size, 0) == (int64_t)size &&
                 platform_positioned_file_snapshot(&file, &after) &&
                 platform_positioned_file_snapshot_equal(&before, &after) && !memchr(bytes, 0, (size_t)size);
    platform_positioned_file_close(&file);
    if (!ok) { free(bytes); return NULL; }
    *length = (size_t)size;
    return bytes;
}

static bool pages_parse_line(const uint8_t *line, size_t size, const char *commit, struct ci_page *out)
{
    if (!size || size >= sizeof(out->body) || !json_valid((const char *)line, size)) return false;
    struct json_value object;
    json_init(&object);
    bool ok = json_read(&object, (const char *)line, size) && object.type == JSON_OBJ;
    const char *directory = ok ? json_get_str(json_get(&object, "dir")) : NULL;
    const char *tree = ok ? json_get_str(json_get(&object, "tree")) : NULL;
    ok = directory && tree && page_directory(directory) && strlen(directory) < sizeof(out->directory) &&
         strlen(tree) < sizeof(out->tree_oid) && page_oid(tree, strlen(tree));
    if (ok) {
        memcpy(out->directory, directory, strlen(directory) + 1);
        memcpy(out->tree_oid, tree, strlen(tree) + 1);
        memcpy(out->source_commit, commit, strlen(commit) + 1);
        memcpy(out->body, line, size);
        out->body[size] = '\0';
    }
    json_free(&object);
    return ok;
}

static bool pages_parse(const uint8_t *bytes, size_t size, const char *commit,
                        struct ci_page *pages, size_t *count)
{
    *count = 0;
    if (!commit || !page_oid(commit, strlen(commit))) return false;
    for (size_t start = 0; start < size;) {
        const uint8_t *end = memchr(bytes + start, '\n', size - start);
        size_t n = end ? (size_t)(end - (bytes + start)) : size - start;
        if (*count == PAGE_COUNT_MAX || !pages_parse_line(bytes + start, n, commit, &pages[*count]))
            return false;
        (*count)++;
        start += n + (end != NULL);
    }
    return codeindex_pages_validate_hints(bytes, size, pages, *count);
}

static bool pages_select(const char *root, const char *commit, struct ci_page *pages,
                         size_t count, size_t *accepted)
{
    int64_t started = platform_time_monotonic_us();
    if (started <= 0) return false;
    *accepted = 0;
    for (size_t i = 0; i < count; i++) {
        int64_t now = platform_time_monotonic_us();
        char actual[65];
        if (now < started || now - started > 60000000 ||
            !zcl_code_pages_subject(root, commit, pages[i].directory, actual)) return false;
        if (!strcmp(actual, pages[i].tree_oid)) pages[(*accepted)++] = pages[i];
    }
    return true;
}

void zcl_native_handle_code_pages_import(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    (void)request;
    pages_refuse(reply, "CODE_PAGES_UNAVAILABLE", "import not implemented");
}
void zcl_native_handle_code_pages_get(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    (void)request;
    pages_refuse(reply, "CODE_PAGES_UNAVAILABLE", "query not implemented");
}
