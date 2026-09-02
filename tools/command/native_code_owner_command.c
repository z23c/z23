/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Name the physical authority room that owns one source path. */

#include "command/native_command.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_context.h"
#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* `exists` means tracked-or-on-disk: the path appears in the current verified
 * code-index generation OR a lstat() of <root>/<path> succeeds. The index is
 * the authority for indexed source; the lstat covers paths outside the
 * maintained source roots (docs prose, fixtures, generated files). */
static const char *owner_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

static const char *owner_str(const struct zcl_command_request *request,
                             const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

static bool owner_on_disk(const char *root, const char *path)
{
    char full[4096];
    int n = snprintf(full, sizeof(full), "%s/%s", root, path);
    if (n <= 0 || (size_t)n >= sizeof(full))
        return false;
    struct stat st;
    return lstat(full, &st) == 0;
}

/* The first path component is the physical authority room (core/, engine/,
 * contexts/<feature>/, cognition/, platform/, tools/, tests/, docs/, ...). */
static void owner_authority(const char *path, char *out, size_t out_size)
{
    const char *slash = strchr(path, '/');
    size_t length = slash ? (size_t)(slash - path) : strlen(path);
    if (length == 0 || length >= out_size) {
        (void)snprintf(out, out_size, "%s", "");
        return;
    }
    (void)snprintf(out, out_size, "%.*s", (int)length, path);
}

/* The nearest owning module directory: the path prefix through the component
 * after the LAST "modules/" segment (e.g. "contexts/wallet/modules/wallet").
 * "" when the path sits under no modules/ directory. */
static void owner_module(const char *path, char *out, size_t out_size)
{
    out[0] = '\0';
    const char *last = NULL;
    for (const char *p = strstr(path, "/modules/"); p;
         p = strstr(p + 1, "/modules/"))
        last = p;
    const char *name = last ? last + strlen("/modules/")
        : (strncmp(path, "modules/", strlen("modules/")) == 0
               ? path + strlen("modules/") : NULL);
    if (!name) return;
    const char *slash = strchr(name, '/');
    if (!slash || slash == name) return;
    size_t length = (size_t)(slash - path);
    if (length >= out_size) return;
    (void)snprintf(out, out_size, "%.*s", (int)length, path);
}

void zcl_native_handle_code_owner(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *path = owner_str(request, "path");
    if (!path) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code owner requires a repo-relative path", "");
        return;
    }

    const char *root = owner_source_root(request);
    struct codeindex *index = codeindex_open_source_view(root);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "measure", true, false,
                               "could not open or rebuild the source index",
                               root);
        return;
    }

    struct ci_file row;
    bool found = false;
    if (!codeindex_file(index, path, &row, &found)) {
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_LOOKUP",
                               "measure", false, false,
                               "could not reconcile an indexed path", path);
        return;
    }

    /* Group purpose joins the public group hierarchy, matching code.map. */
    char group_purpose[160] = {0};
    if (found) {
        static struct ci_group groups[512];
        int group_count = codeindex_groups(index, groups, 512);
        for (int i = 0; i < group_count; i++) {
            if (strcmp(groups[i].path, row.group) == 0) {
                (void)snprintf(group_purpose, sizeof(group_purpose), "%s",
                               groups[i].purpose);
                break;
            }
        }
    }
    codeindex_close(index);

    bool exists = found || owner_on_disk(root, path);
    bool sealed = strncmp(path, "core/", 5) == 0;

    struct ci_context_assignment assignment;
    (void)codeindex_context_classify(path, &assignment);

    char authority[64];
    owner_authority(path, authority, sizeof(authority));
    char module[256];
    owner_module(path, module, sizeof(module));

    const char *verdict = found ? "OWNED" : "UNOWNED";
    char summary[320];
    if (found) {
        (void)snprintf(summary, sizeof(summary),
                       "%s (shape: %s); group %s%s%s; sealed=%s",
                       assignment.context[0] ? assignment.context : authority,
                       assignment.shape, row.group,
                       group_purpose[0] ? " — " : "", group_purpose,
                       sealed ? "yes (consensus-sealed; edits need the unseal ritual)"
                              : "no");
    } else {
        (void)snprintf(summary, sizeof(summary),
                       "UNOWNED: not in the code index%s; authority by path is "
                       "%s/; sealed=%s",
                       exists ? " but present on disk" : " and not on disk",
                       authority, sealed ? "yes" : "no");
    }

    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_bool(&reply->data, "exists", exists);
    (void)json_push_kv_str(&reply->data, "verdict", verdict);
    (void)json_push_kv_str(&reply->data, "authority", authority);
    (void)json_push_kv_bool(&reply->data, "sealed", sealed);
    (void)json_push_kv_str(&reply->data, "context", assignment.context);
    (void)json_push_kv_str(&reply->data, "shape", assignment.shape);
    (void)json_push_kv_str(&reply->data, "basis", assignment.basis);
    (void)json_push_kv_str(&reply->data, "group", found ? row.group : "");
    (void)json_push_kv_str(&reply->data, "group_purpose", group_purpose);
    (void)json_push_kv_str(&reply->data, "module", module);
    (void)json_push_kv_str(&reply->data, "summary", summary);
}
