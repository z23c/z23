/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Read a kept app's immutable source; never open its working files. */
#include "command/native_command.h"
#include "command/native_app_launch.h"
#include "command/app_selection.h"
#include "command/native_app_customize_source.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "zbase64/zbase64.h"
#include "zutf8/zutf8.h"
#include <stdlib.h>
#include <string.h>

#define AC_MANIFEST_BYTES (8u * 1024u * 1024u)
#define AC_ENTRIES 16384u
#define AC_FILE_BYTES (1024u * 1024u)
#define AC_SLICE_DEFAULT 512u
#define AC_SLICE_MAX 2048u
#define AC_PAGE 4u
#define AC_PATH 256u
#define AC_CHANGE 256u
#define AC_REPLY 6144u
#define AC_QUERY 64u
#define AC_SNIPPET 96u

struct ac_read {
    struct zcl_command_reply *reply;
    struct app_launch_env env;
    struct app_selection selected;
    struct zcl_package_copy copy;
    struct vcs_manifest manifest;
    const char *name, *change, *path, *query;
    size_t offset, limit, page;
    uint64_t expected;
    bool pinned;
    struct json_value data;
};

static bool ac_fail(struct ac_read *a, const char *code, const char *message)
{
    zcl_package_copy_fail(a->reply, code, false, message, "app.customize");
    return false;
}

static bool ac_text(const struct json_value *in, const char *key, size_t cap,
                    const char **out, bool required)
{
    const struct json_value *v = json_get(in, key);
    *out = NULL;
    if (!v) return !required;
    if (v->type != JSON_STR) return false;
    *out = json_get_str(v);
    return *out && (!required || **out) && strlen(*out) <= cap && zutf8_validate(*out);
}

static bool ac_integer(const struct json_value *in, const char *key,
                       uint64_t maximum, uint64_t fallback, uint64_t *out)
{
    const struct json_value *v = json_get(in, key);
    *out = fallback;
    if (!v) return true;
    if (v->type != JSON_INT || v->val.i < 0 || (uint64_t)v->val.i > maximum) return false;
    *out = (uint64_t)v->val.i;
    return true;
}

static bool ac_inputs(struct ac_read *a, const struct json_value *in)
{
    static const char *const keys[] = {"name", "change", "expected_revision", "path", "offset", "limit", "page", "query"};
    if (!in || in->type != JSON_OBJ) return ac_fail(a, "BAD_INPUT", "an object is required");
    for (size_t i = 0; i < in->num_children; ++i) {
        bool known = false;
        for (size_t j = 0; j < sizeof(keys)/sizeof(keys[0]); ++j)
            if (!strcmp(in->keys[i], keys[j])) known = true;
        if (!known) return ac_fail(a, "BAD_INPUT", "unknown input member");
    }
    if (!ac_text(in, "name", APP_LAUNCH_ID_MAX, &a->name, true) ||
        !ac_text(in, "change", AC_CHANGE, &a->change, false) ||
        !ac_text(in, "path", AC_PATH, &a->path, false))
        return ac_fail(a, "BAD_INPUT", "name, change and path must be bounded UTF-8 strings");
    uint64_t offset, limit, page;
    a->pinned = json_get(in, "expected_revision") != NULL;
    if (!ac_integer(in, "expected_revision", INT64_MAX, 0, &a->expected) ||
        !ac_integer(in, "offset", AC_FILE_BYTES, 0, &offset) ||
        !ac_integer(in, "limit", AC_SLICE_MAX, AC_SLICE_DEFAULT, &limit) ||
        !ac_integer(in, "page", AC_ENTRIES, 0, &page) || !limit)
        return ac_fail(a, "BAD_INPUT", "invalid revision, offset, limit or manifest page");
    a->offset = (size_t)offset; a->limit = (size_t)limit; a->page = (size_t)page;
    return true;
}

static bool ac_search_shape(struct ac_read *a, const struct json_value *in)
{
    if (!a->query[0] || a->path || json_get(in, "limit"))
        return ac_fail(a, "BAD_INPUT", "query is nonempty and excludes path and limit");
    return a->pinned || ac_fail(a, "REVISION_REQUIRED", "search requires expected_revision from initial context");
}
static bool ac_shape(struct ac_read *a, const struct json_value *in)
{
    if (!ac_text(in, "query", AC_QUERY, &a->query, false))
        return ac_fail(a, "BAD_INPUT", "query must be nonempty UTF-8 of at most 64 bytes");
    if (a->query) return ac_search_shape(a, in);
    if (a->path && (!a->path[0] || a->page || json_get(in, "page")))
        return ac_fail(a, "BAD_INPUT", "file reads and manifest pages are separate requests");
    if (!a->path && (json_get(in, "offset") || json_get(in, "limit")))
        return ac_fail(a, "BAD_INPUT", "offset and limit require a file path");
    if ((a->path || a->page) && !a->pinned)
        return ac_fail(a, "REVISION_REQUIRED", "use expected_revision from the initial context for every file or later page");
    return true;
}

static bool ac_catalog_entry(struct ac_read *a, struct app_launch_entry *selected)
{
    if (app_selection_route_reserved(a->name)) {
        if (app_launch_kept_entry(a->name, selected)) return true;
        return ac_fail(a, "BAD_KEPT_ROUTE", "invalid kept route");
    }
    struct app_launch_registry registry;
    app_launch_registry_load(&a->env, &registry);
    if (registry.config_error[0]) return ac_fail(a, "CONFIG_REFUSED", "the app catalog is unsafe or malformed");
    const struct app_launch_entry *entry = app_launch_registry_find(&registry, a->name);
    if (!entry) return ac_fail(a, "UNKNOWN_APP", "no app has this name; inspect app.list first");
    *selected = *entry;
    return true;
}
static bool ac_select(struct ac_read *a)
{
    char why[256];
    if (!app_launch_env_from_process(&a->env, why, sizeof(why)))
        return ac_fail(a, "STATE_FAILED", "launcher state cannot be resolved");
    struct app_launch_entry entry;
    if (!ac_catalog_entry(a, &entry)) return false;
    enum app_selection_result result = app_selection_load(a->env.state_dir, entry.id, &a->selected);
    if (result == APP_SELECTION_ABSENT)
        return ac_fail(a, "SELECTION_REQUIRED", "Make My Copy and Keep a version before requesting its source; no version was selected");
    if (result != APP_SELECTION_OK || a->selected.revision > INT64_MAX)
        return ac_fail(a, "SELECTION_UNREADABLE", "kept selection is invalid or unavailable");
    if (a->pinned && a->expected != a->selected.revision)
        return ac_fail(a, "SELECTION_STALE", "the kept revision changed; request fresh context before reading or editing");
    return true;
}

static bool ac_source(struct ac_read *a)
{
    char version[65];
    zcl_hex_encode(a->selected.version, 32, version);
    if (!zcl_package_copy_open_selected_as(a->selected.copy, ZCL_PACKAGE_COPY_READ,
            &a->copy, a->reply, "app.customize", version)) return false;
    if (memcmp(a->copy.fork_version, a->selected.fork, 32) ||
        memcmp(a->copy.parent_release, a->selected.parent, 32) ||
        memcmp(a->copy.selected_version, a->selected.version, 32))
        return ac_fail(a, "SELECTION_MISMATCH", "the selected copy ancestry does not match Keep");
    enum zcl_package_copy_adoption auth = zcl_package_copy_adopted(a->selected.datadir, &a->copy, NULL);
    if (auth != ZCL_PACKAGE_COPY_ADOPTED && auth != ZCL_PACKAGE_COPY_RECEIVED_TRUSTED)
        return ac_fail(a, "NOT_ADOPTED", "the copy lacks current local adoption or trusted-receive authority");
    if (!vcs_tree_load_readonly_bounded(a->selected.copy, a->copy.selected_tree,
            AC_MANIFEST_BYTES, AC_ENTRIES, &a->manifest))
        return ac_fail(a, "SOURCE_UNREADABLE", "selected manifest is missing, corrupt or exceeds the context bounds");
    return true;
}

bool app_customize_source(const char *name, uint64_t revision,
    struct app_selection *selection, struct zcl_package_copy *copy,
    struct zcl_command_reply *reply)
{
    struct ac_read *a = zcl_calloc(1, sizeof(*a), "app-customize-source");
    if (!a) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate source context", "app.edit"); return false; }
    a->name = name; a->expected = revision; a->pinned = true; a->reply = reply;
    bool ok = ac_select(a) && ac_source(a);
    if (ok) {
        *selection = a->selected;
        *copy = a->copy;
        memset(&a->copy, 0, sizeof(a->copy));
    }
    vcs_manifest_free(&a->manifest);
    zcl_package_copy_close(&a->copy);
    free(a);
    return ok;
}

static bool ac_identity(struct ac_read *a)
{
    struct json_value *d = &a->data;
    return json_push_kv_str(d, "name", a->selected.app) &&
        json_push_kv_int(d, "selection_revision", (int64_t)a->selected.revision) &&
        zcl_package_copy_push_root(d, "version", a->selected.version) && zcl_package_copy_push_root(d, "head_version", a->copy.head_version) &&
        zcl_package_copy_push_root(d, "source_root", a->copy.selected_tree) &&
        zcl_package_copy_push_root(d, "fork", a->selected.fork) && zcl_package_copy_push_root(d, "parent_release", a->selected.parent) &&
        json_push_kv_str(d, "change", a->change ? a->change : "") &&
        json_push_kv_str(d, "authority", "read-only-selected-source") &&
        json_push_kv_str(d, "editing", "Working files may differ. Read pinned source here; editing, building, preview and Keep are separate owner actions.");
}

static bool ac_row(struct json_value *row, const struct vcs_entry *e)
{
    json_set_object(row);
    return e->size <= INT64_MAX && strlen(e->path) <= AC_PATH && zutf8_validate(e->path) &&
        json_push_kv_str(row, "path", e->path) && json_push_kv_int(row, "size", (int64_t)e->size) &&
        json_push_kv_int(row, "mode", e->mode) && zcl_package_copy_push_root(row, "blob", e->blob);
}

static bool ac_page(struct ac_read *a)
{
    if (a->page > a->manifest.count) return ac_fail(a, "BAD_INPUT", "manifest page exceeds the selected tree");
    struct json_value rows; json_init(&rows); json_set_array(&rows);
    size_t i = a->page;
    bool ok = true;
    while (ok && i < a->manifest.count && i - a->page < AC_PAGE) {
        struct json_value row; json_init(&row);
        ok = ac_row(&row, &a->manifest.entries[i]);
        if (ok && json_write(&rows, NULL, 0) + json_write(&row, NULL, 0) > 2048u) {
            json_free(&row); break;
        }
        ok = ok && json_push_back(&rows, &row);
        json_free(&row);
        if (ok) ++i;
    }
    ok = ok && json_push_kv(&a->data, "files", &rows) &&
        json_push_kv_int(&a->data, "file_count", (int64_t)a->manifest.count) &&
        json_push_kv_int(&a->data, "next_page", (int64_t)i) &&
        json_push_kv_bool(&a->data, "complete", i == a->manifest.count);
    json_free(&rows);
    if (!ok) return ac_fail(a, "CONTEXT_REFUSED", "manifest path is unrepresentable or context allocation failed");
    return true;
}

static bool ac_bytes(struct json_value *data, const uint8_t *part, size_t count)
{
    bool ok = true;
    char content[AC_SLICE_MAX * 2u + 1u];
    bool text = !memchr(part, 0, count) && zutf8_validate_n((const char *)part, count);
    if (text) { memcpy(content, part, count); content[count] = 0; }
    else ok = zbase64_encode(part, count, content, sizeof(content));
    return ok && json_push_kv_str(data, "encoding", text ? "utf8" : "base64") &&
        json_push_kv_str(data, "content", content) && json_push_kv_int(data, "bytes", (int64_t)count);
}
static bool ac_slice(struct ac_read *a, const uint8_t *bytes, size_t size)
{
    size_t count = size - a->offset;
    if (count > a->limit) count = a->limit;
    const uint8_t *part = size ? bytes + a->offset : (const uint8_t *)"";
    return ac_bytes(&a->data, part, count) &&
        json_push_kv_int(&a->data, "offset", (int64_t)a->offset) &&
        json_push_kv_int(&a->data, "next_offset", (int64_t)(a->offset + count)) &&
        json_push_kv_bool(&a->data, "complete", a->offset + count == size);
}

static bool ac_content(struct ac_read *a, const struct vcs_entry *e)
{
    if (e->size > AC_FILE_BYTES) return ac_fail(a, "FILE_TOO_LARGE", "selected file exceeds the 1 MiB verified-read bound");
    uint8_t *bytes = NULL; size_t size = 0;
    if (vcs_object_get_readonly_bounded(a->selected.copy, e->blob, VCS_TAG_BLOB,
            AC_FILE_BYTES, &bytes, &size) != 0)
        return ac_fail(a, "BLOB_UNREADABLE", "selected blob is missing or corrupt; no working-file fallback");
    bool ok = size == e->size && a->offset <= size;
    if (!ok) { free(bytes); return ac_fail(a, "BLOB_RANGE", "blob length or requested offset disagrees with the selected manifest"); }
    ok = ac_slice(a, bytes, size);
    free(bytes);
    return ok || ac_fail(a, "CONTEXT_REFUSED", "file context allocation failed");
}

static bool ac_file(struct ac_read *a)
{
    for (size_t i = 0; i < a->manifest.count; ++i) {
        const struct vcs_entry *e = &a->manifest.entries[i];
        if (strcmp(e->path, a->path)) continue;
        struct json_value row; json_init(&row);
        bool ok = ac_row(&row, e) && json_push_kv(&a->data, "file", &row);
        json_free(&row);
        return ok ? ac_content(a, e) : ac_fail(a, "CONTEXT_REFUSED", "file metadata allocation failed");
    }
    return ac_fail(a, "PATH_UNKNOWN", "path is not an exact member of the kept source manifest");
}

struct ac_search {
    struct json_value matches, skipped;
    size_t page, offset, scanned, bytes, found;
};
static bool ac_search_match(struct ac_search *s, const struct vcs_entry *e,
    const uint8_t *bytes, size_t size, size_t offset)
{
    size_t count = size - offset;
    if (count > AC_SNIPPET) count = AC_SNIPPET;
    struct json_value row; json_init(&row);
    bool ok = ac_row(&row, e) && json_push_kv_int(&row, "offset", (int64_t)offset) &&
        ac_bytes(&row, bytes + offset, count) && json_push_back(&s->matches, &row);
    json_free(&row);
    if (ok) ++s->found;
    return ok;
}
static bool ac_search_bytes(struct ac_read *a, struct ac_search *s,
    const struct vcs_entry *e, const uint8_t *bytes, size_t size)
{
    size_t n = strlen(a->query);
    while (s->offset <= size && size - s->offset >= n && s->found < 2) {
        if (memcmp(bytes + s->offset, a->query, n)) { ++s->offset; continue; }
        if (!ac_search_match(s, e, bytes, size, s->offset)) return false;
        s->offset += n; /* Literal non-overlapping matches, including across replies. */
    }
    if (size - s->offset < n) { ++s->page; s->offset = 0; }
    return true;
}
static bool ac_search_skip(struct ac_search *s, const struct vcs_entry *e)
{
    struct json_value row; json_init(&row); json_set_object(&row);
    bool ok = e->size <= INT64_MAX && json_push_kv_int(&row, "page", (int64_t)s->page) &&
        json_push_kv_int(&row, "size", (int64_t)e->size) &&
        json_push_kv_str(&row, "reason", "file_exceeds_1MiB") && json_push_back(&s->skipped, &row);
    json_free(&row); ++s->page; s->offset = 0;
    return ok;
}
static bool ac_search_file(struct ac_read *a, struct ac_search *s)
{
    const struct vcs_entry *e = &a->manifest.entries[s->page];
    if (s->offset > e->size) return ac_fail(a, "BLOB_RANGE", "search offset exceeds selected file");
    if (e->size > AC_FILE_BYTES) return ac_search_skip(s, e);
    uint8_t *bytes = NULL; size_t size = 0;
    if (vcs_object_get_readonly_bounded(a->selected.copy, e->blob, VCS_TAG_BLOB,
            AC_FILE_BYTES, &bytes, &size) != 0)
        return ac_fail(a, "BLOB_UNREADABLE", "search blob missing or corrupt; no working-file fallback");
    bool ok = size == e->size;
    if (!ok) ac_fail(a, "BLOB_RANGE", "search blob length disagrees with selected manifest");
    ++s->scanned; s->bytes += size;
    if (ok) ok = ac_search_bytes(a, s, e, bytes, size);
    free(bytes); return ok;
}
static bool ac_search_result(struct ac_read *a, const struct ac_search *s)
{
    size_t unsearched = 0;
    for (size_t i = 0; i < a->manifest.count; ++i)
        if (a->manifest.entries[i].size > AC_FILE_BYTES) ++unsearched;
    return json_push_kv_str(&a->data, "query", a->query) &&
        json_push_kv_int(&a->data, "page", (int64_t)a->page) &&
        json_push_kv_int(&a->data, "offset", (int64_t)a->offset) &&
        json_push_kv(&a->data, "matches", &s->matches) && json_push_kv(&a->data, "skipped", &s->skipped) &&
        json_push_kv_int(&a->data, "unsearched_files", (int64_t)unsearched) &&
        json_push_kv_str(&a->data, "coverage", "nonoverlapping-literal-from-request-cursor") &&
        json_push_kv_int(&a->data, "scanned_files", (int64_t)s->scanned) &&
        json_push_kv_int(&a->data, "scanned_bytes", (int64_t)s->bytes) &&
        json_push_kv_int(&a->data, "next_page", (int64_t)s->page) &&
        json_push_kv_int(&a->data, "next_offset", (int64_t)s->offset) &&
        json_push_kv_bool(&a->data, "complete", s->page == a->manifest.count);
}
static bool ac_search(struct ac_read *a)
{
    if (a->page > a->manifest.count || (a->page == a->manifest.count && a->offset))
        return ac_fail(a, "BAD_INPUT", "search cursor exceeds selected manifest");
    struct ac_search s = {.page = a->page, .offset = a->offset};
    json_init(&s.matches); json_set_array(&s.matches); json_init(&s.skipped); json_set_array(&s.skipped);
    bool ok = true;
    for (size_t visited = 0; ok && visited < AC_PAGE && s.page < a->manifest.count && s.found < 2; ++visited)
        ok = ac_search_file(a, &s);
    if (ok) ok = ac_search_result(a, &s);
    json_free(&s.matches); json_free(&s.skipped);
    if (!ok && a->reply->status == ZCL_COMMAND_STATUS_PASSED)
        ac_fail(a, "CONTEXT_REFUSED", "search context allocation or metadata encoding failed");
    return ok;
}
static bool ac_still_selected(struct ac_read *a)
{
    struct app_selection now;
    if (app_selection_load(a->env.state_dir, a->selected.app, &now) != APP_SELECTION_OK ||
        now.revision != a->selected.revision || memcmp(now.version, a->selected.version, 32) ||
        strcmp(now.copy, a->selected.copy))
        return ac_fail(a, "SELECTION_STALE", "selection changed while reading; discard context and request it again");
    return true;
}

static bool ac_next_cursor(struct ac_read *a, struct json_value *next)
{
    if (a->query) return json_push_kv_str(next, "query", a->query) &&
        json_push_kv_int(next, "page", json_get_int(json_get(&a->data, "next_page"))) &&
        json_push_kv_int(next, "offset", json_get_int(json_get(&a->data, "next_offset")));
    if (a->path) return json_push_kv_str(next, "path", a->path) &&
        json_push_kv_int(next, "offset", json_get_int(json_get(&a->data, "next_offset"))) &&
        json_push_kv_int(next, "limit", (int64_t)a->limit);
    return json_push_kv_int(next, "page", json_get_int(json_get(&a->data, "next_page")));
}
static bool ac_next(struct ac_read *a)
{
    if (json_get_bool(json_get(&a->data, "complete"))) return true;
    struct json_value next; json_init(&next); json_set_object(&next);
    bool ok = json_push_kv_str(&next, "name", a->selected.app) &&
        json_push_kv_int(&next, "expected_revision", (int64_t)a->selected.revision);
    ok = ok && ac_next_cursor(a, &next);
    char wire[2048];
    size_t size = ok ? json_write(&next, wire, sizeof(wire)) : 0;
    if (size == 0) ok = false;
    /* Navigation is optional. The response retains exact path/revision and
     * offset/page so an escaped path need not fit the native next envelope. */
    if (ok && size < sizeof(a->reply->next[0].input_json))
        ok = zcl_command_reply_add_next(a->reply, "app.customize", wire, "read the next pinned source page");
    json_free(&next);
    return ok;
}

static bool ac_first_file(struct ac_read *a)
{
    if (a->query || a->path || a->page >= a->manifest.count) return true;
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "name", a->selected.app) &&
        json_push_kv_int(&input, "expected_revision", (int64_t)a->selected.revision) &&
        json_push_kv_str(&input, "path", a->manifest.entries[a->page].path);
    char wire[2048];
    size_t n = ok ? json_write(&input, wire, sizeof(wire)) : 0;
    if (!n) ok = false;
    if (ok && n < sizeof(a->reply->next[0].input_json))
        ok = zcl_command_reply_add_next(a->reply,
            "app.customize", wire, "read this exact saved file; use other listed paths with the same expected_revision");
    json_free(&input); return ok;
}

static bool ac_read_context(struct ac_read *a, const struct json_value *input)
{
    bool ok = ac_inputs(a, input) && ac_shape(a, input) && ac_select(a) && ac_source(a);
    if (ok && !ac_identity(a)) ok = ac_fail(a, "CONTEXT_REFUSED", "context allocation failed");
    if (ok) ok = a->query ? ac_search(a) : (a->path ? ac_file(a) : ac_page(a));
    if (ok) ok = ac_still_selected(a);
    return ok;
}

static bool ac_finish_context(struct ac_read *a, const struct zcl_command_request *request, bool ok)
{
    size_t budget = AC_REPLY;
    if (request->success_data_budget_provided && request->success_data_budget < budget)
        budget = request->success_data_budget;
    if (ok && json_write(&a->data, NULL, 0) > budget)
        ok = ac_fail(a, "CONTEXT_REFUSED", "escaped context exceeds the reply bound; request a smaller file slice");
    if (ok && (!ac_next(a) || !ac_first_file(a))) ok = ac_fail(a, "CONTEXT_REFUSED", "cannot encode the next pinned read");
    return ok;
}

void zcl_native_handle_app_customize(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    struct ac_read *a = zcl_calloc(1, sizeof(*a), "app-customize");
    if (!a) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate source context", "app.customize"); return; }
    a->reply = reply; json_init(&a->data); json_set_object(&a->data);
    bool ok = ac_read_context(a, request->input);
    ok = ac_finish_context(a, request, ok);
    if (ok) { json_free(&reply->data); reply->data = a->data; json_init(&a->data); }
    else reply->next_count = 0;
    json_free(&a->data); vcs_manifest_free(&a->manifest); zcl_package_copy_close(&a->copy); free(a);
}
