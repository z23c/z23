/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Read a kept app's immutable source; never open its working files. */
#include "command/native_command.h"
#include "command/native_app_launch.h"
#include "command/native_app_compose.h"
#include "command/app_selection.h"
#include "command/native_app_customize_source.h"
#include "command/native_app_customize_tasks.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "models/package_resident.h"
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
    const char *name, *change, *path, *query, *source_version;
    char resident_root[65];
    size_t offset, limit, page;
    uint64_t expected;
    bool pinned, resident;
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
    static const char *const keys[] = {"name", "change", "expected_revision", "path", "offset", "limit", "page", "query", "source_version"};
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
    if (!a->query[0] || (a->path && (!a->path[0] || json_get(in, "page"))) || json_get(in, "limit"))
        return ac_fail(a, "BAD_INPUT", "query is nonempty; path search excludes page and all search excludes limit");
    return a->pinned || ac_fail(a, "REVISION_REQUIRED", "search requires expected_revision from initial context");
}
static bool ac_source_input(struct ac_read *a, const struct json_value *in)
{
    uint8_t root[32];
    if (!ac_text(in, "source_version", 64, &a->source_version, false) ||
        (a->source_version && (strlen(a->source_version) != 64 ||
         !zcl_hex_decode_lower(a->source_version, root, 32))))
        return ac_fail(a, "BAD_INPUT", "source_version must be an exact lowercase root");
    if (a->source_version && !a->pinned)
        return ac_fail(a, "REVISION_REQUIRED", "source_version requires expected_revision");
    return true;
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
/* No version is kept yet: name the two commands that make one. */
/* Existing resident acceptance is the only source of the kept identity. */
static bool ac_tasks_source_next(struct zcl_command_reply *reply, const char *directory,
                                 const struct package_resident_record *kept)
{
    struct json_value args; json_init(&args); json_set_object(&args);
    bool ok = json_push_kv_str(&args, "root", kept->current.package_root) &&
        json_push_kv_str(&args, "datadir", directory);
    char wire[sizeof(reply->next[0].input_json)];
    size_t n = ok ? json_write(&args, wire, sizeof(wire)) : 0;
    bool added = false;
    if (n && n < 384 && n < sizeof(wire) && !strchr(wire, '\''))
        added = zcl_command_reply_add_next(reply, "zcode.package.show", wire,
            "Inspect metadata for the kept package when its release is available locally.");
    json_free(&args);
    return added;
}

static bool ac_tasks_identity_facts(struct json_value *facts,
                                    const struct package_resident_record *kept)
{
    return json_push_kv_str(facts, "kept_root", kept->current.package_root) &&
        json_push_kv_str(facts, "kept_receipt", kept->current.receipt_id) &&
        json_push_kv_int(facts, "kept_generation", kept->generation) &&
        json_push_kv_str(facts, "kept_program", kept->current.program);
}

static void ac_tasks_recovery(struct zcl_command_reply *reply)
{
    const char *directory = zcl_native_command_datadir();
    if (!directory || !directory[0]) return;
    struct package_resident_record kept = {0};
    bool have_kept = ac_tasks_kept_read(directory, &kept);
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    bool facts_ok = json_push_kv_str(&facts, "kind", "tasks-source-profile") &&
        json_push_kv_str(&facts, "data_directory", directory);
    if (have_kept) facts_ok = facts_ok && ac_tasks_identity_facts(&facts, &kept);
    if (facts_ok) (void)json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
    if (have_kept && ac_tasks_source_next(reply, directory, &kept))
        (void)snprintf(reply->error.message, sizeof(reply->error.message),
            "A kept Tasks program exists. Inspect its package metadata using the first next action, then call app.customize with path, expected_revision=kept_generation and source_version=kept_root.");
    struct json_value next_args; json_init(&next_args); json_set_object(&next_args);
    bool ok = json_push_kv_str(&next_args, "action", "offer-status") &&
        json_push_kv_str(&next_args, "datadir", directory);
    char wire[sizeof(reply->next[0].input_json)];
    size_t n = ok ? json_write(&next_args, wire, sizeof(wire)) : 0;
    if (n && n < 384 && n < sizeof(wire) && !strchr(wire, '\''))
        (void)zcl_command_reply_add_next(reply, "app.tasks", wire,
            "Inspect the exact kept Tasks program in this profile.");
    json_free(&next_args);
}

static bool ac_selection_required(struct ac_read *a)
{
    if (strcmp(a->name, "tasks") == 0) {
        (void)ac_fail(a, "SELECTION_REQUIRED", "No app copy is selected. For the program kept in Tasks, read app.tasks offer-status using the same data directory.");
        return false;
    }
    return ac_fail(a, "SELECTION_REQUIRED", "No version is selected. Plan a copy of this app in the same data directory, then save the new copy.");
}

/* Offer only a complete, inert copy plan bound to the selected profile. */
static void ac_copy_recovery(struct ac_read *a)
{
    const char *directory = zcl_native_command_datadir();
    if (!directory || !directory[0]) return;
    struct json_value args; json_init(&args); json_set_object(&args);
    bool ok = json_push_kv_str(&args, "app", a->name) &&
              json_push_kv_str(&args, "datadir", directory);
    char wire[sizeof(a->reply->next[0].input_json)];
    size_t n = ok ? json_write(&args, wire, sizeof(wire)) : 0;
    if (n && n < 384 && n < sizeof(wire) && !strchr(wire, '\''))
        (void)zcl_command_reply_add_next(a->reply, "app.copy", wire,
            "Review a copy plan in the same data directory.");
    json_free(&args);
}

static bool ac_select(struct ac_read *a)
{
    char why[256];
    if (!app_launch_env_from_process(&a->env, why, sizeof(why)))
        return ac_fail(a, "STATE_FAILED", "launcher state cannot be resolved");
    struct app_launch_entry entry;
    if (!ac_catalog_entry(a, &entry)) return false;
    enum app_selection_result result = app_selection_load(a->env.state_dir, entry.id, &a->selected);
    if (result == APP_SELECTION_ABSENT && !strcmp(a->name, "tasks") && !a->query &&
        ((a->source_version && a->pinned) || (!a->path && !a->pinned))) {
        a->resident = true;
        (void)snprintf(a->selected.app, sizeof(a->selected.app), "%s", entry.id);
        return true;
    }
    if (result == APP_SELECTION_ABSENT) return ac_selection_required(a);
    if (result != APP_SELECTION_OK || a->selected.revision > INT64_MAX)
        return ac_fail(a, "SELECTION_UNREADABLE", "kept selection is invalid or unavailable");
    if (a->pinned && a->expected != a->selected.revision)
        return ac_fail(a, "SELECTION_STALE", "the kept revision changed; request fresh context before reading or editing");
    return true;
}

/* Reuse the copy authority's full-chain and exact-member validation. Keep
 * membership was checked first; do not combine observations of changed heads. */
static bool ac_source_choice(struct ac_read *a)
{
    if (!a->source_version) return true;
    uint8_t requested[32];
    if (strlen(a->source_version) != 64 || !zcl_hex_decode_lower(a->source_version, requested, 32))
        return ac_fail(a, "BAD_INPUT", "source_version must be an exact lowercase root");
    if (!memcmp(requested, a->copy.selected_version, 32)) return true;
    struct zcl_package_copy source = {0};
    if (!zcl_package_copy_open_selected_as(a->selected.copy, ZCL_PACKAGE_COPY_READ,
            &source, a->reply, "app.customize", a->source_version)) return false;
    bool same = !memcmp(source.fork_version, a->copy.fork_version, 32) &&
        !memcmp(source.parent_release, a->copy.parent_release, 32) &&
        !memcmp(source.head_version, a->copy.head_version, 32);
    if (!same) {
        zcl_package_copy_close(&source);
        return ac_fail(a, "SELECTION_MISMATCH", "copy history changed while choosing source");
    }
    zcl_package_copy_close(&a->copy);
    a->copy = source;
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
    if (!ac_source_choice(a)) return false;
    enum zcl_package_copy_adoption auth = zcl_package_copy_adopted(a->selected.datadir, &a->copy, NULL);
    if (auth != ZCL_PACKAGE_COPY_ADOPTED && auth != ZCL_PACKAGE_COPY_RECEIVED_TRUSTED)
        return ac_fail(a, "NOT_ADOPTED", "the copy lacks current local adoption or trusted-receive authority");
    if (!vcs_tree_load_readonly_bounded(a->selected.copy, a->copy.selected_tree,
            AC_MANIFEST_BYTES, AC_ENTRIES, &a->manifest))
        return ac_fail(a, "SOURCE_UNREADABLE", "selected manifest is missing, corrupt or exceeds the context bounds");
    return true;
}

bool app_customize_source(const char *name, uint64_t revision,
    const char *source_version,
    struct app_selection *selection, struct zcl_package_copy *copy,
    struct zcl_command_reply *reply)
{
    struct ac_read *a = zcl_calloc(1, sizeof(*a), "app-customize-source");
    if (!a) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate source context", "app.edit"); return false; }
    a->name = name; a->expected = revision; a->pinned = true; a->reply = reply;
    a->source_version = source_version;
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
        zcl_package_copy_push_root(d, "source_version", a->copy.selected_version) &&
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

static size_t ac_path_index(const struct ac_read *a)
{
    size_t i = 0;
    while (i < a->manifest.count && strcmp(a->manifest.entries[i].path, a->path)) ++i;
    return i;
}

static bool ac_file(struct ac_read *a)
{
    size_t i = ac_path_index(a);
    if (i == a->manifest.count)
        return ac_fail(a, "PATH_UNKNOWN", "path is not an exact member of the kept source manifest");
    const struct vcs_entry *e = &a->manifest.entries[i];
    struct json_value row; json_init(&row);
    bool ok = ac_row(&row, e) && json_push_kv(&a->data, "file", &row);
    json_free(&row);
    return ok ? ac_content(a, e) : ac_fail(a, "CONTEXT_REFUSED", "file metadata allocation failed");
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
static bool ac_search_skip(struct ac_read *a, struct ac_search *s, const struct vcs_entry *e)
{
    struct json_value row; json_init(&row); json_set_object(&row);
    bool ok = e->size <= INT64_MAX && json_push_kv_int(&row, "page", (int64_t)(a->path ? 0 : s->page)) &&
        json_push_kv_int(&row, "size", (int64_t)e->size) &&
        json_push_kv_str(&row, "reason", "file_exceeds_1MiB") &&
        (!a->path || json_push_kv_str(&row, "path", e->path)) && json_push_back(&s->skipped, &row);
    json_free(&row); ++s->page; s->offset = 0;
    return ok;
}
static bool ac_search_file(struct ac_read *a, struct ac_search *s)
{
    const struct vcs_entry *e = &a->manifest.entries[s->page];
    if (s->offset > e->size) return ac_fail(a, "BLOB_RANGE", "search offset exceeds selected file");
    if (e->size > AC_FILE_BYTES) return ac_search_skip(a, s, e);
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
static bool ac_search_coverage(struct ac_read *a, const struct ac_search *s, size_t unsearched, size_t end)
{
    return json_push_kv_int(&a->data, "unsearched_files", (int64_t)unsearched) &&
        json_push_kv_str(&a->data, "coverage", "nonoverlapping-literal-from-request-cursor") &&
        json_push_kv_int(&a->data, "scanned_files", (int64_t)s->scanned) &&
        json_push_kv_int(&a->data, "scanned_bytes", (int64_t)s->bytes) &&
        json_push_kv_int(&a->data, "next_page", (int64_t)(a->path ? 0 : s->page)) &&
        json_push_kv_int(&a->data, "next_offset", (int64_t)s->offset) &&
        json_push_kv_bool(&a->data, "complete", s->page == end);
}
static bool ac_search_result(struct ac_read *a, const struct ac_search *s, size_t begin, size_t end)
{
    size_t unsearched = 0;
    for (size_t i = begin; i < end; ++i)
        if (a->manifest.entries[i].size > AC_FILE_BYTES) ++unsearched;
    return json_push_kv_str(&a->data, "query", a->query) &&
        (!a->path || json_push_kv_str(&a->data, "path", a->path)) &&
        json_push_kv_int(&a->data, "page", (int64_t)a->page) &&
        json_push_kv_int(&a->data, "offset", (int64_t)a->offset) &&
        json_push_kv(&a->data, "matches", &s->matches) && json_push_kv(&a->data, "skipped", &s->skipped) &&
        ac_search_coverage(a, s, unsearched, end);
}
static bool ac_search(struct ac_read *a)
{
    if (a->page > a->manifest.count || (a->page == a->manifest.count && a->offset))
        return ac_fail(a, "BAD_INPUT", "search cursor exceeds selected manifest");
    size_t begin = 0, end = a->manifest.count;
    if (a->path) {
        begin = ac_path_index(a);
        if (begin == end) return ac_fail(a, "PATH_UNKNOWN", "path is not an exact member of the kept source manifest");
        end = begin + 1;
    }
    struct ac_search s = {.page = a->path ? begin : a->page, .offset = a->offset};
    json_init(&s.matches); json_set_array(&s.matches); json_init(&s.skipped); json_set_array(&s.skipped);
    bool ok = true;
    for (size_t visited = 0; ok && visited < AC_PAGE && s.page < end && s.found < 2; ++visited)
        ok = ac_search_file(a, &s);
    if (ok) ok = ac_search_result(a, &s, begin, end);
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
        (a->path ? json_push_kv_str(next, "path", a->path) :
         json_push_kv_int(next, "page", json_get_int(json_get(&a->data, "next_page")))) &&
        json_push_kv_int(next, "offset", json_get_int(json_get(&a->data, "next_offset")));
    if (a->path) return json_push_kv_str(next, "path", a->path) &&
        json_push_kv_int(next, "offset", json_get_int(json_get(&a->data, "next_offset"))) &&
        json_push_kv_int(next, "limit", (int64_t)a->limit);
    return json_push_kv_int(next, "page", json_get_int(json_get(&a->data, "next_page")));
}
static bool ac_next_identity(struct ac_read *a, struct json_value *next)
{
    return json_push_kv_str(next, "name", a->selected.app) &&
        json_push_kv_int(next, "expected_revision", (int64_t)a->selected.revision) &&
        (!a->source_version || zcl_package_copy_push_root(next, "source_version", a->copy.selected_version));
}
static bool ac_next(struct ac_read *a)
{
    if (json_get_bool(json_get(&a->data, "complete"))) return true;
    struct json_value next; json_init(&next); json_set_object(&next);
    bool ok = ac_next_identity(a, &next);
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

static bool ac_first_try(struct ac_read *a, const char *path, bool *added)
{
    *added = false;
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = ac_next_identity(a, &input) && json_push_kv_str(&input, "path", path);
    char wire[2048]; size_t n = ok ? json_write(&input, wire, sizeof(wire)) : 0;
    if (!n) ok = false;
    if (ok && n < sizeof(a->reply->next[0].input_json)) {
        ok = zcl_command_reply_add_next(a->reply, "app.customize", wire,
            "read this exact saved file; use other listed paths with the same expected_revision");
        *added = ok;
    }
    json_free(&input); return ok;
}
static bool ac_first_resident(struct ac_read *a)
{
    const struct json_value *rows = json_get(&a->data, "files");
    for (size_t i = 0; i < json_size(rows); ++i) {
        const struct json_value *row = json_at(rows, i), *size = json_get(row, "size");
        const char *path = json_get_str(json_get(row, "path"));
        if (!path || strlen(path) > AC_PATH || !size || size->type != JSON_INT ||
            size->val.i < 0 || (uint64_t)size->val.i > AC_FILE_BYTES) continue;
        bool added = false;
        if (!ac_first_try(a, path, &added)) return false;
        if (added) break;
    }
    return true;
}
static bool ac_first_file(struct ac_read *a)
{
    if (a->query || a->path) return true;
    if (a->resident) return ac_first_resident(a);
    if (a->page >= a->manifest.count) return true;
    bool added = false;
    return ac_first_try(a, a->manifest.entries[a->page].path, &added);
}

static bool ac_tasks_file_row(struct ac_read *a, const struct ac_tasks_file *file)
{
    struct json_value row; json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "path", a->path) &&
        json_push_kv_int(&row, "size", (int64_t)file->size) &&
        json_push_kv_int(&row, "mode", file->mode) && json_push_kv(&a->data, "file", &row);
    json_free(&row); return ok;
}

static bool ac_tasks_page_row(struct json_value *row, const struct vcs_package_file *file)
{
    json_set_object(row);
    return file->size <= INT64_MAX && json_push_kv_str(row, "path", file->path) &&
        json_push_kv_int(row, "size", (int64_t)file->size) && json_push_kv_int(row, "mode", file->mode);
}

static bool ac_tasks_page_rows(struct ac_read *a, const struct vcs_package_manifest *m)
{
    if (a->page > m->count) return false;
    struct json_value rows; json_init(&rows); json_set_array(&rows);
    size_t i = a->page; bool ok = true;
    while (ok && i < m->count && i - a->page < AC_PAGE) {
        const struct vcs_package_file *f = &m->files[i];
        struct json_value row; json_init(&row);
        ok = ac_tasks_page_row(&row, f);
        if (ok && json_write(&rows, NULL, 0) + json_write(&row, NULL, 0) > 2048u) {
            json_free(&row); break;
        }
        ok = ok && json_push_back(&rows, &row); json_free(&row);
        if (ok) ++i;
    }
    ok = ok && json_push_kv(&a->data, "files", &rows) &&
        json_push_kv_int(&a->data, "file_count", (int64_t)m->count) &&
        json_push_kv_int(&a->data, "next_page", (int64_t)i) &&
        json_push_kv_bool(&a->data, "complete", i == m->count);
    json_free(&rows); return ok;
}

static bool ac_tasks_page_still(struct ac_read *a, const char *directory,
                                const struct package_resident_record *kept)
{
    struct package_resident_record now = {0}; struct app_selection selected;
    return ac_tasks_kept_read(directory, &now) && now.generation == kept->generation &&
        package_resident_identity_equal(&now.current, &kept->current) &&
        app_selection_load(a->env.state_dir, a->selected.app, &selected) == APP_SELECTION_ABSENT;
}

static bool ac_tasks_page(struct ac_read *a)
{
    const char *directory = zcl_native_command_datadir();
    struct package_resident_record kept = {0}; struct vcs_package_manifest manifest;
    if (!directory || !ac_tasks_manifest_read(directory, a->source_version, a->expected, &kept, &manifest))
        return a->pinned ? ac_fail(a, "SOURCE_UNREADABLE", "kept package identity or manifest is unavailable") : ac_selection_required(a);
    struct app_selection now;
    bool ok = app_selection_load(a->env.state_dir, a->selected.app, &now) == APP_SELECTION_ABSENT;
    if (ok) {
        (void)snprintf(a->resident_root, sizeof(a->resident_root), "%s", kept.current.package_root);
        a->source_version = a->resident_root; a->selected.revision = (uint64_t)kept.generation;
        ok = zcl_hex_decode_lower(a->source_version, a->copy.selected_version, 32) &&
            json_push_kv_str(&a->data, "name", "tasks") &&
            json_push_kv_int(&a->data, "selection_revision", kept.generation) &&
            json_push_kv_str(&a->data, "source_version", a->source_version) &&
            json_push_kv_str(&a->data, "source_root", a->source_version) &&
            json_push_kv_str(&a->data, "kept_receipt", kept.current.receipt_id) &&
            json_push_kv_str(&a->data, "change", a->change ? a->change : "") && ac_tasks_page_rows(a, &manifest);
    }
    if (ok) ok = ac_tasks_page_still(a, directory, &kept);
    vcs_package_manifest_free(&manifest);
    return ok || ac_fail(a, "SOURCE_UNREADABLE", "kept source changed or context is unavailable");
}

/* Resident source is a content-addressed package, not a saved personal copy. */
static bool ac_tasks_context(struct ac_read *a)
{
    const char *directory = zcl_native_command_datadir();
    struct ac_tasks_file file = {0};
    if (!directory || !ac_tasks_file_read(directory, a->source_version, a->expected, a->path, &file))
        return ac_fail(a, "SOURCE_UNREADABLE", "kept package, identity or requested member is unavailable, stale or invalid");
    struct app_selection now;
    bool selected_absent = app_selection_load(a->env.state_dir, a->selected.app, &now) == APP_SELECTION_ABSENT;
    if (!selected_absent) { free(file.bytes); return ac_fail(a, "SELECTION_STALE", "selection changed while reading; discard context and request it again"); }
    bool ok = a->offset <= file.size;
    if (ok) {
        a->selected.revision = (uint64_t)file.kept.generation;
        ok = zcl_hex_decode_lower(a->source_version, a->copy.selected_version, 32) &&
            json_push_kv_str(&a->data, "name", "tasks") &&
            json_push_kv_int(&a->data, "selection_revision", file.kept.generation) &&
            json_push_kv_str(&a->data, "source_version", a->source_version) &&
            json_push_kv_str(&a->data, "source_root", a->source_version) &&
            json_push_kv_str(&a->data, "kept_receipt", file.kept.current.receipt_id) &&
            ac_tasks_file_row(a, &file) && ac_slice(a, file.bytes, file.size);
    }
    free(file.bytes);
    return ok || ac_fail(a, "SOURCE_UNREADABLE", "kept source range or response is unavailable");
}

static bool ac_read_context(struct ac_read *a, const struct json_value *input)
{
    bool ok = ac_inputs(a, input) && ac_source_input(a, input) && ac_shape(a, input) && ac_select(a);
    if (ok && a->resident) return a->path ? ac_tasks_context(a) : ac_tasks_page(a);
    if (ok) ok = ac_source(a);
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
    if (ok && (a->resident ? (!ac_first_file(a) || !ac_next(a)) : (!ac_next(a) || !ac_first_file(a)))) ok = ac_fail(a, "CONTEXT_REFUSED", "cannot encode the next pinned read");
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
    else {
        reply->next_count = 0;
        if (a->name && !strcmp(reply->error.code, "SELECTION_REQUIRED")) {
            if (!strcmp(a->name, "tasks")) ac_tasks_recovery(reply);
            else ac_copy_recovery(a);
        }
    }
    json_free(&a->data); vcs_manifest_free(&a->manifest); zcl_package_copy_close(&a->copy); free(a);
}
