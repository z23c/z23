/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Save a one-file draft derived from the source selected at request start. */
#include "command/native_app_customize_source.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "json/json.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"
#include "vcs/vcs_manifest.h"
#include "zutf8/zutf8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define EDIT_PATH_MAX 256u
#define EDIT_COMMAND "app.edit"
struct edit {
    struct zcl_command_reply *reply;
    struct app_selection selection;
    struct zcl_package_copy copy;
    struct vcs_manifest manifest;
    const char *name, *path, *content, *source_version;
    uint64_t revision;
    mode_t mode;
    uint8_t head[32], blob[32], tree[32], version[32], plan[32];
    bool confirm;
    bool possible_persistent_mutation;
    char scratch[4400];
};
static bool edit_fail(struct edit *e, const char *code, bool mutated, const char *why)
{
    zcl_package_copy_fail(e->reply, code, mutated || e->possible_persistent_mutation, why,
        e->possible_persistent_mutation ? "copy metadata or draft CAS objects may remain; history publication is separate" : EDIT_COMMAND);
    return false;
}
static bool edit_hex(const struct json_value *in, const char *key, uint8_t out[32])
{
    const struct json_value *v = json_get(in, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && strlen(s) == 64 && zcl_hex_decode_lower(s, out, 32);
}
static const char *edit_string(const struct json_value *in, const char *key, size_t limit)
{
    const struct json_value *v = json_get(in, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && strlen(s) <= limit && zutf8_validate(s) ? s : NULL;
}
static bool edit_input_keys(struct edit *e, const struct json_value *in)
{
    static const char *const keys[] = {"name", "expected_revision", "expected_head", "path", "expected_blob", "content", "plan_id", "confirm", "source_version"};
    if (!in || in->type != JSON_OBJ || in->num_children < 6 || in->num_children > 9)
        return edit_fail(e, "BAD_INPUT", false, "six edit inputs and optional plan_id/confirm are required");
    for (size_t i = 0; i < in->num_children; ++i) {
        bool found = false;
        for (size_t j = 0; j < sizeof(keys)/sizeof(keys[0]); ++j)
            if (!strcmp(in->keys[i], keys[j])) found = true;
        if (!found) return edit_fail(e, "BAD_INPUT", false, "unknown edit input");
    }
    return true;
}
static bool edit_source_input(struct edit *e, const struct json_value *in)
{
    if (!json_get(in, "source_version")) return true;
    uint8_t root[32];
    e->source_version = edit_string(in, "source_version", 64);
    return (e->source_version && edit_hex(in, "source_version", root)) ||
        edit_fail(e, "BAD_INPUT", false, "source_version must be an exact lowercase root");
}
static bool edit_inputs(struct edit *e, const struct json_value *in)
{
    if (!edit_input_keys(e, in)) return false;
    const struct json_value *rev = json_get(in, "expected_revision");
    e->name = edit_string(in, "name", APP_SELECTION_ID_MAX);
    e->path = edit_string(in, "path", EDIT_PATH_MAX);
    e->content = edit_string(in, "content", ZCL_COMMAND_APP_EDIT_CONTENT_MAX);
    if (!e->name || !e->name[0] || !e->path || !vcs_package_path_valid(e->path) ||
        !e->content || !rev || rev->type != JSON_INT || rev->val.i < 1 ||
        !edit_hex(in, "expected_head", e->head) || !edit_hex(in, "expected_blob", e->blob))
        return edit_fail(e, "BAD_INPUT", false, "invalid revision, path, text or identity");
    const struct json_value *confirm = json_get(in, "confirm");
    if (confirm && confirm->type != JSON_BOOL)
        return edit_fail(e, "BAD_INPUT", false, "confirm must be boolean");
    e->confirm = confirm && json_get_bool(confirm);
    e->revision = (uint64_t)rev->val.i;
    return edit_source_input(e, in);
}
static bool edit_source(struct edit *e)
{
    if (!app_customize_source(e->name, e->revision, e->source_version, &e->selection, &e->copy, e->reply)) return false;
    if (memcmp(e->copy.head_version, e->head, 32))
        return edit_fail(e, "HEAD_STALE", false, "the copy head changed; request fresh context");
    if (!vcs_tree_load_readonly_bounded(e->selection.copy, e->copy.selected_tree,
                                        8u * 1024u * 1024u, 16384u, &e->manifest))
        return edit_fail(e, "SOURCE_UNREADABLE", false, "selected source tree is unavailable");
    for (size_t i = 0; i < e->manifest.count; ++i) {
        const struct vcs_entry *entry = &e->manifest.entries[i];
        if (!strcmp(entry->path, e->path)) {
            if (memcmp(entry->blob, e->blob, 32)) return edit_fail(e, "BLOB_STALE", false, "source blob differs from expected identity");
            e->mode = (mode_t)(entry->mode & 0777u);
            return true;
        }
    }
    return edit_fail(e, "PATH_UNKNOWN", false, "path is not in the selected tree");
}
/* Fixed-width identities plus length-delimited strings bind the entire plan. */
static void edit_plan_part(struct sha3_256_ctx *h, const char *s)
{
    uint64_t n = strlen(s);
    uint8_t len[8];
    zcl_write_u64_le(len, n);
    sha3_256_write(h, len, sizeof(len));
    sha3_256_write(h, (const uint8_t *)s, (size_t)n);
}
static void edit_make_plan(struct edit *e)
{
    struct sha3_256_ctx h; sha3_256_init(&h);
    edit_plan_part(&h, "zcl.app_edit.plan.v2");
    edit_plan_part(&h, e->selection.app);
    edit_plan_part(&h, e->selection.copy);
    edit_plan_part(&h, e->selection.datadir);
    sha3_256_write(&h, e->selection.version, 32);
    sha3_256_write(&h, e->copy.selected_version, 32);
    sha3_256_write(&h, e->copy.selected_tree, 32);
    sha3_256_write(&h, e->selection.fork, 32);
    sha3_256_write(&h, e->selection.parent, 32);
    sha3_256_write(&h, e->selection.package, 32);
    sha3_256_write(&h, e->selection.env, 32);
    sha3_256_write(&h, e->selection.dependencies, 32);
    sha3_256_write(&h, e->selection.record, 32);
    sha3_256_write(&h, e->selection.image, 32);
    sha3_256_write(&h, e->head, 32); sha3_256_write(&h, e->blob, 32);
    uint8_t revision[8];
    zcl_write_u64_le(revision, e->revision);
    sha3_256_write(&h, revision, sizeof(revision));
    edit_plan_part(&h, e->path); edit_plan_part(&h, e->content);
    sha3_256_finalize(&h, e->plan);
}
static bool edit_reopen(struct edit *e)
{
    uint8_t selected_tree[32]; memcpy(selected_tree, e->copy.selected_tree, 32);
    char version[65]; zcl_hex_encode(e->copy.selected_version, 32, version);
    zcl_package_copy_close(&e->copy);
    /* Checked writer open may create copy metadata before it can fail. */
    e->possible_persistent_mutation = true;
    if (!zcl_package_copy_open_selected(e->selection.copy, &e->copy, e->reply, EDIT_COMMAND, version)) {
        e->reply->error.mutated = true;
        (void)snprintf(e->reply->error.evidence, sizeof(e->reply->error.evidence),
                       "copy metadata may have changed during writer open; reconcile before retrying");
        return false;
    }
    enum zcl_package_copy_adoption auth = zcl_package_copy_adopted(e->selection.datadir, &e->copy, NULL);
    if ((auth != ZCL_PACKAGE_COPY_ADOPTED && auth != ZCL_PACKAGE_COPY_RECEIVED_TRUSTED) ||
        memcmp(e->copy.fork_version, e->selection.fork, 32) ||
        memcmp(e->copy.parent_release, e->selection.parent, 32) ||
        memcmp(e->copy.selected_tree, selected_tree, 32))
        return edit_fail(e, "SELECTION_MISMATCH", false, "copy grant or ancestry changed");
    if (memcmp(e->copy.head_version, e->head, 32))
        return edit_fail(e, "HEAD_STALE", false, "the copy head changed; request fresh context");
    return true;
}
static bool edit_write(struct edit *e)
{
    char path[4400];
    if (!platform_temp_directory_create("z23-edit-", e->scratch, sizeof(e->scratch)) ||
        vcs_tree_materialize(e->selection.copy, e->copy.selected_tree, e->scratch,
                             VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) != VCS_OK ||
        !zcl_path_join(path, sizeof(path), e->scratch, e->path))
        return edit_fail(e, "SOURCE_MATERIALIZE_FAILED", false, "cannot create private source draft");
    if (chmod(path, e->mode | S_IWUSR) != 0)
        return edit_fail(e, "EDIT_WRITE_FAILED", false, "cannot make private draft writable");
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return edit_fail(e, "EDIT_WRITE_FAILED", false, "cannot open draft file");
    size_t n = strlen(e->content), at = 0;
    while (at < n) {
        ssize_t wrote = write(fd, e->content + at, n - at);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { close(fd); return edit_fail(e, "EDIT_WRITE_FAILED", false, "cannot write draft file"); }
        at += (size_t)wrote;
    }
    bool restored = fchmod(fd, e->mode) == 0;
    if (close(fd) != 0 || !restored) return edit_fail(e, "EDIT_WRITE_FAILED", false, "cannot restore draft mode");
    e->possible_persistent_mutation = true;
    if (vcs_tree_capture_into(e->scratch, e->selection.copy, e->tree) != VCS_OK)
        return edit_fail(e, "SOURCE_CAPTURE_FAILED", false, "cannot capture stable draft source");
    if (!memcmp(e->tree, e->copy.selected_tree, 32))
        return edit_fail(e, "NO_CHANGES", false, "replacement is identical to selected source");
    return true;
}
static bool edit_push_root(struct json_value *out, const char *key, const uint8_t hash[32])
{
    char hex[65]; zcl_hex_encode(hash, 32, hex);
    return json_push_kv_str(out, key, hex);
}
static bool edit_save(struct edit *e)
{
    const struct vcs_snapshot_meta meta = {.phase = ZCL_PACKAGE_COPY_SAVE_PHASE};
    const struct vcs_snapshot_tree_limits limits = {8u * 1024u * 1024u, 16384u,
        VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES};
    int rc = vcs_snapshot_from_tree(e->copy.repo, e->tree, e->head, &meta, &limits, e->version);
    if (rc == VCS_REFUSED) return edit_fail(e, "SNAPSHOT_REFUSED", false, "head changed or sealed source edit refused");
    if (rc == VCS_EPARTIAL) {
        edit_fail(e, "SNAPSHOT_PARTIAL", true, "publication outcome is uncertain; reconcile before retrying");
        struct json_value facts; json_init(&facts); json_set_object(&facts);
        zcl_package_copy_push_root(&facts, "candidate_version", e->version);
        (void)json_push_kv(&e->reply->data, "failure_facts", &facts);
        json_free(&facts);
        return false;
    }
    if (rc != VCS_OK) return edit_fail(e, "SNAPSHOT_FAILED", true,
        "snapshot failed; a seal token may have been consumed, so reconcile before retrying");
    return true;
}
static bool edit_describe_plan(struct edit *e)
{
    struct zcl_command_reply *reply = e->reply;
    bool ok = json_push_kv_str(&reply->data, "stage", "plan") &&
        edit_push_root(&reply->data, "plan_id", e->plan) &&
        edit_push_root(&reply->data, "source_version", e->copy.selected_version) &&
        edit_push_root(&reply->data, "kept_version", e->selection.version) &&
        edit_push_root(&reply->data, "source_root", e->copy.selected_tree) &&
        json_push_kv_int(&reply->data, "source_selection_revision", (int64_t)e->revision);
    if (!ok) edit_fail(e, "REPLY_FAILED", false, "cannot describe edit plan");
    return ok;
}
static void edit_next_build(struct edit *e, const char *version)
{
    struct zcl_command_reply *reply = e->reply;
    struct json_value next; json_init(&next); json_set_object(&next);
    if (json_push_kv_str(&next, "copy", e->selection.copy) &&
        json_push_kv_str(&next, "datadir", e->selection.datadir) &&
        json_push_kv_str(&next, "version", version)) {
        char wire[4400];
        size_t n = json_write(&next, wire, sizeof(wire));
        if (n && n < sizeof(wire) && n < sizeof(reply->next[0].input_json))
            (void)zcl_command_reply_add_next(reply, "app.build", wire, "build the saved draft version");
    }
    json_free(&next);
}
static void edit_describe_commit(struct edit *e)
{
    struct zcl_command_reply *reply = e->reply;
    char version[65]; zcl_hex_encode(e->version, 32, version);
    bool described = edit_push_root(&reply->data, "version", e->version) &&
        edit_push_root(&reply->data, "source_root", e->tree) &&
        edit_push_root(&reply->data, "source_version", e->copy.selected_version) &&
        edit_push_root(&reply->data, "kept_version", e->selection.version) &&
        json_push_kv_int(&reply->data, "source_selection_revision", (int64_t)e->revision);
    if (!described)
        zcl_package_copy_fail(reply, "REPLY_FAILED", true,
            "draft saved but reply allocation failed; reconcile candidate version", version);
    edit_next_build(e, version);
    reply->error.mutated = true;
}
#endif

void zcl_native_handle_app_edit(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
#if !defined(_WIN32)
    struct edit *e = zcl_calloc(1, sizeof(*e), "app-edit");
    if (!e) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate draft", EDIT_COMMAND); return; }
    e->reply = reply;
    bool ok = request && edit_inputs(e, request->input) && edit_source(e);
    if (ok) edit_make_plan(e);
    if (ok && !e->confirm) ok = edit_describe_plan(e);
    if (ok && e->confirm)
        ok = zcl_package_copy_plan_matches(request->input, e->plan, reply, EDIT_COMMAND) &&
             edit_reopen(e) && edit_write(e) && edit_save(e);
    if (ok && e->confirm) edit_describe_commit(e);
    if (e->scratch[0]) (void)zcl_tree_remove(e->scratch);
    vcs_manifest_free(&e->manifest);
    zcl_package_copy_close(&e->copy);
    free(e);
#else
    (void)request;
    zcl_package_copy_fail(reply, "PLATFORM_UNAVAILABLE", false,
                          "editing is unavailable on this platform", "app.edit");
#endif
}
