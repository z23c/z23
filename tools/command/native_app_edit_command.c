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
#include "vcs/vcs_object.h"
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
    const char *replacement;
    char *splice_content;
    size_t offset, delete_length;
    bool splice;
    uint64_t revision;
    uint64_t blob_size;
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
    static const char *const keys[] = {"name", "expected_revision", "expected_head", "path", "expected_blob", "content", "offset", "delete_length", "replacement", "plan_id", "confirm", "source_version"};
    if (!in || in->type != JSON_OBJ || in->num_children < 6 || in->num_children > 11)
        return edit_fail(e, "BAD_INPUT", false, "provide content or offset, delete_length and replacement with the required edit identities");
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
static bool edit_splice_input(struct edit *e, const struct json_value *in)
{
    const struct json_value *offset = json_get(in, "offset"), *del = json_get(in, "delete_length");
    const struct json_value *replacement = json_get(in, "replacement");
    e->splice = offset || del || replacement;
    if (e->splice) {
        e->replacement = edit_string(in, "replacement", ZCL_COMMAND_APP_EDIT_CONTENT_MAX);
        if (json_get(in, "content") || !offset || offset->type != JSON_INT || offset->val.i < 0 ||
            !del || del->type != JSON_INT || del->val.i < 0 || !e->replacement ||
            (uint64_t)offset->val.i > ZCL_COMMAND_APP_EDIT_CONTENT_MAX ||
            (uint64_t)del->val.i > ZCL_COMMAND_APP_EDIT_CONTENT_MAX)
            return edit_fail(e, "BAD_INPUT", false, "provide content or valid offset, delete_length and replacement, not both");
        e->offset = (size_t)offset->val.i; e->delete_length = (size_t)del->val.i;
    }
    return true;
}
static bool edit_confirmation_input(struct edit *e, const struct json_value *in)
{
    const struct json_value *confirm = json_get(in, "confirm");
    if (confirm && confirm->type != JSON_BOOL)
        return edit_fail(e, "BAD_INPUT", false, "confirm must be boolean");
    e->confirm = confirm && json_get_bool(confirm);
    return true;
}
static bool edit_inputs(struct edit *e, const struct json_value *in)
{
    if (!edit_input_keys(e, in) || !edit_splice_input(e, in)) return false;
    const struct json_value *rev = json_get(in, "expected_revision");
    e->name = edit_string(in, "name", APP_SELECTION_ID_MAX);
    e->path = edit_string(in, "path", EDIT_PATH_MAX);
    e->content = edit_string(in, "content", ZCL_COMMAND_APP_EDIT_CONTENT_MAX);
    if (!e->name || !e->name[0] || !e->path || !vcs_package_path_valid(e->path) ||
        (!e->splice && !e->content) || !rev || rev->type != JSON_INT || rev->val.i < 1 ||
        !edit_hex(in, "expected_head", e->head) || !edit_hex(in, "expected_blob", e->blob))
        return edit_fail(e, "BAD_INPUT", false, "invalid revision, path, text or identity");
    e->revision = (uint64_t)rev->val.i;
    return edit_confirmation_input(e, in) && edit_source_input(e, in);
}
static bool edit_source_text(struct edit *e, const uint8_t *bytes, size_t size)
{
    return zutf8_validate_n((const char *)bytes, size) ||
        edit_fail(e, "BAD_INPUT", false, "splice range or selected text is invalid");
}
static bool edit_splice_range(struct edit *e, const uint8_t *bytes, size_t size, size_t insert)
{
    bool valid = e->offset <= size && e->delete_length <= size - e->offset;
    size_t end = valid ? e->offset + e->delete_length : 0;
    if (valid) valid = (!e->offset || e->offset == size || (bytes[e->offset] & 0xc0) != 0x80) &&
        (end == size || (bytes[end] & 0xc0) != 0x80) &&
        insert <= ZCL_COMMAND_APP_EDIT_CONTENT_MAX - (size - e->delete_length) && (!size || !memchr(bytes, 0, size));
    if (!valid) return edit_fail(e, "BAD_INPUT", false, "splice range or selected text is invalid");
    return edit_source_text(e, bytes, size);
}
/* Splice only authenticated, bounded UTF-8 bytes from the selected blob. */
static bool edit_splice(struct edit *e)
{
    if (!e->splice) return true;
    uint8_t *bytes = NULL; size_t size = 0, insert = strlen(e->replacement);
    if (e->blob_size > ZCL_COMMAND_APP_EDIT_CONTENT_MAX ||
        vcs_object_get_readonly_bounded(e->selection.copy, e->blob, VCS_TAG_BLOB,
            ZCL_COMMAND_APP_EDIT_CONTENT_MAX, &bytes, &size) != 0 || size != e->blob_size) {
        free(bytes); return edit_fail(e, "SOURCE_UNREADABLE", false, "selected file is unavailable");
    }
    if (!edit_splice_range(e, bytes, size, insert)) { free(bytes); return false; }
    size_t end = e->offset + e->delete_length;
    size_t total = size - e->delete_length + insert;
    e->splice_content = zcl_malloc(total + 1, "app-edit-splice");
    if (!e->splice_content) { free(bytes); return edit_fail(e, "OUT_OF_MEMORY", false, "cannot allocate edited text"); }
    if (e->offset) memcpy(e->splice_content, bytes, e->offset);
    memcpy(e->splice_content + e->offset, e->replacement, insert);
    if (size > end) memcpy(e->splice_content + e->offset + insert, bytes + end, size - end);
    e->splice_content[total] = 0; e->content = e->splice_content;
    free(bytes); return true;
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
            e->blob_size = entry->size;
            return true;
        }
    }
    return edit_fail(e, "PATH_UNKNOWN", false, "path is not in the selected tree");
}
/* A missing or corrupt blob keeps the original plan and confirmation path. */
static bool edit_identical(struct edit *e)
{
    size_t size = strlen(e->content), actual = 0;
    if ((uint64_t)size != e->blob_size) return false;
    uint8_t *bytes = NULL;
    bool same = vcs_object_get_readonly_bounded(e->selection.copy, e->blob, VCS_TAG_BLOB,
        size, &bytes, &actual) == 0 && actual == size && (!size || !memcmp(bytes, e->content, size));
    free(bytes); return same;
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
    edit_plan_part(&h, e->splice ? "zcl.app_edit.splice.v1" : "zcl.app_edit.plan.v2");
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
    if (e->splice) {
        uint8_t part[8]; zcl_write_u64_le(part, e->offset); sha3_256_write(&h, part, sizeof(part));
        zcl_write_u64_le(part, e->delete_length); sha3_256_write(&h, part, sizeof(part));
        edit_plan_part(&h, e->replacement);
    }
    sha3_256_finalize(&h, e->plan);
}
static bool edit_prepare_plan(struct edit *e)
{
    if (!e->confirm && edit_identical(e))
        return edit_fail(e, "NO_CHANGES", false, "the selected file already has these bytes");
    edit_make_plan(e); return true;
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
        vcs_tree_materialize_disposable(e->selection.copy, e->copy.selected_tree, e->scratch,
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
static bool edit_next_build(struct edit *e, const char *version)
{
    struct zcl_command_reply *reply = e->reply;
    struct json_value next; json_init(&next); json_set_object(&next);
    bool ok = json_push_kv_str(&next, "copy", e->selection.copy) &&
        json_push_kv_str(&next, "datadir", e->selection.datadir) &&
        json_push_kv_str(&next, "version", version) &&
        json_push_kv(&reply->data, "build_input", &next);
    if (ok) {
        char wire[sizeof(reply->next[0].input_json)];
        size_t n = json_write(&next, wire, sizeof(wire));
        if (!n) ok = false;
        else if (n < sizeof(wire))
            ok = zcl_command_reply_add_next(reply, "app.build", wire, "build the saved draft version");
        else
            ok = json_push_kv_str(&reply->data, "build_hint",
                "Pass build_input to app.build to build this saved draft version.");
    }
    json_free(&next);
    return ok;
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
    if (described) described = edit_next_build(e, version);
    if (!described)
        zcl_package_copy_fail(reply, "REPLY_FAILED", true,
            "draft saved but reply allocation failed; reconcile candidate version", version);
    reply->error.mutated = true;
}
#endif

#if !defined(_WIN32)
static void edit_execute(struct edit *e, const struct zcl_command_request *request)
{
    bool ok = request && edit_inputs(e, request->input) && edit_source(e) && edit_splice(e);
    if (ok) ok = edit_prepare_plan(e);
    if (ok && !e->confirm) ok = edit_describe_plan(e);
    if (ok && e->confirm)
        ok = zcl_package_copy_plan_matches(request->input, e->plan, e->reply, EDIT_COMMAND) &&
             edit_reopen(e) && edit_write(e) && edit_save(e);
    if (ok && e->confirm) edit_describe_commit(e);
}
static void edit_run(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct edit *e = zcl_calloc(1, sizeof(*e), "app-edit");
    if (!e) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate draft", EDIT_COMMAND); return; }
    e->reply = reply;
    edit_execute(e, request);
    if (e->scratch[0]) (void)zcl_tree_remove(e->scratch);
    vcs_manifest_free(&e->manifest);
    zcl_package_copy_close(&e->copy);
    free(e->splice_content);
    free(e);
}
#endif

void zcl_native_handle_app_edit(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
#if !defined(_WIN32)
    edit_run(request, reply);
#else
    (void)request;
    zcl_package_copy_fail(reply, "PLATFORM_UNAVAILABLE", false,
                          "editing is unavailable on this platform", "app.edit");
#endif
}
