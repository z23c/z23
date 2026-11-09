/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Show a verified share plan before recording owner receive trust. */
#include "command/native_app_receive_command.h"
#include "command/native_app_commit_progress.h"
#include "command/native_app_receive_flow.h"
#include "command/native_app_confirm.h"
#include "command/native_zcode_package_copy.h"
#include "command/native_zcode_package_bundle.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/file_metadata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AR_PATH 4400u
#define AR_PREVIEW_RECEIPT_MAX 8192u
struct receive_work {
    struct app_confirm view;
    struct json_value receiver_args;
    bool default_destination, parents_may_have_changed, preview;
    char datadir[AR_PATH];
    char plan[65], release[65], package[65], publisher[67];
    char name[257], version[257], parent[65], destination[AR_PATH];
};
static bool ar_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_package_copy_fail(reply, code, false, why, "app.receive");
    return false;
}
static bool ar_text(char *out, size_t cap, const struct json_value *data, const char *key)
{
    const struct json_value *value = json_get(data, key);
    const char *text = value && value->type == JSON_STR ? json_get_str(value) : NULL;
    if (!text || !*text || strlen(text) >= cap) return false;
    memcpy(out, text, strlen(text) + 1);
    return true;
}
static bool ar_root(const char *text, size_t bytes)
{
    uint8_t root[33];
    return bytes <= sizeof(root) && strlen(text) == bytes * 2 &&
        zcl_hex_decode_lower(text, root, bytes);
}
static bool ar_input_keys(const struct json_value *input)
{
    static const char *const allowed[] = {"file", "datadir", "destination", "day", "preview"};
    if (!input || input->type != JSON_OBJ || input->num_children < 1 || input->num_children > 5)
        return false;
    for (size_t i = 0; i < input->num_children; ++i) {
        bool known = false;
        for (size_t j = 0; j < sizeof(allowed) / sizeof(allowed[0]); ++j)
            if (!strcmp(input->keys[i], allowed[j])) known = true;
        if (!known) return false;
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(input->keys[i], input->keys[j])) return false;
    }
    return true;
}
static bool ar_preview_input(struct receive_work *w, const struct json_value *input)
{
    const struct json_value *preview = json_get(input, "preview");
    if (preview && preview->type != JSON_BOOL) return false;
    w->preview = preview && json_get_bool(preview);
    return true;
}
static bool ar_inputs(struct receive_work *w, const struct json_value *input)
{
    if (!ar_input_keys(input) || !ar_preview_input(w, input)) return false;
    static const char *const paths[] = {"file", "datadir", "destination"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (i && !json_get(input, paths[i])) continue;
        char path[AR_PATH];
        if (!ar_text(path, sizeof(path), input, paths[i]) || path[0] != '/' ||
            !json_push_kv_str(&w->receiver_args, paths[i], path)) return false;
        if (i == 2) memcpy(w->destination, path, strlen(path) + 1);
    }
    w->default_destination = !json_get(input, "destination");
    const struct json_value *day = json_get(input, "day");
    return !day || (day->type == JSON_INT && day->val.i >= 0 &&
        json_push_kv_int(&w->receiver_args, "day", day->val.i));
}
static bool ar_datadir(struct receive_work *w, struct zcl_command_reply *reply)
{
    const char *dir = zcl_package_copy_datadir(&w->receiver_args, reply, "app.receive");
    if (!dir) return false;
    if (dir[0] != '/' || strlen(dir) >= sizeof(w->datadir))
        return ar_fail(reply, "BAD_INPUT", "The bound datadir must be a bounded absolute path.");
    memcpy(w->datadir, dir, strlen(dir) + 1);
    return json_get(&w->receiver_args, "datadir") ||
        json_push_kv_str(&w->receiver_args, "datadir", w->datadir) ||
        ar_fail(reply, "OUT_OF_MEMORY", "Cannot retain the resolved datadir.");
}
/* Find an existing canonical ancestor without writes. Missing suffixes are
 * created relative to retained handles only after native confirmation. */
static bool ar_parent_anchor(const char *path, char anchor[AR_PATH])
{
    memcpy(anchor, path, strlen(path) + 1);
    for (;;) {
        enum platform_directory_probe_result found = platform_directory_probe_real(anchor);
        if (found == PLATFORM_DIRECTORY_PROBE_OK) break;
        if (found != PLATFORM_DIRECTORY_PROBE_MISSING) return false;
        char *slash = strrchr(anchor, '/');
        if (!slash || slash == anchor) return false;
        *slash = 0;
    }
    char canonical[AR_PATH];
    return platform_directory_canonical_real(anchor, canonical, sizeof(canonical)) &&
        !strcmp(canonical, anchor);
}
static bool ar_parent_leaf(const char *leaf)
{
    size_t n = strlen(leaf);
    return n > 0 && n <= PLATFORM_DIRECTORY_CHILD_LEAF_MAX &&
        strcmp(leaf, ".") && strcmp(leaf, "..") && !strchr(leaf, '\\') &&
        !strchr(leaf, ':') && leaf[n - 1] != '.' && leaf[n - 1] != ' ';
}
static enum platform_directory_result ar_parent_step(struct receive_work *w,
    struct platform_directory_transaction *root, const char *leaf, bool create)
{
    struct platform_directory_transaction child;
    platform_directory_transaction_init(&child);
    enum platform_directory_result rc =
        platform_directory_transaction_open_child(root, leaf, false, &child);
    if (rc == PLATFORM_DIRECTORY_MISSING && create) {
        w->parents_may_have_changed = true; /* mkdir can precede an error */
        rc = platform_directory_transaction_open_child(root, leaf, true, &child);
    }
    if (rc != PLATFORM_DIRECTORY_OK) {
        platform_directory_transaction_close(&child); return rc;
    }
    platform_directory_transaction_close(root);
    *root = child; return PLATFORM_DIRECTORY_OK;
}
static bool ar_parent_suffix_valid(char *suffix)
{
    char *at = suffix;
    while (*at) {
        char *slash = strchr(at, '/');
        if (slash) *slash = 0;
        if (!ar_parent_leaf(at)) return false;
        if (!slash) break;
        at = slash + 1;
        if (!*at) return false;
    }
    return true;
}
static bool ar_parent_walk(struct receive_work *w,
    struct platform_directory_transaction *root, char *suffix, bool create)
{
    char check[AR_PATH]; memcpy(check, suffix, strlen(suffix) + 1);
    if (!ar_parent_suffix_valid(check)) return false;
    char *at = suffix;
    while (*at) {
        char *slash = strchr(at, '/');
        if (slash) *slash = 0;
        enum platform_directory_result rc = ar_parent_step(w, root, at, create);
        if (rc == PLATFORM_DIRECTORY_MISSING && !create) return true;
        if (rc != PLATFORM_DIRECTORY_OK) return false;
        if (!slash) break;
        at = slash + 1;
    }
    return true;
}
/* All suffix components are checked before this can create even the first.
 * Bootstrap returns only the private child, never its 0755 HOME parent. */
static bool ar_parent_bootstrap(struct receive_work *w, const char *anchor,
    struct platform_directory_transaction *root, char *suffix, bool create)
{
    char check[AR_PATH]; memcpy(check, suffix, strlen(suffix) + 1);
    if (!ar_parent_suffix_valid(check)) return false;
    char *slash = strchr(suffix, '/');
    if (slash) *slash = 0;
    if (create) w->parents_may_have_changed = true;
    enum platform_directory_result rc = platform_directory_transaction_bootstrap_child(anchor, suffix, create, root);
    if (rc == PLATFORM_DIRECTORY_MISSING && !create) return true;
    if (rc != PLATFORM_DIRECTORY_OK) return false;
    return !slash || ar_parent_walk(w, root, slash + 1, create);
}
static bool ar_default_parent(struct receive_work *w, bool create,
    struct zcl_command_reply *reply)
{
    char path[AR_PATH], anchor[AR_PATH];
    int n = snprintf(path, sizeof(path), "%s/copies", w->datadir);
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    bool ok = n > 0 && (size_t)n < sizeof(path) && ar_parent_anchor(w->datadir, anchor);
    if (ok && !strcmp(anchor, w->datadir))
        ok = platform_directory_transaction_open(&root, anchor) &&
            ar_parent_walk(w, &root, path + strlen(anchor) + 1, create);
    else if (ok)
        ok = ar_parent_bootstrap(w, anchor, &root, path + strlen(anchor) + 1, create);
    platform_directory_transaction_close(&root);
    return ok || ar_fail(reply, "UNSAFE_RECEIVE_PARENT",
        "Default receive needs a canonical owner-controlled ancestor, private existing datadir and safe missing components.");
}
bool app_receive_profile_validate(const char *datadir, char *anchor, size_t anchor_cap,
    struct zcl_command_reply *reply)
{
    char parent[AR_PATH];
    if (!reply || !datadir || datadir[0] != '/' || strlen(datadir) >= AR_PATH || !anchor)
        return reply ? ar_fail(reply, "BAD_INPUT", "An absolute bounded app profile is required.") : false;
    struct receive_work *w = zcl_calloc(1, sizeof(*w), "receive-profile");
    if (!w) return ar_fail(reply, "OUT_OF_MEMORY", "Cannot validate the app profile.");
    memcpy(w->datadir, datadir, strlen(datadir) + 1);
    bool ok = ar_default_parent(w, false, reply);
    if (ok && !ar_parent_anchor(datadir, parent))
        ok = ar_fail(reply, "UNSAFE_RECEIVE_PARENT", "The app profile ancestor changed during validation.");
    free(w);
    if (!ok) return false;
    if (strlen(parent) >= anchor_cap) return ar_fail(reply, "BAD_INPUT", "The profile ancestor is too long.");
    memcpy(anchor, parent, strlen(parent) + 1); return true;
}
static bool ar_pick_verified(struct receive_work *w,
    const struct json_value *data, struct zcl_command_reply *reply)
{
    char name[ZCL_PACKAGE_ADOPT_NAME_MAX + 1u], release_name[257];
    if (!ar_text(release_name, sizeof(release_name), data, "name"))
        return ar_fail(reply, "RECEIVE_PLAN_INVALID", "The verified bundle has no bounded name.");
    if (!zcl_package_copy_pick_name(w->datadir, release_name, name,
        w->destination, sizeof(w->destination), reply)) return false;
    if (platform_file_shape_read(w->destination) != PLATFORM_FILE_SHAPE_MISSING)
        return ar_fail(reply, "DESTINATION_EXISTS", "The suggested destination is not absent.");
    return json_push_kv_str(&w->receiver_args, "destination", w->destination) ||
        ar_fail(reply, "OUT_OF_MEMORY", "Cannot retain the selected destination.");
}
static bool ar_pick_destination(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.bundle.verify", NULL);
    struct zcl_command_reply verified; struct json_value in;
    zcl_command_reply_init(&verified, "zcl.zcode_package_bundle_verify.v1");
    json_init(&in); json_set_object(&in);
    bool ok = spec && spec->handler &&
        json_push_kv_str(&in, "file", zcl_package_copy_str(&w->receiver_args, "file"));
    if (ok) {
        struct zcl_command_request call = *request;
        call.spec = spec; call.input = &in; call.invoked_name = spec->path;
        spec->handler(&call, &verified);
        ok = verified.status == ZCL_COMMAND_STATUS_PASSED;
        if (!ok) app_confirm_forward_failure(reply, &verified);
    } else ar_fail(reply, "RECEIVE_UNAVAILABLE", "Native bundle verification is unavailable.");
    if (ok) ok = ar_pick_verified(w, &verified.data, reply);
    json_free(&in); zcl_command_reply_free(&verified); return ok;
}
static bool ar_paths(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply)
{
    if (!ar_datadir(w, reply)) return false;
    if (!w->default_destination) return true;
    return ar_default_parent(w, false, reply) && ar_pick_destination(request, w, reply);
}
static bool ar_call(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *out)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.bundle.receive", NULL);
    if (!spec || !spec->handler || spec->authority != ZCL_COMMAND_AUTH_OWNER) return false;
    struct zcl_command_request inner = *request;
    inner.spec = spec;
    inner.input = &w->receiver_args;
    inner.invoked_name = spec->path;
    spec->handler(&inner, out);
    return true;
}
static bool ar_verified(const struct json_value *data)
{
    const struct json_value *verified = json_get(data, "verified");
    const struct json_value *executed = json_get(data, "executed");
    return verified && verified->type == JSON_BOOL && json_get_bool(verified) &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed);
}
static bool ar_plan_fields(struct receive_work *w, const struct json_value *data)
{
    if (!ar_verified(data)) return false;
    if (!ar_text(w->plan, sizeof(w->plan), data, "plan_id") ||
        !ar_text(w->release, sizeof(w->release), data, "release_id") ||
        !ar_text(w->package, sizeof(w->package), data, "package_root") ||
        !ar_text(w->publisher, sizeof(w->publisher), data, "publisher_fingerprint") ||
        !ar_text(w->name, sizeof(w->name), data, "name") ||
        !ar_text(w->version, sizeof(w->version), data, "semver")) return false;
    if (json_get(data, "parent_release_root") &&
        (!ar_text(w->parent, sizeof(w->parent), data, "parent_release_root") ||
         !ar_root(w->parent, 32))) return false;
    return ar_root(w->plan, 32) && ar_root(w->release, 32) &&
        ar_root(w->package, 32) && ar_root(w->publisher, 33);
}
/* zpb_describe's committed fields are also present in the verified plan.
 * Retain even unknown plan additions conservatively, but replace its stage
 * and exclude the plan-only id/instruction. No copy or trust write occurs. */
static bool ar_receipt_common(struct json_value *out, const struct json_value *plan)
{
    json_init(out); json_set_object(out);
    for (size_t i = 0; i < plan->num_children; ++i) {
        const char *key = plan->keys[i];
        if (!strcmp(key, "stage") || !strcmp(key, "plan_id") || !strcmp(key, "next")) continue;
        if (!json_push_kv(out, key, &plan->children[i])) return false;
    }
    return json_push_kv_str(out, "stage", "commit");
}
/* Match zpb_keep_reply/zpb_record_write's shape. The future version is exactly
 * 64 lowercase hex bytes, so any such placeholder has identical encoded size.
 * next is a 512-byte producer buffer: 511 maximally escaped bytes bound every
 * possible formatted/truncated instruction, without duplicating its prose. */
static bool ar_receipt_commit_fields(struct json_value *out, const struct receive_work *w)
{
    char version[65], trust[AR_PATH], next[512];
    memset(version, 'f', 64); version[64] = 0;
    memset(next, 1, sizeof(next) - 1); next[sizeof(next) - 1] = 0;
    int n = snprintf(trust, sizeof(trust), "%s/%s/%s.%s.trust", w->datadir,
        ZCL_PACKAGE_RECEIVE_TRUST_DIR, version, w->release);
    if (n <= 0 || (size_t)n >= sizeof(trust)) return false;
    return json_push_kv_str(out, "destination", w->destination) &&
        json_push_kv_str(out, "version", version) && json_push_kv_str(out, "trust_record", trust) &&
        json_push_kv_str(out, "next", next);
}
static bool ar_preview_receipt_bound(const struct receive_work *w,
    const struct json_value *plan, struct zcl_command_reply *reply)
{
    if (!w->preview) return true;
    struct json_value projected; json_init(&projected);
    bool ok = ar_receipt_common(&projected, plan) && ar_receipt_commit_fields(&projected, w);
    size_t bytes = ok ? json_write(&projected, NULL, 0) : 0;
    json_free(&projected);
    if (!ok || !bytes) return ar_fail(reply, "PREVIEW_RECEIPT_PROJECTION_FAILED",
        "Cannot reserve the complete receive receipt; nothing was received.");
    return bytes <= AR_PREVIEW_RECEIPT_MAX || ar_fail(reply, "PREVIEW_RECEIPT_TOO_LARGE",
        "The escaped receive receipt exceeds the preview reserve; shorten the copy or datadir path, or receive without preview.");
}
static bool ar_plan(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply,
    const struct app_receive_identity *expected)
{
    struct zcl_command_reply plan;
    zcl_command_reply_init(&plan, "zcl.zcode_package_bundle_receive.v1");
    bool called = ar_call(request, w, &plan);
    bool ok = called && plan.status == ZCL_COMMAND_STATUS_PASSED;
    if (!called) ar_fail(reply, "RECEIVE_UNAVAILABLE", "Native owner receive is unavailable.");
    else if (!ok) app_confirm_forward_failure(reply, &plan);
    else if (!(ok = ar_plan_fields(w, &plan.data)))
        ar_fail(reply, "RECEIVE_PLAN_INVALID", "The verified receive plan cannot be displayed exactly.");
    if (ok && expected) {
        uint8_t release[32], package[32], publisher[33];
        ok = zcl_hex_decode_lower(w->release, release, sizeof(release)) &&
            zcl_hex_decode_lower(w->package, package, sizeof(package)) &&
            zcl_hex_decode_lower(w->publisher, publisher, sizeof(publisher)) &&
            !memcmp(release, expected->release_id, sizeof(release)) &&
            !memcmp(package, expected->package_root, sizeof(package)) &&
            !memcmp(publisher, expected->publisher, sizeof(publisher));
        if (!ok) ar_fail(reply, "RECEIVE_IDENTITY_MISMATCH", "The verified receive identity differs from the selected offer.");
    }
    if (ok) ok = ar_preview_receipt_bound(w, &plan.data, reply);
    zcl_command_reply_free(&plan);
    return ok;
}
static bool ar_model(struct receive_work *w, char *why, size_t cap)
{
    struct zcl_present_model_v1 *m = &w->view.model;
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "receive-%.12s", w->plan);
    (void)snprintf(m->title, sizeof(m->title), "Receive this app copy?");
    (void)snprintf(m->summary, sizeof(m->summary), "Review all pages. Nothing runs now.");
    m->action_count = 4;
    app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CONFIRM, "receive", "Receive copy");
    bool ok = app_confirm_field(m, "Permission: ", "Allow future requested builds and runs of this exact publisher and package. Receiving this copy runs nothing.") &&
        app_confirm_field(m, "Name: ", w->name) && app_confirm_field(m, "Version: ", w->version) &&
        app_confirm_field(m, "Publisher: ", w->publisher) && app_confirm_field(m, "Release: ", w->release) &&
        app_confirm_field(m, "Package: ", w->package) && app_confirm_field(m, "Destination: ", w->destination) &&
        app_confirm_field(m, "Parent release: ", w->parent[0] ? w->parent : "None (first release)") &&
        app_confirm_field(m, "Changes: ", w->parent[0] ? "Unavailable: this receive plan supplies no parent comparison." : "No parent to compare") &&
        app_confirm_field(m, "Trust: ", "Check the publisher and package root with the sender before confirming.");
    return ok && app_confirm_prepare(&w->view, why, cap);
}
static bool ar_result_matches(const struct receive_work *w, const struct json_value *data)
{
    const char *release = zcl_package_copy_str(data, "release_id");
    const char *package = zcl_package_copy_str(data, "package_root");
    const char *publisher = zcl_package_copy_str(data, "publisher_fingerprint");
    const char *destination = zcl_package_copy_str(data, "destination");
    const char *version = zcl_package_copy_str(data, "version");
    const char *trust = zcl_package_copy_str(data, "trust_record");
    return release && package && publisher && destination && version && trust &&
        !strcmp(release, w->release) && !strcmp(package, w->package) &&
        !strcmp(publisher, w->publisher) && !strcmp(destination, w->destination) && ar_root(version, 32);
}
/* Revalidate before creating default parents, but never change the approved
 * path or plan. The native commit independently rechecks its existing guards. */
static bool ar_default_recheck(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply)
{
    if (platform_file_shape_read(w->destination) != PLATFORM_FILE_SHAPE_MISSING)
        return ar_fail(reply, "DESTINATION_EXISTS", "The approved destination is no longer absent.");
    struct zcl_command_reply plan;
    zcl_command_reply_init(&plan, "zcl.zcode_package_bundle_receive.v1");
    bool called = ar_call(request, w, &plan);
    const char *id = zcl_package_copy_str(&plan.data, "plan_id");
    bool ok = called && plan.status == ZCL_COMMAND_STATUS_PASSED;
    if (!called) ar_fail(reply, "RECEIVE_UNAVAILABLE", "Native owner receive is unavailable.");
    else if (!ok) app_confirm_forward_failure(reply, &plan);
    else if (!id || strcmp(id, w->plan))
        ok = ar_fail(reply, "PLAN_MISMATCH", "The approved receive plan changed; review again.");
    zcl_command_reply_free(&plan);
    return ok && ar_default_parent(w, true, reply);
}
static void ar_commit(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply)
{
    if (w->default_destination && !ar_default_recheck(request, w, reply)) {
        reply->error.mutated |= w->parents_may_have_changed;
        return;
    }
    if (!json_push_kv_str(&w->receiver_args, "plan_id", w->plan) ||
        !json_push_kv_str(&w->receiver_args, "trust_publisher", w->publisher) ||
        !json_push_kv_str(&w->receiver_args, "trust_root", w->package) ||
        !json_push_kv_bool(&w->receiver_args, "confirm", true)) {
        (void)ar_fail(reply, "OUT_OF_MEMORY", "Cannot submit the approved receive plan.");
        reply->error.mutated |= w->parents_may_have_changed;
        return;
    }
    struct zcl_command_reply result;
    zcl_command_reply_init(&result, "zcl.zcode_package_bundle_receive.v1");
    bool called = ar_call(request, w, &result);
    if (!called) ar_fail(reply, "RECEIVE_UNAVAILABLE", "Native owner receive is unavailable.");
    else if (result.status != ZCL_COMMAND_STATUS_PASSED) app_confirm_forward_failure(reply, &result);
    else if (!ar_result_matches(w, &result.data))
        zcl_package_copy_fail(reply, "RECEIVE_RESULT_MISMATCH", true,
            "The receive completed but its result did not match the displayed plan; inspect before retrying.", w->destination);
    else {
        json_free(&reply->data);
        reply->data = result.data;
        json_init(&result.data);
        reply->error.mutated = true;
    }
    reply->error.mutated |= w->parents_may_have_changed;
    zcl_command_reply_free(&result);
}
static const struct app_commit_progress_labels ar_progress_labels = {
    .name = "receive-copy", .request_id = "receive-copy", .title = "Receiving your copy",
    .summary = "Saving your approved received copy. Closing waits for completion; it does not undo saved changes.",
    .finishing = "Finishing your copy", .allocation = "receive-copy/progress",
    .unavailable = "RECEIVE_PROGRESS_UNAVAILABLE", .start_failed = "RECEIVE_THREAD_FAILED", .join_failed = "RECEIVE_JOIN_FAILED",
};
static void ar_commit_worker(void *work, const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ar_commit(request, work, reply);
}
static bool ar_progress_receipt(struct zcl_command_reply *reply,
    const struct app_commit_progress_outcome *out)
{
    bool offer = out->joined && out->ui_ok && !out->close_requested;
    if (out->started && !offer && reply->status == ZCL_COMMAND_STATUS_PASSED) {
        if (!json_push_kv_str(&reply->data, "continuation", "received") ||
            !json_push_kv_bool(&reply->data, "continuation_executed", false) ||
            !json_push_kv_bool(&reply->data, "receive_progress_ui_failed", !out->ui_ok))
            zcl_package_copy_fail(reply, "OUT_OF_MEMORY", reply->error.mutated,
                "Copy saved, but progress outcome could not be described; inspect retained state.", "app.receive");
    }
    return offer && reply->status == ZCL_COMMAND_STATUS_PASSED;
}
static bool ar_progress_commit(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context
#ifdef ZCL_TESTING
    , const struct app_commit_progress_test_hooks *hooks
#endif
)
{
    struct app_commit_progress_outcome out = app_commit_progress_run(
        request, reply, ar_commit_worker, w, &ar_progress_labels, presenter, context
#ifdef ZCL_TESTING
        , hooks
#endif
    );
    return ar_progress_receipt(reply, &out);
}
#if defined(ZCL_TESTING) && !defined(_WIN32)
bool zcl_test_app_receive_progress(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
    const struct app_commit_progress_test_hooks *hooks)
{
    if (!request || !reply || !hooks || !hooks->commit) return false;
    /* Only this internal fixture entry can replace commit; production never
     * accepts hooks or skips the existing owner confirmation. */
    return ar_progress_commit(request, NULL, reply, presenter, context, hooks);
}
#endif
static void ar_commit_preview(const struct zcl_command_request *request,
    struct receive_work *w, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path)
{
    bool offer = ar_progress_commit(request, w, reply, presenter, context
#ifdef ZCL_TESTING
        , NULL
#endif
    );
    const char *stage = zcl_package_copy_str(&reply->data, "stage");
    if (offer && w->preview && reply->status == ZCL_COMMAND_STATUS_PASSED &&
        reply->exit_code == 0 && stage && !strcmp(stage, "commit"))
    {
#ifdef ZCL_TESTING
        if (worker_path) app_receive_flow_run_test(w->datadir, reply, presenter, context, worker_path);
        else
#else
        (void)worker_path;
#endif
            app_receive_flow_run(w->datadir, reply, presenter, context);
    }
}
static void ar_run(const struct zcl_command_request *request, struct zcl_command_reply *reply,
    const struct app_receive_identity *expected, app_confirm_presenter presenter, void *context,
    const char *worker_path)
{
    if (!request || !reply) return;
    struct receive_work *w = zcl_calloc(1, sizeof(*w), "app-receive");
    if (!w) { ar_fail(reply, "OUT_OF_MEMORY", "Cannot prepare receive confirmation."); return; }
    json_init(&w->receiver_args); json_set_object(&w->receiver_args);
    if (!ar_inputs(w, request->input)) ar_fail(reply, "BAD_INPUT", "Provide an absolute file; optional datadir/destination are absolute, day is nonnegative, and preview is boolean.");
    else if (ar_paths(request, w, reply) && ar_plan(request, w, reply, expected)) {
        char why[256] = {0};
        if (!ar_model(w, why, sizeof(why)) || !app_confirm_show(&w->view, presenter, context, why, sizeof(why)))
            ar_fail(reply, "CONFIRMATION_UNAVAILABLE", "The exact receive plan could not be displayed; nothing was kept.");
        else if (w->view.confirmed) ar_commit_preview(request, w, reply, presenter, context, worker_path);
        else if (!json_push_kv_str(&reply->data, "status", "canceled"))
            ar_fail(reply, "OUT_OF_MEMORY", "Cannot describe cancellation; nothing was kept.");
    }
    app_confirm_free(&w->view);
    json_free(&w->receiver_args);
    free(w);
}
void zcl_native_handle_app_receive(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ar_run(request, reply, NULL, NULL, NULL, NULL);
}
void zcl_native_app_receive_expected(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_receive_identity *expected)
{
    if (!expected) { if (reply) ar_fail(reply, "BAD_INPUT", "Expected receive identity is required."); return; }
    ar_run(request, reply, expected, NULL, NULL, NULL);
}
#if defined(ZCL_TESTING)
void zcl_test_app_receive_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{
    if (presenter) ar_run(request, reply, NULL, presenter, context, NULL);
}
void zcl_test_app_receive_expected(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_receive_identity *expected,
    app_confirm_presenter presenter, void *context)
{
    if (presenter && expected) ar_run(request, reply, expected, presenter, context, NULL);
}
void zcl_test_app_receive_expected_worker(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_receive_identity *expected,
    app_confirm_presenter presenter, void *context, const char *worker_path)
{
    if (presenter && expected && worker_path) ar_run(request, reply, expected, presenter, context, worker_path);
}
#endif
