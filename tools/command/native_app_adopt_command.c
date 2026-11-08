/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Show an owner the exact verified adoption plan before making a copy. */
#include "command/native_command.h"
#include "command/native_app_adopt.h"
#include "command/native_app_installed_copy.h"
#include "command/native_app_confirm.h"
#include "command/native_app_personalize_command.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/presentation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AC_PATH 4400
#define AC_ROOT 65
#define AC_COMMAND "app.adopt"

struct ac_plan {
    char datadir[AC_PATH], copy[AC_PATH];
    char plan[AC_ROOT], release[AC_ROOT], package[AC_ROOT];
    char publisher[67], name[257], version[257];
    char key_path[AC_PATH], local_publisher[67];
    bool key_exists;
    bool has_parent, parent_known, changes_known, changes_truncated;
    char parent_release[AC_ROOT], parent_package[AC_ROOT], changes_unavailable[257];
    int64_t changes_total;
    size_t changes_shown;
    struct { char path[1537], kind[16]; } changes[16];
};
struct ac_work {
    struct ac_plan plan;
    struct app_confirm view;
};

static void ac_fail(struct zcl_command_reply *reply, const char *code,
                    const char *message, const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "adopt", false, false,
        message, detail ? detail : "");
}
static void ac_forward_failure(struct zcl_command_reply *reply,
                               const struct zcl_command_reply *source)
{
    const struct zcl_command_error *e = &source->error;
    zcl_command_reply_fail(reply, source->status, source->exit_code,
        e->code, e->phase, e->retryable, e->mutated, e->message, e->evidence);
}
static bool ac_copy(char *dst, size_t cap, const struct json_value *data,
                    const char *key)
{
    const char *v = json_get_str(json_get(data, key));
    if (!v || !*v || strlen(v) >= cap) return false;
    memcpy(dst, v, strlen(v) + 1);
    return true;
}
static bool ac_root(const char *value, size_t bytes)
{
    uint8_t digest[33];
    return value && bytes <= sizeof(digest) && strlen(value) == bytes * 2 &&
           zcl_hex_decode_lower(value, digest, bytes);
}
static bool ac_change_rows(struct ac_plan *p, const struct json_value *rows)
{
    for (size_t i = 0; i < p->changes_shown; ++i) {
        const struct json_value *row = json_at(rows, i);
        if (!ac_copy(p->changes[i].path, sizeof(p->changes[i].path), row, "path") ||
            !ac_copy(p->changes[i].kind, sizeof(p->changes[i].kind), row, "change")) return false;
        if (strcmp(p->changes[i].kind, "added") && strcmp(p->changes[i].kind, "removed") &&
            strcmp(p->changes[i].kind, "modified")) return false;
    }
    return true;
}
static bool ac_changes(struct ac_plan *p, const struct json_value *data)
{
    const struct json_value *missing = json_get(data, "changes_unavailable");
    if (missing) return missing->type == JSON_STR &&
        ac_copy(p->changes_unavailable, sizeof(p->changes_unavailable), data, "changes_unavailable");
    const struct json_value *count = json_get(data, "changes");
    const struct json_value *rows = json_get(data, "changed_paths");
    const struct json_value *truncated = json_get(data, "changed_paths_truncated");
    if (!count || count->type != JSON_INT || json_get_int(count) < 0 ||
        !rows || rows->type != JSON_ARR || json_size(rows) > 16 ||
        !truncated || truncated->type != JSON_BOOL) return false;
    p->changes_total = json_get_int(count);
    p->changes_shown = json_size(rows);
    p->changes_truncated = json_get_bool(truncated);
    if ((uint64_t)p->changes_total < p->changes_shown ||
        p->changes_truncated != ((uint64_t)p->changes_total > p->changes_shown)) return false;
    if (!ac_change_rows(p, rows)) return false;
    p->changes_known = true;
    return true;
}
static bool ac_parent(struct ac_plan *p, const struct json_value *data)
{
    const struct json_value *parent = json_get(data, "has_parent");
    if (!parent || parent->type != JSON_BOOL) return false;
    p->has_parent = json_get_bool(parent);
    if (!p->has_parent) return true;
    if (!ac_copy(p->parent_release, sizeof(p->parent_release), data, "parent_release_root") ||
        !ac_root(p->parent_release, 32)) return false;
    if (json_get(data, "parent_package_root")) {
        if (!ac_copy(p->parent_package, sizeof(p->parent_package), data, "parent_package_root") ||
            !ac_root(p->parent_package, 32)) return false;
        p->parent_known = true;
    }
    return ac_changes(p, data);
}
static bool ac_plan_fields(struct ac_plan *p, const struct json_value *data,
                           const char *requested)
{
    if (!ac_copy(p->plan, sizeof(p->plan), data, "plan_id") ||
        !ac_copy(p->release, sizeof(p->release), data, "release_root") ||
        !ac_copy(p->package, sizeof(p->package), data, "package_root") ||
        !ac_copy(p->publisher, sizeof(p->publisher), data, "publisher") ||
        !ac_copy(p->name, sizeof(p->name), data, "name") ||
        !ac_copy(p->version, sizeof(p->version), data, "semver") ||
        !ac_copy(p->copy, sizeof(p->copy), data, "copy")) return false;
    return ac_root(p->plan, 32) && ac_root(p->release, 32) &&
           ac_root(p->package, 32) && ac_root(p->publisher, 33) &&
           strcmp(p->release, requested) == 0 && p->copy[0] == '/' && ac_parent(p, data);
}

/* Use the same native adopt handler for both steps: the second invocation
 * must rederive and match the exact displayed plan before writing. */
static bool ac_adopt(const struct zcl_command_request *request,
                     const struct ac_plan *p, bool commit,
                     struct zcl_command_reply *out)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.adopt", NULL);
    if (!spec || !spec->handler || spec->authority != ZCL_COMMAND_AUTH_OWNER) return false;
    struct json_value inner_args;
    json_init(&inner_args); json_set_object(&inner_args);
    bool ok = json_push_kv_str(&inner_args, "root", p->release) &&
              json_push_kv_str(&inner_args, "datadir", p->datadir);
    if (commit) ok = ok && json_push_kv_str(&inner_args, "plan_id", p->plan) &&
                             json_push_kv_bool(&inner_args, "confirm", true);
    if (ok) {
        struct zcl_command_request inner = *request;
        inner.spec = spec; inner.input = &inner_args; inner.invoked_name = spec->path;
        spec->handler(&inner, out);
    }
    json_free(&inner_args);
    return ok;
}
static bool ac_plan_read(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply, struct ac_plan *p)
{
    const char *root = zcl_package_copy_str(request->input, "release_root");
    if (!ac_root(root, 32)) {
        ac_fail(reply, "BAD_RELEASE_ROOT", "Choose an exact persisted release.", AC_COMMAND);
        return false;
    }
    const char *dir = zcl_package_copy_datadir(request->input, reply, AC_COMMAND);
    if (!dir) return false;
    if (strlen(dir) >= sizeof(p->datadir)) {
        ac_fail(reply, "BAD_DATADIR", "The application data directory is too long.", AC_COMMAND);
        return false;
    }
    (void)snprintf(p->datadir, sizeof(p->datadir), "%s", dir);
    (void)snprintf(p->release, sizeof(p->release), "%s", root);
    struct zcl_command_reply plan;
    zcl_command_reply_init(&plan, "zcl.zcode_package_adopt.v1");
    bool ran = ac_adopt(request, p, false, &plan);
    bool ok = ran && plan.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok) ok = ac_plan_fields(p, &plan.data, root);
    if (!ran) ac_fail(reply, "ADOPT_PLAN_FAILED", "Could not prepare the copy plan.", AC_COMMAND);
    else if (plan.status != ZCL_COMMAND_STATUS_PASSED) ac_forward_failure(reply, &plan);
    else if (!ok) ac_fail(reply, "ADOPT_PLAN_INVALID", "The release plan cannot be shown exactly.", AC_COMMAND);
    zcl_command_reply_free(&plan);
    return ok && app_personalize_key_probe(reply, p->key_path, sizeof(p->key_path),
                                           p->local_publisher, &p->key_exists);
}

/* The bitmap renderer clips wide text. Split each verified field into
 * individually width-checked rows and refuse anything that needs a second
 * page: the human must see the whole decision before either action. */
static bool ac_parent_rows(struct zcl_present_model_v1 *m, const struct ac_plan *p)
{
    if (!p->has_parent)
        return app_confirm_field(m, "Parent: ", "None (first release)") &&
               app_confirm_field(m, "Changes: ", "No parent to compare");
    if (!app_confirm_field(m, "Parent release: ", p->parent_release)) return false;
    if (!app_confirm_field(m, "Parent package: ", p->parent_known ? p->parent_package : "Unavailable")) return false;
    if (!p->changes_known) return app_confirm_field(m, "Changes unavailable: ", p->changes_unavailable);
    char count[96];
    (void)snprintf(count, sizeof(count), "%lld total, %zu shown%s",
                   (long long)p->changes_total, p->changes_shown,
                   p->changes_truncated ? " (truncated)" : " (complete)");
    if (!app_confirm_field(m, "Changed files: ", count)) return false;
    for (size_t i = 0; i < p->changes_shown; ++i) {
        char label[32];
        (void)snprintf(label, sizeof(label), "%s: ", p->changes[i].kind);
        if (!app_confirm_field(m, label, p->changes[i].path)) return false;
    }
    return true;
}
static bool ac_personal_rows(struct zcl_present_model_v1 *m, const struct ac_plan *p)
{
    char namespace_name[64], personal_name[257];
    const char *slash = strchr(p->name, '/');
    const char *target = "Assigned from your new local identity after confirmation.";
    if (p->key_exists) {
        if (!slash || !app_personalize_namespace(p->local_publisher, namespace_name, sizeof(namespace_name)))
            return false;
        int n = snprintf(personal_name, sizeof(personal_name), "%s/%s", namespace_name, slash + 1);
        if (n <= 0 || (size_t)n >= sizeof(personal_name)) return false;
        target = personal_name;
    }
    return app_confirm_field(m, "Personal copy: ", "Save a personal publisher name; keep the original source and history.") &&
        app_confirm_field(m, "Local identity: ", p->key_exists ? p->local_publisher : "Create a local signing identity after confirmation.") &&
        app_confirm_field(m, "Personal package: ", target) &&
        app_confirm_field(m, "Sharing: ", "Nothing is signed or published by this action.");
}
static bool ac_model(struct ac_work *w, char *why, size_t cap)
{
    w->view.window_title = "Make my copy";
    struct zcl_present_model_v1 *m = &w->view.model;
    const struct ac_plan *p = &w->plan;
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "adopt-%.12s", p->plan);
    (void)snprintf(m->title, sizeof(m->title), "Make my copy?");
    (void)snprintf(m->summary, sizeof(m->summary), "Review all pages. Nothing runs now.");
    m->action_count = 4;
    app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CONFIRM, "make-copy", "Make my copy");
    if (!app_confirm_field(m, "Permission: ", "Allow future builds and requested runs; no code runs now.") ||
        !app_confirm_field(m, "Name: ", p->name) || !app_confirm_field(m, "Version: ", p->version) ||
        !app_confirm_field(m, "Publisher: ", p->publisher) || !app_confirm_field(m, "Release: ", p->release) ||
        !app_confirm_field(m, "Package: ", p->package) || !app_confirm_field(m, "Destination: ", p->copy) ||
        !ac_parent_rows(m, p) || !ac_personal_rows(m, p)) {
        (void)snprintf(why, cap, "The exact plan contains text that cannot be displayed.");
        return false;
    }
    return app_confirm_prepare(&w->view, why, cap);
}
static bool ac_commit_matches(const struct ac_plan *p, const struct json_value *data)
{
    const char *copy = zcl_package_copy_str(data, "copy");
    const char *release = zcl_package_copy_str(data, "release_root");
    const char *package = zcl_package_copy_str(data, "package_root");
    const char *root = zcl_package_copy_str(data, "root_commit");
    return copy && release && package && root && ac_root(root, 32) &&
        !strcmp(copy, p->copy) && !strcmp(release, p->release) && !strcmp(package, p->package);
}
static bool ac_key_matches(struct zcl_command_reply *reply, const struct ac_plan *p)
{
    char path[AC_PATH], publisher[67]; bool exists = false;
    if (!app_personalize_key_probe(reply, path, sizeof(path), publisher, &exists)) return false;
    if (exists == p->key_exists && !strcmp(path, p->key_path) &&
        !strcmp(publisher, p->local_publisher)) return true;
    ac_fail(reply, "PUBLISHER_CHANGED", "The local identity changed; review a fresh copy plan.", p->copy);
    return false;
}
static bool ac_personal_plan_matches(const struct ac_plan *p, const struct json_value *data)
{
    const char *path = zcl_package_copy_str(data, "key_path");
    const char *publisher = json_get_str(json_get(data, "publisher_fingerprint"));
    const struct json_value *exists = json_get(data, "key_exists");
    return path && publisher && exists && exists->type == JSON_BOOL &&
        !strcmp(path, p->key_path) && !strcmp(publisher, p->local_publisher) &&
        json_get_bool(exists) == p->key_exists;
}
/* Always initializes result, including unavailable-handler failure; the caller
 * may unconditionally inspect/free it. Reinitialization after free is intentional. */
static bool ac_personal_call(const struct zcl_command_request *request,
    const struct ac_plan *p, const char *root, struct zcl_command_reply *result)
{
    zcl_command_reply_init(result, "zcl.app_personalize.v1");
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "app.personalize", NULL);
    if (!spec || !spec->handler || spec->authority != ZCL_COMMAND_AUTH_OWNER) return false;
    struct json_value inner_args; json_init(&inner_args); json_set_object(&inner_args);
    bool ok = json_push_kv_str(&inner_args, "copy", p->copy) &&
        json_push_kv_str(&inner_args, "datadir", p->datadir) &&
        json_push_kv_str(&inner_args, "version", root) &&
        json_push_kv_str(&inner_args, "expected_head", root);
    struct zcl_command_request inner = *request;
    inner.spec = spec; inner.input = &inner_args; inner.invoked_name = spec->path;
    if (ok) spec->handler(&inner, result);
    if (ok && result->status == ZCL_COMMAND_STATUS_PASSED) {
        const char *plan = zcl_package_copy_str(&result->data, "plan_id");
        ok = ac_personal_plan_matches(p, &result->data) && ac_root(plan, 32) &&
            json_push_kv_str(&inner_args, "plan_id", plan) &&
            json_push_kv_bool(&inner_args, "confirm", true);
        if (ok) {
            zcl_command_reply_free(result);
            zcl_command_reply_init(result, "zcl.app_personalize.v1");
            spec->handler(&inner, result);
        }
    }
    json_free(&inner_args); return ok;
}
static void ac_personalize(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct ac_plan *p, const char *root)
{
    struct zcl_command_reply result;
    bool called = ac_personal_call(request, p, root, &result);
    if (!called) ac_fail(reply, "PERSONAL_COPY_INCOMPLETE",
        "The copy exists; its personal identity could not be confirmed. Review it before continuing.", p->copy);
    else if (result.status != ZCL_COMMAND_STATUS_PASSED) ac_forward_failure(reply, &result);
    else {
        const char *version = zcl_package_copy_str(&result.data, "version");
        const char *name = zcl_package_copy_str(&result.data, "namespace");
        if (!ac_root(version, 32) || !name ||
            !json_push_kv_str(&reply->data, "version", version) ||
            !json_push_kv_str(&reply->data, "namespace", name))
            ac_fail(reply, "PERSONAL_COPY_REPLY_FAILED",
                "The personal copy may be saved; inspect its history before continuing.", p->copy);
    }
    /* The original adopted copy already exists even if personalization failed. */
    reply->error.mutated = true;
    zcl_command_reply_free(&result);
}
static void ac_commit(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const struct ac_plan *p)
{
    if (!ac_key_matches(reply, p)) return;
    struct zcl_command_reply result;
    zcl_command_reply_init(&result, "zcl.zcode_package_adopt.v1");
    bool called = ac_adopt(request, p, true, &result);
    if (!called) ac_fail(reply, "ADOPT_COMMIT_FAILED", "Could not submit the approved copy plan.", AC_COMMAND);
    else if (result.status != ZCL_COMMAND_STATUS_PASSED) ac_forward_failure(reply, &result);
    else if (!ac_commit_matches(p, &result.data)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "ADOPT_RESULT_MISMATCH", "adopt", false, true,
            "The copy completed but its result did not match the displayed plan.", p->copy);
    } else {
        const char *root = zcl_package_copy_str(&result.data, "root_commit");
        bool published = json_push_kv_str(&reply->data, "copy", p->copy) &&
            json_push_kv_str(&reply->data, "root_commit", root) &&
            json_push_kv_str(&reply->data, "release_root", p->release) &&
            json_push_kv_str(&reply->data, "package_root", p->package) &&
            json_push_kv_bool(&reply->data, "adopted", true) &&
            json_push_kv_bool(&reply->data, "executed", false);
        if (!published)
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "ADOPT_REPLY_FAILED", "adopt", false, true,
                "The copy was made but its result could not be returned.", p->copy);
        else ac_personalize(request, reply, p, root);
    }
    zcl_command_reply_free(&result);
}

static void ac_run(const struct zcl_command_request *request,
                   struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{
    if (!request || !reply) return;
    struct ac_work *w = zcl_calloc(1, sizeof(*w), "app-adopt");
    if (!w) { ac_fail(reply, "OUT_OF_MEMORY", "Cannot prepare the confirmation.", AC_COMMAND); return; }
    if (!ac_plan_read(request, reply, &w->plan)) { free(w); return; }
    char why[256] = {0};
    if (!ac_model(w, why, sizeof(why))) {
        ac_fail(reply, "CONFIRMATION_UNAVAILABLE", "Cannot display the exact copy plan.", why);
        app_confirm_free(&w->view); free(w); return;
    }
    bool shown = app_confirm_show(&w->view, presenter, context, why, sizeof(why));
    app_confirm_free(&w->view);
    if (!shown) ac_fail(reply, "CONFIRMATION_UNAVAILABLE", "Cannot open the confirmation window.", why);
    else if (w->view.confirmed) ac_commit(request, reply, &w->plan);
    else (void)json_push_kv_str(&reply->data, "status", "canceled");
    free(w);
}

void zcl_native_handle_app_adopt(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    if (request && json_get(request->input, "name")) {
        app_installed_copy_run(request, reply, NULL, NULL);
        return;
    }
    ac_run(request, reply, NULL, NULL);
}

void app_adopt_installed_confirmed(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const uint8_t package[32],
    const char *key_path, const char *publisher)
{
    if (!key_path || key_path[0] != '/' || !ac_root(publisher, 33)) {
        ac_fail(reply, "PUBLISHER_CHANGED", "The seeded publisher identity is unavailable.", AC_COMMAND);
        return;
    }
    struct ac_plan *p = zcl_calloc(1, sizeof(*p), "app-installed-adopt");
    if (!p) { ac_fail(reply, "OUT_OF_MEMORY", "Cannot prepare the personal copy.", AC_COMMAND); return; }
    uint8_t actual[32];
    if (ac_plan_read(request, reply, p)) {
        if (!zcl_hex_decode_lower(p->package, actual, sizeof(actual)) || memcmp(actual, package, 32))
            ac_fail(reply, "PACKAGE_CHANGED", "The seeded release does not match the approved installed source.", p->release);
        else if (!p->key_exists || strcmp(p->key_path, key_path) ||
                 strcmp(p->local_publisher, publisher))
            ac_fail(reply, "PUBLISHER_CHANGED", "The publisher changed after the approved source was saved.", p->release);
        else ac_commit(request, reply, p);
    }
    free(p);
}
#if defined(ZCL_TESTING)
void zcl_test_app_adopt_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, zcl_test_app_adopt_presenter presenter, void *context)
{
    if (presenter && request && json_get(request->input, "name"))
        app_installed_copy_run(request, reply, presenter, context);
    else if (presenter) ac_run(request, reply, presenter, context);
}
bool zcl_test_app_adopt_model(const struct json_value *plan,
    struct zcl_present_model_v1 *model, uint32_t *page_count)
{
    if (!plan || !model || !page_count) return false;
    struct ac_work *w = zcl_calloc(1, sizeof(*w), "app-adopt-test-model");
    if (!w) return false;
    const char *root = zcl_package_copy_str(plan, "release_root");
    char why[256];
    bool ok = root && ac_plan_fields(&w->plan, plan, root) && ac_model(w, why, sizeof(why));
    if (ok) { *model = w->view.model; *page_count = w->view.page_count; }
    app_confirm_free(&w->view); free(w); return ok;
}
#endif
