/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bind a kept selection to read-only planning and local owner consent. */
#include "command/native_app_personalize_view.h"
#include "command/native_app_personalize_command.h"
#include "command/native_app_launch.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "vcs/package_release.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define APV_COMMAND "app.personalize"
struct apv_work {
    struct app_confirm view;
    struct app_launch_env env;
    struct app_selection selection;
    struct json_value input;
    struct zcl_command_reply plan;
    char name[APP_SELECTION_ID_MAX + 1], version[65], head[65];
    uint64_t revision;
};
static bool apv_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_package_copy_fail(reply, code, false, why, APV_COMMAND);
    return false;
}
static bool apv_inputs(struct apv_work *w, const struct json_value *in,
                       struct zcl_command_reply *reply)
{
    if (!in || in->type != JSON_OBJ || in->num_children != 2)
        return apv_fail(reply, "BAD_INPUT", "Provide only kept name and expected_revision.");
    unsigned seen = 0;
    for (size_t i = 0; i < in->num_children; ++i) {
        unsigned bit = !strcmp(in->keys[i], "name") ? 1u :
                       !strcmp(in->keys[i], "expected_revision") ? 2u : 0u;
        if (!bit || (seen & bit))
            return apv_fail(reply, "BAD_INPUT", "Duplicate, mixed or unknown personalization inputs.");
        seen |= bit;
    }
    const struct json_value *revision = json_get(in, "expected_revision");
    const char *name = zcl_package_copy_str(in, "name");
    if (!name || !*name || strlen(name) > APP_SELECTION_ID_MAX ||
        !revision || revision->type != JSON_INT || json_get_int(revision) < 1)
        return apv_fail(reply, "BAD_INPUT", "Name an existing kept revision using a positive integer.");
    memcpy(w->name, name, strlen(name) + 1);
    w->revision = (uint64_t)json_get_int(revision);
    return true;
}
static bool apv_selection(struct apv_work *w, struct zcl_command_reply *reply)
{
    char why[256] = {0};
    if (!app_launch_env_from_process(&w->env, why, sizeof(why)))
        return apv_fail(reply, "STATE_FAILED", "Cannot resolve kept app state.");
    if (app_selection_load(w->env.state_dir, w->name, &w->selection) != APP_SELECTION_OK)
        return apv_fail(reply, "SELECTION_UNAVAILABLE", "The kept selection is missing or unreadable.");
    if (w->selection.revision != w->revision)
        return apv_fail(reply, "SELECTION_STALE", "The kept revision changed; request fresh context.");
    zcl_hex_encode(w->selection.version, 32, w->version);
    return true;
}
static bool apv_directories(struct apv_work *w, struct zcl_command_reply *reply)
{
    char copy[APP_SELECTION_PATH_MAX], data[APP_SELECTION_PATH_MAX];
    bool ok = platform_directory_canonical_real(w->selection.copy, copy, sizeof(copy)) &&
        platform_directory_canonical_real(w->selection.datadir, data, sizeof(data)) &&
        !strcmp(copy, w->selection.copy) && !strcmp(data, w->selection.datadir);
    return ok || apv_fail(reply, "COPY_CHANGED", "Kept copy or datadir no longer names its canonical directory.");
}
static bool apv_source(struct apv_work *w, struct zcl_command_reply *reply)
{
    if (!apv_directories(w, reply)) return false;
    struct zcl_package_copy copy = {0};
    if (!zcl_package_copy_open_selected_as(w->selection.copy, ZCL_PACKAGE_COPY_READ,
            &copy, reply, APV_COMMAND, w->version)) return false;
    bool same = !memcmp(copy.fork_version, w->selection.fork, 32) &&
        !memcmp(copy.parent_release, w->selection.parent, 32) &&
        !memcmp(copy.selected_version, w->selection.version, 32);
    zcl_hex_encode(copy.head_version, 32, w->head);
    zcl_package_copy_close(&copy);
    return same || apv_fail(reply, "SELECTION_MISMATCH", "The selected source ancestry changed.");
}
static bool apv_plan(const struct zcl_command_request *request,
                     struct apv_work *w, struct zcl_command_reply *reply)
{
    json_set_object(&w->input);
    bool ok = json_push_kv_str(&w->input, "copy", w->selection.copy) &&
        json_push_kv_str(&w->input, "datadir", w->selection.datadir) &&
        json_push_kv_str(&w->input, "version", w->version) &&
        json_push_kv_str(&w->input, "expected_head", w->head);
    if (!ok) return apv_fail(reply, "OUT_OF_MEMORY", "Cannot prepare personalization inputs.");
    struct zcl_command_request inner = *request;
    inner.input = &w->input;
    zcl_native_handle_app_personalize(&inner, &w->plan);
    if (w->plan.status != ZCL_COMMAND_STATUS_PASSED) {
        app_confirm_forward_failure(reply, &w->plan); return false;
    }
    return true;
}
/* Measure a maximum complete native success data object before consent.
 * The registry allowance includes maximum envelope/timing widths. Direct
 * test callers use a conservative 4096-byte data ceiling within the 8192 cap. */
static bool apv_project_success(struct json_value *out, const struct apv_work *w)
{
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1], space[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1];
    uint8_t root[32]; memset(root, 0xff, sizeof(root));
    memset(name, 'a', sizeof(name) - 1); name[sizeof(name) - 1] = 0;
    memset(space, 'a', sizeof(space) - 1); space[sizeof(space) - 1] = 0;
    json_set_object(out);
    return zcl_package_copy_push_root(out, "version", root) &&
        zcl_package_copy_push_root(out, "source_root", root) &&
        json_push_kv_str(out, "name", name) && json_push_kv_str(out, "namespace", space) &&
        json_push_kv_bool(out, "key_created", false) && json_push_kv_bool(out, "changed", false) &&
        json_push_kv_str(out, "copy", w->selection.copy) &&
        json_push_kv_str(out, "datadir", w->selection.datadir);
}
static bool apv_receipt_bound(const struct zcl_command_request *request,
    struct apv_work *w, struct zcl_command_reply *reply)
{
    struct json_value projected; json_init(&projected);
    bool ok = apv_project_success(&projected, w);
    size_t bytes = ok ? json_write(&projected, NULL, 0) : 0;
    json_free(&projected);
    if (!ok || !bytes) return apv_fail(reply, "OUT_OF_MEMORY", "Cannot reserve the successor receipt.");
    size_t limit = request->success_data_budget_provided ? request->success_data_budget : 4096u;
    if (!request->success_data_budget_provided && request->budget_bytes &&
        request->budget_bytes < ZCL_COMMAND_LIST_BUDGET)
        return apv_fail(reply, "RECEIPT_TOO_LARGE", "A reduced reply budget needs the registry's envelope allowance.");
    return bytes <= limit || apv_fail(reply, "RECEIPT_TOO_LARGE",
        "The exact successor and copy locations exceed the reply allowance; nothing was personalized.");
}
static bool apv_plan_field(struct apv_work *w, const char *label, const char *key)
{
    const char *value = zcl_package_copy_str(&w->plan.data, key);
    return value && app_confirm_field(&w->view.model, label, value);
}
static bool apv_identity_fields(struct apv_work *w)
{
    char revision[32];
    (void)snprintf(revision, sizeof(revision), "%llu", (unsigned long long)w->revision);
    return app_confirm_field(&w->view.model, "Kept app: ", w->name) &&
        app_confirm_field(&w->view.model, "Kept revision: ", revision) &&
        apv_plan_field(w, "Copy: ", "copy") &&
        app_confirm_field(&w->view.model, "Datadir: ", w->selection.datadir) &&
        apv_plan_field(w, "Saved version: ", "version") &&
        apv_plan_field(w, "Source: ", "source_root") &&
        apv_plan_field(w, "Current HEAD: ", "head_version") &&
        apv_plan_field(w, "Original name: ", "original_name");
}
static bool apv_namespace_fields(struct apv_work *w)
{
    const struct json_value *pending = json_get(&w->plan.data, "namespace_pending");
    if (!pending || pending->type != JSON_BOOL) return false;
    if (json_get_bool(pending))
        return app_confirm_field(&w->view.model, "Identity: ",
            "Create a local publishing key after confirmation; personal namespace is pending.");
    return apv_plan_field(w, "Publisher: ", "publisher_fingerprint") &&
        apv_plan_field(w, "Personal namespace: ", "namespace") &&
        apv_plan_field(w, "Personal name: ", "name");
}
static bool apv_model(struct apv_work *w, bool prepare, char *why, size_t cap)
{
    const char *plan = zcl_package_copy_str(&w->plan.data, "plan_id");
    uint8_t decoded[32];
    if (!plan || strlen(plan) != 64 || !zcl_hex_decode_lower(plan, decoded, sizeof(decoded)))
        return false;
    struct zcl_present_model_v1 *m = &w->view.model;
    w->view.window_title = "Personalize kept app";
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "personalize-%.12s", plan);
    (void)snprintf(m->title, sizeof(m->title), "%s", prepare ?
        "Prepare your copy for changes?" : "Personalize this saved version?");
    (void)snprintf(m->summary, sizeof(m->summary), "Review every page before confirming.");
    m->action_count = 4;
    app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CONFIRM, "personalize", "Personalize");
    return (!prepare || app_confirm_field(m, "Your choice: ",
            "Prepare a personal draft for your AI so you can share the version you later Keep. Your current kept app stays available.")) &&
        apv_identity_fields(w) && apv_namespace_fields(w) &&
        app_confirm_field(m, "Effect: ",
            "Save a metadata-only successor, or return the unchanged version if already personal. Working files and Keep stay unchanged. No build, run or share.") &&
        app_confirm_prepare(&w->view, why, cap);
}
static bool apv_still_selected(struct apv_work *w, struct zcl_command_reply *reply)
{
    struct app_selection now;
    if (app_selection_load(w->env.state_dir, w->name, &now) != APP_SELECTION_OK)
        return apv_fail(reply, "SELECTION_STALE", "The kept selection is no longer readable.");
    bool same = now.revision == w->selection.revision &&
        !strcmp(now.copy, w->selection.copy) && !strcmp(now.datadir, w->selection.datadir) &&
        !memcmp(now.version, w->selection.version, 32) && !memcmp(now.fork, w->selection.fork, 32) &&
        !memcmp(now.parent, w->selection.parent, 32) && !memcmp(now.package, w->selection.package, 32) &&
        !memcmp(now.env, w->selection.env, 32) && !memcmp(now.dependencies, w->selection.dependencies, 32) &&
        !memcmp(now.record, w->selection.record, 32) && !memcmp(now.image, w->selection.image, 32);
    return same || apv_fail(reply, "SELECTION_STALE", "The kept choice changed; review a new plan.");
}
static void apv_commit(const struct zcl_command_request *request,
                       struct apv_work *w, struct zcl_command_reply *reply)
{
    if (!apv_still_selected(w, reply) || !apv_directories(w, reply)) return;
    const char *plan = zcl_package_copy_str(&w->plan.data, "plan_id");
    if (!json_push_kv_str(&w->input, "plan_id", plan) ||
        !json_push_kv_bool(&w->input, "confirm", true)) {
        apv_fail(reply, "OUT_OF_MEMORY", "Cannot prepare the confirmed plan."); return;
    }
    struct zcl_command_reply result;
    zcl_command_reply_init(&result, "zcl.app_personalize.v1");
    struct zcl_command_request inner = *request;
    inner.input = &w->input;
    zcl_native_handle_app_personalize(&inner, &result);
    if (result.status != ZCL_COMMAND_STATUS_PASSED) app_confirm_forward_failure(reply, &result);
    else {
        json_free(&reply->data); reply->data = result.data; json_init(&result.data);
        reply->error = result.error;
        if (!json_push_kv_str(&reply->data, "copy", w->selection.copy) ||
            !json_push_kv_str(&reply->data, "datadir", w->selection.datadir)) {
            const char *version = zcl_package_copy_str(&reply->data, "version");
            zcl_package_copy_fail(reply, "REPLY_FAILED", result.error.mutated,
                "Personalization returned a saved version but its build locations could not be encoded; reconcile before retrying.",
                version ? version : APV_COMMAND);
        }
    }
    zcl_command_reply_free(&result);
}
static void apv_prepared_reply(struct apv_work *w, struct zcl_command_reply *reply)
{
    if (!apv_still_selected(w, reply) ||
        !json_push_kv_str(&reply->data, "version", w->version))
        if (reply->status == ZCL_COMMAND_STATUS_PASSED)
            apv_fail(reply, "OUT_OF_MEMORY", "Cannot describe the prepared source.");
}
static void apv_offer(const struct zcl_command_request *request, struct apv_work *w,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context, bool prepare)
{
    char why[256] = {0};
    const struct json_value *personal = json_get(&w->plan.data, "already_personalized");
    if (prepare && personal && personal->type == JSON_BOOL && json_get_bool(personal))
        apv_prepared_reply(w, reply);
    else if (!apv_model(w, prepare, why, sizeof(why)) ||
        !app_confirm_show(&w->view, presenter, context, why, sizeof(why)))
        apv_fail(reply, "CONFIRMATION_UNAVAILABLE", "The exact personalization plan could not be displayed.");
    else if (w->view.confirmed) apv_commit(request, w, reply);
    else if (!json_push_kv_str(&reply->data, "status", "canceled"))
        apv_fail(reply, "OUT_OF_MEMORY", "Cannot describe cancellation.");
}
static void apv_run(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
                    bool prepare)
{
    if (!request || !reply) return;
    struct apv_work *w = zcl_calloc(1, sizeof(*w), "app-personalize-view");
    if (!w) { apv_fail(reply, "OUT_OF_MEMORY", "Cannot prepare owner confirmation."); return; }
    json_init(&w->input);
    zcl_command_reply_init(&w->plan, "zcl.app_personalize.v1");
    if (apv_inputs(w, request->input, reply) && apv_selection(w, reply) &&
        apv_source(w, reply) && apv_plan(request, w, reply) && apv_receipt_bound(request, w, reply)) {
        apv_offer(request, w, reply, presenter, context, prepare);
    }
    app_confirm_free(&w->view); zcl_command_reply_free(&w->plan);
    json_free(&w->input); free(w);
}
void app_personalize_view_run(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{ apv_run(request, reply, NULL, NULL, false); }
void app_personalize_view_prepare(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{ apv_run(request, reply, NULL, NULL, true); }
void app_personalize_view_prepare_present(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{ apv_run(request, reply, presenter, context, true); }
#if defined(ZCL_TESTING)
void zcl_test_app_personalize_view_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{ if (presenter) apv_run(request, reply, presenter, context, false); }
void zcl_test_app_personalize_prepare(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{ if (presenter) apv_run(request, reply, presenter, context, true); }
#endif
