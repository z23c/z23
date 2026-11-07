/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bind installed source to native consent before local publication and copying. */
#include "command/native_app_installed_copy.h"
#include "command/native_app_commit_progress.h"
#include "command/app_installed_source_resolve.h"
#include "command/native_app_adopt.h"
#include "command/native_app_seed_installed.h"
#include "command/native_app_receive_flow.h"
#include "command/native_app_personalize_command.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/temp_directory.h"
#include "keys/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct aic_work {
    struct app_confirm view;
    struct app_installed_source source;
    char datadir[4400], key[4400], publisher[67];
    bool key_exists;
#if defined(ZCL_TESTING)
    const struct app_commit_progress_test_hooks *test_hooks;
#endif
};
static bool aic_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_package_copy_fail(reply, code, reply->error.mutated, why, "app.adopt");
    return false;
}
static bool aic_keys(const struct json_value *in)
{
    if (!in || in->type != JSON_OBJ || in->num_children < 1 || in->num_children > 2) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < in->num_children; ++i) {
        unsigned bit = !strcmp(in->keys[i], "name") ? 1u : !strcmp(in->keys[i], "datadir") ? 2u : 0;
        if (!bit || (seen & bit) || in->children[i].type != JSON_STR) return false;
        seen |= bit;
    }
    const char *name = zcl_package_copy_str(in, "name");
    return name && !strcmp(name, "skycombat");
}
static bool aic_project_receipt(struct json_value *data, const char *dir)
{
    char copy[4700], suffix[256], root[65], space[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1];
    memset(suffix, 'a', sizeof(suffix) - 1); suffix[sizeof(suffix) - 1] = 0;
    memset(root, 'f', sizeof(root) - 1); root[sizeof(root) - 1] = 0;
    memset(space, 'a', sizeof(space) - 1); space[sizeof(space) - 1] = 0;
    int n = snprintf(copy, sizeof(copy), "%s/copies/%s", dir, suffix);
    return n > 0 && (size_t)n < sizeof(copy) &&
        json_push_kv_str(data, "copy", copy) && json_push_kv_str(data, "root_commit", root) &&
        json_push_kv_str(data, "release_root", root) && json_push_kv_str(data, "package_root", root) &&
        json_push_kv_bool(data, "adopted", true) && json_push_kv_bool(data, "executed", false) &&
        json_push_kv_str(data, "version", root) && json_push_kv_str(data, "namespace", space);
}
static bool aic_receipt_bound(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *dir)
{
    struct json_value data; json_init(&data); json_set_object(&data);
    bool ok = aic_project_receipt(&data, dir);
    size_t bytes = ok ? json_write(&data, NULL, 0) : 0;
    json_free(&data);
    if (!ok || !bytes) return aic_fail(reply, "OUT_OF_MEMORY", "Cannot reserve the personal copy receipt.");
    if (!request->success_data_budget_provided && request->budget_bytes &&
        request->budget_bytes < ZCL_COMMAND_LIST_BUDGET)
        return aic_fail(reply, "RECEIPT_TOO_LARGE", "A reduced reply budget needs the registry's envelope allowance.");
    size_t allowance = request->success_data_budget_provided ? request->success_data_budget : 12288u;
    /* Existing compact worker/Keep report plus worst-case JSON escaping of
     * one retained private scratch path on constructor cleanup failure. */
    const size_t continuation = 8192u + 6u * PLATFORM_TEMP_PATH_MAX;
    return (bytes <= allowance && continuation <= allowance - bytes) ||
        aic_fail(reply, "RECEIPT_TOO_LARGE", "The copy and preview receipts exceed the available reply size.");
}
static bool aic_inputs(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, struct aic_work *w)
{
    if (!aic_keys(request->input)) return aic_fail(reply, "BAD_INPUT", "Provide installed app name skycombat and optional datadir only.");
    const char *dir = zcl_package_copy_datadir(request->input, reply, "app.adopt");
    if (!dir) return false;
    if (dir[0] != '/' || strlen(dir) >= sizeof(w->datadir))
        return aic_fail(reply, "BAD_DATADIR", "An absolute bounded application data directory is required.");
    memcpy(w->datadir, dir, strlen(dir) + 1);
    if (!aic_receipt_bound(request, reply, dir)) return false;
    char why[256];
    if (!app_installed_source_resolve("skycombat", &w->source, why, sizeof(why)))
        return aic_fail(reply, "INSTALLED_SOURCE_UNAVAILABLE", why);
    return app_personalize_key_probe(reply, w->key, sizeof(w->key), w->publisher, &w->key_exists);
}
static bool aic_root(struct zcl_present_model_v1 *m, const char *label, const uint8_t root[32])
{
    char hex[65]; zcl_hex_encode(root, 32, hex);
    return app_confirm_field(m, label, hex);
}
static bool aic_model(struct aic_work *w, char *why, size_t cap)
{
    struct zcl_present_model_v1 *m = &w->view.model;
    w->view.window_title = "Make my copy";
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "installed-copy");
    (void)snprintf(m->title, sizeof(m->title), "Make Sky Combat yours?");
    (void)snprintf(m->summary, sizeof(m->summary), "Create an editable personal copy from this installed version.");
    zcl_hex_encode(w->source.projection_sha3, 32, m->exact_root);
    m->action_count = 4;
    app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CONFIRM, "make-copy", "Make my copy");
    return app_confirm_field(m, "App: ", w->source.app) &&
        app_confirm_field(m, "Data directory: ", w->datadir) &&
        app_confirm_field(m, "Destination: ", "A new available name in this directory's copies folder.") &&
        app_confirm_field(m, "Local identity: ", w->key_exists ? w->publisher : "Create a private local publishing key. No signup.") &&
        app_confirm_field(m, "Effect: ", "Verify source, sign and save a local release, then create your personal copy. No network publication or execution now.") &&
        app_confirm_field(m, "Permission: ", "Allow future builds and requested runs of your copy.") &&
        aic_root(m, "Source package: ", w->source.package_root) &&
        aic_root(m, "Installed image: ", w->source.build.image_sha3) &&
        app_confirm_prepare(&w->view, why, cap);
}
static bool aic_recheck(struct aic_work *w, struct zcl_command_reply *reply)
{
    struct app_installed_source current; app_installed_source_init(&current);
    char why[256], key[4400], publisher[67]; bool exists = false;
    bool ok = app_installed_source_resolve("skycombat", &current, why, sizeof(why)) &&
        !memcmp(current.projection_sha3, w->source.projection_sha3, 32);
    app_installed_source_free(&current);
    if (!ok) return aic_fail(reply, "INSTALLED_SOURCE_CHANGED", "The installed app changed; review a fresh copy request.");
    if (!app_personalize_key_probe(reply, key, sizeof(key), publisher, &exists)) return false;
    return (exists == w->key_exists && !strcmp(key, w->key) && !strcmp(publisher, w->publisher)) ||
        aic_fail(reply, "PUBLISHER_CHANGED", "The local publishing identity changed; review a fresh request.");
}
static void aic_adopt(const struct zcl_command_request *request, struct aic_work *w,
    const struct zcl_command_reply *seed, struct zcl_command_reply *reply)
{
    const char *release = zcl_package_copy_str(&seed->data, "release_id");
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = release && json_push_kv_str(&input, "release_root", release) &&
        json_push_kv_str(&input, "datadir", w->datadir);
    if (ok) {
        struct zcl_command_request inner = *request; inner.input = &input;
        app_adopt_installed_confirmed(&inner, reply, w->source.package_root,
            zcl_package_copy_str(&seed->data, "key_path"),
            zcl_package_copy_str(&seed->data, "publisher"));
    } else (void)aic_fail(reply, "COPY_INCOMPLETE", "The local release was saved but the copy request could not be prepared.");
    reply->error.mutated |= seed->error.mutated;
    json_free(&input);
}
static void aic_commit(const struct zcl_command_request *request, struct aic_work *w,
    struct zcl_command_reply *reply)
{
    if (!aic_recheck(w, reply)) return;
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "app", w->source.app) &&
        json_push_kv_str(&input, "datadir", w->datadir);
    struct zcl_command_reply seed; zcl_command_reply_init(&seed, "zcl.app_seed.v1");
    if (ok) {
        struct zcl_command_request inner = *request; inner.input = &input;
        const struct app_seed_installed_owner owner = {
            .key_path = w->key, .publisher = w->publisher, .exists = w->key_exists,
        };
        app_seed_installed_commit(&inner, &seed, &w->source, &owner);
        if (seed.status != ZCL_COMMAND_STATUS_PASSED) app_confirm_forward_failure(reply, &seed);
        else aic_adopt(request, w, &seed, reply);
    } else (void)aic_fail(reply, "OUT_OF_MEMORY", "Cannot prepare the approved copy.");
    zcl_command_reply_free(&seed); json_free(&input);
}
static const struct app_commit_progress_labels aic_progress_labels = {
    .name = "installed-copy", .request_id = "installed-copy-progress", .title = "Making your copy",
    .summary = "Saving your approved personal copy. Closing waits for completion; it does not undo saved changes.",
    .finishing = "Finishing your copy", .allocation = "installed-copy/progress",
    .unavailable = "COPY_PROGRESS_UNAVAILABLE", .start_failed = "COPY_THREAD_FAILED", .join_failed = "COPY_JOIN_FAILED",
};
static void aic_commit_worker(void *work, const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    aic_commit(request, work, reply);
}
static bool aic_progress_receipt(struct zcl_command_reply *reply,
    const struct app_commit_progress_outcome *out)
{
    bool offer = out->joined && out->ui_ok && !out->close_requested;
    if (out->started && !offer && reply->status == ZCL_COMMAND_STATUS_PASSED) {
        if (!json_push_kv_str(&reply->data, "continuation", "adopted") ||
            !json_push_kv_bool(&reply->data, "continuation_executed", false) ||
            !json_push_kv_bool(&reply->data, "copy_progress_ui_failed", !out->ui_ok))
            (void)aic_fail(reply, "OUT_OF_MEMORY", "Copy saved, but progress outcome could not be described; inspect retained state.");
    }
    return offer;
}
static bool aic_progress_commit(const struct zcl_command_request *request,
    struct aic_work *w, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context)
{
#if !defined(_WIN32)
    /* Plain global guard, not pthread_once. Main owner excludes concurrent
     * ecc_start/ecc_stop through commit completion; no operator key is created. */
    if (!ecc_start_once())
        return aic_fail(reply, "CRYPTO_UNAVAILABLE", "Cannot initialize signing machinery; copying was not started.");
#endif
    struct app_commit_progress_outcome out = app_commit_progress_run(
        request, reply, aic_commit_worker, w, &aic_progress_labels, presenter, context
#ifdef ZCL_TESTING
        , w->test_hooks
#endif
    );
    return aic_progress_receipt(reply, &out);
}
#if defined(ZCL_TESTING) && !defined(_WIN32)
bool zcl_test_app_installed_copy_progress(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
    const struct app_installed_copy_test_hooks *hooks)
{
    if (!request || !reply || !hooks || !hooks->commit) return false;
    struct aic_work *w = zcl_calloc(1, sizeof(*w), "installed-copy/test-work");
    if (!w) return aic_fail(reply, "OUT_OF_MEMORY", "Cannot allocate progress fixture.");
    const struct app_commit_progress_test_hooks shared = {
        .commit = hooks->commit, .context = hooks->context,
        .worker_alloc_label = hooks->worker_alloc_label, .refuse_start = hooks->refuse_start,
    };
    w->test_hooks = &shared;
    bool offer = aic_progress_commit(request, w, reply, presenter, context);
    free(w);
    return offer;
}
#endif
void app_installed_copy_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{
    if (!request || !reply) return;
    struct aic_work *w = zcl_calloc(1, sizeof(*w), "app-installed-copy");
    if (!w) { (void)aic_fail(reply, "OUT_OF_MEMORY", "Cannot prepare the installed copy."); return; }
    app_installed_source_init(&w->source);
    if (aic_inputs(request, reply, w)) {
        char why[256];
        if (!aic_model(w, why, sizeof(why)) || !app_confirm_show(&w->view, presenter, context, why, sizeof(why)))
            (void)aic_fail(reply, "CONFIRMATION_UNAVAILABLE", "Cannot display the installed copy request.");
        else if (w->view.confirmed) {
            bool offer = aic_progress_commit(request, w, reply, presenter, context);
            if (offer && reply->status == ZCL_COMMAND_STATUS_PASSED)
                app_adopted_flow_run(w->datadir, reply, presenter, context);
        }
        else if (!json_push_kv_str(&reply->data, "status", "canceled"))
            (void)aic_fail(reply, "OUT_OF_MEMORY", "Cannot describe cancellation.");
    }
    app_confirm_free(&w->view); app_installed_source_free(&w->source); free(w);
}
