/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Navigate node advertisements without granting receive authority. */
#include "command/native_app_discover.h"
#include "command/native_app_discover_view.h"
#include "command/native_app_get_stage.h"
#include "command/native_app_compose.h"
#include "command/native_app_confirm.h"
#include "command/native_zcode_package_copy.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct discover {
    struct zcl_app_offer_row *rows; size_t count, index;
    const char *datadir; app_library_presenter presenter;
    app_confirm_presenter receive_presenter; void *context;
    const char *worker_path;
    bool error_presented, host_requested;
};
static bool ad_host_choice(struct discover *d, struct zcl_command_reply *reply, bool *host_original)
{
    const char *stage = zcl_package_copy_str(&reply->data, "stage");
    if (!stage || strcmp(stage, "commit") || reply->status != ZCL_COMMAND_STATUS_PASSED) return true;
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "discover-host-choice");
    if (!v) return json_push_kv_str(&reply->data, "hosting_status", "not enabled: choice unavailable");
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "discover-host-original");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Help share this original app?");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "Optional: keep its original files and offer them to others.");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "decline", "Not now");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "host", "Help share");
    char why[256] = {0};
    const struct zcl_app_offer *offer = &d->rows[d->index].offer;
    bool shown = app_confirm_field(&v->model, "Original app: ", offer->name) &&
        app_confirm_field(&v->model, "Original publisher: ", offer->publisher) &&
        app_confirm_field(&v->model, "Original package: ", offer->root) &&
        app_confirm_field(&v->model, "Hosting: ", "Store the original app files on disk and use bandwidth to serve them publicly while this node runs. Its offer renews until you stop hosting.") &&
        app_confirm_field(&v->model, "Availability: ", "Public discovery waits for a ready endpoint; this does not guarantee availability.") &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, d->receive_presenter, d->context, why, sizeof(why));
    *host_original = shown && v->confirmed;
    d->host_requested = *host_original;
    app_confirm_free(v); free(v);
    if (!shown) return json_push_kv_str(&reply->data, "hosting_status", "not enabled: choice unavailable");
    if (!*host_original) return json_push_kv_str(&reply->data, "hosting_status", "not enabled: declined");
    return true;
}
static bool ad_host_result(struct discover *d, struct zcl_command_reply *reply)
{
    if (!d->host_requested) return true;
    const char *status = zcl_package_copy_str(&reply->data, "hosting_status");
    const char *stop = zcl_package_copy_str(&reply->data, "hosting_stop_command");
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "discover-host-result");
    if (!v) { app_get_host_result_unavailable(reply); return false; }
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "discover-host-result");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Original app hosting");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "%s", status ? status : "Hosting outcome unavailable; inspect before retrying.");
    v->copy_text = stop;
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
    char why[256] = {0};
    bool ready = app_confirm_field(&v->model, "Stop: ", stop ? "Press C to copy the stop command." : "No confirmed stop command is available.") &&
        app_confirm_prepare(v, why, sizeof(why));
    bool shown = ready && app_confirm_show(v, d->receive_presenter, d->context, why, sizeof(why));
    app_confirm_free(v); free(v);
    if (!shown) app_get_host_result_unavailable(reply);
    return shown;
}
static bool ad_consume(void *context, const char *path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply, bool *host_original)
{
    struct discover *d = context; struct json_value in; json_init(&in); json_set_object(&in);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.receive", NULL);
    bool ok = spec && json_push_kv_str(&in, "file", path) &&
        json_push_kv_str(&in, "datadir", d->datadir) && json_push_kv_bool(&in, "preview", true);
    if (!ok) zcl_package_copy_fail(reply, "RECEIVE_UNAVAILABLE", false, "Cannot prepare native Receive.", "app.library");
    else {
        struct zcl_command_request request = {.input = &in, .spec = spec, .invoked_name = spec->path};
#if defined(ZCL_TESTING)
        if (d->receive_presenter && d->worker_path)
            zcl_test_app_receive_expected_worker(&request, reply, identity, d->receive_presenter, d->context, d->worker_path);
        else if (d->receive_presenter) zcl_test_app_receive_expected(&request, reply, identity, d->receive_presenter, d->context);
        else
#endif
            zcl_native_app_receive_expected(&request, reply, identity);
        ok = reply->status == ZCL_COMMAND_STATUS_PASSED;
        if (ok) ok = ad_host_choice(d, reply, host_original);
    }
    json_free(&in); return ok;
}
static bool ad_event(struct discover *d, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    char why[256] = {0};
    return d->presenter(d->context, model, NULL, event, why, sizeof(why)) &&
        event->struct_size == sizeof(*event) && event->abi_version == ZCL_PRESENT_ABI_V1 &&
        (event->outcome == ZCL_PRESENT_WINDOW_DISMISSED ||
         (event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index < model->action_count));
}
static bool ad_error(struct discover *d, const char *message, bool retry)
{
    struct zcl_present_model_v1 m; struct zcl_present_window_event_v1 event = {0};
    zcl_present_model_init_v1(&m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m.request_id, sizeof(m.request_id), "discover-error");
    (void)snprintf(m.title, sizeof(m.title), "Discover unavailable");
    (void)snprintf(m.summary, sizeof(m.summary), "%s", message);
    m.action_count = retry ? 2 : 1;
    if (retry) app_confirm_action(&m.actions[0], ZCL_PRESENT_ACTION_SELECT, "retry", "Retry");
    app_confirm_action(&m.actions[retry ? 1 : 0], ZCL_PRESENT_ACTION_CANCEL, "back", "Back");
    bool shown = ad_event(d, &m, &event);
    d->error_presented = shown;
    return shown && retry && event.outcome == ZCL_PRESENT_WINDOW_ACTION && event.action_index == 0;
}
static bool ad_catalog(struct discover *d, struct zcl_command_reply *reply)
{
    struct zcl_command_reply why;
    bool ok = zcl_app_offer_catalog(d->rows, ZCL_APP_OFFER_ROWS_MAX, &d->count, &why);
    if (!ok) { d->count = 0; zcl_app_inner_fail(reply, &why, false); }
    else { zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1"); }
    zcl_command_reply_free(&why); d->index = 0; return ok;
}
static bool ad_review(struct discover *d, struct zcl_command_reply *reply)
{
    if (!app_get_stage_consume(&d->rows[d->index], d->datadir, ad_consume, d, reply)) {
        (void)ad_error(d, reply->error.message, false);
        return false;
    }
    if (!ad_host_result(d, reply)) { (void)ad_error(d, reply->error.message, false); return false; }
    const char *status = zcl_package_copy_str(&reply->data, "status");
    return !status || strcmp(status, "canceled");
}
static void ad_move(struct discover *d, const char *id)
{
    if (!strcmp(id, "previous") && d->index) --d->index;
    if (!strcmp(id, "next") && d->index + 1 < d->count) ++d->index;
}
static bool ad_loop(struct discover *d, struct zcl_command_reply *reply)
{
    bool loaded = false;
    for (;;) {
        if (!loaded) {
            if (!ad_catalog(d, reply)) {
                if (ad_error(d, "The node catalog could not be read.", true)) continue;
                return false;
            }
            loaded = true;
        }
        struct zcl_present_model_v1 model; struct zcl_present_window_event_v1 event = {0};
        d->error_presented = false;
        if (!app_discover_view(&model, d->count ? &d->rows[d->index] : NULL, d->index, d->count) ||
            !ad_event(d, &model, &event)) {
            zcl_package_copy_fail(reply, "PRESENTATION_FAILED", false, "The advertisement could not be displayed.", "app.library"); return false;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED) return false;
        const char *id = model.actions[event.action_index].id;
        if (!strcmp(id, "back")) return false;
        if (!strcmp(id, "refresh")) { loaded = false; continue; }
        if (!strcmp(id, "review")) return ad_review(d, reply);
        ad_move(d, id);
    }
}
static bool ad_run(const char *datadir, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, struct zcl_command_reply *reply,
    bool *error_presented, const char *worker_path)
{
    if (error_presented) *error_presented = false;
    if (!datadir || datadir[0] != '/' || strnlen(datadir, 4400) >= 4400) {
        zcl_package_copy_fail(reply, "MISSING_DATADIR", false, "An absolute app profile is required for Discover.", "app.library"); return false;
    }
    struct discover d = {.datadir = datadir, .presenter = presenter,
        .receive_presenter = receive_presenter, .context = context, .worker_path = worker_path};
    d.rows = zcl_calloc(ZCL_APP_OFFER_ROWS_MAX, sizeof(*d.rows), "app-discover/catalog");
    if (!d.rows) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot load advertisements.", "app.library"); return false; }
    bool received = ad_loop(&d, reply);
    if (error_presented) *error_presented = d.error_presented;
    free(d.rows); return received;
}
bool app_discover_run(const char *datadir, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, struct zcl_command_reply *reply,
    bool *error_presented)
{
    return ad_run(datadir, presenter, receive_presenter, context, reply, error_presented, NULL);
}
#ifdef ZCL_TESTING
bool app_discover_run_test(const char *datadir, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, struct zcl_command_reply *reply,
    bool *error_presented, const char *worker_path)
{
    return ad_run(datadir, presenter, receive_presenter, context, reply, error_presented, worker_path);
}
#endif
