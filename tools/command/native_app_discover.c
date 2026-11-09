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
    bool error_presented;
};
static bool ad_consume(void *context, const char *path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply)
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
