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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct discover {
    struct zcl_app_offer_row *rows; size_t count, index;
    struct zcl_app_offer_position *history, next;
    size_t page, history_capacity;
    bool has_more, select_last;
    const char *datadir; app_library_presenter presenter;
    app_confirm_presenter receive_presenter; void *context;
    const char *worker_path;
    bool error_presented, host_requested;
};
#ifdef ZCL_TESTING
static void (*ad_test_evidence_hook)(const struct zcl_app_offer_row *, const struct json_value *, const struct json_value *);
void app_discover_test_evidence_hook(void (*hook)(const struct zcl_app_offer_row *, const struct json_value *, const struct json_value *))
{ ad_test_evidence_hook = hook; }
#endif
static void ad_rebuild_status(struct zcl_command_reply *reply, const char *status)
{
    if (!json_push_kv_str(&reply->data, "rebuild_report", status))
        zcl_package_copy_fail(reply, "REBUILD_RESULT_UNAVAILABLE", true,
            "the received copy remains; the report outcome could not be retained", "app.library");
}
static bool ad_comparison(struct app_confirm *v, bool available, size_t count)
{
    char text[192];
    if (available)
        (void)snprintf(text, sizeof(text), "%zu distinct signing keys reported matching builds; local snapshot, global total unknown.", count);
    else
        (void)snprintf(text, sizeof(text), "Matching reports unavailable or incomplete; global total unknown.");
    return app_confirm_field(&v->model, "Matching reports: ", text) &&
        app_confirm_field(&v->model, "Compared: ", "Same release, image, target and environment. Reports are self-reported; they do not prove independent builders or execution.");
}
static bool ad_rebuild_choice(struct discover *d, const struct zcl_app_rebuild *r, bool available, size_t count, bool *chosen)
{
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "discover-rebuild-choice");
    if (!v) return false;
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "discover-report-rebuild");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Share this build result?");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "Optional: publish a signed result that others can compare.");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "decline", "Not now");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "publish", "Publish result");
    char why[256] = {0};
    bool shown = app_confirm_field(&v->model, "Original app: ", d->rows[d->index].offer.name) &&
        app_confirm_field(&v->model, "Original publisher: ", r->publisher) &&
        app_confirm_field(&v->model, "Original release: ", r->release_root) &&
        app_confirm_field(&v->model, "Built image: ", r->image) && ad_comparison(v, available, count) &&
        app_confirm_field(&v->model, "Public result: ", "Your node signs and posts this build result publicly for up to 30 days. It identifies this node and the build.") &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, d->receive_presenter, d->context, why, sizeof(why));
    *chosen = shown && v->confirmed;
    app_confirm_free(v); free(v); return shown;
}
static bool ad_result_comparison(struct app_confirm *v, const struct zcl_command_reply *reply)
{
    const struct json_value *n = json_get(&reply->data, "matching_rebuild_keys");
    const char *status = zcl_package_copy_str(&reply->data, "rebuild_count_status");
    bool available = n && n->type == JSON_INT && json_get_int(n) >= 0 && status &&
        !strcmp(status, "local snapshot; global count unknown");
    return ad_comparison(v, available, available ? (size_t)json_get_int(n) : 0);
}
static bool ad_rebuild_result(struct discover *d, struct zcl_command_reply *reply, bool posted)
{
    const char *status = zcl_package_copy_str(&reply->data, "rebuild_report");
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "discover-rebuild-result");
    if (!v) {
        if (posted) app_get_rebuild_result_unavailable(reply);
        else zcl_package_copy_fail(reply, "REBUILD_RESULT_UNAVAILABLE", true, "The kept copy remains; build comparison could not be displayed.", "app.library");
        return false;
    }
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "discover-rebuild-result");
    (void)snprintf(v->model.title, sizeof(v->model.title), "%s", posted ? "Build result publication" : "Build comparison");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "%s", status ? status : "Result unavailable; inspect before retrying.");
    v->copy_text = zcl_package_copy_str(&reply->data, "rebuild_retry");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
    char why[256] = {0};
    bool shown = ad_result_comparison(v, reply) &&
        app_confirm_field(&v->model, "Retry: ", v->copy_text ? "Press C to copy the retry command after checking the board." : "No retry is suggested.") &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, d->receive_presenter, d->context, why, sizeof(why));
    app_confirm_free(v); free(v);
    if (!shown) {
        if (posted) app_get_rebuild_result_unavailable(reply);
        else zcl_package_copy_fail(reply, "REBUILD_RESULT_UNAVAILABLE", true, "The kept copy remains; build comparison could not be displayed.", "app.library");
    }
    return shown;
}
static void ad_rebuild_observed(void *context, const struct json_value *wire, const struct json_value *opened, struct zcl_command_reply *reply)
{
    struct discover *d = context; struct zcl_app_rebuild observation;
#ifdef ZCL_TESTING
    if (ad_test_evidence_hook) ad_test_evidence_hook(&d->rows[d->index], wire, opened);
#endif
    enum app_get_rebuild_state state = app_get_rebuild_prepare(&d->rows[d->index], wire, opened, &observation);
    if (state == APP_GET_REBUILD_INVALID) { ad_rebuild_status(reply, "not published: build evidence unavailable"); return; }
    struct zcl_command_reply why; size_t count = 0;
    bool available = zcl_app_rebuild_count(&observation, &count, &why);
    zcl_command_reply_free(&why);
    if (state == APP_GET_REBUILD_CACHED) {
        ad_rebuild_status(reply, "not published: cached image");
        bool ok = (!available || json_push_kv_int(&reply->data, "matching_rebuild_keys", (int64_t)count)) &&
            json_push_kv_str(&reply->data, "rebuild_count_status", available ? "local snapshot; global count unknown" : "incomplete: board query unavailable or capped");
        if (!ok) zcl_package_copy_fail(reply, "REBUILD_RESULT_UNAVAILABLE", true, "The kept copy remains; build comparison could not be retained.", "app.library");
        else (void)ad_rebuild_result(d, reply, false);
        return;
    }
    bool chosen = false;
    if (!ad_rebuild_choice(d, &observation, available, count, &chosen)) { ad_rebuild_status(reply, "not published: choice unavailable"); return; }
    if (!chosen) { ad_rebuild_status(reply, "not published: declined"); return; }
    if (app_get_rebuild_publish(&observation, reply)) (void)ad_rebuild_result(d, reply, true);
}
void app_discover_report_observation(const struct zcl_app_offer_row *row,
    app_confirm_presenter presenter, void *context, const struct json_value *build,
    const struct json_value *opened, struct zcl_command_reply *reply)
{
    if (!row || !reply) return;
    struct zcl_app_offer_row selected = *row;
    struct discover d = {.rows = &selected, .receive_presenter = presenter, .context = context};
    ad_rebuild_observed(&d, build, opened, reply);
}
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
        zcl_native_app_receive_observed(&request, reply, identity, d->receive_presenter, d->context,
            d->worker_path, ad_rebuild_observed, d);
        ok = reply->status == ZCL_COMMAND_STATUS_PASSED;
        if (ok) ok = ad_host_choice(d, reply, host_original);
    }
    json_free(&in); return ok;
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
    bool shown = app_discover_present_event(d->presenter, d->context, &m, &event);
    d->error_presented = shown;
    return shown && retry && event.outcome == ZCL_PRESENT_WINDOW_ACTION && event.action_index == 0;
}
static bool ad_catalog(struct discover *d, struct zcl_command_reply *reply)
{
    struct zcl_command_reply why;
    struct zcl_app_offer_page page = {0};
    const struct zcl_app_offer_position *before = d->page ? &d->history[d->page - 1] : NULL;
    bool ok = zcl_app_offer_catalog_page(d->rows, ZCL_APP_OFFER_ROWS_MAX, before, &page, &why);
    if (!ok) { d->count = 0; zcl_app_inner_fail(reply, &why, false); }
    else {
        d->count = page.count; d->has_more = page.has_more; d->next = page.next;
        d->index = d->select_last && d->count ? d->count - 1 : 0;
        d->select_last = false;
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
    }
    zcl_command_reply_free(&why); return ok;
}
static bool ad_review(struct discover *d, struct zcl_command_reply *reply)
{
    if (!app_get_stage_consume_progress(&d->rows[d->index], d->datadir, ad_consume, d, reply, d->receive_presenter, d->context)) {
        (void)ad_error(d, reply->error.message, false);
        return false;
    }
    if (!ad_host_result(d, reply)) { (void)ad_error(d, reply->error.message, false); return false; }
    const char *status = zcl_package_copy_str(&reply->data, "status");
    return !status || strcmp(status, "canceled");
}
/* Keep only page cursors, not copies of the potentially large offer rows. */
static bool ad_next_page(struct discover *d, struct zcl_command_reply *reply)
{
    if (d->page >= d->history_capacity) {
        size_t n = d->history_capacity ? d->history_capacity : 8;
        if (n > SIZE_MAX / 2 || n * 2 > SIZE_MAX / sizeof(*d->history)) {
            zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot retain the Discover page cursor.", "app.library");
            return false;
        }
        n *= 2;
        void *p = zcl_realloc(d->history, n * sizeof(*d->history), "discover/page-cursors");
        if (!p) {
            zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot retain the Discover page cursor.", "app.library");
            return false;
        }
        d->history = p; d->history_capacity = n;
    }
    d->history[d->page] = d->next;
    ++d->page;
    d->select_last = false;
    return true;
}

static bool ad_navigate(struct discover *d, const char *id, bool *loaded,
                        struct zcl_command_reply *reply)
{
    if (!strcmp(id, "refresh")) {
        d->page = 0; d->select_last = false; *loaded = false;
    } else if (!strcmp(id, "previous")) {
        if (d->index) --d->index;
        else if (d->page) { --d->page; d->select_last = true; *loaded = false; }
    } else if (!strcmp(id, "next")) {
        if (d->index + 1 < d->count) ++d->index;
        else if (d->has_more) {
            if (!ad_next_page(d, reply)) return false;
            *loaded = false;
        }
    }
    return true;
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
        if (!app_discover_page_view(&model, d->count ? &d->rows[d->index] : NULL, d->index, d->count,
                                    d->page > 0, d->has_more) ||
            !app_discover_present_event(d->presenter, d->context, &model, &event)) {
            zcl_package_copy_fail(reply, "PRESENTATION_FAILED", false, "The advertisement could not be displayed.", "app.library"); return false;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED) return false;
        const char *id = model.actions[event.action_index].id;
        if (!strcmp(id, "back")) return false;
        if (!strcmp(id, "review") && d->count) return ad_review(d, reply);
        if (!ad_navigate(d, id, &loaded, reply)) return false;
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
    free(d.history); free(d.rows); return received;
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
