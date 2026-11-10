/* Copyright 2026 Rhett Creighton.
 * SPDX-License-Identifier: Apache-2.0
 * Explicit link -> verified catalog -> staged Receive. The caller owns the
 * selected profile and native presenters. This file depends on the reviewed
 * scratch, progress, form and bytes-stage interfaces being integrated first. */
#include "command/native_app_network_link.h"
#include "command/native_app_network_job.h"
#include "command/native_app_discover_view.h"
#include "command/native_app_discover.h"
#include "command/native_app_get_stage.h"
#include "command/native_app_receive_command.h"
#include "command/native_app_confirm.h"
#include "command/native_app_commit_progress.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "base/hex.h"
#include "platform/rng.h"
#include "base/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "command/native_app_library_command.h"
#include "command/native_app_network_controller.h"
#include "command/native_app_scratch.h"
#include "util/file_tree_ops.h"
#if !defined(_WIN32)
#include <sys/stat.h>
#if defined(ZCL_TESTING)
#include <sys/wait.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
/* Windows must explicitly refuse. Retain original scratch on any detected
 * replacement or uncertain child reaping; report cleanup failure truthfully. */

/* Copyright 2026 Rhett Creighton.
 * SPDX-License-Identifier: Apache-2.0
 * Cancellable owned network child and local progress window. */
#include "command/native_app_network_job.h"
#include "command/native_app_confirm.h"
#include "util/thread_registry.h"
#include "platform/time_compat.h"
#include <stdatomic.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
struct an_progress {
    struct app_network_job_args args;
    struct app_network_job_result result;
    atomic_bool cancel, done;
    struct app_confirm view;
    pthread_t thread;
    char mode[16], url[257], carrier[63], scratch[4400];
    struct zcl_app_offer_row selected;
#if defined(ZCL_TESTING)
    bool (*test_worker)(void *, const struct app_network_job_args *, struct app_network_job_result *);
    void *test_context;
#endif
};
static bool an_progress_cancelled(void *context)
{
    struct an_progress *p = context;
    return atomic_load_explicit(&p->cancel, memory_order_acquire);
}
static void *an_progress_worker(void *context)
{
    struct an_progress *p = context;
    p->args.cancel = an_progress_cancelled; p->args.cancel_context = p;
#if defined(ZCL_TESTING)
    if (p->test_worker) (void)p->test_worker(p->test_context, &p->args, &p->result);
    else
#endif
        (void)app_network_job_run(&p->args, &p->result);
    atomic_store_explicit(&p->done, true, memory_order_release);
    return NULL;
}
static void an_progress_tick(void *context, const struct zcl_present_window_event_v1 *event,
    bool close_requested, bool *redraw, bool *allow_close)
{
    struct an_progress *p = context; (void)event;
    if (close_requested) atomic_store_explicit(&p->cancel, true, memory_order_release);
    *redraw = false;
    *allow_close = atomic_load_explicit(&p->done, memory_order_acquire);
}
static bool an_progress_own_args(struct an_progress *p)
{
    const struct app_network_job_args *a = &p->args;
    if (!an_scratch_copy_text(p->mode, sizeof(p->mode), a->mode, true) ||
        !an_scratch_copy_text(p->url, sizeof(p->url), a->url, true) ||
        !an_scratch_copy_text(p->scratch, sizeof(p->scratch), a->scratch, true) ||
        (a->carrier_onion && !an_scratch_copy_text(p->carrier, sizeof(p->carrier), a->carrier_onion, true))) return false;
    if (a->selected) p->selected = *a->selected;
    p->args.mode = p->mode; p->args.url = p->url; p->args.scratch = p->scratch;
    p->args.carrier_onion = a->carrier_onion ? p->carrier : NULL;
    p->args.selected = a->selected ? &p->selected : NULL;
    return true;
}
/* Only call on the native owner thread. args are copied before the worker starts. Even if UI fails, cancellation is signalled and the child
 * owner is joined before scratch cleanup. Permanent join error must retain p
 * and scratch; caller may not free either or pretend child cleanup succeeded. */
static bool an_progress_run(struct an_progress *p, app_confirm_presenter presenter,
    void *context, bool *started, bool *joined, char *why, size_t cap)
{
    *started = false; *joined = false;
    atomic_init(&p->cancel, false); atomic_init(&p->done, false);
    if (!an_progress_own_args(p)) return false;
    zcl_present_model_init_v1(&p->view.model, ZCL_PRESENT_MODEL_STATUS_CARD);
    snprintf(p->view.model.request_id, sizeof(p->view.model.request_id), "app-network-progress");
    snprintf(p->view.model.title, sizeof(p->view.model.title), "Getting app");
    snprintf(p->view.model.summary, sizeof(p->view.model.summary), "Connecting and checking the shared version. Close to cancel.");
    if (!app_confirm_prepare(&p->view, why, cap)) { app_confirm_free(&p->view); return false; }
    p->view.page = (struct zcl_present_window_v1){.struct_size = sizeof(p->view.page),
        .abi_version = ZCL_PRESENT_ABI_V1, .title = p->view.model.title,
        .pixels = p->view.bitmaps[0].pixels, .width = p->view.bitmaps[0].width,
        .height = p->view.bitmaps[0].height, .pixel_format = ZCL_PRESENT_RGB8};
    const struct zcl_present_window_pages_v1 pages = {.struct_size = sizeof(pages),
        .abi_version = ZCL_PRESENT_ABI_V1, .pages = &p->view.page, .page_count = 1};
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = p, .update = an_progress_tick}, .input = app_commit_progress_ignore_input};
    if (thread_registry_spawn("app-network", an_progress_worker, p, &p->thread) != 0) {
        app_confirm_free(&p->view); return false;
    }
    *started = true;
    bool shown = presenter ? presenter(context, &p->view.model, &pages, &live, why, cap) :
        zcl_present_window_run_live_view_v1(&pages, 0, &live, why, cap);
    if (!shown) atomic_store_explicit(&p->cancel, true, memory_order_release);
    while (!atomic_load_explicit(&p->done, memory_order_acquire))
        platform_sleep_ms(10); /* real-clock: owned worker completion barrier */
    int rc; do { rc = pthread_join(p->thread, NULL); } while (rc == EINTR);
    *joined = rc == 0;
    app_confirm_free(&p->view);
    return shown && *joined;
}

/* One local, explicit link submission. */
static bool an_link_form(char out[ZCL_PRESENT_WINDOW_FORM_VALUE_MAX + 1],
                         bool *submitted, char *why, size_t cap)
{
    struct zcl_present_model_v1 model;
    zcl_present_model_init_v1(&model, ZCL_PRESENT_MODEL_INPUT_FORM);
    snprintf(model.request_id, sizeof(model.request_id), "app-link");
    snprintf(model.title, sizeof(model.title), "Open a shared app");
    snprintf(model.summary, sizeof(model.summary), "Paste an app link to review it.");
    model.item_count = 1;
    model.items[0].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    model.items[0].flags = ZCL_PRESENT_ITEM_REQUIRED;
    snprintf(model.items[0].id, sizeof(model.items[0].id), "link");
    snprintf(model.items[0].label, sizeof(model.items[0].label), "App link");
    model.action_count = 2;
    app_confirm_action(&model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "back", "Back");
    app_confirm_action(&model.actions[1], ZCL_PRESENT_ACTION_SUBMIT, "open", "Open");
    struct zcl_present_window_form_v1 form;
    struct zcl_present_model_bitmap_v1 bitmap = {0};
    if (!zcl_present_window_form_from_model_v1(&model, &form, why, cap) ||
        !zcl_present_model_render_v1(&model, &bitmap, why, cap)) return false;
    struct zcl_present_window_v1 window = {
        .struct_size = sizeof(window), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = model.title, .pixels = bitmap.pixels, .width = bitmap.width,
        .height = bitmap.height, .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &window, .page_count = 1,
    };
    struct zcl_present_window_event_v1 event = {0};
    bool ok = zcl_present_window_run_pages_form_actions_v1(&pages, model.action_count,
        &form, NULL, NULL, &event, why, cap);
    zcl_present_model_bitmap_free_v1(&bitmap);
    if (!ok || event.struct_size != sizeof(event) || event.abi_version != ZCL_PRESENT_ABI_V1 ||
        (event.outcome != ZCL_PRESENT_WINDOW_DISMISSED &&
         (event.outcome != ZCL_PRESENT_WINDOW_ACTION || event.action_index >= model.action_count))) return false;
    *submitted = event.outcome == ZCL_PRESENT_WINDOW_ACTION && event.action_index == 1;
    if (*submitted) memcpy(out, form.fields[0].value, sizeof(form.fields[0].value));
    else out[0] = 0;
    return true;
}
/* Caller validates complete URL with app_network_link_parse; invalid links
 * return to the form with an explanation. This sketch depends on the bounded
 * explicit-paste implementation and must not connect until Submit. */

struct an_controller {
    const char *datadir;
    app_library_presenter cards;
    app_confirm_presenter notices;
    void *context; bool error_presented;
#if defined(ZCL_TESTING)
    const struct app_network_test_hooks *hooks;
#endif
};
/* Declared in the staged integration, all per-call. These own a real native
 * form, cancellable worker with retained scratch, and existing Receive. */
static bool an_link_form(char out[257], bool *submitted, char *why, size_t cap);
static const char *an_error_code(enum app_network_error error)
{
    switch (error) {
    case APP_NETWORK_TIMEOUT: return "NETWORK_TIMEOUT";
    case APP_NETWORK_INVALID_RESPONSE: return "INVALID_SIGNED_RESPONSE";
    case APP_NETWORK_CHANGED_OFFER: return "OFFER_CHANGED";
    case APP_NETWORK_CONTENT_MISMATCH: return "CONTENT_MISMATCH";
    case APP_NETWORK_STORE_REFUSED: return "STORE_REFUSED";
    default: return "NETWORK_UNAVAILABLE";
    }
}
static bool an_retryable(const struct zcl_command_reply *reply)
{
    return !strcmp(reply->error.code, "NETWORK_UNAVAILABLE") || !strcmp(reply->error.code, "NETWORK_TIMEOUT");
}
static struct an_scratch *an_job_scratch(const char *datadir, uint8_t random[18],
    struct zcl_command_reply *reply)
{
    char anchor[AG_PATH], token[33];
    if (!app_receive_profile_validate(datadir, anchor, sizeof(anchor), reply)) return NULL;
    if (!rng_host_fill(random, 18)) {
        zcl_package_copy_fail(reply, "NETWORK_UNAVAILABLE", false, "Cannot prepare a private connection.", "app.library"); return NULL;
    }
    zcl_hex_encode(random, 16, token);
    struct an_scratch *scratch = zcl_calloc(1, sizeof(*scratch), "app-network.scratch");
    if (!scratch) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot prepare private storage.", "app.library"); return NULL; }
    if (an_scratch_create(scratch, anchor, token)) return scratch;
    bool clean = scratch->created && an_scratch_cleanup(scratch, true);
    if (!scratch->created) { if (scratch->root >= 0) close(scratch->root); if (scratch->parent >= 0) close(scratch->parent); }
    bool mutated = scratch->created && !clean; free(scratch);
    zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", mutated, "Cannot safely prepare a private connection.", "app.library");
    return NULL;
}
static bool an_job_reply(struct app_network_job_result *result, bool shown, struct zcl_command_reply *reply)
{
    if (shown && !result->cancelled && result->error == APP_NETWORK_OK) return true;
    free(result->bytes); result->bytes = NULL; result->len = 0;
    if (result->cancelled && shown) {
        if (!json_push_kv_str(&reply->data, "status", "canceled"))
            zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot record cancellation.", "app.library");
    } else zcl_package_copy_fail(reply, shown ? an_error_code(result->error) : "PRESENTATION_FAILED", false,
        shown ? "The app could not be retrieved or verified." : "Connection display failed.", "app.library");
    return false;
}
static bool an_job_finish(struct an_progress *p, struct an_scratch *scratch,
    bool started, bool joined, bool shown, struct app_network_job_result *result, struct zcl_command_reply *reply)
{
    if (started && (!joined || (p->result.launched && !p->result.reaped))) {
        zcl_package_copy_fail(reply, "NETWORK_CLEANUP_UNKNOWN", true,
            "Connection cleanup could not be confirmed.", "app.library"); return false;
    }
    *result = p->result;
    result->cancelled = result->cancelled || atomic_load_explicit(&p->cancel, memory_order_acquire);
    bool clean = an_scratch_cleanup(scratch, true); free(scratch); free(p);
    if (!clean) {
        free(result->bytes); result->bytes = NULL; result->len = 0;
        zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", true,
            "Private connection cleanup could not be confirmed.", "app.library"); return false;
    }
    return an_job_reply(result, shown, reply);
}
static bool an_run_job(const char *datadir, const char *mode, const char *url,
    const char *carrier, const struct zcl_app_offer_row *selected,
    struct an_controller *controller, struct app_network_job_result *result,
    struct zcl_command_reply *reply)
{
#if defined(ZCL_TESTING)
    if (controller->hooks && controller->hooks->job)
        return controller->hooks->job(controller->context, mode, url, carrier, selected, result, reply);
#endif
    uint8_t random[18]; char why[256] = {0};
    struct an_scratch *scratch = an_job_scratch(datadir, random, reply); if (!scratch) return false;
    struct an_progress *p = zcl_calloc(1, sizeof(*p), "app-network.progress");
    if (!p) {
        bool clean = an_scratch_cleanup(scratch, true); free(scratch);
        zcl_package_copy_fail(reply, "OUT_OF_MEMORY", !clean, "Cannot prepare the connection.", "app.library"); return false;
    }
    unsigned port = 1024u + (((unsigned)random[16] << 8 | random[17]) % (53569u - 1024u + 1u));
#if defined(ZCL_TESTING)
    if (controller->hooks) { p->test_worker = controller->hooks->worker; p->test_context = controller->context; }
#endif
    p->args = (struct app_network_job_args){.mode = mode, .url = url, .carrier_onion = carrier,
        .scratch = scratch->path, .selected = selected, .scratch_dev = (uint64_t)scratch->dev,
        .scratch_ino = (uint64_t)scratch->ino, .bootstrap_port = port, .timeout_ms = 120000u};
    bool started = false, joined = false;
    bool shown = an_progress_run(p, controller->notices, controller->context, &started, &joined, why, sizeof(why));
    return an_job_finish(p, scratch, started, joined, shown, result, reply);
}
struct an_report { const struct zcl_app_offer_row *row; app_confirm_presenter presenter; void *context; };
static void an_report_observed(void *context, const struct json_value *build,
    const struct json_value *opened, struct zcl_command_reply *reply)
{
    struct an_report *report = context;
    app_discover_report_observation(report->row, report->presenter, report->context, build, opened, reply);
}
static bool an_receive_impl(struct an_controller *c, const char *path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply,
    const struct zcl_app_offer_row *row)
{
    struct json_value in; json_init(&in); json_set_object(&in);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.receive", NULL);
    bool ok = spec && json_push_kv_str(&in, "file", path) &&
        json_push_kv_str(&in, "datadir", c->datadir) && json_push_kv_bool(&in, "preview", true);
    if (!ok) zcl_package_copy_fail(reply, "RECEIVE_UNAVAILABLE", false,
        "Cannot prepare native Receive.", "app.library");
    else {
        struct zcl_command_request request = {.input = &in, .spec = spec, .invoked_name = spec->path};
        app_confirm_presenter presenter = c->notices; const char *worker_path = NULL;
#if defined(ZCL_TESTING)
        if (c->hooks && c->hooks->receive) { presenter = c->hooks->receive; worker_path = c->hooks->worker_path; }
#endif
        if (row) {
            struct an_report report = {.row = row, .presenter = presenter, .context = c->context};
            zcl_native_app_receive_observed(&request, reply, identity, presenter, c->context,
                                           worker_path, an_report_observed, &report);
        } else {
#if defined(ZCL_TESTING)
            if (c->hooks && c->hooks->receive) {
                if (worker_path) zcl_test_app_receive_expected_worker(&request, reply, identity, presenter, c->context, worker_path);
                else zcl_test_app_receive_expected(&request, reply, identity, presenter, c->context);
            } else
#endif
                zcl_native_app_receive_expected(&request, reply, identity);
        }
        ok = reply->status == ZCL_COMMAND_STATUS_PASSED;
    }
    json_free(&in); return ok;
}
static bool an_receive(void *context, const char *path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply)
{ return an_receive_impl(context, path, identity, reply, NULL); }
struct an_direct_receive { struct an_controller *controller; const char *frame, *post_id; };
static bool an_direct_consume(void *context, const char *path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply)
{
    struct an_direct_receive *direct = context; struct zcl_app_offer_row row = {0};
    if (!app_network_frame_row(direct->frame, direct->post_id, platform_time_wall_unix(), &row)) {
        zcl_package_copy_fail(reply, "INVALID_SIGNED_RESPONSE", false,
            "The signed offer is no longer valid.", "app.library"); return false;
    }
    return an_receive_impl(direct->controller, path, identity, reply, &row);
}
#if defined(ZCL_TESTING)
bool zcl_test_app_network_direct_consume(const char *frame, const char *post_id,
    const struct app_network_test_hooks *hooks, void *context, struct zcl_command_reply *reply)
{
    struct an_controller c = {.hooks = hooks, .context = context};
    struct an_direct_receive direct = {.controller = &c, .frame = frame, .post_id = post_id};
    return an_direct_consume(&direct, "unused", NULL, reply);
}
#endif
static bool an_card(struct an_controller *c, struct zcl_app_offer_row *rows,
    size_t count, size_t *selected, bool *review, bool *refresh, struct zcl_command_reply *reply)
{
    size_t index = 0; *review = false; *refresh = false;
    for (;;) {
        struct zcl_present_model_v1 model; struct zcl_present_window_event_v1 event = {0};
        if (!app_discover_view(&model, count ? &rows[index] : NULL, index, count)) {
            zcl_package_copy_fail(reply, "PRESENTATION_FAILED", false, "Cannot prepare the advertisement.", "app.library"); return false;
        }
        if (!count) snprintf(model.summary, sizeof(model.summary), "No offers available from this source. Refresh or go back.");
        if (!app_discover_present_event(c->cards, c->context, &model, &event)) {
            zcl_package_copy_fail(reply, "PRESENTATION_FAILED", false, "Cannot show the advertisement.", "app.library"); return false;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED) return true;
        const char *id = model.actions[event.action_index].id;
        if (!strcmp(id, "back")) return true;
        if (!strcmp(id, "review") && count) { *selected = index; *review = true; return true; }
        if (!strcmp(id, "previous") && index) --index;
        else if (!strcmp(id, "next") && index + 1 < count) ++index;
        else if (!strcmp(id, "refresh")) { *refresh = true; return true; }
    }
}
/* Every network job owns fresh scratch and reaps before cleanup. */
static bool an_review_bytes(struct an_controller *c, const char *url,
    const struct zcl_app_offer_row *row, struct zcl_command_reply *reply)
{
    char onion[63];
    if (strlen(row->offer.onion) < 62) return false;
    memcpy(onion, row->offer.onion, 62); onion[62] = 0;
    struct app_network_job_result carrier = {0};
    if (!an_run_job(c->datadir, "carrier", url, onion, row, c, &carrier, reply)) return false;
    bool ok = app_get_stage_consume_bytes(row, c->datadir, carrier.bytes, carrier.len,
                                          an_receive, c, reply);
    free(carrier.bytes);
    const char *status = zcl_package_copy_str(&reply->data, "status");
    return ok && (!status || strcmp(status, "canceled"));
}
static bool an_notice(struct an_controller *c, const char *title, const char *summary,
    bool retry, bool *again)
{
    struct zcl_present_model_v1 model; struct zcl_present_window_event_v1 event = {0};
    zcl_present_model_init_v1(&model, ZCL_PRESENT_MODEL_STATUS_CARD);
    snprintf(model.request_id, sizeof(model.request_id), "app-network-notice");
    snprintf(model.title, sizeof(model.title), "%s", title);
    snprintf(model.summary, sizeof(model.summary), "%s", summary);
    model.action_count = retry ? 2 : 1;
    app_confirm_action(&model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "back", "Back");
    if (retry) app_confirm_action(&model.actions[1], ZCL_PRESENT_ACTION_SELECT, "continue",
        !strcmp(title, "Some offers shown") ? "Continue" : "Retry");
    bool ok = app_discover_present_event(c->cards, c->context, &model, &event);
    c->error_presented = ok;
    *again = ok && retry && event.outcome == ZCL_PRESENT_WINDOW_ACTION && event.action_index == 1;
    return ok;
}
static bool an_form_input(struct an_controller *c, char url[257], struct app_network_link *link,
    struct zcl_command_reply *reply, bool *shown)
{
    char why[256]; bool submitted = false, ok;
#if defined(ZCL_TESTING)
    if (c->hooks && c->hooks->form) ok = c->hooks->form(c->context, url, &submitted, why, sizeof(why));
    else
#endif
        ok = an_link_form(url, &submitted, why, sizeof(why));
    if (!ok) {
        zcl_package_copy_fail(reply, "PRESENTATION_FAILED", false, "Cannot show app link entry.", "app.library"); return false;
    }
    if (!submitted) return false;
    if (app_network_link_parse(url, link)) return true;
    bool unused; (void)an_notice(c, "App link not recognized", "Paste the complete app link and try again.", false, &unused);
    *shown = c->error_presented;
    zcl_package_copy_fail(reply, "BAD_INPUT", false, "The app link is invalid.", "app.library"); return false;
}
/* reply is initialized on entry; cancel preserves the existing failure. */
static bool an_retry(struct an_controller *c, struct zcl_command_reply *reply, bool *shown)
{
    bool again = false, retry = an_retryable(reply);
    bool retry_selected = an_notice(c, retry ? "Could not connect" : "Could not verify app",
        retry ? "Try again, or ask for a share file." : "Ask for a new app link or share file.", retry, &again) && again;
    if (retry_selected) {
        c->error_presented = false;
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
    } else *shown = c->error_presented;
    return retry_selected;
}
static bool an_review_loop(struct an_controller *c, const char *url, const struct zcl_app_offer_row *row,
    struct zcl_command_reply *reply, bool *shown)
{
    for (;;) {
        bool done = an_review_bytes(c, url, row, reply);
        if (done || reply->status == ZCL_COMMAND_STATUS_PASSED || reply->error.mutated || !an_retryable(reply)) return done;
        if (!an_retry(c, reply, shown)) return false;
    }
}
static bool an_selected_review(struct an_controller *c, const char *url,
    const struct app_network_link *link, const struct zcl_app_offer_row *row,
    struct zcl_command_reply *reply, bool *shown)
{
    char exact[257];
    int n = link->exact ? snprintf(exact, sizeof(exact), "%s", url) :
        snprintf(exact, sizeof(exact), "%s/%s", url, row->post_id);
    if (n <= 0 || (size_t)n >= sizeof(exact)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false, "The selected app link is too long.", "app.library"); return false;
    }
    return an_review_loop(c, exact, row, reply, shown);
}
static bool an_catalog_loop(struct an_controller *c, const char *url, const struct app_network_link *link,
    struct zcl_command_reply *reply, bool *shown)
{
    for (;;) {
        struct app_network_job_result catalog = {0};
        if (!an_run_job(c->datadir, link->exact ? "exact" : "catalog", url, NULL, NULL, c, &catalog, reply)) {
            if (catalog.cancelled || reply->error.mutated || !an_retry(c, reply, shown)) return false;
            continue;
        }
        if (catalog.incomplete) {
            bool proceed;
            if (!an_notice(c, "Some offers shown", "This is a sample, not a complete list.", true, &proceed) || !proceed) return false;
        }
        size_t selected = 0; bool review = false, refresh = false;
        if (!an_card(c, catalog.rows, catalog.count, &selected, &review, &refresh, reply)) return false;
        if (refresh) continue;
        if (!review) return false;
        return an_selected_review(c, url, link, &catalog.rows[selected], reply, shown);
    }
}
static bool an_direct_loop(struct an_controller *c, const char *url, const struct app_network_link *link,
    struct zcl_command_reply *reply, bool *shown)
{
    for (;;) {
        struct app_network_job_result result = {0};
        if (!an_run_job(c->datadir, "direct", url, NULL, NULL, c, &result, reply)) {
            if (result.cancelled || reply->error.mutated || !an_retry(c, reply, shown)) return false;
            continue;
        }
        struct zcl_app_offer_row row = {0};
        bool valid = app_network_frame_row(result.frame, link->post_id, platform_time_wall_unix(), &row);
        struct an_direct_receive direct = {.controller = c, .frame = result.frame, .post_id = link->post_id};
        bool ok = valid && app_get_stage_consume_bytes(&row, c->datadir, result.bytes, result.len,
                                                       an_direct_consume, &direct, reply);
        free(result.bytes);
        if (!valid) zcl_package_copy_fail(reply, "INVALID_SIGNED_RESPONSE", false,
            "The signed offer is no longer valid.", "app.library");
        const char *status = zcl_package_copy_str(&reply->data, "status");
        return ok && (!status || strcmp(status, "canceled"));
    }
}
static bool an_open_link(const char *datadir, app_library_presenter cards,
    app_confirm_presenter notices, void *context, struct zcl_command_reply *reply, bool *shown
#if defined(ZCL_TESTING)
    , const struct app_network_test_hooks *hooks
#endif
)
{
    if (shown) *shown = false;
    if (!datadir || !cards || !reply || !shown) return false;
    struct an_controller c = {.datadir = datadir, .cards = cards, .notices = notices, .context = context};
#if defined(ZCL_TESTING)
    c.hooks = hooks;
#endif
    char url[257]; struct app_network_link link;
    if (!an_form_input(&c, url, &link, reply, shown)) return false;
    return link.exact ? an_direct_loop(&c, url, &link, reply, shown) :
        an_catalog_loop(&c, url, &link, reply, shown);
}


#if defined(ZCL_TESTING)
static bool an_test_scratch_init(const char *datadir, struct an_scratch *scratch,
    char path[AG_PATH], struct zcl_command_reply *reply)
{
    char anchor[AG_PATH], token[33]; uint8_t random[16];
    if (!app_receive_profile_validate(datadir, anchor, sizeof(anchor), reply) || !rng_host_fill(random, sizeof(random))) return false;
    zcl_hex_encode(random, sizeof(random), token);
    if (!an_scratch_create(scratch, anchor, token)) {
        if (scratch->created) (void)an_scratch_cleanup(scratch, true);
        else { if (scratch->root >= 0) close(scratch->root); if (scratch->parent >= 0) close(scratch->parent); }
        return false;
    }
    int n = snprintf(path, AG_PATH, "%s/offer.z23share", scratch->path);
    int file = n > 0 && (size_t)n < AG_PATH ? openat(scratch->root, "offer.z23share", O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (file < 0) { (void)an_scratch_cleanup(scratch, true); return false; }
    close(file); return true;
}
static bool an_test_live_replace(const char *path, bool (*replace)(void *, const char *, long),
    void *context, bool *started, bool *reaped)
{
    *started = false;
    int pipefd[2]; if (pipe(pipefd)) return false;
    pid_t child = fork();
    if (child == 0) { char byte; close(pipefd[1]); _exit(read(pipefd[0], &byte, 1) < 0 ? 2 : 0); }
    close(pipefd[0]); *started = child > 0;
    bool changed = child > 0 && replace(context, path, (long)child);
    close(pipefd[1]); int status = 0; pid_t waited = -1;
    if (child > 0) do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    *reaped = child > 0 && waited == child && WIFEXITED(status);
    return changed;
}
bool zcl_test_app_network_scratch_replace(const char *datadir,
    bool (*replace)(void *, const char *, long), void *context,
    bool *reaped, struct zcl_command_reply *reply)
{
    if (reaped) *reaped = false;
    if (!datadir || !replace || !reaped || !reply) return false;
    char path[AG_PATH]; struct an_scratch scratch;
    if (!an_test_scratch_init(datadir, &scratch, path, reply)) return false;
    bool started = false;
    bool changed = an_test_live_replace(path, replace, context, &started, reaped);
    bool clean = an_scratch_cleanup(&scratch, !started || *reaped);
    if (!clean) zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", true, "Private cleanup could not be confirmed.", "app.library");
    return changed && *reaped && clean;
}
bool zcl_test_app_network_open_link(const char *datadir, app_library_presenter cards,
    app_confirm_presenter notices, void *context, struct zcl_command_reply *reply,
    bool *shown, const struct app_network_test_hooks *hooks)
{ return an_open_link(datadir, cards, notices, context, reply, shown, hooks); }
#endif

#endif

bool app_network_open_link(const char *datadir, app_library_presenter cards,
    app_confirm_presenter notices, void *context, struct zcl_command_reply *reply, bool *shown)
{
#if !defined(_WIN32)
    return an_open_link(datadir, cards, notices, context, reply, shown
#if defined(ZCL_TESTING)
        , NULL
#endif
    );
#else
    (void)datadir; (void)cards; (void)notices; (void)context; if (shown) *shown = false; if (reply) zcl_package_copy_fail(reply, "PLATFORM_UNAVAILABLE", false, "Opening an app link is unavailable on this platform.", "app.library"); return false;
#endif
}
