/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Keep received-app build, preview and Keep decisions in native windows. */
#include "command/native_app_receive_flow.h"
#include "command/native_app_commit_progress.h"
#include "command/native_app_receive_job.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_compose.h"
#include "command/native_zcode_package_copy.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "platform/time_compat.h"
#include "json/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct receive_flow {
    struct zcl_command_reply *reply;
    struct app_receive_preview *preview;
    app_confirm_presenter presenter;
    void *context;
    struct json_value operations;
    const char *status;
    bool adopted, closed;
    int executed; /* 0: no open worker; -1: outcome uncertain; 1: validated open. */
};
struct receive_progress {
    struct app_receive_job *job;
    struct app_confirm view;
    bool close_seen;
    bool notice_failed;
};
static bool arf_fail(struct receive_flow *f, const char *code, const char *message)
{
    zcl_package_copy_fail(f->reply, code, true, message, f->adopted ? "app.adopt preview" : "app.receive preview");
    return false;
}
static bool arf_status(struct receive_flow *f, const char *status)
{
    f->status = status;
    return true;
}
static void arf_model(const struct receive_flow *f, struct app_confirm *view, const char *title, const char *summary)
{
    zcl_present_model_init_v1(&view->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(view->model.request_id, sizeof(view->model.request_id), "%s", f->adopted ? "adopted-app" : "received-app");
    (void)snprintf(view->model.title, sizeof(view->model.title), "%s", title);
    (void)snprintf(view->model.summary, sizeof(view->model.summary), "%s", summary);
}
static bool arf_fields(struct receive_flow *f, struct app_confirm *view)
{
    const char *name = zcl_package_copy_str(&f->reply->data, f->adopted ? "copy" : "name");
    const char *version = zcl_package_copy_str(&f->reply->data, "version");
    return name && version && app_confirm_field(&view->model, f->adopted ? "Personal copy: " : "App: ", name) &&
        app_confirm_field(&view->model, "Saved version: ", version);
}
static void arf_actions(struct app_confirm *view, const char *action)
{
    view->model.action_count = 4;
    app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", action);
}
static bool arf_choose(struct receive_flow *f, const char *title, const char *summary,
    const char *action, bool *chosen)
{
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "receive-flow/choice");
    *chosen = false;
    if (!view) return arf_fail(f, "OUT_OF_MEMORY", "Cannot show the next choice.");
    arf_model(f, view, title, summary); arf_actions(view, action);
    char why[256] = {0};
    bool ok = arf_fields(f, view) && app_confirm_prepare(view, why, sizeof(why)) &&
        app_confirm_show(view, f->presenter, f->context, why, sizeof(why));
    if (ok) *chosen = view->confirmed;
    app_confirm_free(view); free(view);
    return ok || arf_fail(f, "CONTINUATION_UNAVAILABLE", f->adopted ? "The next choice could not be displayed; the adopted copy is retained." : "The next choice could not be displayed; the received copy is retained.");
}
/* This callback observes only a completed immutable capture. It never enters
 * command dispatch, joins a thread, or performs filesystem/database work. */
static bool arf_waiting_notice(struct receive_progress *p)
{
    struct zcl_present_model_bitmap_v1 next = {0};
    char why[128] = {0};
    (void)snprintf(p->view.model.summary, sizeof(p->view.model.summary),
        "Waiting for the operation to finish before closing.");
    if (!zcl_present_model_render_page_v1(&p->view.model, 0, &next, why, sizeof(why))) return false;
    zcl_present_model_bitmap_free_v1(&p->view.bitmaps[0]);
    p->view.bitmaps[0] = next;
    p->view.page.pixels = next.pixels;
    return true;
}
static void arf_tick(void *context, const struct zcl_present_window_event_v1 *event,
    bool close_requested, bool *redraw, bool *allow_close)
{
    (void)event;
    struct receive_progress *p = context;
    struct app_receive_job_result result;
    *redraw = false;
    *allow_close = app_receive_job_poll(p->job, &result);
    if (close_requested && !p->close_seen) {
        p->close_seen = true;
        if (!*allow_close) {
            *redraw = arf_waiting_notice(p);
            p->notice_failed = !*redraw;
        }
    }
}
static bool arf_progress(struct receive_flow *f, struct receive_progress *p,
    const char *stage)
{
    arf_model(f, &p->view, stage, "This window stays open until the operation finishes.");
    char why[256] = {0};
    if (!arf_fields(f, &p->view) || !app_confirm_prepare(&p->view, why, sizeof(why))) return false;
    p->view.page = (struct zcl_present_window_v1){
        .struct_size = sizeof(p->view.page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = p->view.model.title, .pixels = p->view.bitmaps[0].pixels,
        .width = p->view.bitmaps[0].width, .height = p->view.bitmaps[0].height,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    const struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &p->view.page, .page_count = 1,
    };
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = p, .update = arf_tick},
        .input = app_commit_progress_ignore_input,
    };
    return f->presenter ? f->presenter(f->context, &p->view.model, &pages, &live, why, sizeof(why)) :
        zcl_present_window_run_live_view_v1(&pages, 0, &live, why, sizeof(why));
}
/* Summaries are observations, not validation. Full worker envelopes remain
 * available to the exact-version binder until the stage finishes. Never copy
 * arbitrary worker objects or repeat long filesystem paths into the receipt. */
static bool arf_summary_text(const char *s)
{
    if (!s || strlen(s) > 64) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        if (*p < 0x20 || *p > 0x7e || *p == '"' || *p == '\\') return false;
    return true;
}
static bool arf_summary_identity(struct json_value *out, const struct json_value *data)
{
    static const char *const text[] = {"stage", "version", "package_root",
        "plan_id", "record_id", "image_sha3", "name", "ready_basis", "start_token", "mapped_proof"};
    for (size_t i = 0; i < sizeof(text) / sizeof(text[0]); ++i) {
        const struct json_value *v = json_get(data, text[i]);
        if (v && v->type == JSON_STR && arf_summary_text(json_get_str(v)) &&
            !json_push_kv(out, text[i], v)) return false;
    }
    return true;
}
static bool arf_summary_execution(struct json_value *out, const struct json_value *data)
{
    static const char *const scalar[] = {"ready", "pid", "executed", "selection_revision"};
    for (size_t i = 0; i < sizeof(scalar) / sizeof(scalar[0]); ++i) {
        const struct json_value *v = json_get(data, scalar[i]);
        if (v && (v->type == JSON_BOOL || v->type == JSON_INT) &&
            !json_push_kv(out, scalar[i], v)) return false;
    }
    return true;
}
static bool arf_result_summary(struct json_value *out, const struct json_value *wire)
{
    const struct json_value *data = json_get(wire, "data");
    if (!data) data = json_get(json_get(wire, "error"), "facts");
    if (!data) data = wire; /* Also accepts the already-bound Keep result data. */
    if (!arf_summary_identity(out, data) || !arf_summary_execution(out, data)) return false;
    const struct json_value *status = json_get(wire, "status");
    if (status && status->type == JSON_STR && arf_summary_text(json_get_str(status)) &&
        !json_push_kv(out, "status", status)) return false;
    const char *message = zcl_package_copy_str(json_get(wire, "error"), "message");
    if (message) {
        char excerpt[161]; size_t n = strnlen(message, sizeof(excerpt) - 1);
        for (size_t i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)message[i];
            excerpt[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
        }
        excerpt[n] = 0;
        if (!json_push_kv_str(out, "error_excerpt", excerpt)) return false;
    }
    return true;
}
static bool arf_transport_fields(struct json_value *out, const struct app_receive_job_result *result)
{
    return json_push_kv_int(out, "capture_status", result->capture_status) &&
        json_push_kv_bool(out, "exit_observed", result->evidence.exit_observed) &&
        json_push_kv_int(out, "exit_code", result->evidence.exit_code) &&
        json_push_kv_bool(out, "timed_out", result->evidence.timed_out) &&
        json_push_kv_bool(out, "stdout_complete", result->evidence.stdout_complete) &&
        json_push_kv_bool(out, "stdout_truncated", result->evidence.stdout_truncated) &&
        json_push_kv_bool(out, "stderr_complete", result->evidence.stderr_complete);
}
static bool arf_observation(struct receive_flow *f,
    const struct app_receive_job_result *result, const struct json_value *wire,
    const char *stage, bool parsed, bool shown, bool notice_failed)
{
    struct json_value observed; json_init(&observed); json_set_object(&observed);
    char tail[257];
    size_t n = result->evidence.stderr_len < 128 ? result->evidence.stderr_len : 128;
    zcl_hex_encode(result->evidence.stderr_tail + result->evidence.stderr_len - n, n, tail);
    bool ok = json_push_kv_str(&observed, "operation", stage) &&
        json_push_kv_bool(&observed, "progress_displayed", shown) &&
        json_push_kv_bool(&observed, "close_notice_failed", notice_failed) &&
        arf_transport_fields(&observed, result) &&
        json_push_kv_str(&observed, "stderr_tail_hex", tail) &&
        json_push_kv_int(&observed, "stderr_bytes_omitted", (int64_t)(result->evidence.stderr_observed - n)) &&
        json_push_kv_bool(&observed, "result_is_summary", true) &&
        json_push_kv_bool(&observed, "result_parsed", parsed) &&
        (!parsed || arf_result_summary(&observed, wire)) &&
        json_push_back(&f->operations, &observed);
    json_free(&observed);
    return ok || arf_fail(f, "OBSERVATION_UNAVAILABLE", f->adopted ? "The operation ran but its result could not be retained; inspect the adopted copy before retrying." : "The operation ran but its result could not be retained; inspect the received copy before retrying.");
}
static bool arf_capture_result(struct receive_flow *f, struct app_receive_job *job,
    struct json_value *wire, const char *stage, bool shown, bool notice_failed)
{
    struct app_receive_job_result result;
    if (!app_receive_job_poll(job, &result))
        return arf_fail(f, "WORKER_UNOBSERVED", "The operation has no completed observation.");
    bool parsed = result.evidence.stdout_complete && !result.evidence.stdout_truncated &&
        result.stdout_len && json_read(wire, result.stdout_json, result.stdout_len);
    if (!arf_observation(f, &result, wire, stage, parsed, shown, notice_failed)) return false;
    if (!result.transport_ok) {
        const struct json_value *error = parsed ? json_get(wire, "error") : NULL;
        const char *message = zcl_package_copy_str(error, "message");
        return arf_fail(f, result.evidence.timed_out ? "PREVIEW_TIMEOUT" : "PREVIEW_WORKER_FAILED",
            message ? message : "The operation did not finish successfully; inspect the retained copy before retrying.");
    }
    return parsed || arf_fail(f, "PREVIEW_RESULT_INVALID", "The operation returned no complete structured result.");
}
static void arf_cleanup_notice(struct receive_flow *f)
{
    /* Always diagnose immediately, including when the display is unavailable. */
    (void)fprintf(stderr, "%s: worker cleanup unconfirmed; retaining ownership and retrying cleanup only.\n", f->adopted ? "app.adopt" : "app.receive");
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "receive-flow/cleanup");
    if (!view) return;
    arf_model(f, view, "Cleanup is not confirmed", "The operation will not run again. Closing this notice retries cleanup; this request remains open until cleanup is confirmed.");
    arf_actions(view, "Retry cleanup");
    char why[256] = {0};
    if (arf_fields(f, view) && app_confirm_prepare(view, why, sizeof(why)))
        (void)app_confirm_show(view, f->presenter, f->context, why, sizeof(why));
    app_confirm_free(view); free(view);
}
static bool arf_job(struct receive_flow *f, enum app_receive_job_command command,
    const struct json_value *input, const char *stage, struct json_value *wire)
{
    json_init(wire);
    struct receive_progress *p = zcl_calloc(1, sizeof(*p), "receive-flow/progress");
    if (!p) return arf_fail(f, "OUT_OF_MEMORY", "Cannot prepare the progress window.");
    enum app_receive_job_start_result started = app_receive_job_start(NULL, command, input, &p->job);
    if (started != APP_RECEIVE_JOB_STARTED) {
        free(p); return arf_fail(f, "PREVIEW_WORKER_UNAVAILABLE", "Cannot start this platform's preview worker.");
    }
    if (command == APP_RECEIVE_JOB_OPEN) f->executed = -1;
    bool shown = arf_progress(f, p, stage);
    bool cleanup_failed = false;
    /* A join error is an invariant failure, not cancellation. Retain this
     * synchronous owner and retry cleanup only; never abandon or rerun work.
     * No bounded recovery is promised if the platform cannot join the thread. */
    while (!app_receive_job_join(p->job)) {
        arf_cleanup_notice(f);
        cleanup_failed = true;
        platform_sleep_ms(1000);
    }
    bool ok = arf_capture_result(f, p->job, wire, stage, shown, p->notice_failed);
    while (!app_receive_job_join_free(&p->job)) {
        arf_cleanup_notice(f);
        cleanup_failed = true;
        platform_sleep_ms(1000);
    }
    app_confirm_free(&p->view);
    bool notice_failed = p->notice_failed, closed = p->close_seen;
    free(p);
    if (!ok) return false; /* Never replace a missing-evidence diagnosis. */
    if (cleanup_failed) return arf_fail(f, "PREVIEW_CLEANUP_DELAYED", "Worker cleanup required recovery; the observed operation result is retained.");
    if (notice_failed) return arf_fail(f, "PROGRESS_NOTICE_UNAVAILABLE", "The closing notice could not be displayed; the observed operation result is retained.");
    if (!shown) return arf_fail(f, "PROGRESS_UNAVAILABLE", "Progress could not be displayed; the operation's result must be inspected before retrying.");
    if (closed) { f->closed = true; return false; }
    return true;
}
static bool arf_build(struct receive_flow *f)
{
    struct json_value input, plan, confirm, built;
    json_init(&input); json_init(&plan); json_init(&confirm); json_init(&built);
    bool ok = app_receive_preview_build_input(f->preview, &input) &&
        arf_job(f, APP_RECEIVE_JOB_BUILD, &input, f->adopted ? "Checking the personal saved version" : "Checking the received version", &plan) &&
        app_receive_preview_confirm_input(f->preview, &plan, &confirm, f->reply) &&
        arf_job(f, APP_RECEIVE_JOB_BUILD, &confirm, "Building your app", &built) &&
        app_receive_preview_bind_build(f->preview, &built, f->reply);
    json_free(&input); json_free(&plan); json_free(&confirm); json_free(&built);
    return ok;
}
static bool arf_open(struct receive_flow *f)
{
    struct json_value input, opened; json_init(&input); json_init(&opened);
    bool ok = app_receive_preview_open_input(f->preview, &input) &&
        arf_job(f, APP_RECEIVE_JOB_OPEN, &input, "Opening the built version", &opened) &&
        app_receive_preview_bind_preview(f->preview, &opened, f->reply);
    if (ok) f->executed = 1;
    if (ok) ok = json_push_kv_bool(&f->reply->data, "preview_opened", true);
    json_free(&input); json_free(&opened); return ok;
}
static bool arf_keep(struct receive_flow *f)
{
    bool chosen = false;
    if (!arf_choose(f, "Preview opened", f->adopted ? "Check the app before choosing Keep. Closing leaves your personal copy available." : "Check the app before choosing Keep. Closing leaves your received copy available.", "Keep this version", &chosen)) return false;
    if (!chosen) return arf_status(f, "previewed");
    struct json_value input; json_init(&input);
    enum app_receive_preview_keep_state state = app_receive_preview_keep_input(f->preview, &input, f->reply);
    bool ok = state != APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    if (state == APP_RECEIVE_PREVIEW_KEEP_NEW) {
        struct zcl_command_reply kept;
        ok = zcl_app_inner_call("app.keep", &input, &kept, NULL);
        if (!ok) zcl_app_inner_fail(f->reply, &kept, true);
        else {
            struct json_value summary; json_init(&summary); json_set_object(&summary);
            ok = arf_result_summary(&summary, &kept.data) &&
                json_push_kv(&f->reply->data, "kept", &summary);
            json_free(&summary);
        }
        zcl_command_reply_free(&kept);
    }
    json_free(&input); return ok && arf_status(f, "kept");
}
static void arf_notice(struct receive_flow *f)
{
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "receive-flow/error");
    if (!view) return;
    arf_model(f, view, "The next step did not finish", f->adopted ? "Your adopted copy is retained. Nothing is retried automatically." : "Your received copy is retained. Nothing is retried automatically.");
    arf_actions(view, "Close");
    char excerpt[192]; size_t n = strnlen(f->reply->error.message, sizeof(excerpt) - 1);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)f->reply->error.message[i];
        excerpt[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
    }
    excerpt[n] = 0;
    char why[256] = {0};
    if (app_confirm_field(&view->model, "Message excerpt: ", n ? excerpt : "The result could not be retained.") &&
        app_confirm_prepare(view, why, sizeof(why)))
        (void)app_confirm_show(view, f->presenter, f->context, why, sizeof(why));
    app_confirm_free(view); free(view);
}
/* Receive already committed. A later failure belongs to continuation, so the
 * successful Receive envelope still carries its original receipt. Opt-in
 * callers must inspect continuation; this does not claim preview succeeded. */
static bool arf_retained_error(struct receive_flow *f, struct json_value *error)
{
    if (!json_push_kv_bool(error, f->adopted ? "copy_retained" : "received_copy_retained", true)) return false;
    if (!f->adopted || strcmp(f->reply->error.code, "PREVIEW_CLEANUP_FAILED")) return true;
    /* Constructor-owned scratch path survives compact failure reporting. */
    return json_push_kv_str(error, "retained_scratch", f->reply->error.evidence);
}
static bool arf_finish(struct receive_flow *f, bool ok)
{
    struct json_value execution; json_init(&execution);
    if (f->executed >= 0) json_set_bool(&execution, f->executed == 1);
    bool saved = json_push_kv(&f->reply->data, "continuation_executed", &execution) &&
        json_push_kv_str(&f->reply->data, "continuation", ok ? f->status : "failed");
    json_free(&execution);
    if (ok) return saved;
    struct json_value error; json_init(&error); json_set_object(&error);
    char excerpt[161]; size_t n = strnlen(f->reply->error.message, sizeof(excerpt) - 1);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)f->reply->error.message[i];
        excerpt[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
    }
    excerpt[n] = 0;
    const char *code = arf_summary_text(f->reply->error.code) ? f->reply->error.code : "CONTINUATION_FAILED";
    saved = saved && json_push_kv_str(&error, "code", code) &&
        json_push_kv_str(&error, "message_excerpt", excerpt) &&
        arf_retained_error(f, &error) &&
        json_push_kv_bool(&error, "automatic_retry", false) &&
        json_push_kv(&f->reply->data, "continuation_error", &error);
    json_free(&error);
    if (saved) {
        bool mutated = f->reply->error.mutated;
        memset(&f->reply->error, 0, sizeof(f->reply->error));
        f->reply->error.mutated = mutated;
        f->reply->status = ZCL_COMMAND_STATUS_PASSED;
        f->reply->exit_code = 0;
    }
    return saved;
}
#ifdef ZCL_TESTING
bool app_receive_flow_test_report(struct zcl_command_reply *reply,
    const struct app_receive_job_result *results,
    const struct json_value *const wires[3], bool failed)
{
    static const char *const stages[] = {"build-plan", "build-confirm", "open"};
    struct receive_flow f = {.reply = reply, .status = "kept",
        .executed = failed ? -1 : 1};
    json_init(&f.operations); json_set_array(&f.operations);
    bool ok = true;
    for (size_t i = 0; ok && i < 3; ++i)
        ok = arf_observation(&f, &results[i], wires[i], stages[i], true, true, false);
    ok = ok && json_push_kv(&reply->data, "operations", &f.operations);
    json_free(&f.operations);
    if (ok && !failed) {
        struct json_value kept; json_init(&kept); json_set_object(&kept);
        ok = arf_result_summary(&kept, json_get(wires[2], "data")) &&
            json_push_kv(&reply->data, "kept", &kept);
        json_free(&kept);
    }
    if (ok && failed)
        (void)arf_fail(&f, "PREVIEW_TIMEOUT",
            zcl_package_copy_str(json_get(wires[2], "error"), "message"));
    return ok && arf_finish(&f, !failed);
}
#endif
static bool arf_prepare(struct receive_flow *f, const char *datadir, bool *chosen)
{
    bool ok = f->adopted ?
        app_receive_preview_create_adopted(&f->reply->data, datadir, &f->preview, f->reply) :
        app_receive_preview_create(&f->reply->data, datadir, &f->preview, f->reply);
    return ok && arf_choose(f, "Your copy is ready", f->adopted ?
        "Build and run this personal saved version to preview it. Keep remains a separate choice." :
        "Build and run this received version to preview it. Keep remains a separate choice.",
        "Build and preview", chosen);
}
static bool arf_continue(struct receive_flow *f, bool chosen)
{
    const char *status = f->adopted ? "adopted" : "received";
    bool ok = chosen ? (arf_build(f) && arf_open(f) && arf_keep(f)) : arf_status(f, status);
    if (!ok && f->closed) ok = arf_status(f, status);
    return ok;
}

static void arf_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, bool adopted)
{
    struct receive_flow f = {.reply = reply, .presenter = presenter, .context = context, .status = adopted ? "adopted" : "received", .adopted = adopted};
    json_init(&f.operations); json_set_array(&f.operations);
    bool chosen = false;
    bool ok = arf_prepare(&f, datadir, &chosen);
    if (ok) ok = arf_continue(&f, chosen);
    if (!json_push_kv(&reply->data, "operations", &f.operations))
        ok = arf_fail(&f, "OBSERVATION_UNAVAILABLE", "Operation evidence could not be returned; inspect the retained copy before retrying.");
    json_free(&f.operations);
    if (!ok) {
        reply->error.mutated = true;
        if (reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)arf_fail(&f, "PREVIEW_FAILED", adopted ? "The next step could not be completed; your adopted copy is retained." : "The next step could not be completed; your received copy is retained.");
        arf_notice(&f);
    }
    if (!arf_finish(&f, ok))
        (void)arf_fail(&f, "OBSERVATION_UNAVAILABLE", adopted ? "Adoption committed, but its continuation report could not be returned. Inspect the retained copy before retrying." : "Receive committed, but its continuation report could not be returned. Inspect the retained copy before retrying.");
    app_receive_preview_close(f.preview);
}
void app_receive_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context)
{
    arf_run(datadir, reply, presenter, context, false);
}
void app_adopted_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context)
{
    arf_run(datadir, reply, presenter, context, true);
}
