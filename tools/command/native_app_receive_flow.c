/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Keep received-app build, preview and Keep decisions in native windows. */
#include "command/native_app_receive_flow.h"
#include "command/native_app_commit_progress.h"
#include "command/native_app_receive_job.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_share_reveal.h"
#include "command/app_selection.h"
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
    bool (*revealer)(void *, const char *);
    void *reveal_context;
    struct json_value operations;
    struct json_value build_evidence;
    struct json_value open_evidence;
    app_receive_build_observer observer;
    void *observer_context;
    const char *status;
    bool adopted, closed, draft, recovered, identity_verified;
    int selection_changed; /* -1 after Keep dispatch until its result proves the outcome. */
    bool plan_retry_eligible, plan_retry_requested, plan_retry_used;
    size_t retry_data_budget;
    const char *worker_path;
    int executed; /* 0: no open worker; -1: outcome uncertain; 1: validated open. */
};
struct receive_progress {
    struct app_receive_job *job;
    struct app_confirm view;
    const char *phase;
    char why[256];
    bool close_seen;
    bool notice_failed;
};
static bool arf_fail(struct receive_flow *f, const char *code, const char *message)
{
    zcl_package_copy_fail(f->reply, code, (f->draft || f->recovered) ? f->reply->error.mutated : true,
        message, f->draft ? "app.library draft" : f->adopted ? "app.adopt preview" : "app.receive preview");
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
        app_confirm_field(&view->model, f->draft ? "Draft version: " : "Saved version: ", version) &&
        (!f->recovered || (app_confirm_field(&view->model, "Publisher: ",
            zcl_package_copy_str(&f->reply->data, "publisher_fingerprint")) &&
            app_confirm_field(&view->model, "Package: ", zcl_package_copy_str(&f->reply->data, "package_root")) &&
            app_confirm_path(&view->model, "Copy location: ", zcl_package_copy_str(&f->reply->data, "destination"))));
}
static void arf_actions(struct app_confirm *view, const char *action)
{
    view->model.action_count = 4;
    app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", action);
}
static const char *arf_choice_failure_message(const struct receive_flow *f)
{
    if (f->recovered) return "The next choice could not be displayed. Review the received copy before continuing.";
    return f->adopted ? "The next choice could not be displayed; the adopted copy is retained." :
        "The next choice could not be displayed; the received copy is retained.";
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
    return ok || arf_fail(f, "CONTINUATION_UNAVAILABLE", arf_choice_failure_message(f));
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
    p->phase = "fields";
    if (!arf_fields(f, &p->view)) return false;
    p->phase = "prepare";
    if (!app_confirm_prepare(&p->view, p->why, sizeof(p->why))) return false;
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
    p->phase = "presenter";
    return f->presenter ? f->presenter(f->context, &p->view.model, &pages, &live, p->why, sizeof(p->why)) :
        zcl_present_window_run_live_view_v1(&pages, 0, &live, p->why, sizeof(p->why));
}
static bool arf_progress_error(struct json_value *out, const struct receive_progress *p)
{
    char safe[sizeof(p->why)]; size_t i = 0;
    while (i + 1 < sizeof(safe) && p->why[i]) {
        unsigned char c = (unsigned char)p->why[i];
        safe[i++] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
    }
    safe[i] = 0;
    return json_push_kv_str(out, "progress_failure_phase", p->phase ? p->phase : "unknown") &&
        json_push_kv_str(out, "progress_error", i ? safe : "No detail available");
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
static bool arf_progress_fields(struct json_value *out, bool shown, const struct receive_progress *p)
{
    return json_push_kv_bool(out, "progress_displayed", shown) &&
        json_push_kv_bool(out, "close_notice_failed", p && p->notice_failed) &&
        (shown || (p && arf_progress_error(out, p)));
}
static bool arf_observation(struct receive_flow *f,
    const struct app_receive_job_result *result, const struct json_value *wire,
    const char *stage, bool parsed, bool shown, const struct receive_progress *p)
{
    struct json_value observed; json_init(&observed); json_set_object(&observed);
    char tail[257];
    size_t n = result->evidence.stderr_len < 128 ? result->evidence.stderr_len : 128;
    zcl_hex_encode(result->evidence.stderr_tail + result->evidence.stderr_len - n, n, tail);
    bool ok = json_push_kv_str(&observed, "operation", stage) &&
        arf_progress_fields(&observed, shown, p) &&
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
    struct json_value *wire, const char *stage, bool shown, const struct receive_progress *p)
{
    struct app_receive_job_result result;
    if (!app_receive_job_poll(job, &result))
        return arf_fail(f, "WORKER_UNOBSERVED", "The operation has no completed observation.");
    bool parsed = result.evidence.stdout_complete && !result.evidence.stdout_truncated &&
        result.stdout_len && json_read(wire, result.stdout_json, result.stdout_len);
    if (!arf_observation(f, &result, wire, stage, parsed, shown, p)) return false;
    if (!result.transport_ok) {
        const struct json_value *error = parsed ? json_get(wire, "error") : NULL;
        const char *message = zcl_package_copy_str(error, "message");
        return arf_fail(f, result.evidence.timed_out ? "PREVIEW_TIMEOUT" : "PREVIEW_WORKER_FAILED",
            message ? message : f->recovered ? "The operation did not finish. Review the received copy before retrying." :
                "The operation did not finish successfully; inspect the retained copy before retrying.");
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
static bool arf_recover_progress(struct receive_flow *f)
{
    bool chosen = false;
    bool displayed = arf_choose(f, "Operation result retained",
        "Progress could not be displayed. Continue with the retained result, or close to stop.",
        "Continue", &chosen);
    const char *decision = !displayed ? "unavailable" : chosen ? "continue" : "close";
    struct json_value *ops = &f->operations;
    if (!ops->num_children || !json_push_kv_str(&ops->children[ops->num_children - 1],
                                                "progress_recovery", decision))
        return arf_fail(f, "OBSERVATION_UNAVAILABLE", "The recovery choice could not be retained; inspect the copy before retrying.");
    if (displayed && chosen) return true;
    return arf_fail(f, "PROGRESS_UNAVAILABLE", "Progress could not be displayed; the operation's result must be inspected before retrying.");
}
static bool arf_progress_outcome(struct receive_flow *f, bool shown, bool closed)
{
    if (!shown) {
        if (closed) return arf_fail(f, "PROGRESS_UNAVAILABLE", "Progress could not be displayed; the operation's result must be inspected before retrying.");
        return arf_recover_progress(f);
    }
    if (closed) { f->closed = true; return false; }
    return true;
}
static bool arf_retry_wire(const struct json_value *wire)
{
    const struct json_value *error = json_get(wire, "error");
    const struct json_value *ok = json_get(wire, "ok"), *mutated = json_get(error, "mutated");
    const char *command = zcl_package_copy_str(wire, "command");
    const char *status = zcl_package_copy_str(wire, "status");
    const char *code = zcl_package_copy_str(error, "code");
    return command && !strcmp(command, "app.build") && status && !strcmp(status, "failed") &&
        ok && ok->type == JSON_BOOL && !json_get_bool(ok) &&
        code && !strcmp(code, "ENV_UNAVAILABLE") &&
        mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated);
}
static bool arf_retry_evidence(const struct app_receive_job_result *result,
                               const struct json_value *wire)
{
    return result->capture_status == 2 && result->evidence.exit_observed &&
        result->evidence.exit_code == 2 && !result->evidence.timed_out &&
        result->evidence.stdout_complete && !result->evidence.stdout_truncated &&
        result->evidence.stderr_complete && result->stdout_len && arf_retry_wire(wire);
}
#ifdef ZCL_TESTING
bool app_receive_flow_test_retry_evidence(const struct app_receive_job_result *result,
                                          const struct json_value *wire)
{ return result && wire && arf_retry_evidence(result, wire); }
#endif
static bool arf_retry_stage(const struct receive_flow *f, enum app_receive_job_command command,
                            const struct json_value *input)
{
    return !f->adopted && !f->draft && !f->plan_retry_used && !f->executed &&
        command == APP_RECEIVE_JOB_BUILD && !json_get(input, "confirm");
}
static void arf_retry_record(struct receive_flow *f)
{
    if (!f->operations.num_children) return;
    struct json_value *last = &f->operations.children[f->operations.num_children - 1];
    f->plan_retry_eligible = json_push_kv_str(last, "error_code", "ENV_UNAVAILABLE") &&
        json_push_kv_bool(last, "error_mutated", false);
}
static bool arf_retry_fits(const struct receive_flow *f)
{
    size_t data = json_write(&f->reply->data, NULL, 0);
    size_t prior = json_write(&f->operations, NULL, 0);
    /* Reserve the first observation twice (history plus operations), then
     * 10240 bytes for three maximal later observations, retry metadata and
     * the larger of Keep/failure continuation fields. The serializer fixture
     * exercises that bound against the registry's complete envelope. */
    return data && prior && prior <= 2048u && data <= 4096u &&
        data <= f->retry_data_budget && prior <= (f->retry_data_budget - data) / 2u &&
        f->retry_data_budget - data - 2u * prior >= 10240u;
}
#ifdef ZCL_TESTING
bool app_receive_flow_test_retry_fit(struct zcl_command_reply *reply,
                                    const struct json_value *operations, size_t budget)
{
    struct receive_flow f = {.reply = reply, .operations = *operations, .retry_data_budget = budget};
    return arf_retry_fits(&f);
}
#endif
struct arf_retry_observation { bool ok, shown, closed, notice_failed, cleanup_failed, observed; };
static void arf_retry_consider(struct receive_flow *f, enum app_receive_job_command command,
                               const struct json_value *input, const struct arf_retry_observation *o)
{
    if (!o->ok && arf_retry_stage(f, command, input) && o->shown && !o->closed &&
        !o->notice_failed && !o->cleanup_failed && o->observed) {
        arf_retry_record(f);
        if (f->plan_retry_eligible && !arf_retry_fits(f)) f->plan_retry_eligible = false;
    }
}
#ifdef ZCL_TESTING
bool app_receive_flow_test_retry_gate(const struct app_receive_job_result *result,
    const struct json_value *wire, unsigned flags)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "fixture");
    json_set_object(&reply.data); (void)json_push_kv_str(&reply.data, "fixture", "receipt");
    struct receive_flow f = {.reply = &reply, .retry_data_budget = (flags & 2048u) ? 0 : 14000u,
        .adopted = !!(flags & 1u), .draft = !!(flags & 2u),
        .plan_retry_used = !!(flags & 4u), .executed = (flags & 8u) ? -1 : 0};
    json_init(&f.operations); json_set_array(&f.operations);
    struct json_value item, input; json_init(&item); json_set_object(&item);
    json_init(&input); json_set_object(&input);
    bool ok = json_push_back(&f.operations, &item);
    if (flags & 16u) ok = ok && json_push_kv_bool(&input, "confirm", true);
    const struct arf_retry_observation o = {.ok = !!(flags & 32u), .shown = !(flags & 64u),
        .closed = !!(flags & 128u), .notice_failed = !!(flags & 256u),
        .cleanup_failed = !!(flags & 512u), .observed = result && wire && arf_retry_evidence(result, wire)};
    if (ok) arf_retry_consider(&f, (flags & 1024u) ? APP_RECEIVE_JOB_OPEN : APP_RECEIVE_JOB_BUILD, &input, &o);
    json_free(&input); json_free(&item); json_free(&f.operations); zcl_command_reply_free(&reply);
    return ok && f.plan_retry_eligible;
}
#endif
static bool arf_job_mutates(enum app_receive_job_command command, const struct json_value *input)
{
    return command == APP_RECEIVE_JOB_OPEN ||
        (command == APP_RECEIVE_JOB_BUILD && json_get_bool(json_get(input, "confirm")));
}
static bool arf_job(struct receive_flow *f, enum app_receive_job_command command,
    const struct json_value *input, const char *stage, struct json_value *wire)
{
    json_init(wire);
    struct receive_progress *p = zcl_calloc(1, sizeof(*p), "receive-flow/progress");
    if (!p) return arf_fail(f, "OUT_OF_MEMORY", "Cannot prepare the progress window.");
    enum app_receive_job_start_result started = app_receive_job_start(f->worker_path, command, input, &p->job);
    if (started != APP_RECEIVE_JOB_STARTED) {
        free(p); return arf_fail(f, "PREVIEW_WORKER_UNAVAILABLE", "Cannot start this platform's preview worker.");
    }
    if ((f->draft || f->recovered) && arf_job_mutates(command, input))
        f->reply->error.mutated = true;
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
    size_t before_observation = f->operations.num_children;
    bool ok = arf_capture_result(f, p->job, wire, stage, shown, p);
    struct app_receive_job_result retry_result;
    bool retry_observed = app_receive_job_poll(p->job, &retry_result) &&
        arf_retry_evidence(&retry_result, wire);
    while (!app_receive_job_join_free(&p->job)) {
        arf_cleanup_notice(f);
        cleanup_failed = true;
        platform_sleep_ms(1000);
    }
    app_confirm_free(&p->view);
    bool notice_failed = p->notice_failed, closed = p->close_seen;
    free(p);
    const struct arf_retry_observation retry = {ok, shown, closed, notice_failed, cleanup_failed,
        retry_observed && f->operations.num_children == before_observation + 1u};
    arf_retry_consider(f, command, input, &retry);
    if (!ok) return false; /* Never replace a missing-evidence diagnosis. */
    if (cleanup_failed) return arf_fail(f, "PREVIEW_CLEANUP_DELAYED", "Worker cleanup required recovery; the observed operation result is retained.");
    if (notice_failed) return arf_fail(f, "PROGRESS_NOTICE_UNAVAILABLE", "The closing notice could not be displayed; the observed operation result is retained.");
    return arf_progress_outcome(f, shown, closed);
}
static bool arf_build(struct receive_flow *f)
{
    if ((f->draft || f->recovered) && !app_receive_preview_current(f->preview, f->reply)) return false;
    struct json_value input, plan, confirm, built;
    json_init(&input); json_init(&plan); json_init(&confirm); json_init(&built);
    bool ok = app_receive_preview_build_input(f->preview, &input) &&
        arf_job(f, APP_RECEIVE_JOB_BUILD, &input, f->adopted ? "Checking the personal saved version" : "Checking the received version", &plan) &&
        app_receive_preview_confirm_input(f->preview, &plan, &confirm, f->reply) &&
        arf_job(f, APP_RECEIVE_JOB_BUILD, &confirm, "Building your app", &built) &&
        app_receive_preview_bind_build(f->preview, &built, f->reply);
    if (ok && f->observer) { f->build_evidence = built; json_init(&built); }
    json_free(&input); json_free(&plan); json_free(&confirm); json_free(&built);
    return ok;
}
static bool arf_open(struct receive_flow *f)
{
    if ((f->draft || f->recovered) && !app_receive_preview_current(f->preview, f->reply)) return false;
    struct json_value input, opened; json_init(&input); json_init(&opened);
    bool ok = app_receive_preview_open_input(f->preview, &input) &&
        arf_job(f, APP_RECEIVE_JOB_OPEN, &input, "Opening the built version", &opened) &&
        app_receive_preview_bind_preview(f->preview, &opened, f->reply);
    if (ok) f->executed = 1;
    if (ok) ok = json_push_kv_bool(&f->reply->data, "preview_opened", true);
    if (ok && f->observer) { f->open_evidence = opened; json_init(&opened); }
    json_free(&input); json_free(&opened); return ok;
}
static bool arf_keep_result(struct receive_flow *f, const struct zcl_command_reply *kept, bool *canceled)
{
    const char *status = zcl_package_copy_str(&kept->data, "status");
    if (status && !strcmp(status, "canceled")) { if (f->recovered) f->selection_changed = 0; *canceled = true; return true; }
    if (!status || strcmp(status, "kept"))
        return arf_fail(f, "KEEP_RESULT_INVALID", "Keep returned no confirmed selection; inspect before retrying.");
    if (f->draft || f->recovered) f->reply->error.mutated = true;
    if (f->recovered) f->selection_changed = true;
    struct json_value summary; json_init(&summary); json_set_object(&summary);
    bool ok = arf_result_summary(&summary, &kept->data) && json_push_kv(&f->reply->data, "kept", &summary);
    json_free(&summary); return ok;
}
static const char *arf_keep_summary(const struct receive_flow *f)
{
    if (f->draft) return "Check the app before choosing Keep. This keeps the exact version you previewed; newer changes remain available.";
    if (f->adopted) return "Check the app before choosing Keep. Closing leaves your personal copy available.";
    if (f->recovered) return "Check the app before choosing Keep. Closing ends this review.";
    return "Check the app before choosing Keep. Closing leaves your received copy available.";
}
static bool arf_keep_commit(struct receive_flow *f, struct json_value *input, bool *canceled)
{
    struct zcl_command_reply kept;
    if (f->recovered) f->selection_changed = -1;
    bool ok = zcl_app_inner_call("app.keep", input, &kept, NULL);
    if (!ok) zcl_app_inner_fail(f->reply, &kept, true);
    else ok = arf_keep_result(f, &kept, canceled);
    zcl_command_reply_free(&kept); return ok;
}
static bool arf_keep(struct receive_flow *f)
{
    if ((f->draft || f->recovered) && !app_receive_preview_current(f->preview, f->reply)) return false;
    bool chosen = false;
    if (!arf_choose(f, "Preview opened", arf_keep_summary(f), "Keep this version", &chosen)) return false;
    if (!chosen) return arf_status(f, "previewed");
    struct json_value input; json_init(&input);
    enum app_receive_preview_keep_state state = app_receive_preview_keep_input(f->preview, &input, f->reply);
    bool ok = state != APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    if (f->recovered && state == APP_RECEIVE_PREVIEW_KEEP_SAME) {
        json_free(&input); return arf_status(f, "already_kept");
    }
    if (state == APP_RECEIVE_PREVIEW_KEEP_NEW) {
        bool canceled = false;
        ok = arf_keep_commit(f, &input, &canceled);
        if (canceled) { json_free(&input); return arf_status(f, "previewed"); }
    }
    json_free(&input); return ok && arf_status(f, "kept");
}
static const char *arf_notice_location(struct receive_flow *f, struct app_confirm *view)
{
    if (f->draft) return NULL;
    const char *path = zcl_package_copy_str(&f->reply->data,
        f->adopted ? "copy" : "destination");
    if (!path) return NULL;
    uint32_t start = view->model.item_count;
    if (!app_confirm_path(&view->model, "Copy location: ", path)) {
        view->model.item_count = start;
        return NULL;
    }
#if defined(__APPLE__) || defined(__linux__)
    size_t n = strnlen(path, 4097u);
    if (n > 1 && n < 4097u && path[0] == '/' && path[n - 1] != '/') return path;
#endif
    return NULL;
}
static void arf_reveal_action(struct app_confirm *view, bool enabled)
{
    const char *label = "Close";
#if defined(__APPLE__)
    if (enabled) label = "Show copy";
#elif defined(__linux__)
    if (enabled) label = "Open folder";
#else
    (void)enabled;
#endif
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", label);
}
static bool arf_reveal(struct receive_flow *f, const char *path)
{
    return f->revealer ? f->revealer(f->reveal_context, path) : app_share_reveal(path);
}
static void arf_reveal_failed(struct receive_flow *f, struct app_confirm *view)
{
    app_confirm_free(view);
    view->page_count = 0;
    (void)snprintf(view->model.summary, sizeof(view->model.summary),
        "%s", f->recovered ? "Could not open the copy location. Nothing is retried automatically." :
        "Could not open the copy location. Your copy is retained; nothing is retried automatically.");
    arf_reveal_action(view, false);
    char why[256] = {0};
    if (app_confirm_prepare(view, why, sizeof(why)))
        (void)app_confirm_show(view, f->presenter, f->context, why, sizeof(why));
}
static void arf_notice_show(struct receive_flow *f, struct app_confirm *view)
{
    uint32_t original = view->model.item_count;
    const char *path = arf_notice_location(f, view);
    arf_reveal_action(view, path != NULL);
    if (f->plan_retry_eligible) {
        (void)snprintf(view->model.summary, sizeof(view->model.summary),
            "%s", f->recovered ? "Review the received copy and fix the build tools before trying again." :
            "Your received copy is retained. Fix the build tools before trying again.");
        app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", "Try build again");
    }
    char why[256] = {0};
    bool prepared = app_confirm_prepare(view, why, sizeof(why));
    if (!prepared && view->model.item_count != original) {
        app_confirm_free(view);
        view->page_count = 0;
        view->model.item_count = original;
        path = NULL;
        arf_reveal_action(view, false);
        if (f->plan_retry_eligible)
            app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", "Try build again");
        prepared = app_confirm_prepare(view, why, sizeof(why));
    }
    if (prepared && app_confirm_show(view, f->presenter, f->context, why, sizeof(why)) && view->confirmed) {
        if (f->plan_retry_eligible) f->plan_retry_requested = true;
        else if (path && !arf_reveal(f, path)) arf_reveal_failed(f, view);
    }
}
static const char *arf_notice_summary(const struct receive_flow *f)
{
    if (f->recovered) return "Review the received copy before continuing. Nothing is retried automatically.";
    if (f->draft) return "Your unkept draft is retained. Nothing is retried automatically.";
    if (f->adopted) return "Your adopted copy is retained. Nothing is retried automatically.";
    return "Your received copy is retained. Nothing is retried automatically.";
}
static void arf_notice(struct receive_flow *f)
{
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "receive-flow/error");
    if (!view) return;
    arf_model(f, view, "The next step did not finish", arf_notice_summary(f));
    arf_actions(view, "Close");
    char excerpt[192]; size_t n = strnlen(f->reply->error.message, sizeof(excerpt) - 1);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)f->reply->error.message[i];
        excerpt[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
    }
    excerpt[n] = 0;
    if ((!f->draft || arf_fields(f, view)) &&
        app_confirm_field(&view->model, "Message excerpt: ", n ? excerpt : "The result could not be retained."))
        arf_notice_show(f, view);
    app_confirm_free(view); free(view);
}
#ifdef ZCL_TESTING
bool app_receive_flow_test_retry_notice(struct zcl_command_reply *reply,
                                       app_confirm_presenter presenter, void *context)
{
    struct receive_flow f = {.reply = reply, .presenter = presenter,
        .context = context, .plan_retry_eligible = true};
    arf_notice(&f);
    return f.plan_retry_requested;
}
void app_receive_flow_test_notice_reveal(struct zcl_command_reply *reply, bool adopted, bool draft,
    app_confirm_presenter presenter, void *context, bool (*revealer)(void *, const char *))
{
    struct receive_flow f = {.reply = reply, .adopted = adopted, .draft = draft,
        .presenter = presenter, .context = context, .revealer = revealer, .reveal_context = context};
    arf_notice(&f);
}
void app_receive_flow_test_notice(struct zcl_command_reply *reply, bool adopted,
                                  app_confirm_presenter presenter, void *context)
{
    struct receive_flow f = {.reply = reply, .adopted = adopted,
        .presenter = presenter, .context = context};
    arf_notice(&f);
}
#endif
/* Receive already committed. A later failure belongs to continuation, so the
 * successful Receive envelope still carries its original receipt. Opt-in
 * callers must inspect continuation; this does not claim preview succeeded. */
static bool arf_retained_error(struct receive_flow *f, struct json_value *error)
{
    if (f->recovered && !f->identity_verified) return true;
    if (f->recovered) {
        struct zcl_command_reply check; zcl_command_reply_init(&check, "zcl.app_recovery.v1");
        bool current = f->preview && app_receive_preview_current(f->preview, &check);
        zcl_command_reply_free(&check);
        if (!current) return true; /* the earlier review does not prove present trust or location */
    }
    if (!json_push_kv_bool(error, f->adopted ? "copy_retained" : "received_copy_retained", true)) return false;
    if (!f->adopted || strcmp(f->reply->error.code, "PREVIEW_CLEANUP_FAILED")) return true;
    /* Constructor-owned scratch path survives compact failure reporting. */
    return json_push_kv_str(error, "retained_scratch", f->reply->error.evidence);
}
static bool arf_finish_failure(struct receive_flow *f, bool saved)
{
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
    if (saved && !f->recovered) {
        bool mutated = f->reply->error.mutated;
        memset(&f->reply->error, 0, sizeof(f->reply->error));
        f->reply->error.mutated = mutated;
        f->reply->status = ZCL_COMMAND_STATUS_PASSED;
        f->reply->exit_code = 0;
    }
    return saved;
}
static bool arf_finish(struct receive_flow *f, bool ok)
{
    struct json_value execution; json_init(&execution);
    if (f->executed >= 0) json_set_bool(&execution, f->executed == 1);
    struct json_value selection; json_init(&selection);
    if (f->selection_changed >= 0) json_set_bool(&selection, f->selection_changed == 1);
    bool saved = (!f->recovered || json_push_kv(&f->reply->data, "selection_changed", &selection)) &&
        json_push_kv(&f->reply->data, "continuation_executed", &execution) &&
        json_push_kv_str(&f->reply->data, "continuation", ok ? f->status : "failed");
    json_free(&selection); json_free(&execution);
    return ok ? saved : arf_finish_failure(f, saved);
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
        ok = arf_observation(&f, &results[i], wires[i], stages[i], true, true, NULL);
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
bool app_receive_flow_test_retry_report(struct zcl_command_reply *reply,
    const struct json_value *prior, const struct app_receive_job_result results[3],
    const struct json_value *wire, bool failed)
{
    struct receive_flow f = {.reply = reply, .status = "kept", .executed = failed ? -1 : 1};
    json_init(&f.operations); json_set_array(&f.operations);
    struct receive_progress *p = zcl_calloc(1, sizeof(*p), "retry-budget/progress");
    if (!p) { json_free(&f.operations); return false; }
    p->phase = "presenter"; p->notice_failed = true;
    memset(p->why, '"', sizeof(p->why) - 1);
    bool ok = json_push_kv(&reply->data, "initial_retry_failure", prior) &&
        json_push_back(&f.operations, prior) && json_push_kv_bool(&reply->data, "preview_opened", true);
    for (size_t i = 0; ok && i < 3; ++i) {
        ok = arf_observation(&f, &results[i], wire, "Checking the received version", true, false, p);
        if (ok) ok = json_push_kv_str(&f.operations.children[f.operations.num_children - 1],
                                       "progress_recovery", "unavailable");
    }
    if (ok) ok = json_push_kv(&reply->data, "operations", &f.operations);
    if (ok && !failed) {
        struct json_value kept; json_init(&kept); json_set_object(&kept);
        ok = arf_result_summary(&kept, wire) && json_push_kv(&reply->data, "kept", &kept);
        json_free(&kept);
    }
    if (ok && failed) {
        char message[192]; memset(message, '"', sizeof(message) - 1); message[sizeof(message) - 1] = 0;
        char code[65]; memset(code, 'a', 64); code[64] = 0;
        (void)arf_fail(&f, code, message);
    }
    free(p); json_free(&f.operations);
    return ok && arf_finish(&f, !failed);
}
#endif
static bool arf_prepare(struct receive_flow *f, const char *datadir, bool *chosen)
{
    bool ok;
    if (f->recovered) {
        uint8_t fork[32];
        const char *version = zcl_package_copy_str(&f->reply->data, "version");
        const char *copy = zcl_package_copy_str(&f->reply->data, "destination");
        ok = version && strlen(version) == 64 && zcl_hex_decode_lower(version, fork, 32) &&
            app_receive_preview_create_recovered(copy, datadir, fork, &f->preview, f->reply);
    } else ok = f->adopted ?
        app_receive_preview_create_adopted(&f->reply->data, datadir, &f->preview, f->reply) :
        app_receive_preview_create(&f->reply->data, datadir, &f->preview, f->reply);
    return ok && arf_choose(f, "Your copy is ready", f->recovered ?
        "Build and preview the original received snapshot, even if newer edits exist. Keep is a separate choice." : f->adopted ?
        "Build and run this personal saved version to preview it. Keep remains a separate choice." :
        "Build and run this received version to preview it. Keep remains a separate choice.",
        "Build and preview", chosen);
}
static bool arf_continue(struct receive_flow *f, bool chosen)
{
    const char *status = f->recovered ? "recovered" : f->adopted ? "adopted" : "received";
    bool ok = chosen ? (arf_build(f) && arf_open(f) && arf_keep(f)) : arf_status(f, status);
    /* This card offers Keep or Close; Close ends the owner flow. */
    if (ok && chosen && f->observer && !strcmp(f->status, "kept"))
        f->observer(f->observer_context, &f->build_evidence, &f->open_evidence, f->reply);
    if (ok) ok = f->reply->status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok && f->closed) ok = arf_status(f, status);
    return ok;
}
static bool arf_retry_plan(struct receive_flow *f, const char *datadir)
{
    if (!f->plan_retry_requested || !f->plan_retry_eligible || !f->operations.num_children)
        return false;
    struct json_value *last = &f->operations.children[f->operations.num_children - 1];
    if (!json_push_kv_str(last, "retry_choice", "try_again") ||
        !json_push_kv(&f->reply->data, "initial_retry_failure", last)) {
        f->plan_retry_eligible = f->plan_retry_requested = false;
        return arf_fail(f, "OBSERVATION_UNAVAILABLE", "The retry was not started because its earlier failure could not be retained.");
    }
    f->plan_retry_used = true;
    f->plan_retry_eligible = f->plan_retry_requested = false;
    app_receive_preview_close(f->preview); f->preview = NULL;
    bool mutated = f->reply->error.mutated;
    memset(&f->reply->error, 0, sizeof(f->reply->error));
    f->reply->error.mutated = mutated;
    f->reply->status = ZCL_COMMAND_STATUS_PASSED; f->reply->exit_code = 0;
    bool chosen = false;
    return arf_prepare(f, datadir, &chosen) && arf_continue(f, chosen);
}

static const char *arf_generic_failure(const struct receive_flow *f)
{
    if (f->recovered) return "The next step could not be completed; review the received copy.";
    return f->adopted ? "The next step could not be completed; your adopted copy is retained." :
        "The next step could not be completed; your received copy is retained.";
}
static const char *arf_operations_failure(const struct receive_flow *f)
{
    return f->recovered ? "Operation evidence could not be returned; review the received copy before retrying." :
        "Operation evidence could not be returned; inspect the retained copy before retrying.";
}
static void arf_complete(struct receive_flow *f, const char *datadir, bool ok)
{
    struct zcl_command_reply *reply = f->reply;
    if (!ok) {
        if (!f->recovered) reply->error.mutated = true;
        if (reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)arf_fail(f, "PREVIEW_FAILED", arf_generic_failure(f));
        arf_notice(f);
        if (f->plan_retry_requested) {
            ok = arf_retry_plan(f, datadir);
            if (!ok) arf_notice(f);
        }
    }
    if (!json_push_kv(&reply->data, "operations", &f->operations)) {
        ok = arf_fail(f, "OBSERVATION_UNAVAILABLE", arf_operations_failure(f));
        f->plan_retry_eligible = false;
        arf_notice(f);
    }
    json_free(&f->operations);
    if (!arf_finish(f, ok))
        (void)arf_fail(f, "OBSERVATION_UNAVAILABLE", f->recovered ? "Recovery result could not be returned; review the received copy." : f->adopted ? "Adoption committed, but its continuation report could not be returned. Inspect the retained copy before retrying." : "Receive committed, but its continuation report could not be returned. Inspect the retained copy before retrying.");
    app_receive_preview_close(f->preview);
    json_free(&f->build_evidence);
    json_free(&f->open_evidence);
}
static void arf_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, bool adopted, const char *worker_path,
    app_receive_build_observer observer, void *observer_context, size_t data_budget)
{
    struct receive_flow f = {.reply = reply, .presenter = presenter, .context = context, .status = adopted ? "adopted" : "received", .adopted = adopted, .worker_path = worker_path, .observer = observer, .observer_context = observer_context, .retry_data_budget = data_budget};
    json_init(&f.build_evidence); json_init(&f.open_evidence);
    json_init(&f.operations); json_set_array(&f.operations);
    bool chosen = false;
    bool ok = arf_prepare(&f, datadir, &chosen);
    if (ok) ok = arf_continue(&f, chosen);
    arf_complete(&f, datadir, ok);
}
void app_recovered_flow_run(const char *copy_dir, const char *datadir, const uint8_t expected_fork[32],
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
    const char *worker_path, size_t data_budget)
{
    struct receive_flow f = {.reply = reply, .presenter = presenter, .context = context,
        .status = "recovered", .recovered = true, .worker_path = worker_path, .retry_data_budget = data_budget};
    json_init(&f.build_evidence); json_init(&f.open_evidence);
    json_init(&f.operations); json_set_array(&f.operations);
    bool chosen = false;
    bool ok = expected_fork && app_receive_preview_create_recovered(copy_dir, datadir, expected_fork, &f.preview, reply);
    f.identity_verified = ok;
    if (ok && !app_receive_preview_describe_recovered(f.preview, &reply->data))
        ok = arf_fail(&f, "OBSERVATION_UNAVAILABLE", "The recovered identity could not be retained.");
    if (ok) {
        size_t data_size = json_write(&reply->data, NULL, 0);
        if (!data_size || data_size > data_budget || data_budget - data_size < 10240u)
            ok = arf_fail(&f, "BUDGET_TOO_SMALL", "The recovered result cannot fit safely; no build was started.");
    }
    if (ok) ok = arf_choose(&f, "Your copy is ready", "Build and preview the original received snapshot, even if newer edits exist. Keep is a separate choice.", "Build and preview", &chosen);
    if (ok) ok = arf_continue(&f, chosen);
    arf_complete(&f, datadir, ok);
}
void app_receive_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context)
{
    arf_run(datadir, reply, presenter, context, false, NULL, NULL, NULL, 14000u);
}
void app_receive_flow_run_observed(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path,
    app_receive_build_observer observer, void *observer_context)
{ arf_run(datadir, reply, presenter, context, false, worker_path, observer, observer_context, 14000u); }
void app_receive_flow_run_budgeted(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path,
    app_receive_build_observer observer, void *observer_context, size_t data_budget)
{ arf_run(datadir, reply, presenter, context, false, worker_path, observer, observer_context, data_budget); }
void app_adopted_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context)
{
    arf_run(datadir, reply, presenter, context, true, NULL, NULL, NULL, 0);
}

static bool arf_draft_confirm(struct receive_flow *f, const struct app_selection *selection, uint8_t head[32])
{
    char hex[65]; bool chosen = false;
    if (!app_saved_draft_head(selection, head, f->reply)) return false;
    zcl_hex_encode(head, 32, hex);
    if (!json_push_kv_str(&f->reply->data, "name", selection->app) ||
        !json_push_kv_str(&f->reply->data, "version", hex))
        return arf_fail(f, "OUT_OF_MEMORY", "Cannot describe the draft.");
    if (!arf_choose(f, "Review unkept changes", "Build and preview this exact draft. Keep remains a separate choice.",
            "Build and preview", &chosen)) return false;
    if (chosen) return true;
    if (!json_push_kv_str(&f->reply->data, "status", "canceled"))
        (void)arf_fail(f, "OUT_OF_MEMORY", "Cannot describe cancellation.");
    return false;
}
void app_saved_draft_flow_run(const struct app_selection *selection,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
    const char *worker_path)
{
    if (!selection || !reply) return;
    struct receive_flow f = {.reply = reply, .presenter = presenter, .context = context,
        .status = "draft", .draft = true, .worker_path = worker_path};
    uint8_t head[32];
    if (!arf_draft_confirm(&f, selection, head)) return;
    if (!app_saved_draft_preview_create(selection, head, &f.preview, reply)) return;
    json_init(&f.operations); json_set_array(&f.operations);
    bool ok = arf_build(&f) && arf_open(&f) && arf_keep(&f);
    if (!json_push_kv(&reply->data, "operations", &f.operations))
        ok = arf_fail(&f, "OBSERVATION_UNAVAILABLE", "Inspect the retained draft before retrying.");
    json_free(&f.operations);
    if (!ok && !f.closed) arf_notice(&f);
    if (!arf_finish(&f, ok || f.closed))
        (void)arf_fail(&f, "OBSERVATION_UNAVAILABLE", "Inspect the retained draft before retrying.");
    app_receive_preview_close(f.preview);
}
#ifdef ZCL_TESTING
void app_receive_flow_run_test(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path)
{
    arf_run(datadir, reply, presenter, context, false, worker_path, NULL, NULL, 14000u);
}
#endif
