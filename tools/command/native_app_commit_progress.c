/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Own an approved native commit worker while the main thread presents responsive progress. */
#include "command/native_app_commit_progress.h"
#include "command/native_zcode_package_copy.h"
#include "base/safe_alloc.h"
#include <stdlib.h>
#include <stdio.h>
#if !defined(_WIN32)
#include "util/thread_registry.h"
#include "platform/time_compat.h"
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include <string.h>
static bool acp_fail(struct zcl_command_reply *reply, const char *code, const char *message)
{
    zcl_package_copy_fail(reply, code, reply->error.mutated, message, "native commit progress");
    return false;
}
struct acp {
    void *work; /* Exclusively borrowed by commit until completion. */
    app_commit_progress_commit commit;
    struct app_commit_progress_labels labels;
    struct zcl_command_request request;
    struct json_value input;
    struct zcl_command_reply result;
    pthread_t thread;
    atomic_bool done;
    struct app_confirm view;
    struct zcl_present_model_bitmap_v1 finishing;
    bool close_seen; /* Main thread only. */
#ifdef ZCL_TESTING
    struct app_commit_progress_test_hooks test_hooks;
#endif
};
/* Exceptional completed-but-unjoined ownership, never reusable work. A
 * permanent join error blocks further starts; process teardown owns this
 * retained allocation/handle. No worker uses caller storage after done. */
static _Atomic(struct acp *) acp_unjoined;
static void *acp_worker(void *context)
{
    struct acp *p = context;
    uint64_t failures = zcl_alloc_failure_count();
#ifdef ZCL_TESTING
    if (p->test_hooks.worker_alloc_label)
        zcl_alloc_fault_fail_next(p->test_hooks.worker_alloc_label);
    if (p->test_hooks.commit)
        p->test_hooks.commit(p->test_hooks.context, &p->request, &p->result);
    else
#endif
        p->commit(p->work, &p->request, &p->result);
#ifdef ZCL_TESTING
    zcl_alloc_fault_clear();
#endif
    if (zcl_alloc_failure_count() != failures && p->result.status == ZCL_COMMAND_STATUS_PASSED)
        (void)acp_fail(&p->result, "OUT_OF_MEMORY", "Copy preparation encountered an allocation failure; inspect retained state before retrying.");
    atomic_store_explicit(&p->done, true, memory_order_release);
    return NULL;
}
static bool acp_prepare(struct acp *p, char *why, size_t cap)
{
    struct zcl_present_model_v1 *m = &p->view.model;
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "%s", p->labels.request_id);
    (void)snprintf(m->title, sizeof(m->title), "%s", p->labels.title);
    (void)snprintf(m->summary, sizeof(m->summary), "%s", p->labels.summary);
    if (!app_confirm_prepare(&p->view, why, cap)) return false;
    (void)snprintf(m->summary, sizeof(m->summary), "%s", p->labels.finishing);
    bool ok = zcl_present_model_render_page_v1(m, 0, &p->finishing, why, cap);
    (void)snprintf(m->summary, sizeof(m->summary), "%s", p->labels.summary);
    p->view.page = (struct zcl_present_window_v1){
        .struct_size = sizeof(p->view.page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = p->labels.title, .pixels = p->view.bitmaps[0].pixels,
        .width = p->view.bitmaps[0].width, .height = p->view.bitmaps[0].height,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    return ok;
}
static void acp_tick(void *context, const struct zcl_present_window_event_v1 *event,
    bool close_requested, bool *redraw, bool *allow_close)
{
    (void)event;
    struct acp *p = context;
    *redraw = false;
    *allow_close = atomic_load_explicit(&p->done, memory_order_acquire);
    if (close_requested && !p->close_seen) {
        p->close_seen = true;
        (void)snprintf(p->view.model.summary, sizeof(p->view.model.summary), "%s", p->labels.finishing);
        p->view.page.pixels = p->finishing.pixels;
        *redraw = !*allow_close;
    }
}
static bool acp_show(struct acp *p,
    app_confirm_presenter presenter, void *context, char *why, size_t cap)
{
    const struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &p->view.page, .page_count = 1,
    };
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = p, .update = acp_tick}, .input = app_commit_progress_ignore_input,
    };
    return presenter ? presenter(context, &p->view.model, &pages, &live, why, cap) :
        zcl_present_window_run_live_view_v1(&pages, 0, &live, why, cap);
}
static void acp_free(struct acp *p)
{
    app_confirm_free(&p->view);
    zcl_present_model_bitmap_free_v1(&p->finishing);
    json_free(&p->input); zcl_command_reply_free(&p->result); free(p);
}
static struct acp *acp_new(const struct zcl_command_request *request,
    void *work, app_commit_progress_commit commit, const struct app_commit_progress_labels *labels,
    struct zcl_command_reply *reply
#ifdef ZCL_TESTING
    , const struct app_commit_progress_test_hooks *hooks
#endif
)
{
    struct acp *p = zcl_calloc(1, sizeof(*p), labels->allocation);
    if (!p) { (void)acp_fail(reply, "OUT_OF_MEMORY", "Cannot prepare commit progress."); return NULL; }
    p->work = work; p->commit = commit; p->labels = *labels; p->request = *request;
#ifdef ZCL_TESTING
    if (hooks) p->test_hooks = *hooks;
#endif
    json_init(&p->input); zcl_command_reply_init(&p->result, reply->data_schema);
    p->result.error.mutated = reply->error.mutated;
    atomic_init(&p->done, false);
    char why[256];
    if (!json_copy_checked(&p->input, request->input) || !acp_prepare(p, why, sizeof(why))) {
        acp_free(p);
        (void)acp_fail(reply, labels->unavailable, "Cannot prepare progress; no commit was started.");
        return NULL;
    }
    p->request.input = &p->input;
    return p;
}
/* Completion precedes join, including UI failure. A permanent join error
 * cannot leave a worker accessing request/consent storage after return. */
static bool acp_join(struct acp *p)
{
    while (!atomic_load_explicit(&p->done, memory_order_acquire))
        platform_sleep_ms(10); /* real-clock: approved native worker completion barrier */
    int rc;
    do { rc = pthread_join(p->thread, NULL); } while (rc == EINTR);
    if (!rc) return true;
    fprintf(stderr, "native commit: completed worker join failed (%d); retaining handle and blocking further commits\n", rc);
    p->work = NULL; p->commit = NULL; p->request.context = NULL; p->request.spec = NULL;
    p->request.view = NULL; p->request.cursor = NULL; p->request.invoked_name = NULL;
#ifdef ZCL_TESTING
    memset(&p->test_hooks, 0, sizeof(p->test_hooks));
#endif
    atomic_store_explicit(&acp_unjoined, p, memory_order_release);
    return false;
}
static bool acp_start(struct acp *p, struct zcl_command_reply *reply)
{
    /* Non-NULL tid assigns joining to this invocation, including UI failure. */
    bool refused = false;
#ifdef ZCL_TESTING
    refused = p->test_hooks.refuse_start;
#endif
    if (refused || thread_registry_spawn(p->labels.name, acp_worker, p, &p->thread) != 0) {
        return acp_fail(reply, p->labels.start_failed, "Cannot start commit; no commit operation was started.");
    }
    return true;
}
static struct app_commit_progress_outcome acp_result(struct acp *p,
    struct zcl_command_reply *reply, bool shown, bool joined)
{
    struct app_commit_progress_outcome out = {
        .started = true, .joined = joined, .ui_ok = shown, .close_requested = p->close_seen,
    };
    zcl_command_reply_free(reply); *reply = p->result;
    zcl_command_reply_init(&p->result, reply->data_schema);
    if (!joined) {
        (void)acp_fail(reply, p->labels.join_failed,
            "Commit completed but could not be joined; saved state is retained and automatic retry is blocked.");
    } else acp_free(p);
    return out;
}
#endif
bool app_commit_progress_ignore_input(void *context, const struct zcl_present_input_v1 *input,
    uint32_t *focus, uint32_t *action)
{
    (void)context; (void)input; (void)focus; (void)action;
    return false;
}
struct app_commit_progress_outcome app_commit_progress_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    app_commit_progress_commit commit, void *work, const struct app_commit_progress_labels *labels,
    app_confirm_presenter presenter, void *context
#ifdef ZCL_TESTING
    , const struct app_commit_progress_test_hooks *hooks
#endif
)
{
    struct app_commit_progress_outcome out = {0};
    if (!request || !reply || !commit || !labels) return out;
#if defined(_WIN32)
    (void)presenter; (void)context;
#ifdef ZCL_TESTING
    (void)hooks;
#endif
    commit(work, request, reply);
    out.started = out.joined = out.ui_ok = true;
    return out;
#else
    if (atomic_load_explicit(&acp_unjoined, memory_order_acquire)) {
        (void)acp_fail(reply, labels->join_failed, "A previous commit remains unjoined; no new commit was started.");
        return out;
    }
    struct acp *p = acp_new(request, work, commit, labels, reply
#ifdef ZCL_TESTING
        , hooks
#endif
    );
    if (!p) return out;
    if (!acp_start(p, reply)) { acp_free(p); return out; }
    char why[256];
    bool shown = acp_show(p, presenter, context, why, sizeof(why));
    bool joined = acp_join(p);
    return acp_result(p, reply, shown, joined);
#endif
}
