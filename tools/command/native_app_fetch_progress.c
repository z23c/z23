/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Show deferred-close progress while one carrier fetch is owned and joined. */
#include "command/native_app_fetch_progress.h"
#include "command/native_app_commit_progress.h"
#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
struct afp {
    bool (*fetch)(void *); void *work; bool result;
    atomic_bool done; pthread_t thread; bool closed;
    struct app_confirm view; struct zcl_present_model_bitmap_v1 waiting;
};
static _Atomic(struct afp *) afp_unjoined;
static void *afp_worker(void *context)
{
    struct afp *p = context; p->result = p->fetch(p->work);
    atomic_store_explicit(&p->done, true, memory_order_release); return NULL;
}
static void afp_update(void *context, const struct zcl_present_window_event_v1 *event,
    bool close_requested, bool *redraw, bool *allow_close)
{
    struct afp *p = context; (void)event; *redraw = false;
    *allow_close = atomic_load_explicit(&p->done, memory_order_acquire);
    if (close_requested && !p->closed) {
        p->closed = true;
        (void)snprintf(p->view.model.summary, sizeof(p->view.model.summary), "Waiting for the current download to finish before closing. No Receive will start.");
        p->view.page.pixels = p->waiting.pixels;
        *redraw = !*allow_close;
    }
}
static bool afp_prepare(struct afp *p)
{
    struct zcl_present_model_v1 *m = &p->view.model; char why[256];
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "discover-fetch-progress");
    (void)snprintf(m->title, sizeof(m->title), "Downloading original app files");
    (void)snprintf(m->summary, sizeof(m->summary), "Downloading and checking the selected app. Closing waits for the download to finish.");
    if (!app_confirm_prepare(&p->view, why, sizeof(why))) return false;
    (void)snprintf(m->summary, sizeof(m->summary), "Waiting for the current download to finish before closing. No Receive will start.");
    if (!zcl_present_model_render_page_v1(m, 0, &p->waiting, why, sizeof(why))) return false;
    (void)snprintf(m->summary, sizeof(m->summary), "Downloading and checking the selected app. Closing waits for the download to finish.");
    p->view.page = (struct zcl_present_window_v1){.struct_size = sizeof(p->view.page),
        .abi_version = ZCL_PRESENT_ABI_V1, .title = m->title, .pixels = p->view.bitmaps[0].pixels,
        .width = p->view.bitmaps[0].width, .height = p->view.bitmaps[0].height, .pixel_format = ZCL_PRESENT_RGB8};
    return true;
}
static bool afp_show(struct afp *p, app_confirm_presenter presenter, void *context)
{
    char why[256];
    const struct zcl_present_window_pages_v1 pages = {.struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &p->view.page, .page_count = 1};
    const struct zcl_present_window_live_view_v1 live = {.owner = {.context = p, .update = afp_update},
        .input = app_commit_progress_ignore_input};
    return presenter ? presenter(context, &p->view.model, &pages, &live, why, sizeof(why)) :
        zcl_present_window_run_live_view_v1(&pages, 0, &live, why, sizeof(why));
}
#endif
enum app_fetch_progress_result app_fetch_progress_run(bool (*fetch)(void *), void *work,
    app_confirm_presenter presenter, void *context)
{
#if defined(_WIN32)
    (void)fetch; (void)work; (void)presenter; (void)context; return APP_FETCH_UNAVAILABLE;
#else
    if (!fetch || atomic_load_explicit(&afp_unjoined, memory_order_acquire)) return APP_FETCH_UNAVAILABLE;
    struct afp *p = zcl_calloc(1, sizeof(*p), "discover-fetch-progress");
    if (!p) return APP_FETCH_UNAVAILABLE;
    p->fetch = fetch; p->work = work; atomic_init(&p->done, false);
    if (!afp_prepare(p)) { app_confirm_free(&p->view); zcl_present_model_bitmap_free_v1(&p->waiting); free(p); return APP_FETCH_UNAVAILABLE; }
    if (thread_registry_spawn("app_fetch", afp_worker, p, &p->thread) != 0) {
        app_confirm_free(&p->view); zcl_present_model_bitmap_free_v1(&p->waiting); free(p); return APP_FETCH_UNAVAILABLE;
    }
    bool shown = afp_show(p, presenter, context);
    while (!atomic_load_explicit(&p->done, memory_order_acquire)) platform_sleep_ms(10);
    int rc; do { rc = pthread_join(p->thread, NULL); } while (rc == EINTR);
    if (rc) { p->work = NULL; p->fetch = NULL; atomic_store_explicit(&afp_unjoined, p, memory_order_release); return APP_FETCH_UNAVAILABLE; }
    bool closed = p->closed, result = p->result;
    app_confirm_free(&p->view); zcl_present_model_bitmap_free_v1(&p->waiting); free(p);
    if (!shown) return APP_FETCH_UNAVAILABLE;
    if (closed) return APP_FETCH_CLOSED;
    return result ? APP_FETCH_OK : APP_FETCH_FAILED;
#endif
}
