/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Live owner-controlled link availability, Copy and Stop window. */
#include "command/native_app_host_view.h"
#include "command/native_app_host_controller.h"
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
struct ahv {
    struct app_host_owner *owner; struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 bitmap; struct zcl_present_window_v1 page;
    bool close_requested, failed, dirty, last_available, last_terminal, last_finished, last_stop;
    bool (*copy)(const char *, void *); void *copy_context;
    unsigned copy_feedback; /* 0 none, 1 copied, 2 failed while available */
};
static bool ahv_native_copy(const char *text, void *context)
{ (void)context; return zcl_present_window_copy_ascii_v1(text); }
static bool ahv_clipboard(const struct app_host_ready *ready, void *context)
{
    struct ahv *v = context; char link[256];
    int n = snprintf(link, sizeof(link), "http://%s/board/apps/v1/%s", ready->onion, ready->post_id);
    return n > 0 && (size_t)n < sizeof(link) && v->copy(link, v->copy_context);
}
static const char *ahv_summary(const struct app_host_snapshot *s)
{
    if (s->available) return "Available while this window stays open.";
    if (s->finished && s->outcome == APP_HOST_FAILED) return "Sharing ended unexpectedly.";
    if (s->finished && s->outcome == APP_HOST_EXPIRED) return "Sharing time ended.";
    if (s->terminal || s->finished) return "This link is no longer available.";
    return s->stop ? "Stopping. Please wait." : "Connecting. Please wait.";
}
static bool ahv_render(struct ahv *v, const struct app_host_snapshot *s)
{
    struct zcl_present_model_v1 model; zcl_present_model_init_v1(&model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(model.request_id, sizeof(model.request_id), "app-host-window");
    (void)snprintf(model.title, sizeof(model.title), "Share a link");
    (void)snprintf(model.summary, sizeof(model.summary), "%s", ahv_summary(s));
    model.action_count = 2;
    app_confirm_action(&model.actions[0], ZCL_PRESENT_ACTION_SELECT, "copy", "Copy link");
    app_confirm_action(&model.actions[1], ZCL_PRESENT_ACTION_CANCEL, "stop", "Stop");
    if (s->available && v->copy_feedback && !app_confirm_field(&model, "Copy: ",
        v->copy_feedback == 1 ? "Copied. Send the link to your friend." : "Could not copy the link. Try again.")) return false;
    if (s->available && !app_confirm_field(&model, "Sharing: ", "Keep this window open while your friend receives it.")) return false;
    struct zcl_present_model_bitmap_v1 bitmap = {0}; char why[128];
    if (!zcl_present_model_render_v1(&model, &bitmap, why, sizeof(why))) return false;
    zcl_present_model_bitmap_free_v1(&v->bitmap); v->bitmap = bitmap; v->model = model;
    v->page.pixels = v->bitmap.pixels; v->page.width = v->bitmap.width; v->page.height = v->bitmap.height;
    return true;
}
static void ahv_update(void *context, const struct zcl_present_window_event_v1 *event,
                       bool close_requested, bool *redraw, bool *allow_close)
{
    struct ahv *v = context; (void)event;
    if (close_requested) { v->close_requested = true; app_host_owner_stop(v->owner); }
    struct app_host_snapshot snap;
    if (!app_host_owner_snapshot(v->owner, &snap)) { v->failed = true; v->close_requested = true; app_host_owner_stop(v->owner); *allow_close = false; return; }
    if (!snap.available) v->copy_feedback = 0;
    *redraw = v->dirty || snap.available != v->last_available || snap.terminal != v->last_terminal ||
        snap.finished != v->last_finished || snap.stop != v->last_stop;
    v->dirty = false;
    if (*redraw && !ahv_render(v, &snap)) { v->failed = true; v->close_requested = true; app_host_owner_stop(v->owner); }
    v->last_available = snap.available; v->last_terminal = snap.terminal; v->last_finished = snap.finished; v->last_stop = snap.stop;
    *allow_close = v->close_requested && snap.finished;
}
static bool ahv_action(struct ahv *v, unsigned action)
{
    if (action == 0) {
        bool copied = app_host_owner_copy(v->owner, ahv_clipboard, v);
        struct app_host_snapshot snapshot;
        bool available = app_host_owner_snapshot(v->owner, &snapshot) && snapshot.available;
        v->copy_feedback = copied && available ? 1u : (available ? 2u : 0u);
        v->dirty = true; return true;
    }
    if (action == 1) { v->close_requested = true; app_host_owner_stop(v->owner); return true; }
    return false;
}
static bool ahv_input(void *context, const struct zcl_present_input_v1 *input,
                      uint32_t *focus, uint32_t *action)
{
    struct ahv *v = context; *action = UINT32_MAX;
    if (input->key == ZCL_PRESENT_INPUT_TAB) { *focus = *focus == 0 ? 1 : 0; return true; }
    if (input->key == ZCL_PRESENT_INPUT_ENTER ||
        (input->key == ZCL_PRESENT_INPUT_TEXT && input->character == ' '))
        return ahv_action(v, *focus);
    if (input->key == ZCL_PRESENT_INPUT_TEXT && input->character == 'c') return ahv_action(v, 0);
    if (input->key == ZCL_PRESENT_INPUT_ESCAPE ||
        (input->key == ZCL_PRESENT_INPUT_TEXT && input->character == 'q')) return ahv_action(v, 1);
    if (input->key == ZCL_PRESENT_INPUT_CLICK) {
        uint32_t hit = UINT32_MAX;
        if (zcl_present_window_action_at_v1(v->page.width, v->page.height, (int32_t)v->page.width,
            (int32_t)v->page.height, (int32_t)input->x, (int32_t)input->y, 2, &hit)) return ahv_action(v, hit);
        return true;
    }
    return false;
}
static bool ahv_run(struct app_host_owner *owner, app_confirm_presenter presenter,
    void *context, bool (*copy)(const char *, void *), void *copy_context, char *why, size_t cap)
{
    if (!owner || !copy) return false;
    struct ahv view = {.owner = owner, .copy = copy, .copy_context = copy_context}; struct app_host_snapshot snap;
    if (!app_host_owner_snapshot(owner, &snap) || !ahv_render(&view, &snap)) { app_host_owner_stop(owner); return false; }
    view.last_available = snap.available; view.last_terminal = snap.terminal; view.last_finished = snap.finished; view.last_stop = snap.stop;
    view.page = (struct zcl_present_window_v1){.struct_size = sizeof(view.page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Share a link", .pixels = view.bitmap.pixels, .width = view.bitmap.width,
        .height = view.bitmap.height, .pixel_format = ZCL_PRESENT_RGB8};
    const struct zcl_present_window_pages_v1 pages = {.struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &view.page, .page_count = 1};
    const struct zcl_present_window_live_view_v1 live = {.owner = {.context = &view, .update = ahv_update}, .input = ahv_input};
    bool shown = presenter ? presenter(context, &view.model, &pages, &live, why, cap) :
        zcl_present_window_run_live_view_v1(&pages, 2, &live, why, cap);
    app_host_owner_stop(owner); zcl_present_model_bitmap_free_v1(&view.bitmap);
    return shown && !view.failed && view.close_requested;
}

#if defined(ZCL_TESTING)
bool zcl_test_app_host_view_run(struct app_host_owner *owner, app_confirm_presenter presenter,
    void *context, app_host_test_copy_fn copy, void *copy_context, char *why, size_t cap)
{ return ahv_run(owner, presenter, context, copy, copy_context, why, cap); }
#endif
#endif

bool app_host_view_run(struct app_host_owner *owner, app_confirm_presenter presenter,
                       void *context, char *why, size_t cap)
{
#if !defined(_WIN32)
    return ahv_run(owner, presenter, context, ahv_native_copy, NULL, why, cap);
#else
    (void)owner; (void)presenter; (void)context; (void)why; (void)cap; return false;
#endif
}
