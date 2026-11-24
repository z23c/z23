/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: one native task editor window with durable save feedback. */
#include "services/task_editor.h"
#include "presentation/model_render.h"
#include "base/hex.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

struct task_editor_window {
    struct task_editor *editor;
    bool *back;
    struct zcl_present_model_bitmap_v1 bitmap;
    struct zcl_present_window_v1 page;
    enum task_editor_status painted_status;
    char painted_failure[ZCL_RESULT_MSG_MAX];
    struct zcl_result display_result;
};

struct zcl_result task_editor_model(const struct task_editor *editor,
    struct zcl_present_model_v1 *model)
{
    if (!editor || !model) return ZCL_ERR(-1, "task-editor: visual state required");
    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_FORM);
    (void)snprintf(model->request_id, sizeof(model->request_id), "task-editor");
    (void)snprintf(model->title, sizeof(model->title), "Tasks");
    /* The form names the exact durable snapshot it edits. This is display
     * correlation; the write still rechecks the data revision transactionally. */
    unsigned char payload[TA_PAYLOAD], digest[32];
    uint32_t length;
    if (!ta_state_encode(&editor->saved.state, payload, &length))
        return ZCL_ERR(-1, "task-editor: durable task snapshot is invalid");
    sha3_256(payload, length, digest);
    zcl_hex_encode(digest, sizeof(digest), model->exact_root);
    static const char *const labels[] = { "Saved", "Unsaved changes", "Saving...",
                                          "Save failed", "Not saved yet" };
    if ((unsigned)editor->status >= sizeof(labels)/sizeof(labels[0]))
        return ZCL_ERR(-1, "task-editor: unknown save state");
    (void)snprintf(model->summary, sizeof(model->summary), "%s%s%.200s",
        labels[editor->status], editor->failure[0] ? ": " : "", editor->failure);
    model->item_count = 1;
    model->items[0] = (struct zcl_present_model_item_v1){
        .kind = ZCL_PRESENT_ITEM_FORM_FIELD, .parent_index = ZCL_PRESENT_MODEL_PARENT_NONE,
        .flags = ZCL_PRESENT_ITEM_REQUIRED };
    (void)snprintf(model->items[0].id, sizeof(model->items[0].id), "title");
    (void)snprintf(model->items[0].label, sizeof(model->items[0].label),
        "Task title (up to 95 Basic Latin characters)");
    (void)snprintf(model->items[0].value, sizeof(model->items[0].value), "%s",
                   editor->form.fields[0].value);
    model->action_count = 2;
    model->actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    model->actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(model->actions[0].id, sizeof(model->actions[0].id), "close");
    (void)snprintf(model->actions[0].label, sizeof(model->actions[0].label), "Close");
    (void)snprintf(model->actions[1].id, sizeof(model->actions[1].id), "save");
    (void)snprintf(model->actions[1].label, sizeof(model->actions[1].label), "Save");
    return ZCL_OK;
}

/* The first action names what it does from the state it leaves. */
static void tw_labels(const struct task_editor_window *window,
    struct zcl_present_model_v1 *model)
{
    const struct task_editor *editor = window->editor;
    char *label = model->actions[0].label;
    if (editor->status == TASK_EDITOR_FAILED)
        (void)snprintf(label, sizeof(model->actions[0].label), "%s",
                       window->back ? "Discard & go back" : "Discard & close");
    else if (editor->dirty)
        (void)snprintf(label, sizeof(model->actions[0].label), "%s",
                       window->back ? "Save & back to tasks" : "Save & close");
    else if (window->back) (void)snprintf(label, sizeof(model->actions[0].label), "Back to tasks");
}

static struct zcl_result tw_paint(struct task_editor_window *window)
{
    struct zcl_present_model_v1 model;
    ZCL_CHECK(task_editor_model(window->editor, &model));
    tw_labels(window, &model);
    struct zcl_present_model_bitmap_v1 next = {0};
    char error[256];
    if (!zcl_present_model_render_editor_v1(&model, &next, error, sizeof(error)))
        return ZCL_ERR(-1, "task-editor: display update failed: %s", error);
    zcl_present_model_bitmap_free_v1(&window->bitmap);
    window->bitmap = next;
    window->page.pixels = next.pixels;
    window->page.title = "Tasks";
    return ZCL_OK;
}

static void tw_action(struct task_editor *editor,
    const struct zcl_present_window_event_v1 *event, bool close_requested)
{
    struct zcl_result result = ZCL_OK;
    if (event->outcome == ZCL_PRESENT_WINDOW_ACTION) {
        if (event->action_index == 0)
            result = task_editor_request_close(editor);
        else if (event->action_index == 1 && !editor->pending)
            result = task_editor_submit(editor,
                editor->selected_id ? TASK_DOCUMENT_EDIT : TASK_DOCUMENT_ADD);
    } else if (close_requested) result = task_editor_request_close(editor);
    if (!result.ok) LOG_ERROR("task-editor", "%s", result.message);
}

static void tw_back_intent(bool *back, const struct zcl_present_window_event_v1 *event, bool close_requested)
{
    if (!back) return;
    if (event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index == 0) *back = true;
    else if (close_requested && event->outcome != ZCL_PRESENT_WINDOW_ACTION) *back = false;
}

static void tw_dispatch(struct task_editor_window *window,
    const struct zcl_present_window_event_v1 *event, bool close_requested)
{
    struct task_editor *editor = window->editor;
    bool discard = event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index == 0 &&
        window->painted_status == TASK_EDITOR_FAILED && !close_requested;
    if (discard) {
        if (window->display_result.ok && editor->status == TASK_EDITOR_FAILED && !editor->pending) {
            struct zcl_result result = task_editor_discard_reload(editor);
            if (result.ok && window->back) *window->back = true;
            if (!result.ok) LOG_ERROR("task-editor", "%s", result.message);
        }
    } else {
        tw_back_intent(window->back, event, close_requested);
        tw_action(editor, event, close_requested);
    }
}

static void tw_update(void *opaque, const struct zcl_present_window_event_v1 *event,
    bool close_requested, bool *redraw, bool *allow_close)
{
    struct task_editor_window *window = opaque;
    struct task_editor *editor = window->editor;
    bool changed = false;
    struct zcl_result result = task_editor_poll(editor, &changed);
    if (!result.ok) LOG_ERROR("task-editor", "%s", result.message);
    tw_dispatch(window, event, close_requested);
    *allow_close = editor->closing && !editor->pending && !editor->dirty;
    *redraw = editor->status != window->painted_status ||
        strcmp(editor->failure, window->painted_failure) != 0;
    if (!*redraw) return;
    window->display_result = tw_paint(window);
    if (!window->display_result.ok) {
        LOG_ERROR("task-editor", "%s", window->display_result.message);
        /* Clear the obsolete Saved label without another allocation. Keep
         * the draft and native input overlay alive, with an explicit title. */
        memset(window->bitmap.pixels, 0, ZCL_PRESENT_MODEL_BITMAP_BYTES);
        window->page.title = "Tasks - Display failed; draft retained; Close to save";
    }
    window->painted_status = editor->status;
    (void)snprintf(window->painted_failure, sizeof(window->painted_failure), "%s", editor->failure);
}

#if defined(ZCL_TESTING)
bool zcl_test_task_editor_window_action(struct task_editor *editor,
    enum task_editor_status painted, bool display_ok, bool close_requested, bool *back)
{
    struct task_editor_window window = { .editor = editor, .back = back,
        .painted_status = painted, .display_result = display_ok ? ZCL_OK : ZCL_ERR(-1, "display failed") };
    const struct zcl_present_window_event_v1 event = {
        .outcome = close_requested ? ZCL_PRESENT_WINDOW_DISMISSED : ZCL_PRESENT_WINDOW_ACTION,
        .action_index = close_requested ? UINT32_MAX : 0 };
    bool redraw = false, allow_close = false;
    tw_update(&window, &event, close_requested, &redraw, &allow_close);
    zcl_present_model_bitmap_free_v1(&window.bitmap);
    return allow_close;
}

/* The action labels exactly as the window paints them for this editor. */
struct zcl_result zcl_test_task_editor_window_model(struct task_editor *editor,
    bool from_list, struct zcl_present_model_v1 *model)
{
    bool back = false;
    const struct task_editor_window window = { .editor = editor, .back = from_list ? &back : NULL };
    ZCL_CHECK(task_editor_model(editor, model));
    tw_labels(&window, model);
    return ZCL_OK;
}
#endif

static struct zcl_result tw_run(struct task_editor *editor, bool *back)
{
    if (!editor) return ZCL_ERR(-1, "task-editor: owner required");
    struct task_editor_window window = { .editor = editor, .back = back,
        .painted_status = editor->status, .display_result = ZCL_OK };
    ZCL_CHECK(tw_paint(&window));
    window.page = (struct zcl_present_window_v1){
        .struct_size = sizeof(window.page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Tasks", .pixels = window.bitmap.pixels,
        .width = window.bitmap.width, .height = window.bitmap.height,
        .pixel_format = ZCL_PRESENT_RGB8 };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &window.page, .page_count = 1 };
    const struct zcl_present_window_live_form_v1 live = { .context = &window, .update = tw_update };
    char error[256];
    bool opened = zcl_present_window_run_live_form_v1(&pages, &editor->form,
        &live, error, sizeof(error));
    /* Always retain ownership until an in-flight writer has finished. */
    struct zcl_result finished = task_editor_finish(editor);
    zcl_present_model_bitmap_free_v1(&window.bitmap);
    if (!finished.ok) return finished;
    if (!opened) return ZCL_ERR(-1, "task-editor: native window unavailable: %s", error);
    return window.display_result;
}

struct zcl_result task_editor_window_run(struct task_editor *editor)
{
    return tw_run(editor, NULL);
}

struct zcl_result task_editor_window_back(struct task_editor *editor, bool *back)
{
    if (!back) return ZCL_ERR(-1, "task-editor: navigation output required");
    *back = false;
    return tw_run(editor, back);
}
