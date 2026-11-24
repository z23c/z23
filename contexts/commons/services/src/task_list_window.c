/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: native task-list window over the shared interaction and save owners. */
#include "services/task_list.h"
#include "presentation/model_render.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

struct task_list_window {
    struct task_list list;
    struct zcl_present_model_bitmap_v1 bitmap;
    struct zcl_present_window_v1 page;
    struct zcl_result display;
};

/* The keys the list answers to, as its window title names them. */
static const char tlw_title[] =
    "Tasks - Arrows select; Enter edit; Space complete; Cmd/Ctrl+N new; Delete removes; Cmd/Ctrl+Z undoes";

static struct zcl_result tlw_paint(struct task_list_window *window)
{
    struct zcl_present_model_v1 model;
    ZCL_CHECK(task_list_model(&window->list, &model));
    char error[256];
    struct zcl_present_model_bitmap_v1 next = {0};
    if (!zcl_present_model_render_list_v1(&model, &next, error, sizeof(error)))
        return ZCL_ERR(-1, "task-list: display failed: %s", error);
    zcl_present_model_bitmap_free_v1(&window->bitmap);
    window->bitmap = next;
    window->page.pixels = next.pixels;
    window->page.title = tlw_title;
    window->list.repaint = false;
    return ZCL_OK;
}

static bool tlw_input(void *context, const struct zcl_present_input_v1 *input,
                      uint32_t *focus, uint32_t *action)
{
    struct task_list_window *window = context;
    return task_list_input(&window->list, input, focus, action);
}

static void tlw_update(void *context, const struct zcl_present_window_event_v1 *event,
    bool close_requested, bool *redraw, bool *allow_close)
{
    struct task_list_window *window = context;
    struct task_list *list = &window->list;
    bool update_action = event->outcome == ZCL_PRESENT_WINDOW_ACTION &&
        list->updates && list->update;
    struct zcl_result result = update_action ?
        task_list_action(list, event->action_index) : task_list_poll(list);
    if (result.ok && event->outcome == ZCL_PRESENT_WINDOW_ACTION)
        result = update_action ? task_list_poll(list) :
            task_list_action(list, event->action_index);
    else if (close_requested && event->outcome != ZCL_PRESENT_WINDOW_ACTION)
        list->closing = true;
    if (!result.ok) {
        list->closing = false;
        LOG_ERROR("task-list", "%s", result.message);
    }
    *allow_close = (list->closing || list->open_editor) && !list->editor->pending;
    *redraw = list->repaint;
    if (!*redraw) return;
    window->display = tlw_paint(window);
    if (!window->display.ok) {
        LOG_ERROR("task-list", "%s", window->display.message);
        memset(window->bitmap.pixels, 0, ZCL_PRESENT_MODEL_BITMAP_BYTES);
        window->page.title = "Tasks - Display failed; saved data retained";
        list->repaint = false;
    }
}

/* Back in the list the editor holds no draft, new or otherwise. */
static void tlw_resumed(struct task_list_window *window, struct task_editor *editor)
{
    struct task_list *list = &window->list;
    list->open_editor = false;
    list->menu = false;
    list->notice[0] = '\0';
    list->notice_held = false;
    list->focus = UINT32_MAX;
    list->selected_id = editor->selected_id;
    /* Back means the close finished; nothing is left to save on close. */
    editor->closing = false;
    if (editor->status == TASK_EDITOR_NEW) editor->status = TASK_EDITOR_SAVED;
    task_list_refresh(list);
}

#ifdef ZCL_TESTING
struct zcl_result zcl_test_task_list_window_action(struct task_list *list, uint32_t action)
{
    struct task_list_window window = { .list = *list, .display = ZCL_OK };
    const struct zcl_present_window_event_v1 event = {
        .outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action
    };
    bool redraw = false, allow_close = false;
    tlw_update(&window, &event, false, &redraw, &allow_close);
    *list = window.list;
    zcl_present_model_bitmap_free_v1(&window.bitmap);
    return window.display;
}

/* The list as its window resumes it once the editor window went Back. */
void zcl_test_task_list_window_resumed(struct task_list *list, struct task_editor *editor)
{
    struct task_list_window window = { .list = *list };
    tlw_resumed(&window, editor);
    *list = window.list;
}

/* The title exactly as the window shows it. */
const char *zcl_test_task_list_window_title(void)
{
    return tlw_title;
}
#endif

static struct zcl_result tlw_run(struct task_list_window *window)
{
    ZCL_CHECK(tlw_paint(window));
    window->page = (struct zcl_present_window_v1){
        .struct_size = sizeof(window->page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = tlw_title, .pixels = window->bitmap.pixels, .width = window->bitmap.width,
        .height = window->bitmap.height, .pixel_format = ZCL_PRESENT_RGB8 };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &window->page, .page_count = 1 };
    const struct zcl_present_window_live_view_v1 live = {
        .owner = { .context = window, .update = tlw_update }, .input = tlw_input };
    char error[256];
    bool opened = zcl_present_window_run_live_view_v1(&pages, 4, &live, error, sizeof(error));
    struct zcl_result finished = task_editor_finish(window->list.editor);
    zcl_present_model_bitmap_free_v1(&window->bitmap);
    if (!finished.ok) return finished;
    if (!opened) return ZCL_ERR(-1, "task-list: native window unavailable: %s", error);
    return window->display;
}

static struct zcl_result tlw_journey(struct task_editor *editor, struct task_update *update)
{
    if (!editor) return ZCL_ERR(-1, "task-list: durable editor owner required");
    struct task_list_window window = { .display = ZCL_OK };
    task_list_init(&window.list, editor);
    window.list.update = update;
    window.list.updates = update && update->candidate.package_root[0];
    if (window.list.updates) window.list.focus = 0;
    for (;;) {
        ZCL_CHECK(tlw_run(&window));
        if (!window.list.open_editor) return ZCL_OK;
        ZCL_CHECK(task_editor_select(editor, window.list.new_task ? 0 : window.list.selected_id));
        bool back = false;
        ZCL_CHECK(task_editor_window_back(editor, &back));
        if (!back) return ZCL_OK;
        tlw_resumed(&window, editor);
    }
}

struct zcl_result task_list_window_run_update(struct task_editor *editor, struct task_update *update)
{
    struct zcl_result result = tlw_journey(editor, update);
    if (update) {
        struct zcl_result finished = task_update_finish(update);
        if (result.ok && !finished.ok) result = finished;
    }
    return result;
}

struct zcl_result task_list_window_run(struct task_editor *editor)
{
    return task_list_window_run_update(editor, NULL);
}
