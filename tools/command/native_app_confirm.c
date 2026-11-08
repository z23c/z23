/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Render verified fields and enforce all-page native owner confirmation. */
#include "command/native_app_confirm.h"
#include "command/native_command.h"
#include "presentation/canvas.h"
#include <stdio.h>
#include <string.h>

static bool ac_ascii(const char *value)
{
    if (!value || !*value) return false;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (*p < 0x20 || *p > 0x7e) return false;
    return true;
}
static bool ac_line(struct zcl_present_model_v1 *model, const char *label,
                    const char *value, size_t *used)
{
    if (model->item_count >= ZCL_PRESENT_MODEL_ITEMS_MAX) return false;
    char line[ZCL_PRESENT_MODEL_VALUE_MAX + 1];
    size_t remain = strlen(value), take = remain < 40 ? remain : 40;
    while (take) {
        int n = snprintf(line, sizeof(line), "%s%.*s", label, (int)take, value);
        if (n > 0 && (size_t)n < sizeof(line) &&
            zcl_present_canvas_text_width(line, (size_t)n, 16u) <= 636u) break;
        --take;
    }
    if (!take) return false;
    struct zcl_present_model_item_v1 *item = &model->items[model->item_count];
    item->kind = ZCL_PRESENT_ITEM_TEXT;
    item->status = ZCL_PRESENT_STATUS_INFO;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(item->id, sizeof(item->id), "line-%u", model->item_count);
    (void)snprintf(item->value, sizeof(item->value), "%s", line);
    ++model->item_count;
    *used = take;
    return true;
}
bool app_confirm_field(struct zcl_present_model_v1 *model, const char *label,
                     const char *value)
{
    if (!ac_ascii(value)) return false;
    size_t offset = 0, total = strlen(value);
    while (offset < total) {
        size_t used = 0;
        if (!ac_line(model, offset ? "  " : label, value + offset, &used)) return false;
        offset += used;
    }
    return true;
}
void app_confirm_action(struct zcl_present_model_action_v1 *action,
                      uint16_t kind, const char *id, const char *label)
{
    action->kind = kind;
    (void)snprintf(action->id, sizeof(action->id), "%s", id);
    (void)snprintf(action->label, sizeof(action->label), "%s", label);
}
static bool ac_input_key(const struct zcl_present_input_v1 *input,
                         uint32_t *focus, uint32_t *action)
{
    if (input->key == ZCL_PRESENT_INPUT_PAGE_DOWN || input->key == ZCL_PRESENT_INPUT_DOWN) {
        *action = 2; return true;
    }
    if (input->key == ZCL_PRESENT_INPUT_PAGE_UP || input->key == ZCL_PRESENT_INPUT_UP) {
        *action = 1; return true;
    }
    if (input->key == ZCL_PRESENT_INPUT_TAB) {
        if (*focus >= 4) *focus = 0;
        else *focus = (*focus + (input->shift ? 3u : 1u)) % 4u;
        return true;
    }
    if (input->key == ZCL_PRESENT_INPUT_ENTER ||
        (input->key == ZCL_PRESENT_INPUT_TEXT && input->character == ' ')) {
        if (*focus >= 4) *focus = 0;
        *action = *focus; return true;
    }
    if (input->key == ZCL_PRESENT_INPUT_TEXT && input->character >= '1' && input->character <= '4') {
        *focus = input->character - '1'; *action = *focus; return true;
    }
    return false;
}
static bool ac_input(void *context, const struct zcl_present_input_v1 *input,
                     uint32_t *focus, uint32_t *action)
{
    (void)context;
    if (!input || !focus || !action) return false;
    if (ac_input_key(input, focus, action)) return true;
    if (input->key == ZCL_PRESENT_INPUT_CLICK) {
        uint32_t hit;
        if (zcl_present_window_action_at_v1(ZCL_PRESENT_MODEL_BITMAP_WIDTH, ZCL_PRESENT_MODEL_BITMAP_HEIGHT,
            ZCL_PRESENT_MODEL_BITMAP_WIDTH, ZCL_PRESENT_MODEL_BITMAP_HEIGHT,
            (int32_t)input->x, (int32_t)input->y, 4, &hit)) {
            *focus = hit; *action = hit; return true;
        }
    }
    return false;
}
static void ac_move_page(struct app_confirm *w, uint32_t action, bool *redraw)
{
    uint32_t page = w->page_index;
    if (action == 1 && page > 0) --page;
    else if (action == 2 && page + 1u < w->page_count) ++page;
    if (page == w->page_index) return;
    w->page_index = page;
    w->page.pixels = w->bitmaps[page].pixels;
    w->visited |= 1u << page;
    *redraw = true;
}
static void ac_update(void *context, const struct zcl_present_window_event_v1 *event,
                      bool close_requested, bool *redraw, bool *allow_close)
{
    struct app_confirm *w = context;
    *redraw = false; *allow_close = false;
    if (event->outcome == ZCL_PRESENT_WINDOW_ACTION) {
        if (event->action_index == 0) { w->confirmed = false; *allow_close = true; return; }
        if (event->action_index == 3) {
            uint32_t all = (1u << w->page_count) - 1u;
            w->confirmed = w->visited == all;
            if (w->confirmed) *allow_close = true;
            return;
        }
        w->confirmed = false;
        ac_move_page(w, event->action_index, redraw);
    } else if (close_requested) { w->confirmed = false; *allow_close = true; }
}
static bool ac_present_native(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    (void)context; (void)model;
    return zcl_present_window_run_live_view_v1(pages, 4, live, why, cap);
}
bool app_confirm_show(struct app_confirm *w, app_confirm_presenter presenter, void *context,
                      char *why, size_t cap)
{
    w->confirmed = false;
    w->page_index = 0;
    w->page = (struct zcl_present_window_v1){
        .struct_size = sizeof(w->page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = w->window_title ? w->window_title : w->model.title, .pixels = w->bitmaps[0].pixels,
        .width = w->bitmaps[0].width, .height = w->bitmaps[0].height,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    w->visited = 1u;
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &w->page, .page_count = 1,
    };
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = w, .update = ac_update}, .input = ac_input,
    };
    if (!presenter) presenter = ac_present_native;
    return presenter(context, &w->model, &pages, &live, why, cap);
}
void app_confirm_free(struct app_confirm *w)
{
    for (uint32_t i = 0; i < w->page_count; ++i)
        zcl_present_model_bitmap_free_v1(&w->bitmaps[i]);
}

bool app_confirm_prepare(struct app_confirm *w, char *why, size_t cap)
{
    if (!zcl_present_model_page_count_v1(&w->model, &w->page_count, why, cap) || !w->page_count)
        return false;
    for (uint32_t i = 0; i < w->page_count; ++i)
        if (!zcl_present_model_render_page_v1(&w->model, i, &w->bitmaps[i], why, cap)) return false;
    return true;
}

/* Move the backend failure data with its complete failure classification. */
void app_confirm_forward_failure(struct zcl_command_reply *reply,
                                 struct zcl_command_reply *from)
{
    const struct zcl_command_error *e = &from->error;
    zcl_command_reply_fail(reply, from->status, from->exit_code, e->code,
        e->phase, e->retryable, e->mutated, e->message, e->evidence);
    json_free(&reply->data);
    reply->data = from->data;
    json_init(&from->data);
}
