/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native software cards for renderer-neutral agent documents. */

#include "presentation/model_render.h"

#include "presentation/canvas.h"
#include "presentation_canvas_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct zcl_present_color PAPER = {0xfb, 0xfa, 0xf8};
static const struct zcl_present_color INK = {0x20, 0x20, 0x22};
static const struct zcl_present_color MUTED = {0x69, 0x65, 0x60};
static const struct zcl_present_color RULE = {0xdf, 0xd8, 0xcf};
static const struct zcl_present_color ORANGE = {0xc8, 0x70, 0x35};
static const struct zcl_present_color INFO = {0x32, 0x68, 0x91};
static const struct zcl_present_color GREEN = {0x28, 0x72, 0x4a};
static const struct zcl_present_color YELLOW = {0x9a, 0x6d, 0x18};
static const struct zcl_present_color RED = {0xa1, 0x37, 0x37};
static const struct zcl_present_color GREEN_BG = {0xe5, 0xf2, 0xe9};
static const struct zcl_present_color RED_BG = {0xf8, 0xe5, 0xe3};
static const struct zcl_present_color PANEL = {0xf3, 0xf0, 0xeb};

enum {
    MODEL_CONTENT_TOP = 184,
    MODEL_CONTENT_BOTTOM = 604,
};

static bool render_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

static struct zcl_present_color status_color(uint16_t status)
{
    switch (status) {
    case ZCL_PRESENT_STATUS_INFO: return INFO;
    case ZCL_PRESENT_STATUS_GREEN: return GREEN;
    case ZCL_PRESENT_STATUS_YELLOW: return YELLOW;
    case ZCL_PRESENT_STATUS_RED: return RED;
    default: return MUTED;
    }
}

static void text_fit(struct zcl_present_canvas *canvas, int32_t x, int32_t y,
                     const char *text, uint32_t height, uint32_t max_width,
                     struct zcl_present_color color)
{
    size_t length = strlen(text);
    while (length > 0 && zcl_present_canvas_text_width(
               text, length, height) > max_width)
        length--;
    zcl_present_canvas_text(canvas, x, y, text, length, height, color);
    if (text[length]) {
        const char dots[] = "...";
        uint32_t used = zcl_present_canvas_text_width(text, length, height);
        uint32_t dots_width = zcl_present_canvas_text_width(dots, 3u, height);
        while (length > 0 && used + dots_width > max_width) {
            length--;
            used = zcl_present_canvas_text_width(text, length, height);
        }
        zcl_present_canvas_text(canvas, x + (int32_t)used, y,
                                dots, 3u, height, color);
    }
}

static int32_t render_progress(struct zcl_present_canvas *canvas,
                               const struct zcl_present_model_item_v1 *item,
                               int32_t y)
{
    text_fit(canvas, 42, y, item->label, 16u, 390u, INK);
    text_fit(canvas, 470, y, item->value, 14u, 205u, MUTED);
    zcl_present_canvas_fill_rect(canvas, 42, y + 28, 636u, 12u, RULE);
    uint32_t filled = item->denominator == 0 ? 0 :
        (uint32_t)((uint64_t)636u * item->numerator / item->denominator);
    zcl_present_canvas_fill_rect(canvas, 42, y + 28, filled, 12u,
                                 status_color(item->status));
    return y + 58;
}

static int32_t render_chart_point(
    struct zcl_present_canvas *canvas,
    const struct zcl_present_model_item_v1 *item, int32_t y)
{
    enum { CHART_X = 238, CHART_WIDTH = 300 };
    char fraction[32];
    (void)snprintf(fraction, sizeof(fraction), "%u / %u",
                   item->numerator, item->denominator);
    text_fit(canvas, 42, y + 2, item->label, 15u, 108u, INK);
    text_fit(canvas, 160, y + 2, item->value, 14u, 66u, MUTED);
    text_fit(canvas, 552, y + 2, fraction, 14u, 126u, MUTED);
    zcl_present_canvas_fill_rect(canvas, CHART_X, y + 5,
                                 CHART_WIDTH, 18u, RULE);
    uint32_t filled = (uint32_t)(
        (uint64_t)CHART_WIDTH * item->numerator / item->denominator);
    zcl_present_canvas_fill_rect(canvas, CHART_X, y + 5,
                                 filled, 18u,
                                 status_color(item->status));
    zcl_present_canvas_line(canvas, 42, y + 36, 678, y + 36, RULE);
    return y + 43;
}

static int32_t render_timeline_event(
    struct zcl_present_canvas *canvas,
    const struct zcl_present_model_item_v1 *item, int32_t y)
{
    struct zcl_present_color accent = status_color(item->status);
    zcl_present_canvas_line(canvas, 54, y, 54, y + 47, RULE);
    zcl_present_canvas_fill_rect(canvas, 48, y + 5, 13u, 13u, PAPER);
    zcl_present_canvas_fill_rect(canvas, 51, y + 8, 7u, 7u, accent);
    text_fit(canvas, 76, y + 2, item->label, 15u, 242u, INK);
    text_fit(canvas, 332, y + 2, item->value, 14u, 346u, MUTED);
    return y + 48;
}

static uint32_t graph_depth(const struct zcl_present_model_v1 *model,
                            uint32_t index)
{
    uint32_t depth = 0;
    uint16_t parent = model->items[index].parent_index;
    while (parent != ZCL_PRESENT_MODEL_PARENT_NONE && depth < 8u) {
        depth++;
        parent = model->items[parent].parent_index;
    }
    return depth;
}

static int32_t render_graph_node(
    struct zcl_present_canvas *canvas,
    const struct zcl_present_model_v1 *model, uint32_t index, int32_t y)
{
    const struct zcl_present_model_item_v1 *item = &model->items[index];
    uint32_t depth = graph_depth(model, index);
    int32_t node_x = 48 + (int32_t)(depth * 18u);
    for (uint32_t level = 0; level < depth; level++) {
        int32_t branch_x = 54 + (int32_t)(level * 18u);
        zcl_present_canvas_line(canvas, branch_x, y,
                               branch_x, y + 44, RULE);
    }
    if (depth > 0)
        zcl_present_canvas_line(canvas, node_x - 12, y + 12,
                               node_x, y + 12, RULE);
    zcl_present_canvas_fill_rect(canvas, node_x, y + 6, 13u, 13u,
                                 status_color(item->status));
    uint32_t label_width = node_x < 312 ? (uint32_t)(312 - node_x) : 72u;
    text_fit(canvas, node_x + 20, y + 2, item->label,
             15u, label_width, INK);
    text_fit(canvas, 350, y + 2, item->value, 14u, 328u, MUTED);
    return y + 45;
}

static int32_t render_choice(
    struct zcl_present_canvas *canvas,
    const struct zcl_present_model_item_v1 *item, uint32_t index, int32_t y)
{
    bool selected = (item->flags & ZCL_PRESENT_ITEM_SELECTED) != 0;
    if (selected)
        zcl_present_canvas_fill_rect(canvas, 36, y, 648u, 42u, PANEL);
    zcl_present_canvas_fill_rect(canvas, 46, y + 9, 20u, 20u, RULE);
    zcl_present_canvas_fill_rect(canvas, 49, y + 12, 14u, 14u, PAPER);
    if (selected)
        zcl_present_canvas_fill_rect(canvas, 53, y + 16, 6u, 6u,
                                     status_color(item->status));
    char number[16];
    (void)snprintf(number, sizeof(number), "%u", index + 1u);
    text_fit(canvas, 76, y + 10, number, 13u, 20u, MUTED);
    text_fit(canvas, 106, y + 6, item->label, 16u, 260u, INK);
    text_fit(canvas, 382, y + 7, item->value, 14u, 296u, MUTED);
    zcl_present_canvas_line(canvas, 42, y + 43, 678, y + 43, RULE);
    return y + 50;
}

static int32_t render_form_field(
    struct zcl_present_canvas *canvas,
    const struct zcl_present_model_item_v1 *item, int32_t y)
{
    const bool read_only =
        (item->flags & ZCL_PRESENT_ITEM_READ_ONLY) != 0;
    char label[112];
    (void)snprintf(label, sizeof(label), "%s%s%s", item->label,
                   (item->flags & ZCL_PRESENT_ITEM_REQUIRED) ? "  *" : "",
                   read_only ? "  read only" : "");
    text_fit(canvas, ZCL_PRESENT_MODEL_FORM_X, y, label,
             14u, ZCL_PRESENT_MODEL_FORM_WIDTH, MUTED);
    int32_t input_y = y + ZCL_PRESENT_MODEL_FORM_INPUT_Y_OFFSET;
    zcl_present_canvas_fill_rect(
        canvas, ZCL_PRESENT_MODEL_FORM_X, input_y,
        ZCL_PRESENT_MODEL_FORM_WIDTH, ZCL_PRESENT_MODEL_FORM_INPUT_HEIGHT,
        read_only ? PANEL : PAPER);
    zcl_present_canvas_stroke_rect(
        canvas, ZCL_PRESENT_MODEL_FORM_X, input_y,
        ZCL_PRESENT_MODEL_FORM_WIDTH, ZCL_PRESENT_MODEL_FORM_INPUT_HEIGHT,
        2u, RULE);
    text_fit(canvas, ZCL_PRESENT_MODEL_FORM_X + 12, input_y + 10,
             item->value, 16u, ZCL_PRESENT_MODEL_FORM_WIDTH - 24u, INK);
    return y + ZCL_PRESENT_MODEL_FORM_FIELD_HEIGHT;
}

static int32_t render_diff(struct zcl_present_canvas *canvas,
                           const struct zcl_present_model_item_v1 *item,
                           int32_t y)
{
    struct zcl_present_color bg = PAPER;
    struct zcl_present_color fg = INK;
    const char *prefix = "  ";
    if (item->kind == ZCL_PRESENT_ITEM_DIFF_ADD) {
        bg = GREEN_BG;
        fg = GREEN;
        prefix = "+ ";
    } else if (item->kind == ZCL_PRESENT_ITEM_DIFF_REMOVE) {
        bg = RED_BG;
        fg = RED;
        prefix = "- ";
    }
    zcl_present_canvas_fill_rect(canvas, 32, y, 656u, 27u, bg);
    zcl_present_canvas_text(canvas, 42, y + 5, prefix, 2u, 14u, fg);
    text_fit(canvas, 62, y + 5, item->value, 14u, 610u, fg);
    return y + 28;
}

static int32_t render_row(struct zcl_present_canvas *canvas,
                          const struct zcl_present_model_item_v1 *item,
                          int32_t y)
{
    struct zcl_present_color accent = status_color(item->status);
    zcl_present_canvas_fill_rect(canvas, 42, y + 3, 4u, 31u, accent);
    text_fit(canvas, 58, y + 2, item->label, 14u, 238u, MUTED);
    text_fit(canvas, 310, y + 2, item->value, 16u, 366u, INK);
    zcl_present_canvas_line(canvas, 42, y + 38, 678, y + 38, RULE);
    return y + 45;
}

static int32_t render_item(struct zcl_present_canvas *canvas,
                           const struct zcl_present_model_v1 *model,
                           uint32_t index, int32_t y)
{
    const struct zcl_present_model_item_v1 *item = &model->items[index];
    if (item->kind == ZCL_PRESENT_ITEM_PROGRESS)
        return render_progress(canvas, item, y);
    if (item->kind == ZCL_PRESENT_ITEM_CHART_POINT)
        return render_chart_point(canvas, item, y);
    if (item->kind == ZCL_PRESENT_ITEM_TIMELINE_EVENT)
        return render_timeline_event(canvas, item, y);
    if (item->kind == ZCL_PRESENT_ITEM_GRAPH_NODE)
        return render_graph_node(canvas, model, index, y);
    if (item->kind == ZCL_PRESENT_ITEM_CHOICE)
        return render_choice(canvas, item, index, y);
    if (item->kind == ZCL_PRESENT_ITEM_FORM_FIELD)
        return render_form_field(canvas, item, y);
    if (item->kind == ZCL_PRESENT_ITEM_CANVAS_POINT)
        return y;
    if (item->kind == ZCL_PRESENT_ITEM_DIFF_CONTEXT ||
        item->kind == ZCL_PRESENT_ITEM_DIFF_ADD ||
        item->kind == ZCL_PRESENT_ITEM_DIFF_REMOVE)
        return render_diff(canvas, item, y);
    if (item->kind == ZCL_PRESENT_ITEM_TEXT) {
        text_fit(canvas, 42, y, item->value[0] ? item->value : item->label,
                 16u, 636u, INK);
        return y + 34;
    }
    return render_row(canvas, item, y);
}

static uint32_t item_height(const struct zcl_present_model_item_v1 *item)
{
    if (item->kind == ZCL_PRESENT_ITEM_PROGRESS) return 58u;
    if (item->kind == ZCL_PRESENT_ITEM_CHART_POINT) return 43u;
    if (item->kind == ZCL_PRESENT_ITEM_TIMELINE_EVENT) return 48u;
    if (item->kind == ZCL_PRESENT_ITEM_CHOICE) return 50u;
    if (item->kind == ZCL_PRESENT_ITEM_FORM_FIELD)
        return ZCL_PRESENT_MODEL_FORM_FIELD_HEIGHT;
    if (item->kind == ZCL_PRESENT_ITEM_CANVAS_POINT) return 1u;
    if (item->kind == ZCL_PRESENT_ITEM_DIFF_CONTEXT ||
        item->kind == ZCL_PRESENT_ITEM_DIFF_ADD ||
        item->kind == ZCL_PRESENT_ITEM_DIFF_REMOVE)
        return 28u;
    if (item->kind == ZCL_PRESENT_ITEM_TEXT) return 34u;
    return 45u;
}

static bool page_bounds(const struct zcl_present_model_v1 *model,
                        uint32_t wanted, uint32_t *start_out,
                        uint32_t *end_out, uint32_t *count_out)
{
    uint32_t page = 0;
    uint32_t start = 0;
    if (model->item_count == 0) {
        if (wanted == 0) {
            *start_out = 0;
            *end_out = 0;
        }
        *count_out = 1;
        return wanted == 0;
    }
    while (start < model->item_count) {
        uint32_t end = start;
        uint32_t used = 0;
        uint32_t available = MODEL_CONTENT_BOTTOM - MODEL_CONTENT_TOP;
        while (end < model->item_count) {
            uint32_t height = item_height(&model->items[end]);
            if (end > start && used + height > available) break;
            used += height;
            end++;
        }
        if (page == wanted) {
            *start_out = start;
            *end_out = end;
        }
        page++;
        start = end;
    }
    *count_out = page;
    return wanted < page;
}

bool zcl_present_model_page_count_v1(
    const struct zcl_present_model_v1 *model, uint32_t *page_count,
    char *error, size_t error_cap)
{
    if (!page_count)
        return render_error(error, error_cap,
                            "visual model page-count output is missing");
    *page_count = 0;
    if (!zcl_present_model_validate_v1(model, error, error_cap)) return false;
    uint32_t start = 0, end = 0, count = 0;
    (void)page_bounds(model, 0, &start, &end, &count);
    if (count == 0 || count > ZCL_PRESENT_MODEL_PAGES_MAX)
        return render_error(error, error_cap,
                            "visual model exceeds its page bound");
    *page_count = count;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

static void render_actions(struct zcl_present_canvas *canvas,
                           const struct zcl_present_model_v1 *model)
{
    if (model->action_count == 0) return;
    int32_t y = ZCL_PRESENT_MODEL_ACTION_Y;
    uint32_t total_gap = ZCL_PRESENT_MODEL_ACTION_GAP *
                         (model->action_count - 1u);
    uint32_t width = (ZCL_PRESENT_MODEL_ACTION_WIDTH - total_gap) /
                     model->action_count;
    for (uint32_t i = 0; i < model->action_count; i++) {
        int32_t x = ZCL_PRESENT_MODEL_ACTION_X +
                    (int32_t)(i * (width + ZCL_PRESENT_MODEL_ACTION_GAP));
        bool decisive = model->actions[i].kind == ZCL_PRESENT_ACTION_CONFIRM ||
                        model->actions[i].kind == ZCL_PRESENT_ACTION_SUBMIT;
        struct zcl_present_color fill = decisive ? ORANGE : PANEL;
        struct zcl_present_color text = decisive ? PAPER : INK;
        zcl_present_canvas_fill_rect(canvas, x, y, width,
                                     ZCL_PRESENT_MODEL_ACTION_HEIGHT, fill);
        char numbered[64];
        (void)snprintf(numbered, sizeof(numbered), "%u  %s", i + 1u,
                       model->actions[i].label);
        uint32_t text_width = zcl_present_canvas_text_width(
            numbered, strlen(numbered), 15u);
        int32_t text_x = text_width < width
            ? x + (int32_t)(width - text_width) / 2 : x + 8;
        text_fit(canvas, text_x, y + 12, numbered, 15u, width - 16u, text);
    }
}

bool zcl_present_model_render_page_v1(
    const struct zcl_present_model_v1 *model, uint32_t page_index,
    struct zcl_present_model_bitmap_v1 *bitmap,
    char *error, size_t error_cap)
{
    if (!bitmap)
        return render_error(error, error_cap,
                            "visual model bitmap output is missing");
    *bitmap = (struct zcl_present_model_bitmap_v1){0};
    uint32_t page_count = 0;
    if (!zcl_present_model_page_count_v1(model, &page_count,
                                         error, error_cap))
        return false;
    uint32_t start = 0, end = 0, counted = 0;
    if (!page_bounds(model, page_index, &start, &end, &counted) ||
        counted != page_count)
        return render_error(error, error_cap,
                            "visual model page index is out of range");
    uint8_t *pixels = malloc(ZCL_PRESENT_MODEL_BITMAP_BYTES); // raw-alloc-ok:standalone-presentation-package
    if (!pixels)
        return render_error(error, error_cap,
                            "visual model bitmap allocation failed");
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, pixels,
                                 ZCL_PRESENT_MODEL_BITMAP_BYTES,
                                 ZCL_PRESENT_MODEL_BITMAP_WIDTH,
                                 ZCL_PRESENT_MODEL_BITMAP_HEIGHT)) {
        free(pixels);
        return render_error(error, error_cap,
                            "visual model canvas initialization failed");
    }
    zcl_present_canvas_clear(&canvas, PAPER);
    zcl_present_canvas_fill_rect(&canvas, 0, 0, 12u, canvas.height, ORANGE);
    zcl_present_canvas_text(&canvas, 42, 28, "ZCLASSIC23", 10u, 14u, ORANGE);
    const char *kind = zcl_present_model_kind_name(model->kind);
    text_fit(&canvas, 520, 28, kind, 12u, 158u, MUTED);
    text_fit(&canvas, 42, 60, model->title, 30u, 636u, INK);
    if (model->summary[0])
        text_fit(&canvas, 42, 104, model->summary, 15u, 636u, MUTED);
    if (model->exact_root[0]) {
        char root_line[86];
        (void)snprintf(root_line, sizeof(root_line), "Exact root  %s",
                       model->exact_root);
        text_fit(&canvas, 42, 134, root_line, 12u, 636u, MUTED);
    }
    zcl_present_canvas_line(&canvas, 42, 164, 678, 164, RULE);

    int32_t y = MODEL_CONTENT_TOP;
    if (model->kind == ZCL_PRESENT_MODEL_CANVAS) {
        if (!zcl_present_canvas_draw_model_internal(
                pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES, model,
                UINT32_MAX)) {
            free(pixels);
            return render_error(error, error_cap,
                                "visual model canvas state is invalid");
        }
    } else
        for (uint32_t i = start; i < end; i++)
            y = render_item(&canvas, model, i, y);
    if (page_count > 1u) {
        char page[96];
        (void)snprintf(page, sizeof(page),
                       "Page %u of %u  -  PgUp/PgDn, arrows or wheel",
                       page_index + 1u, page_count);
        text_fit(&canvas, 42, 620, page, 12u, 636u, MUTED);
    }
    render_actions(&canvas, model);
    bitmap->pixels = pixels;
    bitmap->width = canvas.width;
    bitmap->height = canvas.height;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool zcl_present_model_render_v1(const struct zcl_present_model_v1 *model,
                                 struct zcl_present_model_bitmap_v1 *bitmap,
                                 char *error, size_t error_cap)
{
    return zcl_present_model_render_page_v1(model, 0, bitmap,
                                            error, error_cap);
}

void zcl_present_model_bitmap_free_v1(
    struct zcl_present_model_bitmap_v1 *bitmap)
{
    if (!bitmap) return;
    free(bitmap->pixels);
    *bitmap = (struct zcl_present_model_bitmap_v1){0};
}
