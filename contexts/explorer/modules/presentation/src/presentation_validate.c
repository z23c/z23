/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: presentation request validation and hover overlay drawing, initial form focus. */

#include "presentation/presentation.h"

#include "presentation/canvas.h"
#include "presentation/model_render.h"
#include "presentation_validate_internal.h"

#include <stdio.h>
#include <string.h>

bool present_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0)
        (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool bounded_text(const char *text, size_t max)
{
    if (!text) return true;
    size_t n = 0;
    while (n <= max && text[n]) n++;
    return n <= max;
}

static bool present_hover_items_valid(
    const struct zcl_present_window_hover_v1 *hover)
{
    for (uint32_t i = 0; i < hover->item_count; i++) {
        if (hover->items[i].x < hover->plot_left ||
            hover->items[i].x > hover->plot_right ||
            (i > 0 && hover->items[i - 1u].x > hover->items[i].x) ||
            !hover->items[i].text ||
            !bounded_text(hover->items[i].text,
                          ZCL_PRESENT_WINDOW_HOVER_TEXT_MAX))
            return false;
    }
    return true;
}

static bool present_hover_validate(
    const struct zcl_present_window_v1 *request,
    const struct zcl_present_window_hover_v1 *hover,
    char *error, size_t error_cap)
{
    if (!hover || hover->struct_size != sizeof(*hover) ||
        hover->abi_version != ZCL_PRESENT_ABI_V1 || !hover->items ||
        hover->item_count == 0 ||
        hover->item_count > ZCL_PRESENT_WINDOW_HOVER_ITEMS_MAX)
        return present_error(error, error_cap,
                             "presentation hover ABI/count is invalid");
    if (hover->plot_left >= hover->plot_right ||
        hover->plot_top >= hover->plot_bottom ||
        hover->plot_right > request->width ||
        hover->plot_bottom > request->height)
        return present_error(error, error_cap,
                             "presentation hover plot bounds are invalid");
    if (!present_hover_items_valid(hover))
        return present_error(error, error_cap,
                             "presentation hover item is invalid");
    return true;
}

static void present_hover_draw_text(
    struct zcl_present_canvas *canvas, int32_t panel_x, int32_t panel_y,
    const char *text)
{
    const struct zcl_present_color primary = {242, 247, 255};
    const struct zcl_present_color secondary = {169, 186, 207};
    const char *separator = strchr(text, '\n');
    size_t first_len = separator
        ? (size_t)(separator - text) : strlen(text);
    zcl_present_canvas_text_strong(canvas, panel_x + 14, panel_y + 10,
                                   text, first_len, 24u, primary);
    if (separator && separator[1])
        zcl_present_canvas_text_strong(
            canvas, panel_x + 14, panel_y + 47,
            separator + 1, strlen(separator + 1), 19u, secondary);
}

void present_hover_draw(
    uint8_t *pixels, size_t pixels_cap,
    const struct zcl_present_window_v1 *page,
    const struct zcl_present_window_hover_v1 *hover, uint32_t item_index)
{
    if (!pixels || !page || !hover || item_index >= hover->item_count ||
        page->pixel_format != ZCL_PRESENT_RGB8)
        return;
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, pixels, pixels_cap,
                                 page->width, page->height))
        return;
    const struct zcl_present_window_hover_item_v1 *item =
        &hover->items[item_index];
    const struct zcl_present_color crosshair = {112, 240, 216};
    const struct zcl_present_color panel = {15, 24, 39};
    const struct zcl_present_color border = {76, 104, 134};
    zcl_present_canvas_line(&canvas, (int32_t)item->x,
                            (int32_t)hover->plot_top,
                            (int32_t)item->x,
                            (int32_t)hover->plot_bottom, crosshair);
    uint32_t panel_width = page->width > 936u ? 920u
        : (page->width > 16u ? page->width - 16u : page->width);
    uint32_t panel_height = 88u;
    int32_t panel_x = hover->plot_left + panel_width <= page->width
        ? (int32_t)hover->plot_left : 8;
    if ((uint32_t)panel_x + panel_width > page->width)
        panel_x = page->width > panel_width + 8u
            ? (int32_t)(page->width - panel_width - 8u) : 0;
    int32_t panel_y = hover->plot_top >= panel_height + 20u
        ? (int32_t)(hover->plot_top - panel_height - 12u)
        : (int32_t)hover->plot_top + 12;
    zcl_present_canvas_fill_rect(&canvas, panel_x, panel_y,
                                 panel_width, panel_height, panel);
    zcl_present_canvas_stroke_rect(&canvas, panel_x, panel_y,
                                   panel_width, panel_height, 1u, border);
    present_hover_draw_text(&canvas, panel_x, panel_y, item->text);
}

static const char *present_window_bitmap_problem(
    const struct zcl_present_window_v1 *request)
{
    if (!request->pixels || request->width == 0 || request->height == 0 ||
        request->width > ZCL_PRESENT_DIMENSION_MAX ||
        request->height > ZCL_PRESENT_DIMENSION_MAX)
        return "presentation bitmap dimensions are invalid";
    if (request->pixel_format != ZCL_PRESENT_RGB8 &&
        request->pixel_format != ZCL_PRESENT_RGBA8)
        return "presentation pixel format is unsupported";
    uint64_t pixel_bytes = (uint64_t)request->width * request->height *
                           (uint32_t)request->pixel_format;
    if (pixel_bytes == 0 || pixel_bytes > SIZE_MAX)
        return "presentation bitmap size overflows";
    return NULL;
}

static const char *present_window_icon_problem(
    const struct zcl_present_window_v1 *request)
{
    bool any_icon = request->icon_rgba || request->icon_width ||
                    request->icon_height;
    bool complete_icon = request->icon_rgba && request->icon_width > 0 &&
                         request->icon_height > 0 &&
                         request->icon_width <= 256u &&
                         request->icon_height <= 256u;
    if (any_icon && !complete_icon)
        return "presentation icon is incomplete or oversized";
    return NULL;
}

static const char *present_window_problem(
    const struct zcl_present_window_v1 *request)
{
    if (!request || request->struct_size != sizeof(*request) ||
        request->abi_version != ZCL_PRESENT_ABI_V1)
        return "presentation ABI/structure mismatch";
    if (!bounded_text(request->title, ZCL_PRESENT_TITLE_MAX))
        return "presentation title is oversized";
    if (!bounded_text(request->copy_text, ZCL_PRESENT_COPY_TEXT_MAX))
        return "presentation clipboard text is oversized";
    const char *bitmap = present_window_bitmap_problem(request);
    if (bitmap) return bitmap;
    return present_window_icon_problem(request);
}

bool zcl_present_window_validate_v1(
    const struct zcl_present_window_v1 *request,
    char *error, size_t error_cap)
{
    const char *problem = present_window_problem(request);
    if (problem) return present_error(error, error_cap, problem);
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

static bool present_form_geometry(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_form_v1 *form, uint32_t action_count,
    char *error, size_t error_cap)
{
    return !form || (zcl_present_window_form_validate_v1(form, error, error_cap) &&
        action_count == 2u && pages->page_count == 1u &&
        pages->pages[0].pixel_format == ZCL_PRESENT_RGB8 &&
        pages->pages[0].width == ZCL_PRESENT_MODEL_BITMAP_WIDTH &&
        pages->pages[0].height == ZCL_PRESENT_MODEL_BITMAP_HEIGHT);
}

static bool present_canvas_geometry(const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_canvas_v1 *canvas, uint32_t action_count,
    char *error, size_t error_cap)
{
    return !canvas || (zcl_present_window_canvas_validate_v1(canvas, error, error_cap) &&
        action_count == 2u && pages->page_count == 1u &&
        pages->pages[0].pixel_format == ZCL_PRESENT_RGB8 &&
        pages->pages[0].width == ZCL_PRESENT_MODEL_BITMAP_WIDTH &&
        pages->pages[0].height == ZCL_PRESENT_MODEL_BITMAP_HEIGHT);
}

static const char *present_hover_problem(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_hover_v1 *hovers,
    uint32_t action_count, bool hovers_first_page_only,
    uint32_t initial_page, char *error, size_t error_cap)
{
    if (action_count != 0)
        return "presentation hover geometry/actions are invalid";
    if (hovers_first_page_only && initial_page != 0u)
        return "presentation initial page is invalid";
    uint32_t hover_page_count =
        hovers_first_page_only ? 1u : pages->page_count;
    for (uint32_t i = 0; i < hover_page_count; i++)
        if (pages->pages[i].pixel_format != ZCL_PRESENT_RGB8 ||
            !present_hover_validate(
                &pages->pages[i], &hovers[i], error, error_cap))
            return "presentation hover geometry/actions are invalid";
    return NULL;
}

static bool present_copy_bounds_invalid(
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_copy_v1 *copy)
{
    return copy->struct_size != sizeof(*copy) ||
           copy->abi_version != ZCL_PRESENT_ABI_V1 ||
           copy->left >= copy->right || copy->top >= copy->bottom ||
           copy->right > pages->pages[0].width ||
           copy->bottom > pages->pages[0].height;
}

static bool present_controls_conflict(
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hovers)
{
    return (form && canvas) || ((form || canvas) && hovers);
}

const char *present_pages_problem(
    const struct zcl_present_window_pages_v1 *pages,
    uint32_t action_count,
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_canvas_v1 *canvas,
    const struct zcl_present_window_hover_v1 *hovers,
    bool hovers_first_page_only,
    uint32_t initial_page,
    const struct zcl_present_window_copy_v1 *copy,
    const struct zcl_present_window_live_view_v1 *live,
    char *error, size_t error_cap)
{
    if (initial_page >= pages->page_count)
        return "presentation initial page is invalid";
    if (copy && present_copy_bounds_invalid(pages, copy))
        return "presentation image-copy bounds are invalid";
    if (present_controls_conflict(form, canvas, hovers))
        return "presentation controls are mutually exclusive";
    if (!present_form_geometry(pages, form, action_count, error, error_cap))
        return "presentation form geometry/actions are invalid";
    if (live && !live->owner.update)
        return "presentation live form owner is invalid";
    if (!present_canvas_geometry(pages, canvas, action_count, error,
                                 error_cap))
        return "presentation canvas geometry/actions are invalid";
    if (hovers)
        return present_hover_problem(pages, hovers, action_count,
                                     hovers_first_page_only, initial_page,
                                     error, error_cap);
    return NULL;
}

uint32_t present_pages_initial_focus(
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_live_view_v1 *live)
{
    uint32_t focused_control = live && live->input ? UINT32_MAX : 0;
    if (form) {
        while (focused_control < form->field_count &&
               (form->fields[focused_control].flags &
                ZCL_PRESENT_WINDOW_FORM_READ_ONLY))
            focused_control++;
        if (focused_control == form->field_count)
            focused_control = form->field_count;
    }
    return focused_control;
}
