/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one exact bounded native 2D selection control. */

#include "presentation/presentation.h"

#include "presentation/canvas.h"
#include "presentation/model_render.h"
#include "presentation_canvas_internal.h"

#include <stdio.h>
#include <string.h>

static bool canvas_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool canvas_label_valid(const char *label)
{
    size_t length = 0;
    while (length <= ZCL_PRESENT_WINDOW_CANVAS_LABEL_MAX && label[length]) {
        unsigned char byte = (unsigned char)label[length];
        if (byte < 0x20u || byte > 0x7eu) return false;
        length++;
    }
    return length > 0 && length <= ZCL_PRESENT_WINDOW_CANVAS_LABEL_MAX;
}

bool zcl_present_window_canvas_validate_v1(
    const struct zcl_present_window_canvas_v1 *canvas,
    char *error, size_t error_cap)
{
    if (!canvas || canvas->struct_size != sizeof(*canvas) ||
        canvas->abi_version != ZCL_PRESENT_ABI_V1 ||
        canvas->point_count == 0 ||
        canvas->point_count > ZCL_PRESENT_WINDOW_CANVAS_POINTS_MAX ||
        canvas->editable_index >= canvas->point_count)
        return canvas_error(error, error_cap,
                            "presentation canvas ABI/count is invalid");
    uint32_t editable = 0;
    for (uint32_t i = 0; i < canvas->point_count; i++) {
        const struct zcl_present_window_canvas_point_v1 *point =
            &canvas->points[i];
        if ((point->flags &
             ~(uint16_t)ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY) != 0 ||
            point->status > 4u ||
            point->x > ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX ||
            point->y > ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX ||
            !canvas_label_valid(point->label))
            return canvas_error(error, error_cap,
                                "presentation canvas point is invalid");
        editable += !(point->flags &
                      ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY);
    }
    if (editable != 1u ||
        (canvas->points[canvas->editable_index].flags &
         ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY))
        return canvas_error(error, error_cap,
                            "presentation canvas needs one editable point");
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool zcl_present_window_canvas_step_v1(
    struct zcl_present_window_canvas_v1 *canvas,
    int32_t delta_x, int32_t delta_y)
{
    if (!canvas || canvas->editable_index >= canvas->point_count ||
        (delta_x == 0 && delta_y == 0))
        return false;
    struct zcl_present_window_canvas_point_v1 *point =
        &canvas->points[canvas->editable_index];
    if (point->flags & ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY)
        return false;
    int64_t x = (int64_t)point->x + delta_x;
    int64_t y = (int64_t)point->y + delta_y;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x > ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX)
        x = ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX;
    if (y > ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX)
        y = ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX;
    bool changed = point->x != (uint32_t)x || point->y != (uint32_t)y;
    point->x = (uint32_t)x;
    point->y = (uint32_t)y;
    return changed;
}

bool zcl_present_window_canvas_focus_step_v1(
    uint32_t action_count, uint32_t current_focus, int32_t delta,
    uint32_t *next_focus)
{
    uint32_t total = action_count + 1u;
    if (!next_focus || action_count == 0 ||
        action_count > ZCL_PRESENT_WINDOW_ACTIONS_MAX ||
        current_focus >= total || (delta != -1 && delta != 1))
        return false;
    *next_focus = delta > 0
        ? (current_focus + 1u == total ? 0u : current_focus + 1u)
        : (current_focus == 0 ? total - 1u : current_focus - 1u);
    return true;
}

bool zcl_present_window_canvas_point_at_v1(
    uint32_t source_width, uint32_t source_height,
    int32_t target_width, int32_t target_height,
    int32_t mouse_x, int32_t mouse_y,
    uint32_t *normalized_x, uint32_t *normalized_y)
{
    if (!normalized_x || !normalized_y || source_width == 0 ||
        source_height == 0 || target_width <= 0 || target_height <= 0 ||
        mouse_x < 0 || mouse_y < 0)
        return false;
    uint32_t draw_width = (uint32_t)target_width;
    uint32_t draw_height = (uint32_t)((uint64_t)draw_width * source_height /
                                      source_width);
    if (draw_height > (uint32_t)target_height) {
        draw_height = (uint32_t)target_height;
        draw_width = (uint32_t)((uint64_t)draw_height * source_width /
                                source_height);
    }
    if (draw_width == 0 || draw_height == 0) return false;
    uint32_t x0 = ((uint32_t)target_width - draw_width) / 2u;
    uint32_t y0 = ((uint32_t)target_height - draw_height) / 2u;
    if ((uint32_t)mouse_x < x0 || (uint32_t)mouse_y < y0 ||
        (uint32_t)mouse_x >= x0 + draw_width ||
        (uint32_t)mouse_y >= y0 + draw_height)
        return false;
    uint32_t source_x = (uint32_t)((uint64_t)((uint32_t)mouse_x - x0) *
                                   source_width / draw_width);
    uint32_t source_y = (uint32_t)((uint64_t)((uint32_t)mouse_y - y0) *
                                   source_height / draw_height);
    if (source_x < ZCL_PRESENT_MODEL_CANVAS_X ||
        source_y < ZCL_PRESENT_MODEL_CANVAS_Y ||
        source_x >= ZCL_PRESENT_MODEL_CANVAS_X +
                    ZCL_PRESENT_MODEL_CANVAS_WIDTH ||
        source_y >= ZCL_PRESENT_MODEL_CANVAS_Y +
                    ZCL_PRESENT_MODEL_CANVAS_HEIGHT)
        return false;
    *normalized_x = (uint32_t)(
        (uint64_t)(source_x - ZCL_PRESENT_MODEL_CANVAS_X) *
        ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX /
        (ZCL_PRESENT_MODEL_CANVAS_WIDTH - 1u));
    *normalized_y = (uint32_t)(
        (uint64_t)(source_y - ZCL_PRESENT_MODEL_CANVAS_Y) *
        ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX /
        (ZCL_PRESENT_MODEL_CANVAS_HEIGHT - 1u));
    return true;
}

static struct zcl_present_color canvas_status(uint16_t status)
{
    static const struct zcl_present_color colors[] = {
        {0x76, 0x70, 0x69}, {0x28, 0x64, 0x9a}, {0x2f, 0x7d, 0x4b},
        {0xa4, 0x6b, 0x13}, {0xa1, 0x37, 0x37},
    };
    return colors[status <= 4u ? status : 0u];
}

void zcl_present_canvas_draw_state_internal(
    uint8_t *pixels, size_t pixel_bytes,
    const struct zcl_present_window_canvas_v1 *state,
    uint32_t focused_control)
{
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(
            &canvas, pixels, pixel_bytes,
            ZCL_PRESENT_MODEL_BITMAP_WIDTH,
            ZCL_PRESENT_MODEL_BITMAP_HEIGHT))
        return;
    static const struct zcl_present_color panel = {0xf3, 0xf0, 0xeb};
    static const struct zcl_present_color rule = {0xdf, 0xd8, 0xcf};
    static const struct zcl_present_color ink = {0x20, 0x20, 0x22};
    static const struct zcl_present_color muted = {0x76, 0x70, 0x69};
    static const struct zcl_present_color orange = {0xc8, 0x70, 0x35};
    zcl_present_canvas_fill_rect(
        &canvas, ZCL_PRESENT_MODEL_CANVAS_X, ZCL_PRESENT_MODEL_CANVAS_Y,
        ZCL_PRESENT_MODEL_CANVAS_WIDTH, ZCL_PRESENT_MODEL_CANVAS_HEIGHT,
        panel);
    for (uint32_t step = 1; step < 4u; step++) {
        int32_t x = (int32_t)(ZCL_PRESENT_MODEL_CANVAS_X +
            ZCL_PRESENT_MODEL_CANVAS_WIDTH * step / 4u);
        int32_t y = (int32_t)(ZCL_PRESENT_MODEL_CANVAS_Y +
            ZCL_PRESENT_MODEL_CANVAS_HEIGHT * step / 4u);
        zcl_present_canvas_line(
            &canvas, x, ZCL_PRESENT_MODEL_CANVAS_Y, x,
            ZCL_PRESENT_MODEL_CANVAS_Y + ZCL_PRESENT_MODEL_CANVAS_HEIGHT - 1u,
            rule);
        zcl_present_canvas_line(
            &canvas, ZCL_PRESENT_MODEL_CANVAS_X, y,
            ZCL_PRESENT_MODEL_CANVAS_X + ZCL_PRESENT_MODEL_CANVAS_WIDTH - 1u,
            y, rule);
    }
    zcl_present_canvas_stroke_rect(
        &canvas, ZCL_PRESENT_MODEL_CANVAS_X, ZCL_PRESENT_MODEL_CANVAS_Y,
        ZCL_PRESENT_MODEL_CANVAS_WIDTH, ZCL_PRESENT_MODEL_CANVAS_HEIGHT,
        focused_control == 0 ? 3u : 2u,
        focused_control == 0 ? orange : rule);
    for (uint32_t i = 0; i < state->point_count; i++) {
        const struct zcl_present_window_canvas_point_v1 *point =
            &state->points[i];
        uint32_t px = ZCL_PRESENT_MODEL_CANVAS_X +
            point->x * (ZCL_PRESENT_MODEL_CANVAS_WIDTH - 1u) /
                ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX;
        uint32_t py = ZCL_PRESENT_MODEL_CANVAS_Y +
            point->y * (ZCL_PRESENT_MODEL_CANVAS_HEIGHT - 1u) /
                ZCL_PRESENT_WINDOW_CANVAS_COORD_MAX;
        struct zcl_present_color color = i == state->editable_index
            ? orange : canvas_status(point->status);
        if (i == state->editable_index && focused_control == 0) {
            zcl_present_canvas_line(&canvas, (int32_t)px - 12,
                                    (int32_t)py, (int32_t)px + 12,
                                    (int32_t)py, orange);
            zcl_present_canvas_line(&canvas, (int32_t)px,
                                    (int32_t)py - 12, (int32_t)px,
                                    (int32_t)py + 12, orange);
        }
        zcl_present_canvas_fill_rect(
            &canvas, (int32_t)px - 6, (int32_t)py - 6, 13u, 13u, color);
        int32_t label_x = px + 152u <
                ZCL_PRESENT_MODEL_CANVAS_X + ZCL_PRESENT_MODEL_CANVAS_WIDTH
            ? (int32_t)px + 12 : (int32_t)px - 152;
        int32_t label_y = py >= ZCL_PRESENT_MODEL_CANVAS_Y + 22u
            ? (int32_t)py - 18 : (int32_t)py + 10;
        zcl_present_canvas_text(&canvas, label_x, label_y,
                                point->label, strlen(point->label), 13u, ink);
    }
    static const char instruction[] =
        "Click or use arrows to move the orange point";
    zcl_present_canvas_text(
        &canvas, ZCL_PRESENT_MODEL_CANVAS_X,
        ZCL_PRESENT_MODEL_CANVAS_Y + ZCL_PRESENT_MODEL_CANVAS_HEIGHT + 14,
        instruction, sizeof(instruction) - 1u, 13u, muted);
}
