/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic two-tone native action focus rendering. */

#include "presentation_focus_internal.h"

#include "presentation/model_render.h"

#include <stddef.h>

static void focus_pixel(uint8_t *pixels, uint32_t width,
                        uint32_t height, uint32_t channels,
                        uint32_t x, uint32_t y,
                        uint8_t red, uint8_t green, uint8_t blue)
{
    if (x >= width || y >= height) return;
    size_t offset = ((size_t)y * width + x) * channels;
    pixels[offset] = red;
    pixels[offset + 1u] = green;
    pixels[offset + 2u] = blue;
    if (channels == 4u) pixels[offset + 3u] = 0xff;
}

static void focus_outline(uint8_t *pixels, uint32_t width,
                          uint32_t height, uint32_t channels,
                          uint32_t x0, uint32_t y0,
                          uint32_t x1, uint32_t y1,
                          uint32_t thickness,
                          uint8_t red, uint8_t green, uint8_t blue)
{
    if (x0 >= x1 || y0 >= y1) return;
    for (uint32_t inset = 0; inset < thickness; inset++) {
        if (x0 + inset >= x1 || y0 + inset >= y1) break;
        uint32_t left = x0 + inset;
        uint32_t top = y0 + inset;
        uint32_t right = x1 - 1u;
        uint32_t bottom = y1 - 1u;
        if (right < inset || bottom < inset) break;
        right -= inset;
        bottom -= inset;
        if (left > right || top > bottom) break;
        for (uint32_t x = left; x <= right; x++) {
            focus_pixel(pixels, width, height, channels,
                        x, top, red, green, blue);
            focus_pixel(pixels, width, height, channels,
                        x, bottom, red, green, blue);
        }
        for (uint32_t y = top; y <= bottom; y++) {
            focus_pixel(pixels, width, height, channels,
                        left, y, red, green, blue);
            focus_pixel(pixels, width, height, channels,
                        right, y, red, green, blue);
        }
    }
}

void zcl_present_draw_action_focus_internal(
    const struct zcl_present_window_v1 *page,
    uint8_t *pixels, uint32_t width, uint32_t height,
    uint32_t action_count, uint32_t focused_action)
{
    if (!pixels || action_count == 0 || focused_action >= action_count)
        return;
    uint32_t draw_width = width;
    uint32_t draw_height = (uint32_t)((uint64_t)draw_width * page->height /
                                      page->width);
    if (draw_height > height) {
        draw_height = height;
        draw_width = (uint32_t)((uint64_t)draw_height * page->width /
                                page->height);
    }
    if (draw_width == 0 || draw_height == 0) return;
    uint32_t letterbox_x = (width - draw_width) / 2u;
    uint32_t letterbox_y = (height - draw_height) / 2u;
    uint32_t total_gap = ZCL_PRESENT_MODEL_ACTION_GAP * (action_count - 1u);
    uint32_t action_width =
        (ZCL_PRESENT_MODEL_ACTION_WIDTH - total_gap) / action_count;
    uint32_t source_x = ZCL_PRESENT_MODEL_ACTION_X +
        focused_action * (action_width + ZCL_PRESENT_MODEL_ACTION_GAP);
    uint32_t source_x1 = source_x + action_width;
    uint32_t source_y = ZCL_PRESENT_MODEL_ACTION_Y;
    uint32_t source_y1 = source_y + ZCL_PRESENT_MODEL_ACTION_HEIGHT;
    uint32_t x0 = letterbox_x +
        (uint32_t)((uint64_t)source_x * draw_width / page->width);
    uint32_t x1 = letterbox_x +
        (uint32_t)(((uint64_t)source_x1 * draw_width + page->width - 1u) /
                   page->width);
    uint32_t y0 = letterbox_y +
        (uint32_t)((uint64_t)source_y * draw_height / page->height);
    uint32_t y1 = letterbox_y +
        (uint32_t)(((uint64_t)source_y1 * draw_height + page->height - 1u) /
                   page->height);
    uint32_t channels = (uint32_t)page->pixel_format;
    /* Two tones remain visible over orange and dark actions. This is local
     * display state; model bytes and the returned action remain unchanged. */
    focus_outline(pixels, width, height, channels,
                  x0, y0, x1, y1, 3u, 0x16, 0x13, 0x0f);
    if (x1 > x0 + 6u && y1 > y0 + 6u)
        focus_outline(pixels, width, height, channels,
                      x0 + 3u, y0 + 3u, x1 - 3u, y1 - 3u,
                      2u, 0xff, 0xf4, 0xd6);
}
