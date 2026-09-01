/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure bounded hit-testing and keyboard focus transitions. */

#include "presentation/presentation.h"

#include "presentation/model_render.h"

bool zcl_present_window_action_at_v1(
    uint32_t source_width, uint32_t source_height,
    int32_t target_width, int32_t target_height,
    int32_t mouse_x, int32_t mouse_y, uint32_t action_count,
    uint32_t *action_index)
{
    if (!action_index || source_width == 0 || source_height == 0 ||
        target_width <= 0 || target_height <= 0 || mouse_x < 0 ||
        mouse_y < 0 || action_count == 0 ||
        action_count > ZCL_PRESENT_WINDOW_ACTIONS_MAX)
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
    if (source_x < ZCL_PRESENT_MODEL_ACTION_X ||
        source_x >= ZCL_PRESENT_MODEL_ACTION_X +
                    ZCL_PRESENT_MODEL_ACTION_WIDTH ||
        source_y < ZCL_PRESENT_MODEL_ACTION_Y ||
        source_y >= ZCL_PRESENT_MODEL_ACTION_Y +
                    ZCL_PRESENT_MODEL_ACTION_HEIGHT)
        return false;
    uint32_t width = (ZCL_PRESENT_MODEL_ACTION_WIDTH -
                      ZCL_PRESENT_MODEL_ACTION_GAP * (action_count - 1u)) /
                     action_count;
    uint32_t local_x = source_x - ZCL_PRESENT_MODEL_ACTION_X;
    uint32_t stride = width + ZCL_PRESENT_MODEL_ACTION_GAP;
    uint32_t candidate = local_x / stride;
    if (candidate >= action_count || local_x % stride >= width)
        return false;
    *action_index = candidate;
    return true;
}

bool zcl_present_window_page_step_v1(
    uint32_t current_page, uint32_t page_count, int32_t delta,
    uint32_t *next_page)
{
    if (!next_page || page_count == 0 ||
        page_count > ZCL_PRESENT_WINDOW_PAGES_MAX ||
        current_page >= page_count)
        return false;
    int64_t wanted = (int64_t)current_page + delta;
    if (wanted < 0) wanted = 0;
    if (wanted >= (int64_t)page_count) wanted = (int64_t)page_count - 1;
    *next_page = (uint32_t)wanted;
    return true;
}

bool zcl_present_window_action_focus_step_v1(
    uint32_t current_action, uint32_t action_count, int32_t delta,
    uint32_t *next_action)
{
    if (!next_action || action_count == 0 ||
        action_count > ZCL_PRESENT_WINDOW_ACTIONS_MAX ||
        current_action >= action_count || (delta != -1 && delta != 1))
        return false;
    if (delta > 0)
        *next_action = current_action + 1u == action_count
            ? 0u : current_action + 1u;
    else
        *next_action = current_action == 0
            ? action_count - 1u : current_action - 1u;
    return true;
}
