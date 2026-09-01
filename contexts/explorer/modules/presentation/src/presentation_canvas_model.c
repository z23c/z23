/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact model-to-native state bridge for bounded canvases. */

#include "presentation/presentation.h"

#include "presentation/model.h"
#include "presentation_canvas_internal.h"

#include <stdio.h>

static bool canvas_model_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

bool zcl_present_window_canvas_from_model_v1(
    const struct zcl_present_model_v1 *model,
    struct zcl_present_window_canvas_v1 *canvas,
    char *error, size_t error_cap)
{
    if (!model || !canvas || model->kind != ZCL_PRESENT_MODEL_CANVAS ||
        !zcl_present_model_validate_v1(model, error, error_cap))
        return canvas_model_error(error, error_cap,
                                  "presentation canvas model is invalid");
    *canvas = (struct zcl_present_window_canvas_v1){
        .struct_size = sizeof(*canvas),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .point_count = model->item_count,
        .editable_index = UINT32_MAX,
    };
    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        struct zcl_present_window_canvas_point_v1 *point =
            &canvas->points[i];
        if (item->flags & ZCL_PRESENT_ITEM_READ_ONLY)
            point->flags = ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY;
        else
            canvas->editable_index = i;
        point->status = item->status;
        point->x = item->numerator;
        point->y = item->denominator;
        (void)snprintf(point->label, sizeof(point->label), "%s",
                       item->label);
    }
    return zcl_present_window_canvas_validate_v1(
        canvas, error, error_cap);
}

bool zcl_present_canvas_draw_model_internal(
    uint8_t *pixels, size_t pixel_bytes,
    const struct zcl_present_model_v1 *model,
    uint32_t focused_control)
{
    struct zcl_present_window_canvas_v1 canvas;
    char why[128];
    if (!zcl_present_window_canvas_from_model_v1(
            model, &canvas, why, sizeof(why)))
        return false;
    zcl_present_canvas_draw_state_internal(
        pixels, pixel_bytes, &canvas, focused_control);
    return true;
}
