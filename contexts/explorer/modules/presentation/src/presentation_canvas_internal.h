/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private canvas-control renderer shared with the native backend. */

#ifndef ZCL_PRESENTATION_CANVAS_INTERNAL_H
#define ZCL_PRESENTATION_CANVAS_INTERNAL_H

#include "presentation/presentation.h"

struct zcl_present_model_v1;

void zcl_present_canvas_draw_state_internal(
    uint8_t *pixels, size_t pixel_bytes,
    const struct zcl_present_window_canvas_v1 *canvas,
    uint32_t focused_control);
bool zcl_present_canvas_draw_model_internal(
    uint8_t *pixels, size_t pixel_bytes,
    const struct zcl_present_model_v1 *model,
    uint32_t focused_control);

#endif /* ZCL_PRESENTATION_CANVAS_INTERNAL_H */
