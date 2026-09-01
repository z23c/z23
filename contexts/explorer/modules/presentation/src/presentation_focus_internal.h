/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private deterministic focus-ring compositor for native actions. */

#ifndef ZCL_PRESENTATION_FOCUS_INTERNAL_H
#define ZCL_PRESENTATION_FOCUS_INTERNAL_H

#include "presentation/presentation.h"

void zcl_present_draw_action_focus_internal(
    const struct zcl_present_window_v1 *page,
    uint8_t *pixels, uint32_t width, uint32_t height,
    uint32_t action_count, uint32_t focused_action);

#endif /* ZCL_PRESENTATION_FOCUS_INTERNAL_H */
