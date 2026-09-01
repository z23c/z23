/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private bounded form reducers and software overlay contract. */

#ifndef ZCL_PRESENTATION_FORM_INTERNAL_H
#define ZCL_PRESENTATION_FORM_INTERNAL_H

#include "presentation/presentation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool zcl_present_form_required_complete_internal(
    const struct zcl_present_window_form_v1 *form);
void zcl_present_form_draw_state_internal(
    uint8_t *pixels, size_t pixel_bytes,
    const struct zcl_present_window_form_v1 *form,
    uint32_t focused_control, bool required_invalid);

#endif /* ZCL_PRESENTATION_FORM_INTERNAL_H */
