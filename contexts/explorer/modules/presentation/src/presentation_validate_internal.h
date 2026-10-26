/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private presentation request validation and hover overlay contract. */

#ifndef ZCL_PRESENTATION_VALIDATE_INTERNAL_H
#define ZCL_PRESENTATION_VALIDATE_INTERNAL_H

#include "presentation/presentation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool present_error(char *error, size_t cap, const char *message);

void present_hover_draw(
    uint8_t *pixels, size_t pixels_cap,
    const struct zcl_present_window_v1 *page,
    const struct zcl_present_window_hover_v1 *hover, uint32_t item_index);

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
    char *error, size_t error_cap);

uint32_t present_pages_initial_focus(
    const struct zcl_present_window_form_v1 *form,
    const struct zcl_present_window_live_view_v1 *live);

#endif /* ZCL_PRESENTATION_VALIDATE_INTERNAL_H */
