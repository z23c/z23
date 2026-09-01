/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded portable native-form state and deterministic pixel overlay. */

#include "presentation/presentation.h"

#include "presentation/canvas.h"
#include "presentation/model_render.h"
#include "presentation_form_internal.h"

#include <stdio.h>
#include <string.h>

static bool form_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

bool zcl_present_window_form_validate_v1(
    const struct zcl_present_window_form_v1 *form,
    char *error, size_t error_cap)
{
    if (!form || form->struct_size != sizeof(*form) ||
        form->abi_version != ZCL_PRESENT_ABI_V1 ||
        form->field_count == 0 ||
        form->field_count > ZCL_PRESENT_WINDOW_FORM_FIELDS_MAX)
        return form_error(error, error_cap,
                          "presentation form ABI/count is invalid");
    bool editable = false;
    for (uint32_t i = 0; i < form->field_count; i++) {
        const struct zcl_present_window_form_field_v1 *field =
            &form->fields[i];
        if (field->flags & ~(uint16_t)(ZCL_PRESENT_WINDOW_FORM_REQUIRED |
                                      ZCL_PRESENT_WINDOW_FORM_READ_ONLY))
            return form_error(error, error_cap,
                              "presentation form flags are invalid");
        size_t length = 0;
        while (length <= ZCL_PRESENT_WINDOW_FORM_VALUE_MAX &&
               field->value[length]) {
            unsigned char byte = (unsigned char)field->value[length];
            if (byte < 0x20u || byte > 0x7eu)
                return form_error(
                    error, error_cap,
                    "presentation form value is not printable ASCII");
            length++;
        }
        if (length > ZCL_PRESENT_WINDOW_FORM_VALUE_MAX)
            return form_error(error, error_cap,
                              "presentation form value is oversized");
        editable |= !(field->flags & ZCL_PRESENT_WINDOW_FORM_READ_ONLY);
    }
    if (!editable)
        return form_error(error, error_cap,
                          "presentation form has no editable field");
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool zcl_present_window_form_edit_v1(
    struct zcl_present_window_form_v1 *form, uint32_t field_index,
    uint8_t character, bool backspace)
{
    if (!form || field_index >= form->field_count ||
        field_index >= ZCL_PRESENT_WINDOW_FORM_FIELDS_MAX ||
        (form->fields[field_index].flags &
         ZCL_PRESENT_WINDOW_FORM_READ_ONLY))
        return false;
    char *value = form->fields[field_index].value;
    size_t length = 0;
    while (length <= ZCL_PRESENT_WINDOW_FORM_VALUE_MAX && value[length])
        length++;
    if (length > ZCL_PRESENT_WINDOW_FORM_VALUE_MAX) return false;
    if (backspace) {
        if (length > 0) value[length - 1u] = '\0';
        return true;
    }
    if (character < 0x20u || character > 0x7eu ||
        length == ZCL_PRESENT_WINDOW_FORM_VALUE_MAX)
        return false;
    value[length] = (char)character;
    value[length + 1u] = '\0';
    return true;
}

bool zcl_present_window_form_focus_step_v1(
    const struct zcl_present_window_form_v1 *form,
    uint32_t action_count, uint32_t current_focus, int32_t delta,
    uint32_t *next_focus)
{
    if (!form || !next_focus || action_count == 0 ||
        action_count > ZCL_PRESENT_WINDOW_ACTIONS_MAX ||
        (delta != -1 && delta != 1))
        return false;
    uint32_t total = form->field_count + action_count;
    if (form->field_count == 0 ||
        form->field_count > ZCL_PRESENT_WINDOW_FORM_FIELDS_MAX ||
        current_focus >= total ||
        (current_focus < form->field_count &&
         (form->fields[current_focus].flags &
          ZCL_PRESENT_WINDOW_FORM_READ_ONLY)))
        return false;
    uint32_t candidate = current_focus;
    for (uint32_t i = 0; i < total; i++) {
        candidate = delta > 0
            ? (candidate + 1u == total ? 0u : candidate + 1u)
            : (candidate == 0 ? total - 1u : candidate - 1u);
        if (candidate >= form->field_count ||
            !(form->fields[candidate].flags &
              ZCL_PRESENT_WINDOW_FORM_READ_ONLY)) {
            *next_focus = candidate;
            return true;
        }
    }
    return false;
}

bool zcl_present_form_required_complete_internal(
    const struct zcl_present_window_form_v1 *form)
{
    for (uint32_t i = 0; i < form->field_count; i++)
        if ((form->fields[i].flags & ZCL_PRESENT_WINDOW_FORM_REQUIRED) &&
            !form->fields[i].value[0])
            return false;
    return true;
}

void zcl_present_form_draw_state_internal(
    uint8_t *pixels, size_t pixel_bytes,
    const struct zcl_present_window_form_v1 *form,
    uint32_t focused_control, bool required_invalid)
{
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(
            &canvas, pixels, pixel_bytes,
            ZCL_PRESENT_MODEL_BITMAP_WIDTH,
            ZCL_PRESENT_MODEL_BITMAP_HEIGHT))
        return;
    static const struct zcl_present_color paper = {0xfb, 0xfa, 0xf8};
    static const struct zcl_present_color panel = {0xf3, 0xf0, 0xeb};
    static const struct zcl_present_color rule = {0xdf, 0xd8, 0xcf};
    static const struct zcl_present_color ink = {0x20, 0x20, 0x22};
    static const struct zcl_present_color focus = {0xc8, 0x70, 0x35};
    static const struct zcl_present_color red = {0xa1, 0x37, 0x37};
    for (uint32_t i = 0; i < form->field_count; i++) {
        const struct zcl_present_window_form_field_v1 *field =
            &form->fields[i];
        bool read_only =
            (field->flags & ZCL_PRESENT_WINDOW_FORM_READ_ONLY) != 0;
        bool focused = focused_control == i;
        bool missing = required_invalid &&
            (field->flags & ZCL_PRESENT_WINDOW_FORM_REQUIRED) &&
            !field->value[0];
        int32_t y = (int32_t)(ZCL_PRESENT_MODEL_FORM_Y +
            i * ZCL_PRESENT_MODEL_FORM_FIELD_HEIGHT +
            ZCL_PRESENT_MODEL_FORM_INPUT_Y_OFFSET);
        zcl_present_canvas_fill_rect(
            &canvas, ZCL_PRESENT_MODEL_FORM_X, y,
            ZCL_PRESENT_MODEL_FORM_WIDTH,
            ZCL_PRESENT_MODEL_FORM_INPUT_HEIGHT,
            read_only ? panel : paper);
        zcl_present_canvas_stroke_rect(
            &canvas, ZCL_PRESENT_MODEL_FORM_X, y,
            ZCL_PRESENT_MODEL_FORM_WIDTH,
            ZCL_PRESENT_MODEL_FORM_INPUT_HEIGHT,
            focused ? 3u : 2u, missing ? red : (focused ? focus : rule));

        size_t length = strlen(field->value);
        size_t start = 0;
        const uint32_t max_text_width =
            ZCL_PRESENT_MODEL_FORM_WIDTH - 34u;
        while (start < length && zcl_present_canvas_text_width(
                   field->value + start, length - start, 16u) >
               max_text_width)
            start++;
        size_t visible = length - start;
        int32_t text_x = (int32_t)ZCL_PRESENT_MODEL_FORM_X + 12;
        zcl_present_canvas_text(&canvas, text_x, y + 10,
                                field->value + start, visible, 16u, ink);
        if (focused && !read_only) {
            uint32_t used = zcl_present_canvas_text_width(
                field->value + start, visible, 16u);
            int32_t cursor_x = text_x + (int32_t)used + 2;
            zcl_present_canvas_line(&canvas, cursor_x, y + 8,
                                    cursor_x, y + 32, focus);
        }
    }
}
