/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact model-to-native state bridge for bounded forms. */

#include "presentation/presentation.h"

#include "presentation/model.h"

#include <stdio.h>

static bool form_model_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

bool zcl_present_window_form_from_model_v1(
    const struct zcl_present_model_v1 *model,
    struct zcl_present_window_form_v1 *form,
    char *error, size_t error_cap)
{
    if (!model || !form || model->kind != ZCL_PRESENT_MODEL_FORM ||
        !zcl_present_model_validate_v1(model, error, error_cap))
        return form_model_error(error, error_cap,
                                "presentation form model is invalid");
    *form = (struct zcl_present_window_form_v1){
        .struct_size = sizeof(*form),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .field_count = model->item_count,
    };
    for (uint32_t i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        struct zcl_present_window_form_field_v1 *field = &form->fields[i];
        if (item->flags & ZCL_PRESENT_ITEM_REQUIRED)
            field->flags |= ZCL_PRESENT_WINDOW_FORM_REQUIRED;
        if (item->flags & ZCL_PRESENT_ITEM_READ_ONLY)
            field->flags |= ZCL_PRESENT_WINDOW_FORM_READ_ONLY;
        (void)snprintf(field->value, sizeof(field->value), "%s",
                       item->value);
    }
    return zcl_present_window_form_validate_v1(form, error, error_cap);
}
