/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, reviewed native desktop presentation process boundary. */

#ifndef ZCL_VIEWS_UI_PRESENT_H
#define ZCL_VIEWS_UI_PRESENT_H

#include "base/result.h"
#include "presentation/model.h"

#include <stdbool.h>
#include <stddef.h>

struct json_value;

/* Convert one closed native-command input object into the inert model. Nested
 * unknown keys and out-of-range values fail before any process is launched. */
bool ui_present_model_from_json(const struct json_value *input,
                                struct zcl_present_model_v1 *out,
                                char *error, size_t error_cap);

/* Launch a validated inert visual document through the same reviewed child.
 * This is the compatibility/cold path; the resident host consumes the exact
 * same model wire and does not change its authority boundary. */
struct zcl_result ui_present_model_launch(
    const struct zcl_present_model_v1 *model);

/* Internal, exact-flag entry point used only by src/main.c. */
int ui_present_child_main(void);

#endif /* ZCL_VIEWS_UI_PRESENT_H */
