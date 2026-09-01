/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: resident same-binary host for bounded native visual documents. */

#ifndef ZCL_VIEWS_UI_PRESENT_HOST_H
#define ZCL_VIEWS_UI_PRESENT_HOST_H

#include "base/result.h"
#include "presentation/model.h"

#include <stdbool.h>
#include <stdint.h>

struct ui_present_host_result {
    bool resident_host;
    bool host_reused;
    bool view_replaced;
    bool event_received;
    uint32_t action_index;
    bool form_submitted;
    uint32_t form_value_count;
    struct {
        char id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
        char value[ZCL_PRESENT_MODEL_VALUE_MAX + 1u];
    } form_values[ZCL_PRESENT_MODEL_FORM_FIELDS_MAX];
    bool canvas_submitted;
    char canvas_point_id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    uint32_t canvas_x;
    uint32_t canvas_y;
    int64_t ready_us;
};

/* Fail closed before spawning a presentation process when the platform has
 * no usable native display session.  `why` is a stable, named diagnostic for
 * typed command replies and headless acceptance. */
bool ui_present_host_display_ready(char *why, size_t why_cap);

/* Submit one already-validated inert model. Non-interactive calls with the
 * same request_id replace that request's prior display-only window, making
 * progress/status updates live without keeping candidate code or authority
 * resident. Interactive callers wait for one numbered action or dismissal;
 * the caller still owns all policy and authority. */
struct zcl_result ui_present_host_submit(
    const struct zcl_present_model_v1 *model,
    bool wait_for_event,
    struct ui_present_host_result *result);

/* Private exact-argv entry point dispatched before node initialization. */
int ui_present_host_main(void);

#endif /* ZCL_VIEWS_UI_PRESENT_HOST_H */
