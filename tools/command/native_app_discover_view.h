/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Build an honest, selectable native advertisement card. */
#ifndef ZCL_NATIVE_APP_DISCOVER_VIEW_H
#define ZCL_NATIVE_APP_DISCOVER_VIEW_H
#include "command/native_app_offer.h"
#include "presentation/model.h"
#include "command/native_app_library_command.h"
/* Validate a returned event before a caller indexes model actions. */
bool app_discover_present_event(app_library_presenter presenter, void *context,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event);
/* row is NULL only when count is zero. index is zero-based. */
bool app_discover_view(struct zcl_present_model_v1 *model,
    const struct zcl_app_offer_row *row, size_t index, size_t count);
#endif
