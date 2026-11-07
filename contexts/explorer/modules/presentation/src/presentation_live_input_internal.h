/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Private translation of native live-window events to owner callbacks. */
#ifndef ZCL_PRESENTATION_LIVE_INPUT_INTERNAL_H
#define ZCL_PRESENTATION_LIVE_INPUT_INTERNAL_H
#include "presentation/presentation.h"
struct RGFW_window;
union RGFW_event;
bool present_live_input(const struct zcl_present_window_live_view_v1 *live,
    struct RGFW_window *window, const struct zcl_present_window_v1 *page,
    const union RGFW_event *event, uint32_t action_count, uint32_t *focus,
    struct zcl_present_window_event_v1 *result);
#endif
