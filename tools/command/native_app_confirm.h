/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare shared native confirmation rendering and page visitation. */
#ifndef ZCL_NATIVE_APP_CONFIRM_H
#define ZCL_NATIVE_APP_CONFIRM_H
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/presentation.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct app_confirm {
    const char *window_title;
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 bitmaps[ZCL_PRESENT_MODEL_PAGES_MAX];
    struct zcl_present_window_v1 page;
    uint32_t page_count, page_index, visited;
    bool confirmed;
};
typedef bool (*app_confirm_presenter)(void *context,
    const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap);
bool app_confirm_field(struct zcl_present_model_v1 *model, const char *label, const char *value);
void app_confirm_action(struct zcl_present_model_action_v1 *action,
    uint16_t kind, const char *id, const char *label);
bool app_confirm_prepare(struct app_confirm *view, char *why, size_t cap);
bool app_confirm_show(struct app_confirm *view, app_confirm_presenter presenter,
    void *context, char *why, size_t cap);
void app_confirm_free(struct app_confirm *view);
struct zcl_command_reply;
void app_confirm_forward_failure(struct zcl_command_reply *reply,
                                 struct zcl_command_reply *from);
#endif
