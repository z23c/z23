/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Declare the test-only native owner adoption presenter boundary. */
#ifndef ZCL_COMMAND_NATIVE_APP_ADOPT_H
#define ZCL_COMMAND_NATIVE_APP_ADOPT_H
#if defined(ZCL_TESTING)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct zcl_command_request;
struct zcl_command_reply;
struct json_value;
struct zcl_present_model_v1;
struct zcl_present_window_pages_v1;
struct zcl_present_window_live_view_v1;
typedef bool (*zcl_test_app_adopt_presenter)(void *context,
    const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap);
/* Test-only per-invocation dependency; production always uses native UI. */
void zcl_test_app_adopt_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, zcl_test_app_adopt_presenter presenter, void *context);
bool zcl_test_app_adopt_model(const struct json_value *plan,
    struct zcl_present_model_v1 *model, uint32_t *page_count);
#endif
#endif
