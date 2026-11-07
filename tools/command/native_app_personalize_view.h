/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Native owner consent for personalizing an exact kept version. */
#ifndef ZCL_NATIVE_APP_PERSONALIZE_VIEW_H
#define ZCL_NATIVE_APP_PERSONALIZE_VIEW_H
#include "command/native_app_confirm.h"
struct zcl_command_request;
struct zcl_command_reply;
/* Only name + expected_revision; never accepts a caller's decision. */
void app_personalize_view_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
#if defined(ZCL_TESTING)
/* Per-invocation presenter; no production global hook or environment override. */
void zcl_test_app_personalize_view_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context);
#endif
#endif
