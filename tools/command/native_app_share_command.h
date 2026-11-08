/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Declare native kept-version sharing and its test presenter seam. */
#ifndef ZCL_NATIVE_APP_SHARE_COMMAND_H
#define ZCL_NATIVE_APP_SHARE_COMMAND_H
#include "command/native_command.h"
struct app_selection;
#if defined(ZCL_TESTING)
#include "command/native_app_confirm.h"
void zcl_test_app_share_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context);
#endif
struct app_selection;
void zcl_native_app_share_snapshot(const char *name, const char *output,
    struct zcl_command_reply *reply, const struct app_selection *selection);
void zcl_native_handle_app_share(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply);
#endif
