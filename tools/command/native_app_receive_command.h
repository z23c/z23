/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare the native owner-confirmed share-file receiver and test seam. */
#ifndef ZCL_NATIVE_APP_RECEIVE_COMMAND_H
#define ZCL_NATIVE_APP_RECEIVE_COMMAND_H
#include "command/native_command.h"
#if defined(ZCL_TESTING)
#include "command/native_app_confirm.h"
#include "command/native_app_commit_progress.h"
void zcl_test_app_receive_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context);
#if !defined(_WIN32)
/* Per-invocation lifecycle fixture; no public authorization bypass. */
bool zcl_test_app_receive_progress(const struct zcl_command_request *,
    struct zcl_command_reply *, app_confirm_presenter, void *,
    const struct app_commit_progress_test_hooks *);
#endif
#endif
void zcl_native_handle_app_receive(const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
#endif
