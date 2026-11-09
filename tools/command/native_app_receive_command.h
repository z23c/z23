/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare the native owner-confirmed share-file receiver and test seam. */
#ifndef ZCL_NATIVE_APP_RECEIVE_COMMAND_H
#define ZCL_NATIVE_APP_RECEIVE_COMMAND_H
#include "command/native_command.h"
#include <stdint.h>
#include <stddef.h>
/* Validate the same first-use parent policy as Receive without writes. */
bool app_receive_profile_validate(const char *datadir, char *anchor, size_t anchor_cap,
    struct zcl_command_reply *reply);
struct app_receive_identity {
    uint8_t release_id[32], package_root[32], publisher[33];
};
void zcl_native_app_receive_expected(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_receive_identity *expected);
#if defined(ZCL_TESTING)
#include "command/native_app_confirm.h"
#include "command/native_app_commit_progress.h"
void zcl_test_app_receive_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context);
void zcl_test_app_receive_expected(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_receive_identity *expected,
    app_confirm_presenter presenter, void *context);
void zcl_test_app_receive_expected_worker(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_receive_identity *expected,
    app_confirm_presenter presenter, void *context, const char *worker_path);
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
