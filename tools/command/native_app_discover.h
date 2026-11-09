/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Browse verified advertisements and hand one to native Receive. */
#ifndef ZCL_NATIVE_APP_DISCOVER_H
#define ZCL_NATIVE_APP_DISCOVER_H
#include "command/native_app_library_command.h"
/* True means a Receive completed; reply retains its outcome. */
bool app_discover_run(const char *datadir, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, struct zcl_command_reply *reply,
    bool *error_presented);
#ifdef ZCL_TESTING
bool app_discover_run_test(const char *datadir, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, struct zcl_command_reply *reply,
    bool *error_presented, const char *worker_path);
#endif
#endif
