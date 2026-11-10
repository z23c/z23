/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Browse verified advertisements and hand one to native Receive. */
#ifndef ZCL_NATIVE_APP_DISCOVER_H
#define ZCL_NATIVE_APP_DISCOVER_H
#include "command/native_app_library_command.h"
#include "command/native_app_offer.h"
void app_discover_report_observation(const struct zcl_app_offer_row *row,
    app_confirm_presenter presenter, void *context, const struct json_value *build,
    const struct json_value *opened, struct zcl_command_reply *reply);
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
