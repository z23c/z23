/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Browse and revoke local hosting intents using native owner choices. */
#ifndef ZCL_NATIVE_APP_HOST_BROWSER_H
#define ZCL_NATIVE_APP_HOST_BROWSER_H
#include "command/native_app_library_command.h"
void app_library_choice(struct zcl_present_model_v1 *model, const char *id,
                        const char *label, const char *value);
bool app_host_browser_run(app_library_presenter presenter, app_confirm_presenter confirm,
                          void *context, struct zcl_command_reply *reply);
struct app_selection;
typedef bool (*app_host_selection_check)(void *context, struct zcl_command_reply *reply);
bool app_host_original_run(const struct app_selection *selection,
    app_host_selection_check check, void *check_context,
    app_confirm_presenter confirm, void *context, bool *canceled,
    struct zcl_command_reply *reply);
#endif
