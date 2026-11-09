/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Declare native public publishing of an exact saved app selection. */
#ifndef ZCL_NATIVE_APP_PUBLISH_COMMAND_H
#define ZCL_NATIVE_APP_PUBLISH_COMMAND_H
#include "command/native_app_confirm.h"
struct app_selection;
struct zcl_command_reply;
void zcl_native_app_publish_snapshot(const char *name, const struct app_selection *selection,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context);
#endif
