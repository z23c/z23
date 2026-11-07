/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Export an exact saved app source and existing build as inert assets. */
#ifndef ZCL_NATIVE_APP_SOURCE_COMMAND_H
#define ZCL_NATIVE_APP_SOURCE_COMMAND_H
struct zcl_command_request;
struct zcl_command_reply;
void zcl_native_handle_app_source_export(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply);
#endif
