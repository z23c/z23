/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Explicit one-window sharing of one selected kept app. */
#ifndef ZCL_NATIVE_APP_HOST_FLOW_H
#define ZCL_NATIVE_APP_HOST_FLOW_H
#include "command/native_app_confirm.h"
struct app_selection;
struct zcl_command_reply;
/* No hosting before the native confirmation. Caller supplies an installed
 * self executable and a previously loaded selection; confirmation rechecks
 * it at commit. Caller retains reply and receives all mutation facts. */
void app_host_flow(const struct app_selection *, const char *self_path,
    app_confirm_presenter, void *, struct zcl_command_reply *);
#if defined(ZCL_TESTING) && !defined(_WIN32)
void zcl_test_app_host_failure_facts(struct zcl_command_reply *, const char *, const char *, bool);
#endif
#endif
