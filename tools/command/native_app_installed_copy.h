/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Native owner decision for making a copy of an installed app. */
#ifndef ZCL_NATIVE_APP_INSTALLED_COPY_H
#define ZCL_NATIVE_APP_INSTALLED_COPY_H
#include "command/native_app_confirm.h"
struct zcl_command_request;
struct zcl_command_reply;
void app_installed_copy_run(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context);
#if defined(ZCL_TESTING) && !defined(_WIN32)
/* Per-invocation lifecycle fixture only: replaces commit, not owner consent
 * in any public command. Callback/context live until the synchronous join. */
struct app_installed_copy_test_hooks {
    void (*commit)(void *context, const struct zcl_command_request *, struct zcl_command_reply *);
    void *context;
    const char *worker_alloc_label;
    bool refuse_start;
};
bool zcl_test_app_installed_copy_progress(const struct zcl_command_request *,
    struct zcl_command_reply *, app_confirm_presenter, void *,
    const struct app_installed_copy_test_hooks *);
#endif
#endif
