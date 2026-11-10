/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Own the explicit app-link discovery and receive flow. */
#ifndef ZCL_NATIVE_APP_NETWORK_CONTROLLER_H
#define ZCL_NATIVE_APP_NETWORK_CONTROLLER_H
#include "command/native_app_library_command.h"
bool app_network_open_link(const char *datadir, app_library_presenter cards,
    app_confirm_presenter notices, void *context, struct zcl_command_reply *reply, bool *shown);
#if defined(ZCL_TESTING)
#include "command/native_app_network_job.h"
struct app_network_test_hooks {
    bool (*form)(void *, char out[257], bool *, char *, size_t);
    bool (*job)(void *, const char *, const char *, const char *,
        const struct zcl_app_offer_row *, struct app_network_job_result *, struct zcl_command_reply *);
    bool (*worker)(void *, const struct app_network_job_args *, struct app_network_job_result *);
    app_confirm_presenter receive;
};
bool zcl_test_app_network_scratch_replace(const char *datadir,
    bool (*replace)(void *, const char *, long), void *context,
    bool *reaped, struct zcl_command_reply *reply);
bool zcl_test_app_network_open_link(const char *datadir, app_library_presenter cards,
    app_confirm_presenter notices, void *context, struct zcl_command_reply *reply,
    bool *shown, const struct app_network_test_hooks *hooks);
#endif
#endif
