/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Fixed child execution for one bounded app-network request. */
#ifndef ZCL_NATIVE_APP_NETWORK_JOB_H
#define ZCL_NATIVE_APP_NETWORK_JOB_H
#include "command/native_app_network.h"
#include "util/spawn.h"
struct app_network_job_args {
    const char *mode, *url, *carrier_onion, *scratch;
    const struct zcl_app_offer_row *selected; /* carrier mode only */
    uint64_t scratch_dev, scratch_ino;
    unsigned bootstrap_port, timeout_ms;
    zcl_spawn_cancel_fn cancel;
    void *cancel_context;
};
struct app_network_job_result {
    struct zcl_app_offer_row rows[4]; size_t count; bool incomplete;
    uint8_t *bytes; size_t len;
    char frame[APP_NETWORK_FRAME_HEX_CAP];
    enum app_network_error error;
    bool launched, reaped, cancelled;
};
/* Synchronous; UI owner must call on a joined worker thread. Result bytes
 * are caller-owned. Parent retains scratch descriptor and cleans only after
 * child reaped; this function neither writes staged files nor removes trees. */
bool app_network_job_run(const struct app_network_job_args *args,
                         struct app_network_job_result *result);
#if defined(ZCL_TESTING) && !defined(_WIN32)
bool zcl_test_app_network_job_parse(const char *wire, size_t len,
    const struct app_network_job_args *args, struct app_network_job_result *result);
#endif
#endif
