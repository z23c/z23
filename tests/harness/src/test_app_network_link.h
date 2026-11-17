/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Shared test seam between the app discover command and the
 * harness: the sandboxed network worker child, stood in by the tests. */
#ifndef ZCL_TEST_APP_NETWORK_LINK_H
#define ZCL_TEST_APP_NETWORK_LINK_H
#include "command/native_app_network_job.h"
#if defined(ZCL_TESTING)
#include <stdbool.h>
/* Defined in tests/harness/src/test_app_get.c. When the function pointer is
 * set, `app discover` runs it instead of the real same-image worker child;
 * the arguments are exactly what the child would have received. */
extern bool (*zcl_test_app_discover_job)(void *context,
    const struct app_network_job_args *args,
    struct app_network_job_result *result);
extern void *zcl_test_app_discover_job_context;
#endif
#endif
