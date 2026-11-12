/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_service_args_selftest, which execs the shipped discovery
 * against stub systemctl, launchctl, and plutil programs. */

#include "test/test_core.h"

#include "service_args.h"

#include <stdio.h>

int test_service_args(void);
int test_service_args(void)
{
    int rc = zcl_service_args_selftest();
    if (rc == 0)
        printf("test_service_args: all passed\n");
    else
        printf("test_service_args: %d FAILED\n", rc);
    return rc == 0 ? 0 : 1;
}
