/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Test-only transport seam for the typed fleet job. */
#ifndef ZCL_NATIVE_DEV_FLEET_JOB_H
#define ZCL_NATIVE_DEV_FLEET_JOB_H
#if defined(ZCL_TESTING)
#include <stdbool.h>
#include <stddef.h>
typedef int (*zcl_fleet_job_test_transport)(const char *const argv[], char *out,
                                            size_t cap, int timeout_ms, bool *timed_out);
void zcl_fleet_job_set_test_transport(zcl_fleet_job_test_transport fn);
#endif
#endif
