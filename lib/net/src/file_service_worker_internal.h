/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Test-only declarations for the file-service range-worker transport.  The
 * production implementation stays private to file_service.c; focused tests
 * reach only its ownership invariant instead of widening the public API. */

#ifndef ZCL_FILE_SERVICE_WORKER_INTERNAL_H
#define ZCL_FILE_SERVICE_WORKER_INTERNAL_H

#include <stdbool.h>

#ifdef ZCL_TESTING
/* Exercise the exact range-worker socket ownership helpers used by
 * fs_client_sync() against descriptor reuse and cancel-before-publication. */
bool fs_test_range_worker_socket_lifecycle(void);
#endif

#endif
