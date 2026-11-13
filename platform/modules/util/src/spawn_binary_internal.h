/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Internal entry to the existing process-group capture owner. */
#ifndef ZCL_SPAWN_BINARY_INTERNAL_H
#define ZCL_SPAWN_BINARY_INTERNAL_H
#include "util/spawn.h"
#if !defined(_WIN32)
bool zcl_spawn_private_pipe(int p[2]);
#if defined(ZCL_TESTING)
void zcl_spawn_private_prefork(const int *fds, size_t count);
#endif
int zcl_spawn_exact_internal(const char *const argv[], void *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn cancel, void *cancel_ctx, bool *cancelled, bool merge_stderr,
    struct zcl_spawn_binary_observation *out, struct zcl_spawn_measure *measure,
    zcl_spawn_bytes_fn observe, zcl_spawn_end_fn on_end, void *observe_ctx, bool *refused);
#endif
#endif
