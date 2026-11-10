/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * App-only host job: one owner, one immutable signed carrier, no node. */
#ifndef ZCL_NATIVE_APP_HOST_JOB_H
#define ZCL_NATIVE_APP_HOST_JOB_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "util/spawn.h"
#include "chain/chainparamsbase.h"

/* Caller owns all strings and the scratch root until the synchronous run has
 * returned and reaped is true. Caller has already obtained explicit consent,
 * committed and verified the exact carrier, placed it as carrier.z23share inside
 * the scratch root, and retained its scratch identity.
 * The UI must call run on an owned joinable thread and keep this object alive. */
struct app_host_job_args {
    const char *self_path, *scratch_path;
    uint64_t scratch_dev, scratch_ino;
    const char *name, *release_root, *package_root, *publisher, *carrier_sha256;
    uint64_t carrier_size;
    enum chain_network network;
    unsigned duration_ms; /* 3000..86400000; no change to receive timeout */
    int64_t service_deadline_ms; /* owner-set absolute monotonic deadline, or 0 */
    zcl_spawn_cancel_fn cancel;
    void *cancel_context;
};
struct app_host_ready {
    char onion[63], post_id[65], carrier_root[65], carrier_sha256[65];
    char release_root[65], package_root[65], publisher[67];
    uint64_t carrier_size;
};
typedef bool (*app_host_ready_fn)(const struct app_host_ready *, void *);
typedef void (*app_host_unavailable_fn)(void *);
enum app_host_outcome { APP_HOST_FAILED = 0, APP_HOST_STOPPED, APP_HOST_EXPIRED };
struct app_host_job_result {
    bool launched, reaped, cancelled, ready, invalid_frame, timed_out;
    enum app_host_outcome outcome;
};
/* Ready is a bounded canonical line, once only, before EOF. An owner callback
 * receives a borrowed immutable snapshot after exact identity validation. A
 * malformed, duplicate or excessive frame refuses capture and reaps the owned
 * group. Completion requires process EOF and observed reap. The caller must
 * not delete scratch if reaping or its own join is unconfirmed. */
bool app_host_job_run(const struct app_host_job_args *, app_host_ready_fn,
                      app_host_unavailable_fn, void *ready_context, struct app_host_job_result *);
#if defined(ZCL_TESTING)
bool zcl_test_app_host_ready(const struct app_host_job_args *, const void *, size_t,
                             size_t split, struct app_host_ready *);
#endif
#endif
