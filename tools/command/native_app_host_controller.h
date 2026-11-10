/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Synchronized lifecycle of one explicitly consented app hosting window. */
#ifndef ZCL_NATIVE_APP_HOST_CONTROLLER_H
#define ZCL_NATIVE_APP_HOST_CONTROLLER_H
#include "command/native_app_host_job.h"
#if !defined(_WIN32)
#include <pthread.h>
/* Heap-owned by window/controller until worker join and owned child reap. */
struct app_host_state {
    pthread_mutex_t mutex;
    bool stop, available, ever_ready, terminal, finished;
    enum app_host_outcome outcome;
    int64_t started_ms, last_ms, deadline_ms;
    struct app_host_ready ready;
};
struct app_host_snapshot { bool stop, available, ever_ready, terminal, finished; enum app_host_outcome outcome; struct app_host_ready ready; };
typedef bool (*app_host_copy_fn)(const struct app_host_ready *, void *);
bool app_host_state_init(struct app_host_state *);
void app_host_state_stop(struct app_host_state *);
bool app_host_state_cancel(void *);
bool app_host_state_publish(const struct app_host_ready *, void *);
void app_host_state_unavailable(void *);
void app_host_state_finish(struct app_host_state *, enum app_host_outcome);
bool app_host_state_snapshot(struct app_host_state *, struct app_host_snapshot *);
/* Called on the owner UI thread; callback must be bounded and not re-enter.
 * The mutex serializes the copy effect with Stop and observed failure. */
bool app_host_state_copy(struct app_host_state *, app_host_copy_fn, void *);
void app_host_state_destroy(struct app_host_state *);
/* Call only after the user confirms the exact share. Copies every argument to
 * heap-owned storage before starting the child-owning thread; caller retains
 * its scratch descriptors until successful join and reaped result. */
struct app_host_owner;
struct app_host_owner *app_host_owner_start(const struct app_host_job_args *);
void app_host_owner_stop(struct app_host_owner *);
bool app_host_owner_snapshot(struct app_host_owner *, struct app_host_snapshot *);
bool app_host_owner_copy(struct app_host_owner *, app_host_copy_fn, void *);
/* On failure the owner remains valid and must not be freed or scratch removed. */
bool app_host_owner_join(struct app_host_owner *, struct app_host_job_result *);
void app_host_owner_free(struct app_host_owner *); /* only after successful join */
#endif
#endif
