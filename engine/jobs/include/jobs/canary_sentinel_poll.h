/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * canary_sentinel_poll — supervised cadence Job for the replay-canary
 * sentinel watch. Registers in the `ops` supervisor domain and calls
 * canary_sentinel_watch_tick_once() on each tick; the service owns all the
 * scanning/latching logic, so this Job is a pure scheduling shim. */

#ifndef ZCL_JOBS_CANARY_SENTINEL_POLL_H
#define ZCL_JOBS_CANARY_SENTINEL_POLL_H

#include <stdbool.h>

/* Register the poll Job with the ops supervisor. Idempotent. */
void canary_sentinel_poll_register(void);

/* True once the poll Job is registered with the supervisor. */
bool canary_sentinel_poll_is_registered(void);

#endif /* ZCL_JOBS_CANARY_SENTINEL_POLL_H */
