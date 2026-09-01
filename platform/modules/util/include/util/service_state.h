/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * service_state — the node's canonical runtime operational mode.
 *
 * Orthogonal to `enum boot_stage` (one-time, monotonic init
 * checkpoints). service_state is the bidirectional operational answer
 * to "is the node healthy, and is anything being repaired":
 *
 *   BOOT -> RESTORE -> RECONCILE -> { DEGRADED_SERVING | SYNCING } -> HEALTHY
 *                                          \                          /
 *                                           `----- REPAIRING <-------'
 *
 * The contract that makes the node a supervised self-healing service:
 * a *reconcilable* inconsistency at boot moves the node into
 * DEGRADED_SERVING (serving, with a named repair Condition active)
 * instead of exiting. The node is ALWAYS in an observable state and
 * never silently loops or dies; only truly unrecoverable data is
 * fatal, and then LOUD + observable.
 *
 * Transitions are logged. Illegal targets are logged and dropped —
 * operational mode must never abort the node (that is what
 * `boot_stage` is for). */

#ifndef ZCL_UTIL_SERVICE_STATE_H
#define ZCL_UTIL_SERVICE_STATE_H

#include <stddef.h>

enum service_state {
    SERVICE_STATE_BOOT = 0,
    SERVICE_STATE_RESTORE,
    SERVICE_STATE_RECONCILE,
    SERVICE_STATE_DEGRADED_SERVING,
    SERVICE_STATE_SYNCING,
    SERVICE_STATE_HEALTHY,
    SERVICE_STATE_REPAIRING,
    SERVICE_STATE__COUNT
};

/* Current operational mode. Atomic; safe from any thread. */
enum service_state service_state_current(void);

/* Transition to `next`, recording a short human-readable `reason`.
 * Logs every transition. Idempotent (advancing to the current state
 * just refreshes the reason). Never aborts; an out-of-range target is
 * logged and ignored. */
void service_state_advance(enum service_state next, const char *reason);

/* Stable lowercase name, e.g. "degraded_serving". Never NULL. */
const char *service_state_name(enum service_state s);

/* The reason string recorded by the most recent advance. Never NULL.
 * A racy read of a fixed buffer — adequate for diagnostics. */
const char *service_state_reason(void);

/* Copy the current reason into `buf` under the internal lock (non-racy,
 * always NUL-terminated, truncated to `cap`). Safe for serialization.
 * No-op if buf is NULL or cap is 0. */
void service_state_reason_copy(char *buf, size_t cap);

/* `z23 dumpstate service_state` dumper. `out` is initialized by the
 * caller; `key` is unused. Reentrant-safe. */
struct json_value;
bool service_state_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_UTIL_SERVICE_STATE_H */
