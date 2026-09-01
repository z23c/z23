/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Long-operation heartbeat contract (WS-2a).
 *
 * A long_op_scope is opened around any code path that may legitimately
 * take longer than the sync watchdog's per-state stuck timeout
 * (~600s). Each `tick()` resets the watchdog's "no progress" timer
 * and emits an EV_LONG_OP_TICK event so absence of progress on long
 * ops becomes observable separately from sync progress.
 *
 * Usage:
 *   struct long_op_scope op;
 *   long_op_begin(&op, "legacy_cold_import.bulk_copy_block_index");
 *   while (...) {
 *       ... do unit of work ...
 *       long_op_tick(&op);     // safe to call every iteration; rate-limited
 *   }
 *   long_op_end(&op);
 *
 * Thread safety: tick() is safe to call from any thread. begin/end
 * should be called from the same thread.
 *
 * The watchdog (sync_watchdog_service.c) consults long_op_is_active()
 * before declaring STATE_STUCK: if a long_op has ticked recently, the
 * watchdog suppresses the recovery escalation. This generalises the
 * one-off boot_progress hack used by snapshot-import bulk copy in
 * commit 94b708096.
 */
#ifndef ZCL_UTIL_LONG_OP_H
#define ZCL_UTIL_LONG_OP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct long_op_scope {
    const char *label;       /* borrowed; outlives the scope */
    int64_t     begin_us;
    int64_t     last_tick_us;
    int64_t     tick_count;
    bool        registered;
};

void long_op_begin(struct long_op_scope *s, const char *label);
void long_op_tick(struct long_op_scope *s);
void long_op_end(struct long_op_scope *s);

/* For sync_watchdog_service.c to query: returns true if any long_op
 * is currently active and ticking. Watchdog should treat this as
 * "progress observed elsewhere" and not fire STATE_STUCK. The
 * out parameter, if non-NULL, receives the age in seconds of the
 * most-recent tick across all active scopes (0 if none active). */
bool long_op_is_active(int64_t *last_tick_age_secs);

/* Diagnostic accessor: returns the label of the most-recently-ticked
 * active scope, or NULL if no scope is active. */
const char *long_op_recent_label(void);

/* For diagnostics_controller "long_op" subsystem dump per
 * CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool long_op_dump_state_json(struct json_value *out, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_LONG_OP_H */
