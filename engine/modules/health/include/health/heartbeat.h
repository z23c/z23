/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Heartbeat ring — single in-process watchdog surface.
 *
 * Before this module landed, zclassic23 ran six independent watchdog
 * mechanisms (sync_watchdog_service, tip_watchdog, node_health_service,
 * boot_phase, rpc_timeout, plus an out-of-process zcl-watchdog ELF).
 * Each had its own definition of "stuck" and its own thread, and they
 * oscillated between pthread- and alarm-based implementations because
 * nobody owned the watchdog layer.
 *
 * After: every long-running subsystem registers itself once with a
 * declared deadline and an `on_stall` callback. The subsystem calls
 * health_heartbeat(id) on its working cadence. One sweeper thread
 * (registered with thread_registry as "zcl_health_sweep") wakes
 * every g_check_interval_ms milliseconds, iterates the active
 * entries, and fires on_stall edge-triggered when a deadline is
 * missed. There is one watchdog thread for the whole process.
 *
 * Edge-triggered semantics:
 *   - First time a deadline is missed: on_stall fires once
 *   - Subsequent sweeps with no fresh heartbeat: nothing fires
 *     (no repeated callbacks while still stalled)
 *   - A fresh heartbeat resets the edge; the next stall fires again
 *
 * The sync_watchdog_service recovery policy (HEADER_STALL,
 * QUEUE_STARVED, etc.) becomes the body of its on_stall callback;
 * the sync_watchdog *thread* gets removed. Same for the other five.
 */

#ifndef ZCL_HEALTH_HEARTBEAT_H
#define ZCL_HEALTH_HEARTBEAT_H

#include <stdbool.h>
#include <stdint.h>

#define HEALTH_REGISTRY_CAP   64
#define HEALTH_NAME_MAX       40

typedef int health_subsystem_id;
#define HEALTH_INVALID_ID (-1)

/* Register a subsystem with the heartbeat ring. The on_stall callback
 * fires from the sweeper thread when the subsystem hasn't heartbeated
 * in `deadline_secs`. ctx is passed through verbatim.
 *
 * Returns the slot id (>= 0) on success or HEALTH_INVALID_ID on
 * registry-full / NULL entry / bad deadline. `name` is copied
 * (truncated to HEALTH_NAME_MAX-1 chars).
 *
 * Pre-seeds last_beat to "now" so a freshly-registered subsystem
 * has its full deadline before the first stall can fire. */
health_subsystem_id health_register(const char *name,
                                     int64_t deadline_secs,
                                     void (*on_stall)(void *ctx),
                                     void *ctx);

/* Register a periodic tick. `cb` fires from the sweeper thread every
 * `period_secs` regardless of heartbeats — the heartbeat field is
 * ignored for periodic entries. This is what replaces the per-
 * subsystem watchdog threads that just wake on a fixed cadence to
 * run a check (sync_watchdog_check, tip_watchdog drain, etc.).
 *
 * The first fire happens `period_secs` after registration, not
 * immediately. Successive fires target `period_secs` cadence; the
 * actual interval is rounded up to the sweep interval. */
health_subsystem_id health_register_periodic(const char *name,
                                              int64_t period_secs,
                                              void (*cb)(void *ctx),
                                              void *ctx);

/* Note that the subsystem is alive. O(1) — one atomic store. Safe
 * to call from any thread. No-op if id is invalid or the entry is
 * a periodic tick (heartbeats are meaningless there). */
void health_heartbeat(health_subsystem_id id);

/* Free the slot. Subsequent heartbeats with the same id are no-ops.
 * Safe to call from any thread. */
void health_unregister(health_subsystem_id id);

/* Lifecycle.
 *
 * health_start() spawns the sweeper thread via thread_registry as
 * "zcl_health_sweep" and returns true on success. Idempotent.
 * health_stop() requests the sweeper to exit and joins it.
 *
 * Tests can call health_set_check_interval_ms() before health_start()
 * to shorten the 1s default for fast tests. */
bool health_start(void);
void health_stop(void);
void health_set_check_interval_ms(int ms);

/* Snapshot of one registered subsystem. last_beat_age_secs is
 * computed as (now - last_beat). on_stall_fired counts total
 * edge-triggered firings since registration. */
struct health_snapshot {
    char    name[HEALTH_NAME_MAX];
    int64_t deadline_secs;        /* for stall entries; period_secs for periodic */
    int64_t last_beat_age_secs;   /* for stall entries; last-fire age for periodic */
    int     on_stall_fired;       /* total fires (stall edges or periodic ticks) */
    bool    currently_stalled;    /* always false for periodic entries */
    bool    periodic;             /* true if registered via health_register_periodic */
};

/* Fill `out` with up to `max` active entries. Returns the number
 * written. Lock is held only briefly during the copy. */
int health_snapshot_all(struct health_snapshot *out, int max);

/* Reset the entire ring + stop the sweeper. Tests only. */
void health_reset_for_test(void);

/* State-dump convention (see CLAUDE.md "Adding state introspection").
 * Writes the heartbeat ring's runtime state as a JSON object into
 * `out`. `out` must already be initialized (json_set_object'd) by the
 * caller. `key` is unused by this subsystem — pass NULL.
 *
 * Returns true on success, false if `out` is NULL. */
struct json_value;
bool health_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_HEALTH_HEARTBEAT_H */
