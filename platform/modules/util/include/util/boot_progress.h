/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot-progress liveness signal.
 *
 * Long-running synchronous operations (snapshot bulk INSERT,
 * block-by-block catchup, UTXO replay) can take tens of seconds to
 * tens of minutes during boot. systemd's WatchdogSec= timer expects
 * a WATCHDOG=1 ping every WatchdogSec/2; the existing tick in
 * boot_services.c gates that ping on node_health_collect's
 * `snap.healthy` field, which is derived from P2P-driven signals
 * (peer count, mirror lag, tip advance age) and goes stale while the
 * single-writer main thread is busy with a bulk DB op. The unit then
 * trips and systemd kills the process mid-bulk-insert with SIGABRT.
 *
 * This module exposes a second liveness signal that any synchronous
 * worker can bump cheaply, and that the watchdog tick reads alongside
 * `snap.healthy`. If either signal is recent, the ping fires; if both
 * go stale (a truly wedged worker), the watchdog still expires and
 * the unit restarts as intended.
 *
 * Cost: one atomic store on the hot path, one atomic load per tick.
 *
 * Usage:
 *
 *   #include "util/boot_progress.h"
 *
 *   for (int h = start; h <= tip; ++h) {
 *       connect_block(h);
 *       if ((h % 100) == 0) boot_progress_tick("catchup");
 *   }
 *
 * Safe to call before/after boot — no init required, never blocks,
 * no allocation. The label is for debug observability only; it gets
 * round-tripped into `z23 dumpstate boot` so operators can see
 * which subsystem is keeping the watchdog alive.
 */

#ifndef ZCL_UTIL_BOOT_PROGRESS_H
#define ZCL_UTIL_BOOT_PROGRESS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bump the last-progress timestamp. `label` should be a string
 * literal naming the bumping subsystem (e.g. "snapshot_import",
 * "catchup", "utxo_replay"). The pointer is stashed for observability;
 * lifetime must outlive the process (string literals are ideal). */
void boot_progress_tick(const char *label);

/* Return the monotonic CLOCK_MONOTONIC timestamp (in microseconds) of
 * the most recent tick, or 0 if no tick has fired yet. Used by the
 * sd_watchdog pet thread as a bounded startup/long-operation liveness
 * signal. */
int64_t boot_progress_last_us(void);

/* Most recent label, or NULL if no tick has fired yet. Pointer is
 * stable for the lifetime of the process when callers pass string
 * literals as recommended. Read-only — diagnostic use. */
const char *boot_progress_last_label(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_BOOT_PROGRESS_H */
