/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Storage housekeeping: the one periodic writer that keeps the node's
 * datadir bounded.
 *
 * WHAT IT BOUNDS, and why each of these needed a bound at all. Every number
 * below is a real measurement from a fleet box with a 7200 rpm disk, idle at
 * chain tip, whose /proc/pressure/io sat at 52-65%:
 *
 *   progress.kv       2,874 MB, against 1 MB on a sibling box at the same
 *                     height. No compaction existed, so the projection file
 *                     tracked the high-water mark of everything ever indexed.
 *   topology.db-wal     383 MB, against a 49 MB topology.db. The WAL had no
 *                     size-triggered checkpoint and the passive one is a
 *                     no-op whenever a reader holds an old snapshot.
 *   tor.log           1,319 MB of info-level lines under a torrc whose first
 *                     line says "Log notice file". Nothing rotated it.
 *
 * WHY ONE SERVICE RATHER THAN THREE TIMERS. On a spinning disk the cost of
 * maintenance is not CPU, it is the head. Three independent timers will
 * eventually fire together, and a VACUUM, a WAL checkpoint and a log
 * rotation queued behind one head is precisely the stall this service
 * exists to prevent. Every writer here runs in sequence behind the
 * storage-pacing maintenance token (util/storage_pacing.h), which on
 * rotational storage also leaves an idle gap between them.
 *
 * EVERY BOUND IS A COMPILED-IN DEFAULT chosen from the measured storage
 * class. A deployed node needs no configuration to get the right ones.
 */

#ifndef ZCL_SERVICES_STORAGE_HOUSEKEEPING_H
#define ZCL_SERVICES_STORAGE_HOUSEKEEPING_H

#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

struct json_value; /* fwd; see json/json.h */

/* Seconds between sweeps. A minute is far below every bound's fill time
 * (the field box took days to reach 383 MB of WAL) and far above the cost of
 * the sweep itself, which is three size measurements when nothing is over. */
#define STORAGE_HOUSEKEEPING_TICK_SECONDS 60

/* One sweep's outcome, for tests and for typed status. */
struct storage_housekeeping_stats {
    int64_t sweeps;
    int64_t projection_compactions;
    int64_t topology_checkpoints;
    int64_t log_rotations;
    int64_t projection_file_bytes;   /* last measurement, -1 if unmeasured */
    int64_t projection_live_bytes;
    int64_t topology_wal_bytes;
};

/* Run ONE sweep synchronously, in the current thread. This is the whole
 * behaviour of the service; the background thread only calls it on a timer.
 * `datadir` may be NULL, in which case the log rotations are skipped and the
 * two store bounds still run (both stores know their own paths).
 * Never fatal: a bound that cannot be applied this tick is applied the next. */
void storage_housekeeping_sweep(const char *datadir);

/* Launch/stop the periodic thread. Idempotent. start() refuses, with a named
 * zcl_result, a NULL/empty datadir or one that does not exist: a sweeper
 * with nothing to bound is a misconfiguration, not a degraded mode. */
struct zcl_result storage_housekeeping_start(const char *datadir);
void storage_housekeeping_stop(void);

void storage_housekeeping_stats(struct storage_housekeeping_stats *out);
bool storage_housekeeping_dump_state_json(struct json_value *out,
                                          const char *key);

/* Register storage housekeeping as an optional maintenance service on
 * `kernel` (ctx = the DATADIR string, like disk_monitor and bundle_exporter).
 * Fail-safe: a node that cannot start the sweeper still boots, it just stops
 * bounding its own datadir, and the failure is named on stderr. */
struct zcl_service_kernel;
bool storage_housekeeping_register_service(struct zcl_service_kernel *kernel,
                                           const char *datadir);

#endif
