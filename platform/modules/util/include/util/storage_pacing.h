/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Storage pacing organ: ONE answer to "what kind of disk is this datadir on",
 * and ONE table of the write/read bounds that answer implies.
 *
 * WHY THIS EXISTS. Two fleet boxes with 7200 rpm disks sat at 52-65% IO
 * pressure while idle at chain tip. Every individual cause was a bound that
 * had been chosen for a machine where a seek is free: a 2.9 GB projection
 * file nobody compacted, a 383 MB WAL nobody truncated, a 1.3 GB Tor log
 * nobody rotated, and a boot repair that walked three million blocks 36
 * bytes at a time. None of that is tunable per host and none of it should
 * be: a deployed node has to work on whatever disk it lands on, with no
 * operator reading a manual. So the node measures the disk itself and picks
 * tighter bounds when the answer is "spinning".
 *
 * EVERY FIELD IS A COMPILED-IN DEFAULT. The environment overrides below
 * exist for tests and for an operator who already knows better; nothing here
 * is ever a required setting, and a node with no configuration at all gets
 * the right bounds for its hardware.
 *
 * HOW THE CLASS IS DECIDED, in order, first answer wins:
 *   1. ZCL_STORAGE_CLASS=rotational|solid  — explicit operator override.
 *   2. sysfs queue/rotational for the datadir's device (hw_profile), when
 *      that host publishes it.  Linux only.
 *   3. hw_bench's already-measured 4 KiB random pread median, but ONLY when
 *      it is slow enough to prove a seek. It samples a file as small as
 *      128 KiB, so a FAST answer there may just be the page cache and is
 *      not evidence of solid-state storage; a slow one cannot be an artifact.
 *   4. a dedicated timed probe (platform/storage_probe.h): 256 random 4 KiB
 *      reads spread over the largest datadir file of at least 64 MiB. This
 *      is the answer on macOS, on Windows, and inside any container where
 *      sysfs has nothing to say.
 *   5. UNKNOWN — and UNKNOWN is paced exactly like solid state, because the
 *      cost of tight bounds on a fast disk is a little extra housekeeping
 *      while the cost of loose bounds on a slow one is the 65% IO pressure
 *      this module was written to remove.
 */

#ifndef ZCL_STORAGE_PACING_H
#define ZCL_STORAGE_PACING_H

#include "platform/storage_probe.h"

#include <stdbool.h>
#include <stdint.h>

struct json_value; /* fwd; see json/json.h */

/* The bounds one storage class implies. Sizes are bytes, gaps milliseconds. */
struct storage_pacing {
    enum platform_storage_class klass;

    /* Boot walks (block_index top-up, pprev repair) tell the kernel they are
     * about to read a block file front to back, and pre-warm this many bytes
     * ahead of the cursor. Zero means "do not bother" — on flash the syscall
     * costs more than the seek it saves. */
    bool     sequential_readahead;
    int64_t  boot_readahead_window_bytes;

    /* Maintenance writers (projection compaction, WAL truncation, log
     * rotation) take one token and wait this long after each other, so three
     * of them cannot queue behind one head at the same time. */
    bool     serialize_maintenance;
    int64_t  maintenance_gap_ms;

    /* Truncate a SQLite WAL once it exceeds this. */
    int64_t  wal_truncate_bytes;

    /* Rotate an append-only text log once it exceeds this. */
    int64_t  log_rotate_bytes;

    /* Compact a projection store when its file exceeds both this floor and
     * `compact_ratio_pct` percent of the live page bytes inside it. Two
     * conditions, because a ratio alone would compact a 4 MB file forever
     * and a floor alone would compact a legitimately large one. */
    int64_t  compact_floor_bytes;
    int      compact_ratio_pct;
};

/* The compiled-in policy for a class. PURE — no clock, no disk, no cache —
 * so the pacing decision itself is unit-testable by forcing each class. */
struct storage_pacing storage_pacing_for_class(enum platform_storage_class klass);

/* Resolve the class for `datadir` once per process and publish the pacing.
 * Idempotent and thread-safe; never fatal. `datadir` may be NULL, in which
 * case only the override and sysfs steps can answer. Logs the decision once. */
void storage_pacing_init(const char *datadir);

/* Never NULL. Serves the solid-state-shaped default until init() has run, so
 * no caller has to order itself after boot. */
const struct storage_pacing *storage_pacing(void);
enum platform_storage_class storage_pacing_class(void);
/* "override", "sysfs", "bench", "probe" or "default". Never NULL. */
const char *storage_pacing_source(void);

/* Take the maintenance token, having waited out the class's idle gap since
 * the previous maintenance writer finished. Returns true when the token is
 * held; the caller MUST pair it with storage_pacing_maintenance_end(). When
 * the class does not serialise maintenance this is a no-op that returns
 * true, so callers need no conditional. */
bool storage_pacing_maintenance_begin(void);
void storage_pacing_maintenance_end(void);

/* Test seams. force() pins the class without touching a disk; reset() drops
 * the cached decision so the next init() re-resolves. */
void storage_pacing_force_class_for_testing(enum platform_storage_class klass);
void storage_pacing_reset_for_testing(void);

bool storage_pacing_dump_state_json(struct json_value *out, const char *key);

#endif
