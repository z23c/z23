/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * db_maintenance_port — storage interface for the three SQLite
 * housekeeping operations the db_maintenance scheduler runs.
 *
 * db_maintenance is a NON-CONSENSUS background service: it ticks three
 * independent maintenance ops on their own schedules and reports timing
 * via the EV_DB_MAINTENANCE_* events. The only thing it does that touches
 * sqlite is execute one fixed maintenance statement per op. Those three
 * executions are exactly what this port captures, one method per op:
 *
 *   wal_checkpoint(self, out, err, errsz)
 *                                     "PRAGMA wal_checkpoint(TRUNCATE);"
 *                                     Flush committed WAL frames into the
 *                                     main file and truncate the WAL, and
 *                                     report how many frames actually moved
 *                                     (struct db_maintenance_wal_outcome).
 *   analyze(self, err, errsz)         "ANALYZE;"
 *                                     Rebuild sqlite_stat1 planner stats.
 *   vacuum(self, err, errsz)          "VACUUM;"
 *                                     Rebuild + defragment the whole file.
 *
 * One read accessor accompanies the three ops so the service never names
 * sqlite for its WAL-size cap either:
 *
 *   wal_size_bytes(self, out)         sqlite3_db_filename(...,"main") then
 *                                     stat("<db>-wal") — size of the WAL
 *                                     file on disk, used by the size-cap
 *                                     forced-checkpoint path.
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite
 * for this subsystem. It wraps an already-open sqlite3* via `self` and
 * never closes it.
 *
 * Contract for every method:
 *   - Runs the op's SQL verbatim (no statement caching). The WAL checkpoint
 *     is the one exception to "via sqlite3_exec": exec with a NULL callback
 *     DISCARDS the PRAGMA's result row, and that row is where the frame
 *     counts and the busy flag live, so the adapter uses the checkpoint call
 *     that returns them as out-parameters instead.
 *   - Returns true iff the op reported success (SQLITE_OK). For the WAL
 *     checkpoint, note that success does NOT imply the WAL shrank — read the
 *     outcome's frame counts for that.
 *   - On failure returns false and, if `err`/`errsz` are non-NULL, copies
 *     a NUL-terminated SQLite error string into `err` (truncated to
 *     `errsz`). The buffer is left a valid C string in all paths.
 *   - Returns false (with a "no/closed db" message) if `self` is NULL or
 *     the wrapped connection is NULL — the scheduler validates db-open
 *     state before it ever reaches the port, so this is a belt-and-braces
 *     guard.
 *
 * Threading: the scheduler holds its own mutex across the call, so a
 * synchronous run_now and the tick thread never race on the handle.
 */

#ifndef ZCL_PORTS_DB_MAINTENANCE_PORT_H
#define ZCL_PORTS_DB_MAINTENANCE_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What one checkpoint actually achieved, which its true/false return cannot
 * say. A checkpoint that completes having moved ZERO frames leaves the WAL
 * exactly as large as it found it, and reports the same success as one that
 * folded the whole log away — so the frame counts, not the return value, are
 * what tells an operator whether reclamation is happening.
 *
 * `truncate_rc` separately records whether the second-stage filesystem reset
 * succeeded. BUSY/LOCKED there is nonfatal after PASSIVE already moved the
 * frames; any other TRUNCATE error makes the operation fail. */
struct db_maintenance_wal_outcome {
    int64_t log_frames;   /* total frames observed in the WAL;    -1 unknown */
    int64_t ckpt_frames;  /* frames folded into the database;   -1 unknown */
    int     rc;           /* effective SQLite result for the whole request */
    int     truncate_rc;  /* exact file-reset result; -1 when not attempted */
    bool    busy;         /* PASSIVE was refused by a lock                  */
    bool    truncated;    /* the second-stage file reset returned OK       */
};

struct db_maintenance_port {
    void *self;

    /* "PRAGMA wal_checkpoint(TRUNCATE);"
     *
     * `out` may be NULL. When non-NULL it is filled on EVERY path, including
     * the failure paths, so a caller never reads a previous call's numbers. */
    bool (*wal_checkpoint)(void *self, struct db_maintenance_wal_outcome *out,
                           char *err, size_t errsz);

    /* "ANALYZE;" */
    bool (*analyze)(void *self, char *err, size_t errsz);

    /* "VACUUM;" */
    bool (*vacuum)(void *self, char *err, size_t errsz);

    /* Size in bytes of the wrapped connection's write-ahead-log file
     * ("<db path>-wal"). Sets *out and returns true if the DB filename is
     * known and the WAL file stat()s successfully; returns false (out
     * untouched) for a NULL self / NULL out / NULL connection, an
     * in-memory DB with no on-disk path, or a WAL file that does not exist
     * yet (size-unavailable returns false / out untouched). */
    bool (*wal_size_bytes)(void *self, int64_t *out);
};

#endif /* ZCL_PORTS_DB_MAINTENANCE_PORT_H */
