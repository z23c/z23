/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wal_checkpoint_stats — what every node.db WAL checkpoint actually DID.
 *
 * WHY THIS EXISTS. A SQLite checkpoint reports two different things through
 * one return code, and the codebase used to keep only the code:
 *
 *   SQLITE_OK with pnCkpt == 0   the checkpoint ran and moved ZERO frames.
 *                                The WAL is exactly as large as it was.
 *   SQLITE_OK with pnCkpt == pnLog
 *                                the checkpoint drained the whole WAL.
 *
 * Both are "success". Passing NULL for pnLog/pnCkpt — which is what
 * sqlite3_wal_checkpoint_v2(...,NULL,NULL) and `sqlite3_exec("PRAGMA
 * wal_checkpoint(...)", NULL, ...)` both do — throws away the only field that
 * separates them, so a checkpointer that has reclaimed nothing for hours is
 * indistinguishable from one keeping the WAL at zero. A WAL that grew to
 * 9.2x its database was invisible for exactly that reason.
 *
 * SQLite also reports internal contention as SQLITE_OK with busy=1 in the
 * PRAGMA's result ROW, so a caller that discards the row cannot see a
 * checkpoint that never started either. Both shapes land here as their own
 * outcome.
 *
 * This module is a plain publication surface: every checkpoint site records
 * one struct wal_ckpt_record, and readers (telemetry, tests) take a snapshot.
 * All state is atomic scalars plus atomic pointers to STATIC strings, so a
 * recorder never blocks and a reader never takes a lock — no checkpoint site
 * can be slowed down, or wedged, by something that is only watching it.
 */

#ifndef ZCL_UTIL_WAL_CHECKPOINT_STATS_H
#define ZCL_UTIL_WAL_CHECKPOINT_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What a single checkpoint attempt achieved. Ordered least-to-most useful so
 * a reader can compare, and named so a log line reads as prose. */
enum wal_ckpt_outcome {
    WAL_CKPT_UNKNOWN = 0,
    WAL_CKPT_ERROR,    /* sqlite returned a hard error                    */
    WAL_CKPT_BUSY,     /* refused/deferred by a lock: SQLITE_BUSY,
                        * SQLITE_LOCKED, or an OK row carrying busy=1     */
    WAL_CKPT_NOOP,     /* completed, moved ZERO frames, WAL still nonempty */
    WAL_CKPT_PARTIAL,  /* completed, moved some frames but not all        */
    WAL_CKPT_DRAINED,  /* completed, WAL fully folded into the database   */
};

/* One attempt's result. `source` must be a STATIC string (it is stored by
 * pointer and read without a lock). Frame counts are -1 when the caller could
 * not obtain them — never 0, which would claim "nothing was there". */
struct wal_ckpt_record {
    enum wal_ckpt_outcome outcome;
    int         rc;            /* the sqlite result code, for the log line */
    int64_t     log_frames;    /* pnLog:  frames in the WAL after the call */
    int64_t     ckpt_frames;   /* pnCkpt: frames moved into the database   */
    const char *source;        /* static label: who ran this checkpoint    */
};

/* Everything a reader can learn about checkpointing in this process. */
struct wal_ckpt_stats {
    /* The periodic checkpointer thread: armed, or explicitly not, and why.
     * Never "idle" — a checkpointer that was never started is a different
     * fact from one that ran and found nothing to do. */
    bool        periodic_armed;
    const char *periodic_state;   /* static: "armed" | "not_started" | ... */

    int64_t attempts_total;
    int64_t drained_total;
    int64_t partial_total;
    int64_t noop_total;        /* completed and reclaimed NOTHING */
    int64_t busy_total;        /* never got to run */
    int64_t error_total;
    int64_t frames_moved_total;

    /* The last attempt, from any source. */
    int64_t     last_unix;
    int64_t     last_log_frames;
    int64_t     last_ckpt_frames;
    int         last_rc;
    const char *last_outcome;  /* static, from wal_ckpt_outcome_name() */
    const char *last_source;   /* static */

    /* The periodic checkpointer's own split, which is the only thing that
     * separates "the writer queue is backed up" from "the disk is slow":
     * wait is time spent queued behind other writes, exec is time inside
     * sqlite doing checkpoint I/O. */
    int64_t periodic_last_wait_us;
    int64_t periodic_last_exec_us;
    int64_t periodic_max_wait_us;
    int64_t periodic_max_exec_us;
    int64_t periodic_runs_total;
};

/* Classify one checkpoint attempt from what it reported, in terms this layer
 * can state without naming a database engine:
 *
 *   completed    the call returned without a hard error
 *   busy         a lock refused or deferred the checkpoint — either the
 *                engine's busy result code, or a completed call whose result
 *                row said busy
 *   log_frames   frames left in the WAL afterwards, -1 if unknown
 *   ckpt_frames  frames folded into the database, -1 if unknown
 *
 * Frame counts of -1 (unknown) cannot distinguish a drain from a no-op, so an
 * otherwise-clean attempt with unknown counts classifies UNKNOWN rather than
 * claiming success. Pure — the tests call it directly. */
enum wal_ckpt_outcome wal_ckpt_classify(bool completed, bool busy,
                                        int64_t log_frames,
                                        int64_t ckpt_frames);

/* The static name of an outcome, for logs and telemetry. */
const char *wal_ckpt_outcome_name(enum wal_ckpt_outcome o);

/* True when the outcome means the WAL was not reclaimed at all — the
 * condition an operator needs to see and which a bool return code hides. */
bool wal_ckpt_outcome_reclaimed_nothing(enum wal_ckpt_outcome o);

/* Record one attempt. Safe from any thread; never blocks. NULL is ignored. */
void wal_ckpt_stats_note(const struct wal_ckpt_record *r);

/* Record the periodic checkpointer's queue-wait / execution split for the
 * attempt it just completed. Microseconds; negative values are ignored. */
void wal_ckpt_stats_note_periodic_timing(int64_t wait_us, int64_t exec_us);

/* Declare the periodic checkpointer armed or not. `state` must be a STATIC
 * string naming the reason when armed is false. */
void wal_ckpt_stats_set_periodic_armed(bool armed, const char *state);

/* Copy the current publication. NULL is ignored. */
void wal_ckpt_stats_snapshot(struct wal_ckpt_stats *out);

/* Drop every counter back to start-of-process. For tests only — production
 * code never needs it, and a reset would erase the history an operator is
 * reading. */
void wal_ckpt_stats_reset(void);

#endif /* ZCL_UTIL_WAL_CHECKPOINT_STATS_H */
