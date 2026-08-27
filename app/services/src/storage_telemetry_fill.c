// one-result-type-ok:telemetry-fill-provider — E2 (one way out): both public
// functions have contract-fixed bool signatures that this file does not get to
// choose. `storage_telemetry_dump_state_json` is the diagnostics-registry
// dumper ABI (CLAUDE.md "Adding state introspection"), and
// `storage_dump_state_fill` is the telemetry provider contract
// (util/telemetry_render.h): a subsystem it could not read is a SUCCESSFUL
// fill carrying an unavailable leaf with a static reason token, so the reason
// already travels with the failure — inside the snapshot, per leaf, which is
// strictly more than one struct zcl_result could carry. The bool is false only
// on a NULL argument. There is no fallible service surface here.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `storage` telemetry collector — see services/storage_telemetry.h for the
 * contract and, more importantly, for the cost rules this file is shaped by.
 *
 * Sources, and why each one is read the way it is:
 *
 *   progress.kv / projection.kv   pointer loads (progress_store_db,
 *       projection_store_db) plus one O(1) published counter
 *       (stage_cursor_rows_value). No statement is prepared.
 *
 *   block_index.bin integrity     bii_get_recovery_status copies a struct
 *       under a mutex that is only ever held for that copy and for the boot's
 *       one record call.
 *
 *   disk headroom                 the monitor's atomic level is read first and
 *       is the authority for the two boolean verdicts, so they survive even if
 *       the descriptive snapshot is stale. The numbers come from
 *       disk_monitor_status_snapshot.
 *
 *   db_maintenance                read through that service's OWN dumper,
 *       which trylocks. A VACUUM holds the maintenance mutex for minutes, so a
 *       blocking read here would hide exactly the long-running maintenance an
 *       operator is trying to observe. Losing the race sets every maintenance
 *       leaf unavailable with reason "db_maintenance_busy".
 *
 *   db_txn_trace                  read through its dumper, which is a
 *       lock-free seqlock read of a background thread's publication. With the
 *       tracer off the two counters are unavailable, not zero — zero would
 *       claim "no connection holds a transaction", which nobody established.
 *
 * NOT read, deliberately: block_index_projection's dumper, which runs
 * `SELECT COUNT(*) FROM block_index` (millions of rows at tip) for its
 * entry_count. Its cursor would be nice to have; it is not worth queueing the
 * reply behind that scan, and there is no O(1) publication of it today.
 *
 * Reading a peer subsystem's dumper and pulling scalars back out of it with
 * json_get_* is a READ, not a write: this file emits no telemetry JSON of its
 * own, which is what check-telemetry-ontology proves.
 */

#include "services/storage_telemetry.h"

#include "json/json.h"
#include "services/block_index_integrity.h"
#include "services/db_maintenance.h"
#include "services/disk_monitor.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "sync/stage.h"
#include "util/db_txn_trace.h"
#include "util/log_macros.h"
#include "util/telemetry_render.h"
#include "util/wal_checkpoint_stats.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Every reason token this file can attach to a non-present leaf. They are
 * static strings with program lifetime (the render layer borrows them) and
 * they are listed together so a reader can grep the whole vocabulary at once. */
#define SR_MAINT_BUSY      "db_maintenance_busy"
#define SR_MAINT_UNREAD    "db_maintenance_unreadable"
#define SR_MAINT_NEVER_WAL "no_wal_checkpoint_recorded"
#define SR_MAINT_NEVER_VAC "no_vacuum_recorded"
#define SR_CKPT_NO_PERIODIC_RUN "no_periodic_checkpoint_completed"
#define SR_TRACE_OFF       "db_txn_trace_disabled"
#define SR_TRACE_UNREAD    "db_txn_trace_unreadable"
#define SR_DISK_NEVER      "disk_never_polled"
#define SR_DISK_STOPPED    "disk_monitor_not_running"
#define SR_PROJ_CLOSED     "projection_store_closed"
#define SR_CLOCK           "wall_clock_unavailable"

/* ── small readers over a peer dumper's document ──────────────────────────
 * A peer dumper returns a plain object. These pull one scalar out of it and
 * say whether it was actually there, so a missing key becomes an unavailable
 * leaf rather than a zero. */

static bool sr_get_int(const struct json_value *doc, const char *key,
                       int64_t *out)
{
    const struct json_value *v = json_get(doc, key);
    if (!v || v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool sr_get_bool(const struct json_value *doc, const char *key,
                        bool *out)
{
    const struct json_value *v = json_get(doc, key);
    if (!v || v->type != JSON_BOOL)
        return false;
    *out = json_get_bool(v);
    return true;
}

/* Seconds between `then` (a wall-clock unix second) and now, clamped at zero.
 * Returns false when either end is unknown, which is the caller's cue to mark
 * the leaf unavailable instead of publishing a plausible age. */
static bool sr_age_seconds(int64_t then_unix, int64_t now_unix, int64_t *out)
{
    if (then_unix <= 0 || now_unix <= 0)
        return false;
    int64_t age = now_unix - then_unix;
    *out = age > 0 ? age : 0;
    return true;
}

/* ── the database group ─────────────────────────────────────────────────── */

static void fill_stores(struct storage_snapshot *s)
{
    /* Both are pointer loads by contract — no statement, no lock. */
    const void *progress_db = (const void *)progress_store_db();
    const void *projection_db = (const void *)projection_store_db();

    TELEMETRY_SET_BOOL(s, progress_store_open, progress_db != NULL,
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, stage_cursor_rows, stage_cursor_rows_value(),
                      TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_BOOL(s, projection_store_open, projection_db != NULL,
                       TELEMETRY_SRC_IN_PROCESS);

    /* With no projection handle there is nothing to be independent OF, and
     * reporting `false` would read as "the Wave A2 split collapsed" when the
     * truth is "the store is closed" — a different subsystem to go look at. */
    if (!projection_db)
        TELEMETRY_NOT_APPLICABLE_LEAF(s, projection_handle_independent,
                                      SR_PROJ_CLOSED);
    else
        TELEMETRY_SET_BOOL(s, projection_handle_independent,
                           projection_db != progress_db,
                           TELEMETRY_SRC_IN_PROCESS);
}

static void fill_block_index(struct storage_snapshot *s)
{
    struct bii_recovery_status st;
    bii_get_recovery_status(&st);

    TELEMETRY_SET_BOOL(s, block_index_degraded, st.degraded,
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(s, block_index_unsafe_override, st.unsafe_override,
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_TEXT(s, block_index_verdict, bii_verdict_name(st.verdict),
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(s, block_index_heights_repaired,
                       block_index_heights_repaired(),
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, block_index_verified_unix, st.unix_time,
                      TELEMETRY_SRC_IN_PROCESS);
}

static void fill_txn_trace(struct storage_snapshot *s)
{
    bool enabled = zcl_db_txn_trace_enabled();
    TELEMETRY_SET_BOOL(s, txn_trace_enabled, enabled,
                       TELEMETRY_SRC_CONFIG);
    if (!enabled) {
        /* The tracer being off is a configuration fact, not a failure: nobody
         * asked for these numbers, so they are not applicable rather than
         * unreadable. Publishing 0 would assert that no connection holds a
         * transaction, which no one measured. */
        TELEMETRY_NOT_APPLICABLE_LEAF(s, txn_open_holders, SR_TRACE_OFF);
        TELEMETRY_NOT_APPLICABLE_LEAF(s, txn_traced_connections, SR_TRACE_OFF);
        return;
    }

    struct json_value doc;
    json_init(&doc);
    int64_t holders = 0, conns = 0;
    bool ok = db_txn_trace_dump_state_json(&doc, NULL);
    if (ok && sr_get_int(&doc, "open_txn_holders", &holders))
        TELEMETRY_SET_I64(s, txn_open_holders, holders,
                          TELEMETRY_SRC_CACHED_PUBLICATION);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, txn_open_holders, SR_TRACE_UNREAD);
    if (ok && sr_get_int(&doc, "connection_count", &conns))
        TELEMETRY_SET_I64(s, txn_traced_connections, conns,
                          TELEMETRY_SRC_CACHED_PUBLICATION);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, txn_traced_connections, SR_TRACE_UNREAD);
    json_free(&doc);
}

/* ── the disk group ─────────────────────────────────────────────────────── */

static void fill_disk(struct storage_snapshot *s, int64_t now_unix)
{
    /* The atomic level first, and it is the authority for the two verdicts:
     * it is lock-free, so it answers even while the poll mutex is held. */
    enum disk_monitor_level level = disk_monitor_level();
    TELEMETRY_SET_BOOL(s, below_refuse_threshold,
                       level == DISK_MONITOR_CRITICAL,
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(s, below_warn_threshold,
                       level == DISK_MONITOR_LOW ||
                           level == DISK_MONITOR_CRITICAL,
                       TELEMETRY_SRC_IN_PROCESS);

    struct disk_monitor_status st;
    disk_monitor_status_snapshot(&st);
    TELEMETRY_SET_BOOL(s, monitor_running, st.running,
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, warn_free_bytes, st.warn_free_bytes,
                      TELEMETRY_SRC_CONFIG);
    TELEMETRY_SET_I64(s, refuse_free_bytes, st.refuse_free_bytes,
                      TELEMETRY_SRC_CONFIG);

    /* -1 is the monitor's "never polled" sentinel. Passing it through as a
     * value would render a negative byte count and trip the 1 GiB floor with a
     * number that was never measured. */
    if (st.last_free_bytes < 0)
        TELEMETRY_UNAVAILABLE_LEAF(s, free_bytes,
                                   st.running ? SR_DISK_NEVER : SR_DISK_STOPPED);
    else
        TELEMETRY_SET_I64(s, free_bytes, st.last_free_bytes,
                          TELEMETRY_SRC_IN_PROCESS);

    if (st.last_poll_unix <= 0) {
        TELEMETRY_UNAVAILABLE_LEAF(s, last_poll_unix,
                                   st.running ? SR_DISK_NEVER : SR_DISK_STOPPED);
        /* The age of an event that never happened is not a number that got
         * away — it is meaningless. */
        TELEMETRY_NOT_APPLICABLE_LEAF(s, poll_age_seconds, SR_DISK_NEVER);
        return;
    }
    TELEMETRY_SET_I64(s, last_poll_unix, st.last_poll_unix,
                      TELEMETRY_SRC_IN_PROCESS);
    int64_t age = 0;
    if (sr_age_seconds(st.last_poll_unix, now_unix, &age))
        TELEMETRY_SET_I64(s, poll_age_seconds, age, TELEMETRY_SRC_DERIVED);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, poll_age_seconds, SR_CLOCK);
}

/* Every maintenance leaf unavailable for one reason — the shape both the
 * trylock-lost and the dumper-failed paths need, written once so the two can
 * never drift into reporting different subsets. */
static void maintenance_all_unavailable(struct storage_snapshot *s,
                                        const char *why)
{
    TELEMETRY_UNAVAILABLE_LEAF(s, maintenance_worker_running, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, maintenance_failures_total, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, maintenance_runs_total, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, vacuum_age_seconds, why);
}

/* The WAL checkpoint leaves, sourced from the process-wide checkpoint ledger
 * (util/wal_checkpoint_stats.h) rather than from the maintenance worker.
 *
 * WHY THEY MOVED. wal_checkpoint_age_seconds used to be read out of the
 * maintenance worker's dumper alone. That worker was gated behind an
 * environment variable nothing set, so it never ran, so the age leaf read
 * "not_applicable: no_wal_checkpoint_recorded" on every node forever — while
 * the checkpointer that DOES run (one pass every 5 minutes, from the DB
 * service) had no telemetry at all. An operator reading the storage domain
 * got a permanent nothing-happening about the wrong subsystem. Every
 * checkpointer now records into one ledger and this reads that. */
static void fill_wal_checkpoint(struct storage_snapshot *s, int64_t now_unix)
{
    struct wal_ckpt_stats w;
    memset(&w, 0, sizeof(w));
    wal_ckpt_stats_snapshot(&w);

    /* Armed is always a statement, never an absence: the checkpointer
     * publishes its own state, so this leaf is present even when false. */
    TELEMETRY_SET_BOOL(s, wal_checkpointer_armed, w.periodic_armed,
                       TELEMETRY_SRC_IN_PROCESS);

    TELEMETRY_SET_I64(s, wal_checkpoint_attempts_total, w.attempts_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, wal_checkpoint_noop_total, w.noop_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, wal_checkpoint_busy_total, w.busy_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, wal_checkpoint_frames_moved_total,
                      w.frames_moved_total, TELEMETRY_SRC_IN_PROCESS);

    /* The age of a checkpoint that has not happened yet is not a number. */
    int64_t age = 0;
    if (w.attempts_total <= 0 || w.last_unix <= 0)
        TELEMETRY_NOT_APPLICABLE_LEAF(s, wal_checkpoint_age_seconds,
                                      SR_MAINT_NEVER_WAL);
    else if (sr_age_seconds(w.last_unix, now_unix, &age))
        TELEMETRY_SET_I64(s, wal_checkpoint_age_seconds, age,
                          TELEMETRY_SRC_DERIVED);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, wal_checkpoint_age_seconds, SR_CLOCK);

    /* The wait/exec split exists only once the PERIODIC checkpointer has
     * completed a pass — a checkpoint run from anywhere else was never in
     * that queue, so it has no wait to report and a zero would be a claim. */
    if (w.periodic_runs_total <= 0) {
        TELEMETRY_NOT_APPLICABLE_LEAF(s, wal_checkpoint_queue_wait_us,
                                      SR_CKPT_NO_PERIODIC_RUN);
        TELEMETRY_NOT_APPLICABLE_LEAF(s, wal_checkpoint_exec_us,
                                      SR_CKPT_NO_PERIODIC_RUN);
    } else {
        TELEMETRY_SET_I64(s, wal_checkpoint_queue_wait_us,
                          w.periodic_last_wait_us, TELEMETRY_SRC_IN_PROCESS);
        TELEMETRY_SET_I64(s, wal_checkpoint_exec_us,
                          w.periodic_last_exec_us, TELEMETRY_SRC_IN_PROCESS);
    }
}

static void fill_maintenance(struct storage_snapshot *s, int64_t now_unix)
{
    struct json_value doc;
    json_init(&doc);
    if (!db_maintenance_dump_state_json(&doc, NULL)) {
        json_free(&doc);
        maintenance_all_unavailable(s, SR_MAINT_UNREAD);
        return;
    }
    /* The service publishes busy=true when its own trylock lost to an
     * in-flight VACUUM. That is the incompleteness this collector reports
     * rather than waits out. */
    bool busy = false;
    if (!sr_get_bool(&doc, "busy", &busy) || busy) {
        json_free(&doc);
        maintenance_all_unavailable(s, SR_MAINT_BUSY);
        return;
    }

    bool running = false;
    if (sr_get_bool(&doc, "running", &running))
        TELEMETRY_SET_BOOL(s, maintenance_worker_running, running,
                           TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, maintenance_worker_running,
                                   SR_MAINT_UNREAD);

    int64_t n = 0;
    if (sr_get_int(&doc, "total_failures", &n))
        TELEMETRY_SET_I64(s, maintenance_failures_total, n,
                          TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, maintenance_failures_total,
                                   SR_MAINT_UNREAD);
    if (sr_get_int(&doc, "total_runs", &n))
        TELEMETRY_SET_I64(s, maintenance_runs_total, n,
                          TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, maintenance_runs_total, SR_MAINT_UNREAD);

    int64_t last = 0, age = 0;
    if (!sr_get_int(&doc, "vacuum_last_unix", &last) || last <= 0)
        TELEMETRY_NOT_APPLICABLE_LEAF(s, vacuum_age_seconds,
                                      SR_MAINT_NEVER_VAC);
    else if (sr_age_seconds(last, now_unix, &age))
        TELEMETRY_SET_I64(s, vacuum_age_seconds, age, TELEMETRY_SRC_DERIVED);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, vacuum_age_seconds, SR_CLOCK);

    json_free(&doc);
}

/* ── the provider ───────────────────────────────────────────────────────── */

bool storage_dump_state_fill(struct storage_snapshot *s)
{
    if (!s)
        LOG_FAIL("storage_telemetry", "fill: snapshot is NULL");

    int64_t now_unix = telemetry_now_unix();
    if (now_unix > 0)
        TELEMETRY_SET_I64(s, collected_unix, now_unix,
                          TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, collected_unix, SR_CLOCK);

    fill_stores(s);
    fill_block_index(s);
    fill_txn_trace(s);
    fill_disk(s, now_unix);
    fill_maintenance(s, now_unix);
    fill_wal_checkpoint(s, now_unix);
    return true;
}

bool storage_telemetry_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL("storage_telemetry", "dump: out is NULL");

    struct storage_snapshot snap = {0};
    if (!storage_dump_state_fill(&snap))
        LOG_FAIL("storage_telemetry", "dump: could not fill the snapshot");

    const char *group = NULL;
    bool unrecognized = false;
    enum telemetry_view view = telemetry_view_parse(key, &group, &unrecognized);
    (void)unrecognized; /* render reports group_filter_matched; an unknown key
                         * lands on the normal view rather than guessing. */
    return telemetry_render(&g_storage_schema, &snap, view, group, out);
}
