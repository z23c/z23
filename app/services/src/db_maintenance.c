// one-result-type-ok:json-dump-bool — E2 (one way out): the sole remaining
// Dump-state export: db_maintenance_dump_state_json.
// introspection dumper. The dump convention (CLAUDE.md "Adding state
// introspection") mandates a bool return (false = couldn't populate), not
// struct zcl_result; every other fallible surface in this file already
// returns zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Database Maintenance Scheduler — see header for rationale.
 *
 * Implementation strategy
 * -----------------------
 * Each of the three operations has an independent last-run
 * timestamp stored in the service state. The background thread
 * ticks every `tick_seconds` and, for each op, checks
 * `now - last_run >= interval`. When true it runs the op via
 * the same `db_maintenance_run_now()` path that synchronous
 * callers use, so failure reporting is unified.
 *
 * SQLite commands:
 *   wal     → "PRAGMA wal_checkpoint(TRUNCATE);"
 *             Truncates the WAL back to zero after flushing all
 *             committed frames into the main file. Cheap.
 *   analyze → "ANALYZE;"
 *             Rebuilds the sqlite_stat1 table used by the query
 *             planner. Cheap on databases with a few 10s of MB.
 *   vacuum  → "VACUUM;"
 *             Rebuilds the whole file into a new file, copies
 *             across, and replaces it. Holds the DB lock for
 *             the duration — can take minutes for a GB db.
 *             Only run when the caller-supplied gate says OK.
 *
 * Thread safety
 * -------------
 * The scheduler owns a mutex guarding lifecycle state and the
 * last-run timestamps. `run_now` takes the same mutex so a
 * synchronous caller and the scheduler never race on the same
 * op. SQLite calls in `run_now` happen with the mutex held —
 * that's intentional: if the scheduler is mid-vacuum and a test
 * calls run_now("analyze"), the analyze waits for the vacuum
 * rather than fighting over the db handle.
 */

#include "platform/time_compat.h"
#include "services/db_maintenance.h"

#include "event/event.h"
#include "json/json.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "adapters/outbound/persistence/db_maintenance_sqlite.h"
#include "ports/db_maintenance_port.h"

#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "util/wal_checkpoint_stats.h"

/* Supervisor deadline (sec). The scheduler ticks every tick_seconds
 * (default 60) but a single VACUUM can hold the DB lock for minutes on
 * a multi-GB file, blocking the loop between heartbeats. A 10-minute
 * deadline tolerates a long vacuum without a false stall, while still
 * catching a genuinely wedged scheduler. */
#define DB_MAINT_SUPERVISOR_DEADLINE_SEC 600

/* ── Module state ───────────────────────────────────────────── */

struct db_maintenance_state {
    pthread_mutex_t lock;
    pthread_t       thread;
    bool            thread_running;
    bool            stop_requested;

    struct node_db *db;
    struct db_maintenance_schedule sched;

    /* Resolved schedule (defaults applied). */
    int wal_minutes;
    int analyze_hours;
    int vacuum_days;
    int tick_seconds;
    int64_t wal_max_bytes;

    /* Last-run timestamps (UNIX seconds). 0 = never run. */
    int64_t wal_last_unix;
    int64_t wal_last_duration_ms;
    int64_t analyze_last_unix;
    int64_t analyze_last_duration_ms;
    int64_t vacuum_last_unix;
    int64_t vacuum_last_duration_ms;

    int64_t total_runs;
    int64_t total_failures;
    char    last_error[256];

    db_maintenance_vacuum_gate_fn vacuum_gate;

    /* Supervisor liveness. loop_ticks advances once per
     * outer-loop wake so the supervisor sees forward progress between
     * the (sparse) maintenance runs. */
    _Atomic supervisor_child_id supervisor_id;
    _Atomic int64_t             loop_ticks;
};

static struct db_maintenance_state g_dbm = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};

static struct liveness_contract g_dbm_contract;

/* ── Supervisor liveness ────────────────────────────────────── */

static void dbm_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_dbm.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_dbm.loop_ticks));
}

static void dbm_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int64_t runs = -1;
    int64_t failures = -1;
    if (pthread_mutex_trylock(&g_dbm.lock) == 0) {
        runs = g_dbm.total_runs;
        failures = g_dbm.total_failures;
        pthread_mutex_unlock(&g_dbm.lock);
    }
    LOG_WARN("db_maintenance",
             "[db_maint] supervisor stall reason=%s ticks=%lld runs=%lld failures=%lld",
             reason, (long long)atomic_load(&g_dbm.loop_ticks),
             (long long)runs, (long long)failures);
}

static struct zcl_result dbm_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-13, "db_maint: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_dbm.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, DB_MAINT_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, atomic_load(&g_dbm.loop_ticks));
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_dbm_contract, "op.db_maintenance");
    atomic_store(&g_dbm_contract.period_secs, 0);
    atomic_store(&g_dbm_contract.deadline_secs,
                 DB_MAINT_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_dbm_contract.progress_max_quiet_us, 0);
    g_dbm_contract.on_stall = dbm_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_op_sup, &g_dbm_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-14, "db_maint: supervisor_register failed");
    atomic_store(&g_dbm.supervisor_id, id);
    supervisor_progress(id, atomic_load(&g_dbm.loop_ticks));
    supervisor_tick(id);
    return ZCL_OK;
}

/* ── Defaults ───────────────────────────────────────────────── */

void db_maintenance_schedule_defaults(struct db_maintenance_schedule *s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->wal_checkpoint_minutes = DB_MAINT_DEFAULT_WAL_MINUTES;
    s->analyze_hours          = DB_MAINT_DEFAULT_ANALYZE_HOURS;
    s->vacuum_days            = DB_MAINT_DEFAULT_VACUUM_DAYS;
    s->tick_seconds           = 60;
}

void db_maintenance_schedule_wal_cap_only(
    struct db_maintenance_schedule *s)
{
    if (!s) return;
    db_maintenance_schedule_defaults(s);
    s->wal_checkpoint_minutes = -1; /* periodic leg owned by db_service */
    s->analyze_hours = -1;   /* exempt: unbounded index scan, no idle gate */
    s->vacuum_days   = -1;   /* exempt: needs an at-tip-and-idle gate */
}

void db_maintenance_status_snapshot(struct db_maintenance_status *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_dbm.lock);
    out->running                  = g_dbm.thread_running;
    out->wal_last_unix            = g_dbm.wal_last_unix;
    out->wal_last_duration_ms     = g_dbm.wal_last_duration_ms;
    out->analyze_last_unix        = g_dbm.analyze_last_unix;
    out->analyze_last_duration_ms = g_dbm.analyze_last_duration_ms;
    out->vacuum_last_unix         = g_dbm.vacuum_last_unix;
    out->vacuum_last_duration_ms  = g_dbm.vacuum_last_duration_ms;
    out->total_runs               = g_dbm.total_runs;
    out->total_failures           = g_dbm.total_failures;
    snprintf(out->last_error, sizeof(out->last_error),
             "%s", g_dbm.last_error);
    pthread_mutex_unlock(&g_dbm.lock);
}

/* `z23 dumpstate db_maintenance` — WAL-checkpoint / ANALYZE / VACUUM
 * background worker's last-run timestamps, durations, run/failure totals, and
 * last error. See CLAUDE.md "Adding state introspection".
 *
 * A single VACUUM holds g_dbm.lock for its whole (minutes-long) duration, so
 * the diagnostics path must never block on it — a stuck dumpstate call would
 * hide exactly the long-running maintenance an operator is trying to observe.
 * We trylock the worker mutex (same as dbm_on_stall) and, when the worker is
 * mid-op, emit busy:true and skip the per-op snapshot fields. loop_ticks is
 * atomic and always emitted so the worker's liveness is visible even while it
 * holds the lock. */
bool db_maintenance_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    /* Always available without the lock — proves the worker is alive even
     * while a VACUUM holds g_dbm.lock. */
    json_push_kv_int(out, "loop_ticks", atomic_load(&g_dbm.loop_ticks));

    if (pthread_mutex_trylock(&g_dbm.lock) != 0) {
        json_push_kv_bool(out, "busy", true);
        return true;
    }
    bool    running                  = g_dbm.thread_running;
    int64_t wal_last_unix            = g_dbm.wal_last_unix;
    int64_t wal_last_duration_ms     = g_dbm.wal_last_duration_ms;
    int64_t analyze_last_unix        = g_dbm.analyze_last_unix;
    int64_t analyze_last_duration_ms = g_dbm.analyze_last_duration_ms;
    int64_t vacuum_last_unix         = g_dbm.vacuum_last_unix;
    int64_t vacuum_last_duration_ms  = g_dbm.vacuum_last_duration_ms;
    int64_t total_runs               = g_dbm.total_runs;
    int64_t total_failures           = g_dbm.total_failures;
    char    last_error[256];
    snprintf(last_error, sizeof(last_error), "%s", g_dbm.last_error);
    pthread_mutex_unlock(&g_dbm.lock);

    json_push_kv_bool(out, "busy", false);
    json_push_kv_bool(out, "running", running);
    json_push_kv_int (out, "wal_last_unix", wal_last_unix);
    json_push_kv_int (out, "wal_last_duration_ms", wal_last_duration_ms);
    json_push_kv_int (out, "analyze_last_unix", analyze_last_unix);
    json_push_kv_int (out, "analyze_last_duration_ms",
                      analyze_last_duration_ms);
    json_push_kv_int (out, "vacuum_last_unix", vacuum_last_unix);
    json_push_kv_int (out, "vacuum_last_duration_ms",
                      vacuum_last_duration_ms);
    json_push_kv_int (out, "total_runs", total_runs);
    json_push_kv_int (out, "total_failures", total_failures);
    json_push_kv_str (out, "last_error", last_error);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * app/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed total_failures/last_error above — no new
     * health logic. Not emitted on the `busy` early-return above (a VACUUM
     * holding the lock is not itself a failure signal); the rollup
     * tolerates a dumper skipping `_health` on a given cycle. */
    {
        bool ok = total_failures == 0;
        char reason_buf[300] = "";
        if (!ok)
            snprintf(reason_buf, sizeof(reason_buf),
                     "total_failures=%lld last_error=%s",
                     (long long)total_failures, last_error);
        diag_push_health(out, ok, reason_buf);
    }
    return true;
}

void db_maintenance_set_vacuum_gate(db_maintenance_vacuum_gate_fn fn)
{
    pthread_mutex_lock(&g_dbm.lock);
    g_dbm.vacuum_gate = fn;
    pthread_mutex_unlock(&g_dbm.lock);
}

/* ── Helpers ────────────────────────────────────────────────── */

/* Returns true if `op` is one of the three recognised maintenance ops.
 * The SQL each op runs lives behind the db_maintenance_port adapter —
 * this service only names the ops. */
static bool dbm_op_known(const char *op)
{
    if (!op) return false;
    return strcmp(op, "wal")     == 0
        || strcmp(op, "analyze") == 0
        || strcmp(op, "vacuum")  == 0;
}

/* Dispatch a known op to the matching port method. `op` must already be
 * validated by dbm_op_known(). Returns the port method's bool; the error
 * text (on failure) lands in err/errsz. For "wal", `wal_out` (when non-NULL)
 * receives the frame counts that say whether the checkpoint reclaimed
 * anything; the other two ops leave it untouched. */
static bool dbm_run_op_via_port(const struct db_maintenance_port *port,
                                const char *op,
                                struct db_maintenance_wal_outcome *wal_out,
                                char *err, size_t errsz)
{
    if (strcmp(op, "wal") == 0)
        return port->wal_checkpoint(port->self, wal_out, err, errsz);
    if (strcmp(op, "analyze") == 0)
        return port->analyze(port->self, err, errsz);
    /* "vacuum" — the only remaining known op. */
    return port->vacuum(port->self, err, errsz);
}

/* Publish what a checkpoint achieved to the process-wide checkpoint ledger
 * (util/wal_checkpoint_stats.h), so the WAL question can be answered from one
 * place no matter which of the node's checkpointers ran. Returns the outcome
 * so the caller can say it out loud. */
static enum wal_ckpt_outcome dbm_publish_wal_outcome(
    bool completed, const struct db_maintenance_wal_outcome *w)
{
    struct wal_ckpt_record rec = {
        .outcome = wal_ckpt_classify(completed, w->busy,
                                     w->log_frames, w->ckpt_frames),
        .rc = w->rc,
        .log_frames = w->log_frames,
        .ckpt_frames = w->ckpt_frames,
        .source = "db_maintenance",
    };
    wal_ckpt_stats_note(&rec);
    return rec.outcome;
}

/* Update the per-op last-run state after a successful run.
 * Assumes g_dbm.lock is held. */
static void dbm_note_run_locked(const char *op,
                                 int64_t unix_now, int64_t duration_ms)
{
    if (strcmp(op, "wal") == 0) {
        g_dbm.wal_last_unix        = unix_now;
        g_dbm.wal_last_duration_ms = duration_ms;
    } else if (strcmp(op, "analyze") == 0) {
        g_dbm.analyze_last_unix        = unix_now;
        g_dbm.analyze_last_duration_ms = duration_ms;
    } else if (strcmp(op, "vacuum") == 0) {
        g_dbm.vacuum_last_unix        = unix_now;
        g_dbm.vacuum_last_duration_ms = duration_ms;
    }
}

/* ── run_now ────────────────────────────────────────────────── */

struct zcl_result db_maintenance_run_now(struct node_db *db, const char *op)
{
    if (!db || !db->open || !db->db)
        return ZCL_ERR(-1, "db_maint: run_now called with null or closed db");
    if (!dbm_op_known(op))
        return ZCL_ERR(-2, "db_maint: unknown maintenance op: %s",
                       op ? op : "(null)");

    /* The actual SQL execution lives behind the db_maintenance_port. We
     * bind the default sqlite adapter to this db's connection for the
     * duration of the call — the adapter never closes the handle. */
    struct db_maintenance_sqlite_ctx store_ctx;
    struct db_maintenance_port port = {0};
    db_maintenance_sqlite_bind(&store_ctx, db->db, &port);

    pthread_mutex_lock(&g_dbm.lock);

    event_emitf(EV_DB_MAINTENANCE_START, 0, "op=%s", op);

    int64_t start_ms = platform_time_monotonic_ms();
    char errmsg[256];
    errmsg[0] = '\0';
    struct db_maintenance_wal_outcome wal = {
        .log_frames = -1, .ckpt_frames = -1,
        .rc = -1, .truncate_rc = -1,
    };
    bool ok = dbm_run_op_via_port(&port, op, &wal, errmsg, sizeof(errmsg));
    int64_t elapsed_ms = platform_time_monotonic_ms() - start_ms;

    /* A checkpoint is the one op whose success is not the whole answer. Say
     * what it achieved before the pass/fail bookkeeping below, so a run of
     * checkpoints that reclaimed nothing is visible as exactly that rather
     * than as a healthy total_runs climbing. */
    if (strcmp(op, "wal") == 0) {
        enum wal_ckpt_outcome outcome = dbm_publish_wal_outcome(ok, &wal);
        if (wal_ckpt_outcome_reclaimed_nothing(outcome))
            LOG_WARN("db_maintenance",
                     "[db_maint] wal checkpoint reclaimed nothing: "
                     "outcome=%s wal_frames=%lld moved=%lld",
                     wal_ckpt_outcome_name(outcome),
                     (long long)wal.log_frames,
                     (long long)wal.ckpt_frames);
    }

    if (!ok) {
        g_dbm.total_failures++;
        snprintf(g_dbm.last_error, sizeof(g_dbm.last_error),
                 "op=%s %s", op, errmsg[0] ? errmsg : "sqlite error");
        event_emitf(EV_DB_MAINTENANCE_FAILED, 0,
                    "op=%s reason=%s", op,
                    errmsg[0] ? errmsg : "sqlite error");
        struct zcl_result r = ZCL_ERR(-3, "db_maint: op=%s %s",
                                      op,
                                      errmsg[0] ? errmsg : "sqlite error");
        pthread_mutex_unlock(&g_dbm.lock);
        return r;
    }

    dbm_note_run_locked(op, platform_time_wall_unix(), elapsed_ms);
    g_dbm.total_runs++;
    g_dbm.last_error[0] = '\0';

    event_emitf(EV_DB_MAINTENANCE_DONE, 0,
                "op=%s elapsed_ms=%" PRId64,
                op, elapsed_ms);
    pthread_mutex_unlock(&g_dbm.lock);
    return ZCL_OK;
}

struct zcl_result db_maintenance_checkpoint_now(void)
{
    /* Reclaim the node.db WAL using the handle registered by
     * db_maintenance_start, for callers (the disk_full reclaim path) that do
     * not themselves hold the node_db. Routing through run_now serializes with
     * the maintenance thread on g_dbm.lock — no concurrent sqlite access on the
     * shared handle. Read the pointer under the lock, then release it before
     * run_now re-acquires (run_now guards a closed/null db itself). */
    pthread_mutex_lock(&g_dbm.lock);
    struct node_db *db = g_dbm.db;
    pthread_mutex_unlock(&g_dbm.lock);
    if (!db)
        return ZCL_ERR(-21,
            "db_maint: checkpoint_now with no registered db (not started)");
    return db_maintenance_run_now(db, "wal");
}

/* ── Thread loop ────────────────────────────────────────────── */

/* Returns true if `last_unix == 0` (never run) or the interval
 * has elapsed since the last run. */
static bool dbm_due(int64_t last_unix, int64_t interval_seconds)
{
    if (last_unix == 0) return true;
    return (platform_time_wall_unix() - last_unix) >= interval_seconds;
}

/* Returns the WAL file size in bytes, or 0 if unavailable. The on-disk
 * probe lives behind the db_maintenance_port adapter so this service
 * never names sqlite. */
static int64_t dbm_wal_size(struct node_db *db)
{
    if (!db || !db->open || !db->db) return 0;
    struct db_maintenance_sqlite_ctx store_ctx;
    struct db_maintenance_port port = {0};
    db_maintenance_sqlite_bind(&store_ctx, db->db, &port);
    int64_t bytes = 0;
    if (!port.wal_size_bytes(port.self, &bytes))
        return 0;
    return bytes;
}

/* Whether an op's schedule arms it at all. A negative interval means the
 * caller declared the op EXEMPT — deliberately not running — which is a
 * different statement from an interval so long it has not come round yet.
 * Zero means "use the default", which is how every existing caller reaches
 * the DB_MAINT_DEFAULT_* values without naming them. */
static bool dbm_leg_armed(int configured)
{
    return configured >= 0;
}

static void *dbm_thread_fn(void *arg)
{
    (void)arg;
    while (true) {
        pthread_mutex_lock(&g_dbm.lock);
        bool stop = g_dbm.stop_requested;
        struct node_db *db = g_dbm.db;
        int wal_sec     = g_dbm.wal_minutes  * 60;
        int analyze_sec = g_dbm.analyze_hours * 3600;
        int vacuum_sec  = g_dbm.vacuum_days   * 86400;
        int64_t wal_last     = g_dbm.wal_last_unix;
        int64_t analyze_last = g_dbm.analyze_last_unix;
        int64_t vacuum_last  = g_dbm.vacuum_last_unix;
        db_maintenance_vacuum_gate_fn gate = g_dbm.vacuum_gate;
        int tick = g_dbm.tick_seconds;
        int64_t wal_cap = g_dbm.wal_max_bytes;
        pthread_mutex_unlock(&g_dbm.lock);

        if (stop) break;

        atomic_fetch_add(&g_dbm.loop_ticks, 1);
        dbm_supervisor_heartbeat();

        if (db) {
            /* WAL size cap: force checkpoint regardless of interval
             * when WAL exceeds the configured byte limit.
             *
             * The WAL byte cap remains armed even when its periodic interval
             * is exempt; DB service owns the ordinary five-minute cadence.
             * Other interval-zero legs stay exempt rather than becoming due
             * on every tick. */
            bool wal_over_cap = (wal_cap > 0 && dbm_wal_size(db) > wal_cap);
            if (wal_over_cap ||
                (wal_sec > 0 && dbm_due(wal_last, wal_sec)))
                (void)db_maintenance_run_now(db, "wal");
            if (analyze_sec > 0 && dbm_due(analyze_last, analyze_sec))
                (void)db_maintenance_run_now(db, "analyze");
            if (vacuum_sec > 0 && dbm_due(vacuum_last, vacuum_sec)) {
                bool may_vacuum = gate ? gate() : false;
                if (may_vacuum)
                    (void)db_maintenance_run_now(db, "vacuum");
            }
            /* Re-tick after the (possibly minutes-long) maintenance
             * work so the deadline timer is fresh before we sleep. */
            dbm_supervisor_heartbeat();
        }

        /* Sleep in 200ms increments so stop_requested is honoured
         * quickly without waiting a full tick. */
        int total_ms = tick > 0 ? tick * 1000 : 60000;
        int slept = 0;
        while (slept < total_ms) {
            pthread_mutex_lock(&g_dbm.lock);
            bool st = g_dbm.stop_requested;
            pthread_mutex_unlock(&g_dbm.lock);
            if (st) break;
            platform_sleep_ms(200);
            slept += 200;
        }
    }

    pthread_mutex_lock(&g_dbm.lock);
    g_dbm.thread_running = false;
    pthread_mutex_unlock(&g_dbm.lock);
    return NULL;
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct zcl_result db_maintenance_start(struct node_db *db,
                                       const struct db_maintenance_schedule *s)
{
    if (!db || !db->open || !db->db || !s)
        return ZCL_ERR(-10, "db_maint: start called with null db or schedule");

    pthread_mutex_lock(&g_dbm.lock);
    if (g_dbm.thread_running) {
        pthread_mutex_unlock(&g_dbm.lock);
        return ZCL_ERR(-11,
            "db_maint: start called but maintenance thread already running");
    }

    g_dbm.db    = db;
    g_dbm.sched = *s;
    g_dbm.wal_minutes   = !dbm_leg_armed(s->wal_checkpoint_minutes) ? 0
        : s->wal_checkpoint_minutes > 0
        ? s->wal_checkpoint_minutes : DB_MAINT_DEFAULT_WAL_MINUTES;
    g_dbm.analyze_hours = !dbm_leg_armed(s->analyze_hours) ? 0
        : s->analyze_hours > 0
        ? s->analyze_hours : DB_MAINT_DEFAULT_ANALYZE_HOURS;
    g_dbm.vacuum_days   = !dbm_leg_armed(s->vacuum_days) ? 0
        : s->vacuum_days > 0
        ? s->vacuum_days : DB_MAINT_DEFAULT_VACUUM_DAYS;
    g_dbm.tick_seconds  = s->tick_seconds > 0 ? s->tick_seconds : 60;

    /* WAL size cap: schedule value, env override, then default. */
    g_dbm.wal_max_bytes = s->wal_max_bytes > 0
        ? s->wal_max_bytes : DB_MAINT_DEFAULT_WAL_MAX_BYTES;
    const char *env_wal = getenv("ZCL_WAL_MAX_BYTES");
    if (env_wal) {
        int64_t v = strtoll(env_wal, NULL, 10);
        if (v > 0)
            g_dbm.wal_max_bytes = v;
        else if (v == 0)
            g_dbm.wal_max_bytes = 0;  /* disable cap */
    }

    g_dbm.stop_requested = false;
    g_dbm.thread_running = true;

    int rc = thread_registry_spawn("zcl_db_maint", dbm_thread_fn, NULL,
                                       &g_dbm.thread);
    if (rc != 0) {
        g_dbm.thread_running = false;
        pthread_mutex_unlock(&g_dbm.lock);
        return ZCL_ERR(-12,
            "db_maintenance: thread_registry_spawn failed (%d)", rc);
    }
    pthread_mutex_unlock(&g_dbm.lock);

    struct zcl_result sup_r = dbm_register_supervisor();
    if (!sup_r.ok) {
        db_maintenance_stop();
        return sup_r;
    }
    return ZCL_OK;
}

void db_maintenance_stop(void)
{
    pthread_t th;
    bool joinable = false;

    supervisor_child_id id = atomic_load(&g_dbm.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);

    pthread_mutex_lock(&g_dbm.lock);
    if (g_dbm.thread_running) {
        g_dbm.stop_requested = true;
        th = g_dbm.thread;
        joinable = true;
    }
    pthread_mutex_unlock(&g_dbm.lock);

    if (joinable) {
        pthread_join(th, NULL);
        pthread_mutex_lock(&g_dbm.lock);
        g_dbm.thread_running = false;
        g_dbm.stop_requested = false;
        g_dbm.db = NULL;
        pthread_mutex_unlock(&g_dbm.lock);
    }
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_dbm.supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}
