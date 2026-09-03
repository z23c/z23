/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the db_maintenance scheduler.
 *
 * Each test opens a real node_db on a fresh scratch file (node_db
 * creates the full schema so the PRAGMA/ANALYZE/VACUUM paths have
 * actual tables to act on) and drives the service through
 * db_maintenance_run_now() synchronously. The scheduler thread
 * itself is tested via a single start/stop path — the tick
 * interval is configurable so tests don't have to sleep for the
 * default 60 s.
 */

#include "test/test_core.h"
#include "services/db_maintenance.h"
#include "event/event.h"
#include "models/database.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test/setup_result.h"

#define DBM_SCRATCH_DIR "./test-tmp"

static _Atomic int g_ev_start;
static _Atomic int g_ev_done;
static _Atomic int g_ev_failed;

static void dbm_ev_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_DB_MAINTENANCE_START)  atomic_fetch_add(&g_ev_start,  1);
    if (type == EV_DB_MAINTENANCE_DONE)   atomic_fetch_add(&g_ev_done,   1);
    if (type == EV_DB_MAINTENANCE_FAILED) atomic_fetch_add(&g_ev_failed, 1);
}

static void dbm_install_observer(void)
{
    event_clear_observers(EV_DB_MAINTENANCE_START);
    event_clear_observers(EV_DB_MAINTENANCE_DONE);
    event_clear_observers(EV_DB_MAINTENANCE_FAILED);
    atomic_store(&g_ev_start,  0);
    atomic_store(&g_ev_done,   0);
    atomic_store(&g_ev_failed, 0);
    event_observe(EV_DB_MAINTENANCE_START,  dbm_ev_observer, NULL);
    event_observe(EV_DB_MAINTENANCE_DONE,   dbm_ev_observer, NULL);
    event_observe(EV_DB_MAINTENANCE_FAILED, dbm_ev_observer, NULL);
}

#define DBM_CHECK(name, expr) do { \
    printf("%s... ", (name));     \
    if ((expr)) printf("OK\n");   \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Minimal test fixture: a raw sqlite3 connection wrapped in a
 * `struct node_db` shell. We can't use the real `node_db_open`
 * here because it opens ~30 cached prepared statements, which
 * SQLite blocks VACUUM on. The service only touches `ndb.db`
 * and `ndb.open`, so the shell is sufficient for exercising
 * `db_maintenance_run_now`. */
struct dbm_fixture {
    char dbpath[256];
    sqlite3 *raw;
    struct node_db ndb;
};

static bool dbm_fixture_init(struct dbm_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    mkdir(DBM_SCRATCH_DIR, 0755);
    snprintf(f->dbpath, sizeof(f->dbpath),
             DBM_SCRATCH_DIR "/dbm_%d_%s.db", (int)getpid(), tag);
    unlink(f->dbpath);
    char wal[320], shm[320];
    snprintf(wal, sizeof(wal), "%s-wal", f->dbpath);
    snprintf(shm, sizeof(shm), "%s-shm", f->dbpath);
    unlink(wal); unlink(shm);

    if (sqlite3_open_v2(f->dbpath, &f->raw,
            SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return false;
    /* WAL mode so PRAGMA wal_checkpoint(TRUNCATE) has something
     * meaningful to do. */
    if (sqlite3_exec(f->raw, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL)
        != SQLITE_OK)
        return false;
    /* Give the db something to analyze / vacuum — an empty db
     * is a degenerate case and we want to hit the real op paths. */
    if (sqlite3_exec(f->raw,
            "CREATE TABLE kv(k INTEGER PRIMARY KEY, v BLOB);"
            "INSERT INTO kv VALUES(1, randomblob(64));"
            "INSERT INTO kv VALUES(2, randomblob(128));"
            "INSERT INTO kv VALUES(3, randomblob(256));"
            "DELETE FROM kv WHERE k=2;",
            NULL, NULL, NULL) != SQLITE_OK)
        return false;

    f->ndb.db   = f->raw;
    f->ndb.open = true;
    return true;
}

static void dbm_fixture_destroy(struct dbm_fixture *f)
{
    if (f->raw) {
        sqlite3_close(f->raw);
        f->raw = NULL;
    }
    f->ndb.db   = NULL;
    f->ndb.open = false;
    unlink(f->dbpath);
    char wal[320], shm[320];
    snprintf(wal, sizeof(wal), "%s-wal", f->dbpath);
    snprintf(shm, sizeof(shm), "%s-shm", f->dbpath);
    unlink(wal);
    unlink(shm);
}

/* A vacuum gate that always returns false — used to verify that
 * scheduler-driven vacuums respect the gate. */
static bool dbm_gate_always_false(void) { return false; }

int test_db_maintenance(void)
{
    printf("\n=== db_maintenance tests ===\n");
    int failures = 0;

    {
        struct db_maintenance_schedule sched;
        db_maintenance_schedule_wal_cap_only(&sched);
        DBM_CHECK("dbm: boot schedule leaves periodic WAL to DB service",
                  sched.wal_checkpoint_minutes < 0);
        DBM_CHECK("dbm: boot schedule exempts analyze and vacuum",
                  sched.analyze_hours < 0 && sched.vacuum_days < 0);
        DBM_CHECK("dbm: boot schedule keeps the WAL byte cap armed",
                  sched.wal_max_bytes == 0);
    }

    /* ── 1. Each op succeeds via run_now ──────────────────── */
    {
        dbm_install_observer();
        struct dbm_fixture f;
        DBM_CHECK("dbm: fixture opens",
                  dbm_fixture_init(&f, "runops"));

        bool wal_ok     = db_maintenance_run_now(&f.ndb, "wal").ok;
        bool analyze_ok = db_maintenance_run_now(&f.ndb, "analyze").ok;
        bool vacuum_ok  = db_maintenance_run_now(&f.ndb, "vacuum").ok;

        DBM_CHECK("dbm: run_now(wal) succeeds",     wal_ok);
        DBM_CHECK("dbm: run_now(analyze) succeeds", analyze_ok);
        DBM_CHECK("dbm: run_now(vacuum) succeeds",  vacuum_ok);

        int starts = atomic_load(&g_ev_start);
        int dones  = atomic_load(&g_ev_done);
        int fails  = atomic_load(&g_ev_failed);
        DBM_CHECK("dbm: three EV_DB_MAINTENANCE_START events fired",
                  starts == 3);
        DBM_CHECK("dbm: three EV_DB_MAINTENANCE_DONE events fired",
                  dones == 3);
        DBM_CHECK("dbm: no EV_DB_MAINTENANCE_FAILED events",
                  fails == 0);

        dbm_fixture_destroy(&f);
    }

    /* ── 2. Unknown op rejected + counted as 0 runs ───────── */
    {
        dbm_install_observer();
        struct dbm_fixture f;
        dbm_fixture_init(&f, "badop");

        bool ok = db_maintenance_run_now(&f.ndb, "defrag-please").ok;
        DBM_CHECK("dbm: unknown op rejected by run_now", !ok);
        DBM_CHECK("dbm: unknown op emits no events",
                  atomic_load(&g_ev_start)  == 0 &&
                  atomic_load(&g_ev_done)   == 0 &&
                  atomic_load(&g_ev_failed) == 0);

        dbm_fixture_destroy(&f);
    }

    /* ── 3. Closed db rejects run_now cleanly ─────────────── */
    {
        struct node_db fake = {0};
        /* fake.open is false, fake.db is NULL → run_now refuses */
        bool ok = db_maintenance_run_now(&fake, "analyze").ok;
        DBM_CHECK("dbm: run_now with unopened db returns false", !ok);
    }

    /* ── 4. Status snapshot reflects last-run timestamps ─── */
    {
        struct dbm_fixture f;
        dbm_fixture_init(&f, "status");
        ZCL_TEST_SETUP(db_maintenance_run_now(&f.ndb, "wal"));
        ZCL_TEST_SETUP(db_maintenance_run_now(&f.ndb, "analyze"));

        struct db_maintenance_status st;
        db_maintenance_status_snapshot(&st);
        DBM_CHECK("dbm: status snapshot records wal last_unix",
                  st.wal_last_unix > 0);
        DBM_CHECK("dbm: status snapshot records analyze last_unix",
                  st.analyze_last_unix > 0);
        DBM_CHECK("dbm: total_runs advances on each successful run",
                  st.total_runs >= 2);

        dbm_fixture_destroy(&f);
    }

    /* ── 5. Scheduler start/stop lifecycle ────────────────── */
    {
        struct dbm_fixture f;
        dbm_fixture_init(&f, "lifecycle");

        struct db_maintenance_schedule sched;
        db_maintenance_schedule_defaults(&sched);
        /* Generous intervals so the thread doesn't attempt any
         * scheduled runs during the test. */
        sched.tick_seconds           = 3600;

        bool start1 = db_maintenance_start(&f.ndb, &sched).ok;
        bool reject = !db_maintenance_start(&f.ndb, &sched).ok;
        DBM_CHECK("dbm: start() succeeds", start1);
        DBM_CHECK("dbm: second start() rejected while running", reject);

        struct db_maintenance_status st;
        db_maintenance_status_snapshot(&st);
        DBM_CHECK("dbm: status.running true while thread alive", st.running);

        db_maintenance_stop();
        db_maintenance_status_snapshot(&st);
        DBM_CHECK("dbm: status.running false after stop()", !st.running);

        db_maintenance_stop(); /* safe no-op */
        DBM_CHECK("dbm: second stop() is a safe no-op", true);

        dbm_fixture_destroy(&f);
    }

    /* ── 6. Vacuum gate respected by scheduler (run_now bypass) ── */
    {
        dbm_install_observer();
        struct dbm_fixture f;
        dbm_fixture_init(&f, "gate");

        /* Gate says "no" — but run_now still succeeds because
         * the gate only applies to scheduler-driven vacuums.
         * The gate exists so that tests like this can prove the
         * scheduler won't vacuum while the node is busy, without
         * blocking operators who want to force a VACUUM. */
        db_maintenance_set_vacuum_gate(dbm_gate_always_false);
        bool vacuum_ok = db_maintenance_run_now(&f.ndb, "vacuum").ok;
        DBM_CHECK("dbm: run_now(vacuum) bypasses the gate (manual override)",
                  vacuum_ok);
        db_maintenance_set_vacuum_gate(NULL);

        dbm_fixture_destroy(&f);
    }

    /* ── 7. node_db_wal_checkpoint succeeds on open DB ── */
    {
        struct dbm_fixture f;
        dbm_fixture_init(&f, "walcp");
        bool ok = node_db_wal_checkpoint(&f.ndb);
        DBM_CHECK("dbm: node_db_wal_checkpoint succeeds on open db", ok);
        dbm_fixture_destroy(&f);
    }

    /* ── 8. node_db_wal_checkpoint handles NULL gracefully ── */
    {
        bool ok = !node_db_wal_checkpoint(NULL);
        DBM_CHECK("dbm: node_db_wal_checkpoint(NULL) returns false", ok);
    }

    /* ── 9. Boot schedule start reports started (typed status) ──
     * Boot starts this service by default (see "Boot policy" in
     * services/db_maintenance.h); the status snapshot is the typed
     * surface that proves it is alive. */
    {
        struct dbm_fixture f;
        dbm_fixture_init(&f, "bootstart");

        struct db_maintenance_schedule sched;
        db_maintenance_schedule_wal_cap_only(&sched);
        bool started = db_maintenance_start(&f.ndb, &sched).ok;
        DBM_CHECK("dbm: boot schedule start() succeeds", started);

        struct db_maintenance_status st;
        memset(&st, 0, sizeof(st));
        db_maintenance_status_snapshot(&st);
        DBM_CHECK("dbm: boot schedule reports started via typed status",
                  st.running);

        db_maintenance_stop();
        memset(&st, 0, sizeof(st));
        db_maintenance_status_snapshot(&st);
        DBM_CHECK("dbm: status.running false after stop()", !st.running);

        dbm_fixture_destroy(&f);
    }

    /* ── 10. Boot env gate: on by default, DISABLE only opts out ── */
    {
        const char *env = "ZCL_DISABLE_BOOT_DB_MAINT";
        unsetenv(env);
        DBM_CHECK("dbm: boot maintenance starts by default (env unset)",
                  !db_maintenance_boot_opted_out());
        setenv(env, "1", 1);
        DBM_CHECK("dbm: ZCL_DISABLE_BOOT_DB_MAINT=1 opts out",
                  db_maintenance_boot_opted_out());
        setenv(env, "0", 1);
        DBM_CHECK("dbm: =0 does not opt out (only exact \"1\" disables)",
                  !db_maintenance_boot_opted_out());
        setenv(env, "yes", 1);
        DBM_CHECK("dbm: non-\"1\" value does not opt out",
                  !db_maintenance_boot_opted_out());
        unsetenv(env);
    }

    event_clear_observers(EV_DB_MAINTENANCE_START);
    event_clear_observers(EV_DB_MAINTENANCE_DONE);
    event_clear_observers(EV_DB_MAINTENANCE_FAILED);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
