/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the db_txn scoped transaction wrapper.
 *
 * Each test opens an in-memory node_db, drives db_txn through a
 * specific state, and asserts both the behaviour and the events
 * emitted on the bus. A local sync observer counts each event type
 * so assertions can be made against the exact lifecycle ("one begin
 * and one commit" vs "one begin, one rollback, one leaked").
 */

#include "test/test_core.h"
#include "models/db_txn.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/ar_after_commit.h"
#include "event/event.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ── Event counters ─────────────────────────────────────────── */

static _Atomic int g_ev_begin;
static _Atomic int g_ev_commit;
static _Atomic int g_ev_rollback;
static _Atomic int g_ev_rejected;
static _Atomic int g_ev_leaked;

static void dt_observer(enum event_type type, uint32_t peer_id,
                        const void *payload, uint32_t payload_len, void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    switch (type) {
    case EV_DB_TXN_BEGIN:    atomic_fetch_add(&g_ev_begin,    1); break;
    case EV_DB_TXN_COMMIT:   atomic_fetch_add(&g_ev_commit,   1); break;
    case EV_DB_TXN_ROLLBACK: atomic_fetch_add(&g_ev_rollback, 1); break;
    case EV_DB_TXN_REJECTED: atomic_fetch_add(&g_ev_rejected, 1); break;
    case EV_DB_TXN_LEAKED:   atomic_fetch_add(&g_ev_leaked,   1); break;
    default: break;
    }
}

static void dt_install_observer(void)
{
    event_clear_observers(EV_DB_TXN_BEGIN);
    event_clear_observers(EV_DB_TXN_COMMIT);
    event_clear_observers(EV_DB_TXN_ROLLBACK);
    event_clear_observers(EV_DB_TXN_REJECTED);
    event_clear_observers(EV_DB_TXN_LEAKED);
    atomic_store(&g_ev_begin,    0);
    atomic_store(&g_ev_commit,   0);
    atomic_store(&g_ev_rollback, 0);
    atomic_store(&g_ev_rejected, 0);
    atomic_store(&g_ev_leaked,   0);
    event_observe(EV_DB_TXN_BEGIN,    dt_observer, NULL);
    event_observe(EV_DB_TXN_COMMIT,   dt_observer, NULL);
    event_observe(EV_DB_TXN_ROLLBACK, dt_observer, NULL);
    event_observe(EV_DB_TXN_REJECTED, dt_observer, NULL);
    event_observe(EV_DB_TXN_LEAKED,   dt_observer, NULL);
}

#define DT_RUN(name, expr) do { \
    printf("%s... ", (name));   \
    bool _ok = (expr);          \
    if (_ok) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── 1. Commit path: begin + commit emits exactly 1 of each ── */

static int t_commit_path(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, ":memory:");
    if (!opened) { printf("dt: open failed\n"); return 1; }

    struct db_txn *txn = db_txn_begin(&ndb, "test.commit");
    bool begin_ok = txn != NULL;
    bool commit_ok = db_txn_commit(txn);
    db_txn_auto_rollback(&txn);  /* releases handle */

    bool ok = begin_ok && commit_ok &&
              atomic_load(&g_ev_begin)    == 1 &&
              atomic_load(&g_ev_commit)   == 1 &&
              atomic_load(&g_ev_rollback) == 0 &&
              atomic_load(&g_ev_leaked)   == 0;
    DT_RUN("dt: commit path emits begin+commit only", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 2. Explicit rollback: begin + rollback, no leak ───────── */

static int t_explicit_rollback(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct db_txn *txn = db_txn_begin(&ndb, "test.rollback");
    db_txn_rollback(txn);
    db_txn_auto_rollback(&txn);

    bool ok = atomic_load(&g_ev_begin)    == 1 &&
              atomic_load(&g_ev_rollback) == 1 &&  /* explicit */
              atomic_load(&g_ev_leaked)   == 0 &&
              atomic_load(&g_ev_commit)   == 0;
    DT_RUN("dt: explicit rollback emits begin+rollback, no leak", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 3. Leak detection: scope exits without commit/rollback ─ */

static void leak_scope(struct node_db *ndb)
{
    DB_TXN_SCOPE(txn, ndb, "test.leak");
    (void)txn;
    /* Fall out of scope without committing — auto_rollback fires. */
}

static int t_leak_detection(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    leak_scope(&ndb);

    bool ok = atomic_load(&g_ev_begin)    == 1 &&
              atomic_load(&g_ev_leaked)   == 1 &&
              /* auto_rollback emits rollback(leaked) in addition to
               * the LEAKED marker so the db actually rolls back. */
              atomic_load(&g_ev_rollback) == 1 &&
              atomic_load(&g_ev_commit)   == 0;
    DT_RUN("dt: scope exit without commit fires LEAKED + rollback", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 4. Scope + explicit commit: no leak event ─────────────── */

static int t_scope_with_commit(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    bool commit_ok = false;
    {
        DB_TXN_SCOPE(txn, &ndb, "test.scope_commit");
        commit_ok = db_txn_commit(txn);
    }  /* auto_rollback fires here; sees committed, just frees */

    bool ok = commit_ok &&
              atomic_load(&g_ev_begin)    == 1 &&
              atomic_load(&g_ev_commit)   == 1 &&
              atomic_load(&g_ev_leaked)   == 0 &&
              atomic_load(&g_ev_rollback) == 0;
    DT_RUN("dt: scope + explicit commit emits no leak event", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 5. Nesting is rejected ─────────────────────────────────── */

static int t_nesting_rejected(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct db_txn *outer = db_txn_begin(&ndb, "test.nest_outer");
    bool outer_ok = (outer != NULL);

    struct db_txn *inner = db_txn_begin(&ndb, "test.nest_inner");
    bool inner_rejected = (inner == NULL);

    db_txn_rollback(outer);
    db_txn_auto_rollback(&outer);

    bool ok = outer_ok && inner_rejected &&
              atomic_load(&g_ev_begin)    == 1 &&  /* outer only */
              atomic_load(&g_ev_rejected) == 1 &&  /* inner */
              atomic_load(&g_ev_rollback) == 1 &&
              atomic_load(&g_ev_leaked)   == 0;
    DT_RUN("dt: nested db_txn_begin is REJECTED", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 6. NULL db is rejected ─────────────────────────────────── */

static int t_null_db_rejected(void)
{
    int failures = 0;
    dt_install_observer();
    struct db_txn *txn = db_txn_begin(NULL, "test.null_db");
    bool ok = txn == NULL && atomic_load(&g_ev_rejected) == 1;
    DT_RUN("dt: NULL db is REJECTED", ok);
    return failures;
}

/* ── 7. NULL/empty label is rejected ────────────────────────── */

static int t_null_label_rejected(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct db_txn *t1 = db_txn_begin(&ndb, NULL);
    struct db_txn *t2 = db_txn_begin(&ndb, "");
    bool ok = t1 == NULL && t2 == NULL &&
              atomic_load(&g_ev_rejected) == 2;
    DT_RUN("dt: NULL / empty label is REJECTED", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 8. Closed db is rejected ───────────────────────────────── */

static int t_closed_db_rejected(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    /* Never opened — open flag is false */

    struct db_txn *txn = db_txn_begin(&ndb, "test.closed");
    bool ok = txn == NULL && atomic_load(&g_ev_rejected) == 1;
    DT_RUN("dt: closed db is REJECTED", ok);
    return failures;
}

/* ── 9. Idempotent rollback (calling twice is fine) ─────────── */

static int t_idempotent_rollback(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct db_txn *txn = db_txn_begin(&ndb, "test.idem");
    db_txn_rollback(txn);
    db_txn_rollback(txn);  /* second call: no-op */
    db_txn_rollback(txn);  /* third call: no-op */
    db_txn_auto_rollback(&txn);

    bool ok = atomic_load(&g_ev_begin) == 1 &&
              atomic_load(&g_ev_rollback) == 1 &&  /* exactly one */
              atomic_load(&g_ev_leaked) == 0;
    DT_RUN("dt: multiple rollbacks emit exactly one rollback event", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 10. Rollback-after-commit is a harmless no-op ─────────── */

static int t_rollback_after_commit(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct db_txn *txn = db_txn_begin(&ndb, "test.rollback_after_commit");
    db_txn_commit(txn);
    db_txn_rollback(txn);  /* no-op */
    db_txn_auto_rollback(&txn);

    bool ok = atomic_load(&g_ev_begin)    == 1 &&
              atomic_load(&g_ev_commit)   == 1 &&
              atomic_load(&g_ev_rollback) == 0 &&
              atomic_load(&g_ev_leaked)   == 0;
    DT_RUN("dt: rollback after commit is a silent no-op", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 11. Double commit is a bug → LEAKED event ─────────────── */

static int t_double_commit(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct db_txn *txn = db_txn_begin(&ndb, "test.double_commit");
    bool c1 = db_txn_commit(txn);
    bool c2 = db_txn_commit(txn);  /* should fail + emit LEAKED */
    db_txn_auto_rollback(&txn);

    bool ok = c1 && !c2 &&
              atomic_load(&g_ev_commit) == 1 &&
              atomic_load(&g_ev_leaked) == 1;
    DT_RUN("dt: double commit returns false and emits LEAKED", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 12. Long label is truncated, not rejected ─────────────── */

static int t_label_truncation(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    /* Deliberately over DB_TXN_LABEL_MAX */
    char big[DB_TXN_LABEL_MAX + 40];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    struct db_txn *txn = db_txn_begin(&ndb, big);
    bool truncated = txn != NULL &&
                     strlen(txn->label) == (size_t)(DB_TXN_LABEL_MAX - 1);
    db_txn_commit(txn);
    db_txn_auto_rollback(&txn);

    bool ok = truncated &&
              atomic_load(&g_ev_begin) == 1 &&
              atomic_load(&g_ev_commit) == 1;
    DT_RUN("dt: long label is truncated, not rejected", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 13. Auto-rollback no-op on NULL pointer ──────────────── */

static int t_auto_rollback_null(void)
{
    int failures = 0;
    dt_install_observer();
    struct db_txn *txn = NULL;
    db_txn_auto_rollback(&txn);  /* must not crash */
    bool ok = atomic_load(&g_ev_begin)  == 0 &&
              atomic_load(&g_ev_leaked) == 0;
    DT_RUN("dt: auto_rollback on NULL is a safe no-op", ok);
    return failures;
}

/* ── 14. Concurrent txns on different databases ────────────── */

struct dt_thread_args {
    struct node_db *ndb;
    int iterations;
    _Atomic int ok_count;
};

static void *dt_thread_commit_loop(void *p)
{
    struct dt_thread_args *a = p;
    for (int i = 0; i < a->iterations; i++) {
        struct db_txn *txn = db_txn_begin(a->ndb, "test.concurrent");
        if (txn && db_txn_commit(txn)) atomic_fetch_add(&a->ok_count, 1);
        db_txn_auto_rollback(&txn);
    }
    return NULL;
}

static int t_concurrent_different_dbs(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb_a, ndb_b;
    memset(&ndb_a, 0, sizeof(ndb_a));
    memset(&ndb_b, 0, sizeof(ndb_b));
    node_db_open(&ndb_a, ":memory:");
    node_db_open(&ndb_b, ":memory:");

    const int iters = 50;
    struct dt_thread_args args_a = { .ndb = &ndb_a, .iterations = iters };
    struct dt_thread_args args_b = { .ndb = &ndb_b, .iterations = iters };
    atomic_store(&args_a.ok_count, 0);
    atomic_store(&args_b.ok_count, 0);

    pthread_t ta, tb;
    pthread_create(&ta, NULL, dt_thread_commit_loop, &args_a);
    pthread_create(&tb, NULL, dt_thread_commit_loop, &args_b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    bool ok = atomic_load(&args_a.ok_count) == iters &&
              atomic_load(&args_b.ok_count) == iters &&
              atomic_load(&g_ev_begin)  == 2 * iters &&
              atomic_load(&g_ev_commit) == 2 * iters &&
              atomic_load(&g_ev_leaked) == 0;
    DT_RUN("dt: concurrent txns on different dbs succeed", ok);

    node_db_close(&ndb_a);
    node_db_close(&ndb_b);
    return failures;
}

/* ── 15. Induced mid-sequence failure rolls rows back ──────── */

/* This is the test that backs the wave 3 wiring: we write several
 * rows inside a DB_TXN_SCOPE, "abort" by returning before the
 * explicit commit, and then assert that none of the writes are
 * visible to a subsequent read. It is the end-to-end check that the
 * scope actually rolls back real data, not just the event ledger.
 *
 * The helper writes three keys, commits zero of them, and falls out
 * of scope so auto_rollback fires. The caller then verifies every
 * key is absent. */
static void induced_failure_scope(struct node_db *ndb)
{
    DB_TXN_SCOPE(txn, ndb, "test.induced_failure");
    if (!txn) return;

    /* Write three rows. All should disappear on scope exit. */
    (void)node_db_state_set(ndb, "induced.k1", "v1", 2);
    (void)node_db_state_set(ndb, "induced.k2", "v2-longer", 9);
    (void)node_db_state_set(ndb, "induced.k3", "v3", 2);

    /* Simulate a mid-sequence failure: early return WITHOUT
     * committing. The cleanup attribute runs auto_rollback and the
     * three rows above should never reach the final table. */
    return;
}

static int t_rollback_on_induced_failure(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, ":memory:");
    if (!opened) {
        printf("dt: open failed for induced_failure test\n");
        return 1;
    }

    /* Sanity: none of the keys exist yet. */
    char buf[64];
    size_t got = 0;
    bool absent_before =
        !node_db_state_get(&ndb, "induced.k1", buf, sizeof(buf), &got) &&
        !node_db_state_get(&ndb, "induced.k2", buf, sizeof(buf), &got) &&
        !node_db_state_get(&ndb, "induced.k3", buf, sizeof(buf), &got);

    /* Run the aborted scope. */
    induced_failure_scope(&ndb);

    /* All three keys must still be absent — auto_rollback dropped
     * the partial writes. */
    bool absent_after =
        !node_db_state_get(&ndb, "induced.k1", buf, sizeof(buf), &got) &&
        !node_db_state_get(&ndb, "induced.k2", buf, sizeof(buf), &got) &&
        !node_db_state_get(&ndb, "induced.k3", buf, sizeof(buf), &got);

    /* And the event trail shows exactly the leak pattern: one begin,
     * one LEAKED, one rollback(leaked), zero commits. */
    bool events_ok = atomic_load(&g_ev_begin)    == 1 &&
                     atomic_load(&g_ev_leaked)   == 1 &&
                     atomic_load(&g_ev_rollback) == 1 &&
                     atomic_load(&g_ev_commit)   == 0;

    /* Cross-check: a follow-up committed write IS visible, proving
     * the db itself is still healthy after the rollback. */
    struct db_txn *good = db_txn_begin(&ndb, "test.induced_followup");
    bool follow_ok = good != NULL &&
                     node_db_state_set(&ndb, "induced.k4", "v4", 2) &&
                     db_txn_commit(good);
    db_txn_auto_rollback(&good);
    bool follow_visible =
        node_db_state_get(&ndb, "induced.k4", buf, sizeof(buf), &got) &&
        got == 2 && memcmp(buf, "v4", 2) == 0;

    bool ok = absent_before && absent_after && events_ok &&
              follow_ok && follow_visible;
    DT_RUN("dt: induced mid-sequence failure rolls written rows back", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 16. Scoped multi-row wipe rollback (recovery path shape) ── */

/* Mirrors the shape of snapsync_begin_receive after wave-3 wiring:
 * a scoped wipe of an existing set of rows, followed by a simulated
 * mid-sequence abort before commit. The expected behaviour is that
 * the pre-existing rows are still there after rollback — the DELETE
 * never landed. */
static int t_rollback_preserves_pre_existing_rows(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    /* Seed two rows that must survive the aborted wipe. */
    (void)node_db_state_set(&ndb, "preexisting.a", "alpha", 5);
    (void)node_db_state_set(&ndb, "preexisting.b", "bravo", 5);

    /* Scoped wipe that fails halfway — scope exits without
     * committing, auto_rollback restores the rows. */
    {
        DB_TXN_SCOPE(txn, &ndb, "test.wipe_abort");
        if (!txn) {
            node_db_close(&ndb);
            return 1;
        }
        (void)node_db_exec(&ndb, "DELETE FROM node_state");
        /* Fall out of scope without db_txn_commit. */
    }

    char buf[64];
    size_t got = 0;
    bool a_present =
        node_db_state_get(&ndb, "preexisting.a", buf, sizeof(buf), &got) &&
        got == 5 && memcmp(buf, "alpha", 5) == 0;
    bool b_present =
        node_db_state_get(&ndb, "preexisting.b", buf, sizeof(buf), &got) &&
        got == 5 && memcmp(buf, "bravo", 5) == 0;

    bool ok = a_present && b_present &&
              atomic_load(&g_ev_leaked) == 1;
    DT_RUN("dt: aborted scoped wipe preserves pre-existing rows", ok);

    node_db_close(&ndb);
    return failures;
}

/* ── 17. Failed COMMIT explicitly unwinds SQLite state ───────── */

static int t_failed_commit_rolls_back(void)
{
    int failures = 0;
    dt_install_observer();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, ":memory:");
    bool schema_ok = opened && node_db_exec(&ndb,
        "CREATE TABLE dt_parent(id INTEGER PRIMARY KEY);"
        "CREATE TABLE dt_child(parent_id INTEGER NOT NULL,"
        "FOREIGN KEY(parent_id) REFERENCES dt_parent(id) "
        "DEFERRABLE INITIALLY DEFERRED)");

    struct db_txn *txn = schema_ok
        ? db_txn_begin(&ndb, "test.failed_commit") : NULL;
    bool inserted = txn && node_db_exec(
        &ndb, "INSERT INTO dt_child(parent_id) VALUES(7)");
    bool commit_failed = inserted && !db_txn_commit(txn);
    db_txn_auto_rollback(&txn);

    struct node_db_status status = {0};
    node_db_get_status(&ndb, &status);
    sqlite3_stmt *st = NULL;
    bool count_ok = opened && sqlite3_prepare_v2(ndb.db,
        "SELECT COUNT(*) FROM dt_child", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 0;
    sqlite3_finalize(st);

    struct db_txn *followup = opened
        ? db_txn_begin(&ndb, "test.failed_followup") : NULL;
    bool followup_ok = followup && db_txn_commit(followup);
    db_txn_auto_rollback(&followup);
    bool ok = opened && schema_ok && inserted && commit_failed && count_ok &&
              followup_ok && !status.tx_open &&
              atomic_load(&g_ev_rollback) == 1 &&
              atomic_load(&g_ev_leaked) == 0;
    DT_RUN("dt: failed COMMIT rolls back before ownership is released", ok);
    if (opened)
        node_db_close(&ndb);
    return failures;
}

/* ── 18. BUSY_SNAPSHOT: deferred BEGIN + concurrent commit ──────── */

/* A deferred-BEGIN writer whose read snapshot is invalidated by a
 * concurrent commit fails its first write with the extended
 * SQLITE_BUSY_SNAPSHOT code — the class the busy handler can never cure
 * (the 2026-07-27 catchup-poison drumbeat). The only cure is ROLLBACK +
 * a fresh BEGIN IMMEDIATE. Drives two real connections on one file-backed
 * WAL db (the class cannot occur on a single connection). */
static int t_busy_snapshot_rollback_rebegin(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "db_txn", "busy_snapshot");
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);

    struct node_db a;
    memset(&a, 0, sizeof(a));
    bool opened = node_db_open(&a, path);
    /* Bound the (uncurable) busy wait so the assertion stays fast. */
    if (opened)
        sqlite3_busy_timeout(a.db, 1000);

    sqlite3 *b = NULL;
    bool b_open = opened &&
        sqlite3_open_v2(path, &b, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK;
    if (b_open)
        sqlite3_busy_timeout(b, 30000);

    /* A: deferred BEGIN + a SELECT to pin read snapshot S1. */
    bool begun = b_open && node_db_begin(&a);
    char buf[8];
    size_t got = 0;
    bool pinned = begun &&
        !node_db_state_get(&a, "snap.nokey", buf, sizeof(buf), &got);

    /* B: a concurrent writer commits, advancing the db past S1. */
    bool b_committed = pinned &&
        sqlite3_exec(b,
            "BEGIN IMMEDIATE;"
            "INSERT OR REPLACE INTO node_state(key,value) VALUES('snap.b', X'01');"
            "COMMIT;", NULL, NULL, NULL) == SQLITE_OK;

    /* A: its first write after B's commit fails as BUSY_SNAPSHOT. Driven
     * with a raw write stmt so the extended code is read straight off the
     * failing sqlite3_step, not through a wrapper's finalize. */
    sqlite3_stmt *w = NULL;
    bool prep = b_committed &&
        sqlite3_prepare_v2(a.db,
            "INSERT OR REPLACE INTO node_state(key,value) VALUES('snap.a', X'01')",
            -1, &w, NULL) == SQLITE_OK;
    int wrc = prep ? sqlite3_step(w) : SQLITE_OK;
    int xrc = sqlite3_extended_errcode(a.db);
    sqlite3_finalize(w);
    bool snapshot_class = prep && wrc == SQLITE_BUSY &&
                          xrc == SQLITE_BUSY_SNAPSHOT;
    DT_RUN("dt: deferred write after concurrent commit is BUSY_SNAPSHOT",
           snapshot_class);

    /* The cure: ROLLBACK + BEGIN IMMEDIATE + write + COMMIT lands. */
    bool cured = snapshot_class &&
        node_db_rollback(&a) &&
        node_db_begin_immediate(&a) &&
        node_db_state_set(&a, "snap.a", "v", 1) &&
        node_db_commit(&a);

    bool visible = false;
    if (cured) {
        sqlite3_stmt *q = NULL;
        visible = sqlite3_prepare_v2(b,
                      "SELECT value FROM node_state WHERE key='snap.a'",
                      -1, &q, NULL) == SQLITE_OK &&
                  sqlite3_step(q) == SQLITE_ROW;
        sqlite3_finalize(q);
    }
    DT_RUN("dt: ROLLBACK + BEGIN IMMEDIATE retry lands the write",
           cured && visible);

    if (b)
        sqlite3_close(b);
    if (opened)
        node_db_close(&a);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 19. Poisoned COMMIT: abandoned write VM recovery ───────────── */

/* The 2026-07-24→27 live incident: a write VM abandoned in RUN state on
 * the shared FULLMUTEX handle makes every COMMIT fail with "cannot commit
 * transaction - SQL statements in progress" until process restart.
 * node_db_commit's always-on seatbelt must walk the handle's statement
 * list, log + reset the abandoned VM, and leave the handle usable after
 * the caller's ROLLBACK — no restart required. */
static int t_poisoned_commit_recovery(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, ":memory:");
    uint64_t walks_before = node_db_test_commit_recovery_walks();

    bool begun = opened && node_db_begin(&ndb);

    /* Poison the handle: a write VM stepped into RUN state (the RETURNING
     * row) and never reset — exactly the abandoned-mid-step shape. */
    sqlite3_stmt *vm = NULL;
    bool poisoned = begun &&
        sqlite3_prepare_v2(ndb.db,
            "INSERT INTO node_state(key,value) VALUES('poison.k', X'00')"
            " RETURNING key",
            -1, &vm, NULL) == SQLITE_OK &&
        sqlite3_step(vm) == SQLITE_ROW;

    bool commit_failed = poisoned && !node_db_commit(&ndb);
    uint64_t walks_after = node_db_test_commit_recovery_walks();
    sqlite3_finalize(vm);

    DT_RUN("dt: poisoned COMMIT fails and the recovery walk fires",
           commit_failed && walks_after == walks_before + 1);

    /* After the caller's ROLLBACK the handle is healthy: a full
     * BEGIN IMMEDIATE → write → COMMIT cycle lands. */
    bool healthy = commit_failed &&
        node_db_rollback(&ndb) &&
        node_db_begin_immediate(&ndb) &&
        node_db_state_set(&ndb, "poison.ok", "v", 1) &&
        node_db_commit(&ndb);
    char buf[8];
    size_t got = 0;
    bool visible = healthy &&
        node_db_state_get(&ndb, "poison.ok", buf, sizeof(buf), &got) &&
        got == 1 && memcmp(buf, "v", 1) == 0;
    DT_RUN("dt: next COMMIT succeeds after recovery + rollback",
           healthy && visible);

    if (opened)
        node_db_close(&ndb);
    return failures;
}


/* ── after_commit: a hook that must not outrun durability ────────
 *
 * after_save fires when the STATEMENT steps. Inside a transaction that is
 * too early for anything an external observer can see, because a later
 * ROLLBACK erases the row the observer was already told about. These tests
 * drive a small fixture model through the real AR_ADHOC_SAVE lifecycle
 * against a real in-memory node_db, so the queue, the transaction boundary
 * hooks in node_db_begin/commit/rollback and AR_FINISH_SAVE are all under
 * test together rather than mocked.
 *
 * The rollback case is the whole point of the feature and is asserted first
 * among them: hooks queued and then rolled back must NOT fire. */

struct ac_row {
    int64_t id;
    int64_t value;
};

DEFINE_MODEL_CALLBACKS(ac_fixture)

static int      g_ac_commit_fired;
static int      g_ac_save_fired;
static int64_t  g_ac_commit_values[8];

static void ac_after_commit_hook(void *record, void *ctx)
{
    (void)ctx;
    const struct ac_row *r = record;
    if (g_ac_commit_fired < (int)(sizeof(g_ac_commit_values) /
                                  sizeof(g_ac_commit_values[0])))
        g_ac_commit_values[g_ac_commit_fired] = r->value;
    g_ac_commit_fired++;
}

static void ac_after_save_hook(void *record, void *ctx)
{
    (void)record; (void)ctx;
    g_ac_save_fired++;
}

static bool ac_fixture_validate(const struct ac_row *r, struct ar_errors *e)
{
    ar_errors_clear(e);
    validates_custom(e, r != NULL, "row", "is null");
    return !ar_errors_any(e);
}

static bool ac_fixture_save(struct node_db *ndb, const struct ac_row *r)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs = db_ac_fixture_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO ac_fixture(id,value) VALUES(?,?)",
        cbs, "ac_fixture", r, ac_fixture_validate,
        AR_BIND_INT(s, 1, r->id);
        AR_BIND_INT(s, 2, r->value));
}

/* Register once — ar_callbacks accumulates, and these tests run in one
 * process. Counters, not registrations, are what each test resets. */
static void ac_register_hooks_once(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_ac_fixture_callbacks();
    ar_register_after_save(cbs, ac_after_save_hook);
    ar_register_after_commit(cbs, ac_after_commit_hook,
                             sizeof(struct ac_row));
    done = true;
}

static void ac_reset_counters(void)
{
    g_ac_commit_fired = 0;
    g_ac_save_fired = 0;
    memset(g_ac_commit_values, 0, sizeof(g_ac_commit_values));
    ar_after_commit_reset();
}

/* Open an in-memory node_db with the fixture table present. */
static bool ac_open(struct node_db *ndb)
{
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open(ndb, ":memory:")) return false;
    if (!node_db_exec(ndb, "CREATE TABLE IF NOT EXISTS ac_fixture("
                           "id INTEGER PRIMARY KEY, value INTEGER)")) {
        node_db_close(ndb);
        return false;
    }
    ac_register_hooks_once();
    ac_reset_counters();
    return true;
}

static int ac_row_count(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT COUNT(*) FROM ac_fixture", -1, &s,
                           NULL) != SQLITE_OK)
        return -1;
    int n = sqlite3_step(s) == SQLITE_ROW ? (int)sqlite3_column_int64(s, 0) : -1;
    sqlite3_finalize(s);
    return n;
}

/* ── THE test: queued and rolled back must NOT fire ──────────── */

static int t_after_commit_not_fired_on_rollback(void)
{
    int failures = 0;
    struct node_db ndb;
    if (!ac_open(&ndb)) { printf("ac: open failed\n"); return 1; }

    struct db_txn *txn = db_txn_begin(&ndb, "test.after_commit.rollback");
    struct ac_row a = { .id = 1, .value = 111 };
    struct ac_row b = { .id = 2, .value = 222 };
    bool saved = txn && ac_fixture_save(&ndb, &a) && ac_fixture_save(&ndb, &b);

    DT_RUN("ac: after_save fired at statement time, after_commit did not",
           saved && g_ac_save_fired == 2 && g_ac_commit_fired == 0 &&
           ar_after_commit_pending() == 2);

    db_txn_rollback(txn);
    db_txn_auto_rollback(&txn);

    DT_RUN("ac: ROLLBACK discards the queue — no hook fires",
           g_ac_commit_fired == 0 && ar_after_commit_pending() == 0);
    DT_RUN("ac: and the rows the hooks would have announced are gone",
           ac_row_count(&ndb) == 0);

    /* A rolled-back queue must not resurface on the NEXT commit. */
    struct db_txn *txn2 = db_txn_begin(&ndb, "test.after_commit.rollback.next");
    struct ac_row c = { .id = 3, .value = 333 };
    bool saved2 = txn2 && ac_fixture_save(&ndb, &c) && db_txn_commit(txn2);
    db_txn_auto_rollback(&txn2);
    DT_RUN("ac: the next commit fires only its own hook, not the discarded one",
           saved2 && g_ac_commit_fired == 1 && g_ac_commit_values[0] == 333);

    node_db_close(&ndb);
    return failures;
}

/* ── Commit path: fires once each, in registration order ─────── */

static int t_after_commit_fires_on_commit(void)
{
    int failures = 0;
    struct node_db ndb;
    if (!ac_open(&ndb)) { printf("ac: open failed\n"); return 1; }

    struct db_txn *txn = db_txn_begin(&ndb, "test.after_commit.commit");
    struct ac_row a = { .id = 1, .value = 10 };
    struct ac_row b = { .id = 2, .value = 20 };
    struct ac_row c = { .id = 3, .value = 30 };
    bool saved = txn && ac_fixture_save(&ndb, &a) &&
                 ac_fixture_save(&ndb, &b) && ac_fixture_save(&ndb, &c);

    DT_RUN("ac: nothing fires while the transaction is open",
           saved && g_ac_commit_fired == 0 && ar_after_commit_pending() == 3);

    bool committed = saved && db_txn_commit(txn);
    db_txn_auto_rollback(&txn);

    DT_RUN("ac: the outermost commit fires each hook exactly once, in order",
           committed && g_ac_commit_fired == 3 &&
           g_ac_commit_values[0] == 10 &&
           g_ac_commit_values[1] == 20 &&
           g_ac_commit_values[2] == 30 &&
           ar_after_commit_pending() == 0);

    node_db_close(&ndb);
    return failures;
}

/* ── A queued hook sees the record as it was saved ───────────── */

static int t_after_commit_sees_a_copy(void)
{
    int failures = 0;
    struct node_db ndb;
    if (!ac_open(&ndb)) { printf("ac: open failed\n"); return 1; }

    struct db_txn *txn = db_txn_begin(&ndb, "test.after_commit.copy");
    struct ac_row a = { .id = 1, .value = 4242 };
    bool saved = txn && ac_fixture_save(&ndb, &a);
    /* The caller's record is routinely a stack local that is gone, or reused,
     * by commit time. Mutating it here stands in for that. */
    a.value = -1;
    bool committed = saved && db_txn_commit(txn);
    db_txn_auto_rollback(&txn);

    DT_RUN("ac: the hook receives the record as saved, not as later mutated",
           committed && g_ac_commit_fired == 1 &&
           g_ac_commit_values[0] == 4242);

    node_db_close(&ndb);
    return failures;
}

/* ── Outside a transaction the hook fires immediately ────────── */

static int t_after_commit_immediate_without_transaction(void)
{
    int failures = 0;
    struct node_db ndb;
    if (!ac_open(&ndb)) { printf("ac: open failed\n"); return 1; }

    struct ac_row a = { .id = 1, .value = 77 };
    bool saved = ac_fixture_save(&ndb, &a);

    DT_RUN("ac: with no transaction open the hook fires immediately",
           saved && g_ac_commit_fired == 1 && g_ac_commit_values[0] == 77 &&
           ar_after_commit_pending() == 0 && ar_after_commit_depth() == 0);

    node_db_close(&ndb);
    return failures;
}

/* ── Only the OUTERMOST commit drains ────────────────────────── */

static int t_after_commit_only_outermost_drains(void)
{
    int failures = 0;
    ac_reset_counters();

    /* Drive the boundary API directly: db_txn_begin refuses to nest and
     * SQLite refuses a nested BEGIN, so this is the only way to assert the
     * nesting rule itself rather than the wrapper that currently prevents
     * nesting. */
    struct ac_row a = { .id = 1, .value = 9 };
    ar_after_commit_note_begin();
    ar_after_commit_note_begin();
    bool queued = ar_after_commit_enqueue(ac_after_commit_hook, NULL, &a,
                                          sizeof(a));

    ar_after_commit_note_commit(true);
    DT_RUN("ac: an inner commit does not fire early",
           queued && ar_after_commit_depth() == 1 &&
           g_ac_commit_fired == 0 && ar_after_commit_pending() == 1);

    ar_after_commit_note_commit(true);
    DT_RUN("ac: the outermost commit drains",
           ar_after_commit_depth() == 0 && g_ac_commit_fired == 1 &&
           ar_after_commit_pending() == 0);

    /* A failed COMMIT leaves the transaction open, so the queue must survive
     * for the ROLLBACK that has to follow. */
    ac_reset_counters();
    ar_after_commit_note_begin();
    (void)ar_after_commit_enqueue(ac_after_commit_hook, NULL, &a, sizeof(a));
    ar_after_commit_note_commit(false);
    DT_RUN("ac: a FAILED commit neither fires nor discards",
           g_ac_commit_fired == 0 && ar_after_commit_pending() == 1 &&
           ar_after_commit_depth() == 1);
    ar_after_commit_note_rollback();
    DT_RUN("ac: the rollback that follows discards it",
           g_ac_commit_fired == 0 && ar_after_commit_pending() == 0 &&
           ar_after_commit_depth() == 0);

    ac_reset_counters();
    return failures;
}

/* ── Fail closed rather than skip an observer ────────────────── */

static int t_after_commit_refuses_without_a_record_size(void)
{
    int failures = 0;
    ac_reset_counters();
    struct ac_row a = { .id = 1, .value = 5 };

    ar_after_commit_note_begin();
    bool refused = !ar_after_commit_enqueue(ac_after_commit_hook, NULL, &a, 0);
    DT_RUN("ac: a hook with no record size is REFUSED, never silently skipped",
           refused && ar_after_commit_pending() == 0 &&
           g_ac_commit_fired == 0);
    ar_after_commit_note_rollback();

    /* Registration itself refuses a zero size, so the refusal above is a
     * belt-and-braces backstop rather than the only guard. */
    struct ar_callbacks probe;
    ar_callbacks_init(&probe);
    DT_RUN("ac: registering an after_commit hook without a size is refused",
           !ar_register_after_commit(&probe, ac_after_commit_hook, 0) &&
           !ar_register_after_commit(&probe, NULL, sizeof(struct ac_row)) &&
           probe.n_after_commit == 0);

    ac_reset_counters();
    return failures;
}
/* ── Aggregator ─────────────────────────────────────────────── */

int test_db_txn(void)
{
    printf("\n=== db_txn tests ===\n");
    int failures = 0;
    failures += t_commit_path();
    failures += t_explicit_rollback();
    failures += t_leak_detection();
    failures += t_scope_with_commit();
    failures += t_nesting_rejected();
    failures += t_null_db_rejected();
    failures += t_null_label_rejected();
    failures += t_closed_db_rejected();
    failures += t_idempotent_rollback();
    failures += t_rollback_after_commit();
    failures += t_double_commit();
    failures += t_label_truncation();
    failures += t_auto_rollback_null();
    failures += t_concurrent_different_dbs();
    failures += t_rollback_on_induced_failure();
    failures += t_rollback_preserves_pre_existing_rows();
    failures += t_failed_commit_rolls_back();
    failures += t_busy_snapshot_rollback_rebegin();
    failures += t_poisoned_commit_recovery();
    failures += t_after_commit_not_fired_on_rollback();
    failures += t_after_commit_fires_on_commit();
    failures += t_after_commit_sees_a_copy();
    failures += t_after_commit_immediate_without_transaction();
    failures += t_after_commit_only_outermost_drains();
    failures += t_after_commit_refuses_without_a_record_size();

    event_clear_observers(EV_DB_TXN_BEGIN);
    event_clear_observers(EV_DB_TXN_COMMIT);
    event_clear_observers(EV_DB_TXN_ROLLBACK);
    event_clear_observers(EV_DB_TXN_REJECTED);
    event_clear_observers(EV_DB_TXN_LEAKED);
    return failures;
}
