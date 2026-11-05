/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for wallet_canary and wallet_persistence_get_health.
 *
 * The canary is the boot-time self-test that decides whether the
 * daemon may proceed into RPC service or must abort. These tests
 * exercise it directly against a real node.db opened in a temp
 * datadir, so we're checking the actual sqlite3 path the running
 * node takes — not a mock. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "models/database.h"

#include "wallet/wallet_canary.h"
#include "wallet/wallet_lock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WC_RUN(name, expr) do { \
    printf("%s... ", (name));   \
    bool _ok = (expr);          \
    if (_ok) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct wc_fixture {
    char datadir[256];
    char dbpath[320];
    struct node_db ndb;
};

static bool wc_fixture_init(struct wc_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->datadir, sizeof(f->datadir),
             "/tmp/zcl_wc_test_%d_%s", (int)getpid(), tag);
    mkdir(f->datadir, 0755);
    snprintf(f->dbpath, sizeof(f->dbpath), "%s/node.db", f->datadir);
    return node_db_open(&f->ndb, f->dbpath);
}

static void wc_fixture_tear_down(struct wc_fixture *f)
{
    node_db_close(&f->ndb);
    test_cleanup_tmpdir(f->datadir);
}

/* 1. Canary against a freshly-created node.db succeeds and updates
 *    status. This is the signal boot uses to transition out of
 *    STATE A/B into operation. */
static int t_happy(void)
{
    int failures = 0;
    struct wc_fixture f;
    if (!wc_fixture_init(&f, "canary_happy")) {
        printf("wc: fixture init failed\n"); return 1;
    }

    struct wallet_canary_status st = {0};
    int rc = wallet_canary_run(f.ndb.db, &st);
    WC_RUN("canary: fresh DB → WALLET_CANARY_OK",
           rc == WALLET_CANARY_OK);
    WC_RUN("canary: status.ok reflects success",
           st.ok && st.code == WALLET_CANARY_OK);
    WC_RUN("canary: status.last_ok_ts is recent",
           st.last_ok_ts >= (int64_t)platform_time_wall_time_t() - 5);
    WC_RUN("canary: status.error is empty on success",
           st.error[0] == '\0');

    /* Running again must also succeed — fresh probe each time. */
    int64_t prev_ts = st.last_ok_ts;
    sleep(1);
    rc = wallet_canary_run(f.ndb.db, &st);
    WC_RUN("canary: second run also OK",
           rc == WALLET_CANARY_OK);
    WC_RUN("canary: last_ok_ts advanced on second run",
           st.last_ok_ts > prev_ts);

    /* get_status returns a consistent snapshot. */
    struct wallet_canary_status snap = wallet_canary_get_status();
    WC_RUN("canary: get_status reflects most recent run",
           snap.ok && snap.last_ok_ts == st.last_ok_ts);

    wc_fixture_tear_down(&f);
    return failures;
}

/* 2. NULL db → error path, no crash. */
static int t_null_db(void)
{
    int failures = 0;
    struct wallet_canary_status st = {0};
    int rc = wallet_canary_run(NULL, &st);
    WC_RUN("canary: NULL db → ERR_NULL_DB",
           rc == WALLET_CANARY_ERR_NULL_DB);
    WC_RUN("canary: NULL db status.ok is false",
           !st.ok && st.code == WALLET_CANARY_ERR_NULL_DB);
    WC_RUN("canary: NULL db error buffer populated",
           st.error[0] != '\0');
    return failures;
}

/* 3. wallet_canary table missing → ERR_SCHEMA or ERR_PREPARE.
 *    Simulates a pre-migration node.db that predates this commit.
 *
 *    We open a bare sqlite3 handle (not node_db_open) so we control
 *    the schema exactly: no prepared statements, no WAL-mode table
 *    locks. node_db holds prepared statements that keep DROP TABLE
 *    locked out, which is fine for production but hostile to this
 *    fault-injection test. */
static int t_schema_missing(void)
{
    int failures = 0;
    char dbpath[256];
    snprintf(dbpath, sizeof(dbpath),
             "/tmp/zcl_wc_noschema_%d.db", (int)getpid());
    unlink(dbpath);

    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
        printf("wc: sqlite3_open failed\n");
        if (db) sqlite3_close(db);
        return 1;
    }
    /* Deliberately do NOT create wallet_canary. This simulates a
     * datadir opened by a binary predating the D2 schema migration. */

    struct wallet_canary_status st = {0};
    int rc = wallet_canary_run(db, &st);
    WC_RUN("canary: schema missing → ERR_SCHEMA or ERR_PREPARE",
           rc == WALLET_CANARY_ERR_SCHEMA ||
           rc == WALLET_CANARY_ERR_PREPARE);
    WC_RUN("canary: schema-missing status.ok is false",
           !st.ok);
    WC_RUN("canary: schema-missing error populated",
           st.error[0] != '\0');

    sqlite3_close(db);
    unlink(dbpath);
    return failures;
}

/* 4. wallet_persistence_get_health aggregates canary + row count. */
static int t_health_snapshot(void)
{
    int failures = 0;
    struct wc_fixture f;
    if (!wc_fixture_init(&f, "health_snap")) {
        printf("wc: fixture init failed\n"); return 1;
    }

    /* Seed 3 wallet_keys rows directly (same technique as
     * test_wallet_backup). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(f.ndb.db,
        "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed) "
        "VALUES(?,?,?,1)", -1, &st, NULL) == SQLITE_OK) {
        for (int i = 0; i < 3; i++) {
            uint8_t h[20] = {0}, pub[33] = {0}, priv[32] = {0};
            h[0] = (uint8_t)(i + 10);
            pub[0] = 0x02; pub[1] = h[0];
            priv[0] = (uint8_t)(0x80 + i);
            sqlite3_reset(st);
            sqlite3_bind_blob(st, 1, h, sizeof(h), SQLITE_STATIC);
            sqlite3_bind_blob(st, 2, pub, sizeof(pub), SQLITE_STATIC);
            sqlite3_bind_blob(st, 3, priv, sizeof(priv), SQLITE_STATIC);
            sqlite3_step(st);
        }
        sqlite3_finalize(st);
    }

    /* Run canary so health.canary_ok is set. */
    (void)wallet_canary_run(f.ndb.db, NULL);

    struct wallet_persistence_health h =
        wallet_persistence_get_health(f.ndb.db, 3);
    WC_RUN("health: open true for valid handle",
           h.open);
    WC_RUN("health: canary_ok true after canary_run",
           h.canary_ok);
    WC_RUN("health: row_count matches seeded rows",
           h.row_count == 3);
    WC_RUN("health: keystore_count reflects caller",
           h.keystore_count == 3);
    WC_RUN("health: no mismatch when counts agree",
           !h.mismatch);

    /* Caller supplies a different count → mismatch flag. */
    h = wallet_persistence_get_health(f.ndb.db, 5);
    WC_RUN("health: mismatch true when keystore_count diverges",
           h.mismatch);
    WC_RUN("health: mismatch populates last_error",
           h.last_error[0] != '\0');

    /* A locked encrypted wallet has no resident keys (keystore_count 0) while
     * its rows are intact: that is "locked, not compared", never a mismatch.
     * Once unlocked the same disagreement must fail again. */
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    h = wallet_persistence_get_health(f.ndb.db, 0);
    WC_RUN("health: locked encrypted wallet reports locked",
           h.locked && h.row_count == 3);
    WC_RUN("health: locked encrypted wallet is not a mismatch",
           !h.mismatch && h.last_error[0] == '\0');
    WC_RUN("health: unlock of register-only passphrase succeeds",
           wallet_lock_unlock(NULL, NULL, "wallet-canary-test").ok);
    h = wallet_persistence_get_health(f.ndb.db, 0);
    WC_RUN("health: unlocked encrypted wallet still fails a real mismatch",
           !h.locked && h.mismatch && h.last_error[0] != '\0');
    wallet_lock_reset_for_test();

    /* An unreadable row count is UNKNOWN, never an apparent match. This is
     * the production spend gate's fail-closed persistence authority. */
    WC_RUN("health: fixture wallet_keys table drops cleanly",
           sqlite3_exec(f.ndb.db, "DROP TABLE wallet_keys", NULL, NULL,
                        NULL) == SQLITE_OK);
    h = wallet_persistence_get_health(f.ndb.db, 3);
    WC_RUN("health: unreadable row count is fail-closed mismatch",
           h.row_count == -1 && h.mismatch);
    WC_RUN("health: unreadable row count names the query failure",
           h.last_error[0] != '\0');

    /* NULL db → open=false, row_count=-1. */
    h = wallet_persistence_get_health(NULL, 3);
    WC_RUN("health: open false for NULL handle",
           !h.open);
    WC_RUN("health: row_count -1 for NULL handle",
           h.row_count == -1);

    wc_fixture_tear_down(&f);
    return failures;
}

/* ---- Fault injection on a bare in-memory handle -------------------
 * Each fault is a trigger or authorizer on a throwaway table, so each
 * canary failure code is reached for real and pinned exactly. After
 * every run the handle must close cleanly: sqlite3_close returns BUSY
 * if the canary leaked a prepared statement. */

static const char WC_DDL[] =
    "CREATE TABLE wallet_canary(id INTEGER PRIMARY KEY, probe BLOB, "
    "ts INTEGER);";

static sqlite3 *wc_mem_db(const char *extra_sql)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return NULL;
    if (sqlite3_exec(db, WC_DDL, NULL, NULL, NULL) != SQLITE_OK ||
        (extra_sql && sqlite3_exec(db, extra_sql, NULL, NULL, NULL)
                          != SQLITE_OK)) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static int wc_deny_action;

static int wc_authorizer(void *ud, int action, const char *a, const char *b,
                         const char *c, const char *d)
{
    (void)ud; (void)a; (void)b; (void)c; (void)d;
    return action == wc_deny_action ? SQLITE_DENY : SQLITE_OK;
}

/* Run the canary against a handle built with `extra_sql`; check the exact
 * code, the status code, a non-empty error, and a clean close. */
static bool wc_expect_code(const char *extra_sql, int deny_action, int want)
{
    sqlite3 *db = wc_mem_db(extra_sql);
    if (!db) return false;
    wc_deny_action = deny_action;
    if (deny_action)
        sqlite3_set_authorizer(db, wc_authorizer, NULL);
    struct wallet_canary_status st = {0};
    int rc = wallet_canary_run(db, &st);
    bool ok = rc == want && !st.ok && st.code == want &&
              st.error[0] != '\0' && st.last_attempt_ts > 0;
    sqlite3_set_authorizer(db, NULL, NULL);
    return (sqlite3_close(db) == SQLITE_OK) && ok;
}

static bool wc_schema_missing_exact(void)
{
    sqlite3 *db = NULL;
    bool ok = false;
    if (sqlite3_open(":memory:", &db) == SQLITE_OK)
        ok = wallet_canary_run(db, NULL) == WALLET_CANARY_ERR_SCHEMA;
    sqlite3_close(db);
    return ok;
}

static int t_fault_codes(void)
{
    int failures = 0;
    WC_RUN("canary: missing table is exactly ERR_SCHEMA",
           wc_schema_missing_exact());
    WC_RUN("canary: non-schema prepare refusal is ERR_PREPARE",
           wc_expect_code(NULL, SQLITE_INSERT, WALLET_CANARY_ERR_PREPARE));
    WC_RUN("canary: SELECT prepare refusal is ERR_PREPARE",
           wc_expect_code(NULL, SQLITE_SELECT, WALLET_CANARY_ERR_PREPARE));
    WC_RUN("canary: refused INSERT step is ERR_WRITE, statement finalized",
           wc_expect_code("CREATE TRIGGER t BEFORE INSERT ON wallet_canary "
                          "BEGIN SELECT RAISE(ABORT,'no'); END;", 0,
                          WALLET_CANARY_ERR_WRITE));
    WC_RUN("canary: swallowed INSERT leaves no row: ERR_READ, finalized",
           wc_expect_code("CREATE TRIGGER t BEFORE INSERT ON wallet_canary "
                          "BEGIN SELECT RAISE(IGNORE); END;", 0,
                          WALLET_CANARY_ERR_READ));
    WC_RUN("canary: short blob read back is ERR_READ, finalized",
           wc_expect_code("CREATE TRIGGER t AFTER INSERT ON wallet_canary "
                          "BEGIN UPDATE wallet_canary SET probe=x'00' "
                          "WHERE id=new.id; END;", 0,
                          WALLET_CANARY_ERR_READ));
    WC_RUN("canary: different 32-byte blob read back is ERR_MISMATCH",
           wc_expect_code("CREATE TRIGGER t AFTER INSERT ON wallet_canary "
                          "BEGIN UPDATE wallet_canary SET "
                          "probe=zeroblob(32) WHERE id=new.id; END;", 0,
                          WALLET_CANARY_ERR_MISMATCH));
    return failures;
}

/* The stored probe is exactly 32 bytes, success clears a previous error,
 * and a success leaves no statement open. */
static int t_probe_shape(void)
{
    int failures = 0;
    sqlite3 *db = wc_mem_db(NULL);
    if (!db) { printf("wc: memory db failed\n"); return 1; }

    struct wallet_canary_status st = {0};
    (void)wallet_canary_run(NULL, &st);
    WC_RUN("canary: failure leaves an error message",
           !st.ok && st.error[0] != '\0');
    int rc = wallet_canary_run(db, &st);
    WC_RUN("canary: success after failure is OK with empty error",
           rc == WALLET_CANARY_OK && st.ok && st.error[0] == '\0');
    WC_RUN("canary: success after failure clears the stored error too",
           wallet_canary_get_status().error[0] == '\0');

    sqlite3_stmt *q = NULL;
    int len = -1;
    if (sqlite3_prepare_v2(db, "SELECT length(probe) FROM wallet_canary "
                               "WHERE id=1", -1, &q, NULL) == SQLITE_OK) {
        if (sqlite3_step(q) == SQLITE_ROW)
            len = sqlite3_column_int(q, 0);
        sqlite3_finalize(q);
    }
    WC_RUN("canary: stored probe is exactly 32 bytes", len == 32);
    WC_RUN("canary: successful run leaves no open statement",
           sqlite3_close(db) == SQLITE_OK);
    return failures;
}

static int wc_stop_cb(void *ud) { (void)ud; return 1; }

/* last_error provenance in the health snapshot. */
static int t_health_errors(void)
{
    int failures = 0;
    sqlite3 *db = wc_mem_db("CREATE TABLE wallet_keys(x);");
    if (!db) { printf("wc: memory db failed\n"); return 1; }
    wallet_lock_reset_for_test();

    struct wallet_canary_status st = {0};
    (void)wallet_canary_run(NULL, &st);
    struct wallet_persistence_health h = wallet_persistence_get_health(db, 0);
    WC_RUN("health: failed canary is reported with its own message",
           !h.canary_ok && h.last_error[0] != '\0' &&
           strcmp(h.last_error, st.error) == 0 && !h.mismatch &&
           h.row_count == 0);
    h = wallet_persistence_get_health(NULL, 0);
    WC_RUN("health: closed handle keeps the canary message",
           !h.open && strcmp(h.last_error, st.error) == 0);

    (void)wallet_canary_run(db, &st);
    h = wallet_persistence_get_health(db, 0);
    WC_RUN("health: passing canary leaves last_error empty",
           h.canary_ok && h.last_error[0] == '\0' &&
           h.canary_last_ok_ts == st.last_ok_ts && h.canary_last_ok_ts > 0);
    h = wallet_persistence_get_health(NULL, 0);
    WC_RUN("health: closed handle names itself when canary was fine",
           strcmp(h.last_error, "sqlite handle closed") == 0 &&
           h.row_count == -1);

    sqlite3_progress_handler(db, 1, wc_stop_cb, NULL);
    h = wallet_persistence_get_health(db, 0);
    sqlite3_progress_handler(db, 0, NULL, NULL);
    WC_RUN("health: failed count step is a mismatch with a step error",
           h.mismatch && h.row_count == -1 &&
           strncmp(h.last_error, "step count: rc=", 15) == 0);
    WC_RUN("health: handle closes cleanly after the count",
           sqlite3_close(db) == SQLITE_OK);
    return failures;
}

int test_wallet_canary(void)
{
    printf("\n=== wallet_canary tests ===\n");
    int failures = 0;
    failures += t_happy();
    failures += t_null_db();
    failures += t_schema_missing();
    failures += t_health_snapshot();
    failures += t_fault_codes();
    failures += t_probe_shape();
    failures += t_health_errors();
    return failures;
}
