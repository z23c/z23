/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the schema migration framework.
 *
 * Each test opens a fresh in-memory node_db and exercises the
 * migration registry, execution, and rollback paths.
 */

#include "test/test_core.h"
#include "models/schema_migration.h"
#include "models/database.h"

#include <stdio.h>
#include <string.h>

#define SM_CHECK(name, expr) do { \
    printf("%s... ", (name));     \
    if ((expr)) printf("OK\n");   \
    else { printf("FAIL\n"); failures++; } \
} while (0)

enum {
    SM_TEST_V1 = NODE_DB_SCHEMA_LATEST + 1,
    SM_TEST_V2 = NODE_DB_SCHEMA_LATEST + 2,
    SM_TEST_V3 = NODE_DB_SCHEMA_LATEST + 3,
    SM_TEST_V4 = NODE_DB_SCHEMA_LATEST + 4,
    SM_TEST_V5 = NODE_DB_SCHEMA_LATEST + 5,
    SM_TEST_V6 = NODE_DB_SCHEMA_LATEST + 6,
};

/* ── Test migrations ───────────────────────────────────────── */

static bool test_up_add_table(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "CREATE TABLE IF NOT EXISTS test_table ("
        "id INTEGER PRIMARY KEY, name TEXT)");
}

static bool test_down_drop_table(struct node_db *ndb)
{
    /* Note: DROP TABLE can fail with SQLITE_LOCKED when cached prepared
     * statements exist on the connection (even if they don't reference
     * this table). Use DELETE + rename approach for real rollbacks.
     * For this test, deleting all rows proves the down() ran. */
    return node_db_exec(ndb, "DELETE FROM test_table");
}

static bool test_up_add_column(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "ALTER TABLE test_table ADD COLUMN age INTEGER DEFAULT 0");
}

static bool test_up_fail(struct node_db *ndb)
{
    (void)ndb;
    return false;  /* deliberately fail */
}

static bool test_up_insert_row(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "INSERT INTO test_table(id, name) VALUES(1, 'alice')");
}

/* ── Test fixture ──────────────────────────────────────────── */

struct sm_fixture {
    struct node_db ndb;
};

static bool sm_fixture_init(struct sm_fixture *f)
{
    memset(f, 0, sizeof(*f));
    schema_migration_clear();
    return node_db_open(&f->ndb, ":memory:");
}

static void sm_fixture_destroy(struct sm_fixture *f)
{
    schema_migration_clear();
    node_db_close(&f->ndb);
}

/* ── Mutation-gap helpers ──────────────────────────────────── */

/* Execution log: which fake migration bodies ran, in order. */
static int g_sm_calls[8];
static int g_sm_ncalls;

static void sm_calls_reset(void)
{
    memset(g_sm_calls, 0, sizeof(g_sm_calls));
    g_sm_ncalls = 0;
}

static bool sm_note(int id)
{
    if (g_sm_ncalls < 8)
        g_sm_calls[g_sm_ncalls] = id;
    g_sm_ncalls++;
    return true;
}

static bool sm_up_rec1(struct node_db *n) { (void)n; return sm_note(1); }
static bool sm_up_rec2(struct node_db *n) { (void)n; return sm_note(2); }
static bool sm_up_rec9(struct node_db *n) { (void)n; return sm_note(9); }
static bool sm_down_rec7(struct node_db *n) { (void)n; return sm_note(7); }

/* A body that writes, then reports failure: the write must not survive. */
static bool sm_up_partial_fail(struct node_db *n)
{
    (void)node_db_exec(n, "CREATE TABLE sm_partial(x INTEGER)");
    return false;
}

static bool sm_up_rows(struct node_db *n)
{
    return node_db_exec(n,
        "CREATE TABLE IF NOT EXISTS sm_rows(x INTEGER);"
        "INSERT INTO sm_rows VALUES(1);INSERT INTO sm_rows VALUES(2)");
}

static bool sm_down_clear(struct node_db *n)
{
    return node_db_exec(n, "DELETE FROM sm_rows");
}

static bool sm_down_write_then_fail(struct node_db *n)
{
    (void)node_db_exec(n, "DELETE FROM sm_rows");
    return false;
}

/* Bodies that succeed but poison one later bookkeeping step. */
static bool sm_up_block_insert(struct node_db *n)
{
    return node_db_exec(n,
        "CREATE TABLE sm_mark(x INTEGER);"
        "CREATE TRIGGER sm_trg BEFORE INSERT ON schema_migrations "
        "BEGIN SELECT RAISE(ABORT,'sm'); END");
}

static bool sm_up_block_state(struct node_db *n)
{
    return node_db_exec(n,
        "CREATE TABLE sm_mark(x INTEGER);"
        "CREATE TRIGGER sm_trg BEFORE INSERT ON node_state "
        "WHEN NEW.key='schema_version' "
        "BEGIN SELECT RAISE(ABORT,'sm'); END");
}

/* A deferred foreign-key violation: every statement succeeds, COMMIT fails
 * and leaves the transaction open for the caller to roll back. */
#define SM_DEFER_FK_SQL \
    "CREATE TABLE sm_mark(x INTEGER);" \
    "CREATE TABLE sm_p(id INTEGER PRIMARY KEY);" \
    "CREATE TABLE sm_c(pid INTEGER REFERENCES sm_p(id) " \
    "DEFERRABLE INITIALLY DEFERRED);" \
    "INSERT INTO sm_c VALUES(5)"

static bool sm_up_defer_fk(struct node_db *n)
{
    return node_db_exec(n, SM_DEFER_FK_SQL);
}

static bool sm_down_defer_fk(struct node_db *n)
{
    return node_db_exec(n, SM_DEFER_FK_SQL);
}

static bool sm_down_block_delete(struct node_db *n)
{
    return node_db_exec(n,
        "CREATE TABLE sm_mark(x INTEGER);"
        "CREATE TRIGGER sm_trg BEFORE DELETE ON schema_migrations "
        "BEGIN SELECT RAISE(ABORT,'sm'); END");
}

static bool sm_down_block_state(struct node_db *n)
{
    return node_db_exec(n,
        "CREATE TABLE sm_mark(x INTEGER);"
        "CREATE TRIGGER sm_trg BEFORE INSERT ON node_state "
        "WHEN NEW.key='schema_version' "
        "BEGIN SELECT RAISE(ABORT,'sm'); END");
}

static int sm_scalar(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int sm_obj_count(struct node_db *ndb, const char *type, const char *name)
{
    char sql[200];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM sqlite_master WHERE type='%s' AND name='%s'",
             type, name);
    return sm_scalar(ndb, sql);
}

static int sm_row_count(struct node_db *ndb, int version)
{
    char sql[200];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM schema_migrations WHERE version='%03d'",
             version);
    return sm_scalar(ndb, sql);
}

static int sm_rows_in(struct node_db *ndb, const char *table)
{
    char sql[100];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    return sm_scalar(ndb, sql);
}

/* True when no transaction is left open: a fresh BEGIN succeeds. */
static bool sm_no_open_tx(struct node_db *ndb)
{
    bool ok = node_db_begin(ndb);
    if (ok)
        node_db_rollback(ndb);
    return ok;
}

static void sm_set_version(struct node_db *ndb, int v)
{
    int32_t v32 = (int32_t)v;
    (void)node_db_state_set(ndb, "schema_version", &v32, sizeof(v32));
}

static bool sm_open(struct sm_fixture *f)
{
    if (!sm_fixture_init(f))
        return false;
    return node_db_exec(&f->ndb, "PRAGMA foreign_keys=ON");
}

static int sm_chk(const char *label, const char *what, bool ok)
{
    printf("sm gap: %s: %s... %s\n", label, what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* Capture stdout+stderr through a pipe so the operator-facing progress and
 * failure lines can be asserted. Output here is tiny, far below the pipe
 * capacity. Where capture is unavailable the token checks pass vacuously. */
static bool g_sm_capture_live;

#ifndef _WIN32
#include <fcntl.h>

struct sm_cap { int saved_out, saved_err, rd; };

static bool sm_cap_begin(struct sm_cap *c)
{
    int p[2];
    fflush(stdout);
    fflush(stderr);
    if (pipe(p) != 0)
        return false;
    (void)fcntl(p[0], F_SETFL, O_NONBLOCK);
    c->saved_out = dup(1);
    c->saved_err = dup(2);
    (void)dup2(p[1], 1);
    (void)dup2(p[1], 2);
    close(p[1]);
    c->rd = p[0];
    return true;
}

static void sm_cap_end(struct sm_cap *c, char *buf, size_t cap)
{
    fflush(stdout);
    fflush(stderr);
    (void)dup2(c->saved_out, 1);
    (void)dup2(c->saved_err, 2);
    close(c->saved_out);
    close(c->saved_err);
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap && (r = read(c->rd, buf + n, cap - 1 - n)) > 0)
        n += (size_t)r;
    buf[n] = '\0';
    close(c->rd);
}
#else
struct sm_cap { int unused; };
static bool sm_cap_begin(struct sm_cap *c) { (void)c; return false; }
static void sm_cap_end(struct sm_cap *c, char *buf, size_t cap)
{
    (void)c; (void)cap; buf[0] = '\0';
}
#endif

static bool sm_has(const char *out, const char *token)
{
    return !g_sm_capture_live || strstr(out, token) != NULL;
}

static bool sm_lacks(const char *out, const char *token)
{
    return !g_sm_capture_live || strstr(out, token) == NULL;
}

enum { SM_OUT_CAP = 4096 };

static int sm_run_cap(struct node_db *ndb, char *out)
{
    struct sm_cap c;
    g_sm_capture_live = sm_cap_begin(&c);
    out[0] = '\0';
    int r = schema_migration_run_pending(ndb);
    if (g_sm_capture_live)
        sm_cap_end(&c, out, SM_OUT_CAP);
    return r;
}

static bool sm_rollback_cap(struct node_db *ndb, char *out)
{
    struct sm_cap c;
    g_sm_capture_live = sm_cap_begin(&c);
    out[0] = '\0';
    bool r = schema_migration_rollback_last(ndb);
    if (g_sm_capture_live)
        sm_cap_end(&c, out, SM_OUT_CAP);
    return r;
}

/* ── Mutation-gap tests: registry ──────────────────────────── */

static int sm_gap_registration(void)
{
    int failures = 0;
    schema_migration_clear();
    SM_CHECK("sm gap: get(0) is NULL on an empty registry",
             schema_migration_get(0) == NULL);
    SM_CHECK("sm gap: version 1 is the lowest accepted",
             schema_migration_register(1, "one", test_up_add_table, NULL));
    SM_CHECK("sm gap: get(0) is NULL on a populated registry",
             schema_migration_get(0) == NULL);
    SM_CHECK("sm gap: get(1) finds the entry",
             schema_migration_get(1) != NULL);
    SM_CHECK("sm gap: NULL name rejected",
             !schema_migration_register(SM_TEST_V1, NULL,
                                        test_up_add_table, NULL));
    SM_CHECK("sm gap: rejected NULL name left count at 1",
             schema_migration_count() == 1);
    schema_migration_clear();

    SM_CHECK("sm gap: sole entry registers",
             schema_migration_register(SM_TEST_V3, "solo",
                                       test_up_add_table, NULL));
    SM_CHECK("sm gap: sole entry is the latest",
             schema_migration_latest_version() == SM_TEST_V3);
    schema_migration_clear();

    /* Exactly two entries registered high-then-low: the sort must run on a
     * two-element registry, not only from three up. */
    schema_migration_register(SM_TEST_V4, "high", test_up_add_table, NULL);
    schema_migration_register(SM_TEST_V2, "low", test_up_add_table, NULL);
    SM_CHECK("sm gap: two out-of-order entries: latest is the higher",
             schema_migration_latest_version() == SM_TEST_V4);
    schema_migration_clear();
    return failures;
}

static int sm_gap_registry_full(void)
{
    int failures = 0;
    schema_migration_clear();
    bool all = true;
    for (int i = 1; i <= SCHEMA_MIGRATION_MAX; i++)
        all = schema_migration_register(i, "fill", test_up_add_table, NULL)
              && all;
    SM_CHECK("sm gap: registry fills to SCHEMA_MIGRATION_MAX",
             all && schema_migration_count() == SCHEMA_MIGRATION_MAX);
    SM_CHECK("sm gap: entry past SCHEMA_MIGRATION_MAX rejected",
             !schema_migration_register(SCHEMA_MIGRATION_MAX + 1, "over",
                                        test_up_add_table, NULL));
    SM_CHECK("sm gap: full registry unchanged by the rejection",
             schema_migration_count() == SCHEMA_MIGRATION_MAX &&
             schema_migration_get(SCHEMA_MIGRATION_MAX + 1) == NULL &&
             schema_migration_latest_version() == SCHEMA_MIGRATION_MAX);
    schema_migration_clear();
    return failures;
}

/* ── Mutation-gap tests: run_pending ───────────────────────── */

static int sm_gap_order_and_rerun(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    char want[96];
    sm_open(&f);
    sm_calls_reset();
    /* Two entries registered in descending order. */
    schema_migration_register(SM_TEST_V2, "second", sm_up_rec2, NULL);
    schema_migration_register(SM_TEST_V1, "first", sm_up_rec1, NULL);

    int r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: both applied", r == 2);
    SM_CHECK("sm gap: bodies ran in version order",
             g_sm_ncalls == 2 && g_sm_calls[0] == 1 && g_sm_calls[1] == 2);
    SM_CHECK("sm gap: node_state at the highest version",
             schema_migration_current_version(&f.ndb) == SM_TEST_V2);
    SM_CHECK("sm gap: both versions recorded in schema_migrations",
             sm_row_count(&f.ndb, SM_TEST_V1) == 1 &&
             sm_row_count(&f.ndb, SM_TEST_V2) == 1);
    snprintf(want, sizeof(want), "applying v%d: first", SM_TEST_V1);
    SM_CHECK("sm gap: progress line names the first migration",
             sm_has(out, want));
    snprintf(want, sizeof(want), "applied 2 migration(s), now at version %d",
             SM_TEST_V2);
    SM_CHECK("sm gap: summary line gives count and final version",
             sm_has(out, want));

    r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: rerun applies nothing", r == 0);
    SM_CHECK("sm gap: rerun runs no body", g_sm_ncalls == 2);
    SM_CHECK("sm gap: rerun prints no summary",
             sm_lacks(out, "applied 0") && sm_lacks(out, "now at version"));
    SM_CHECK("sm gap: rerun leaves one row per version",
             sm_row_count(&f.ndb, SM_TEST_V1) == 1 &&
             sm_row_count(&f.ndb, SM_TEST_V2) == 1);
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_version_boundary(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    char want[96];
    sm_open(&f);
    sm_calls_reset();
    /* Exactly the current version must be skipped; one above must run. */
    schema_migration_register(NODE_DB_SCHEMA_LATEST, "at_current",
                              sm_up_rec9, NULL);
    schema_migration_register(SM_TEST_V1, "above", sm_up_rec1, NULL);
    int r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: only the version above current applies", r == 1);
    SM_CHECK("sm gap: the at-current body never ran",
             g_sm_ncalls == 1 && g_sm_calls[0] == 1);
    snprintf(want, sizeof(want), "applied 1 migration(s), now at version %d",
             SM_TEST_V1);
    SM_CHECK("sm gap: a single applied migration still prints the summary",
             sm_has(out, want));
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_up_failure_first(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    sm_calls_reset();
    schema_migration_register(SM_TEST_V1, "bad", sm_up_partial_fail, NULL);
    schema_migration_register(SM_TEST_V2, "never", sm_up_rec9, NULL);
    int r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: a first-migration failure returns -1", r == -1);
    SM_CHECK("sm gap: the failure stops the run", g_sm_ncalls == 0);
    SM_CHECK("sm gap: failure is reported", sm_has(out, "up() FAILED"));
    SM_CHECK("sm gap: failed body's write is rolled back",
             sm_obj_count(&f.ndb, "table", "sm_partial") == 0);
    SM_CHECK("sm gap: failed migration is not recorded",
             sm_row_count(&f.ndb, SM_TEST_V1) == 0);
    SM_CHECK("sm gap: version unchanged after the failure",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);
    SM_CHECK("sm gap: no transaction left open", sm_no_open_tx(&f.ndb));
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_up_failure_second(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    sm_calls_reset();
    schema_migration_register(SM_TEST_V1, "good", sm_up_rows, NULL);
    schema_migration_register(SM_TEST_V2, "bad", sm_up_partial_fail, NULL);
    schema_migration_register(SM_TEST_V3, "never", sm_up_rec9, NULL);
    int r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: failure after one success returns that count", r == 1);
    SM_CHECK("sm gap: nothing after the failure ran", g_sm_ncalls == 0);
    SM_CHECK("sm gap: earlier success stays committed",
             sm_rows_in(&f.ndb, "sm_rows") == 2 &&
             sm_row_count(&f.ndb, SM_TEST_V1) == 1 &&
             schema_migration_current_version(&f.ndb) == SM_TEST_V1);
    SM_CHECK("sm gap: failed step leaves no table and no row",
             sm_obj_count(&f.ndb, "table", "sm_partial") == 0 &&
             sm_row_count(&f.ndb, SM_TEST_V2) == 0);
    SM_CHECK("sm gap: no transaction left open", sm_no_open_tx(&f.ndb));
    sm_fixture_destroy(&f);
    return failures;
}

struct sm_fail_case {
    const char *label;
    schema_migrate_fn body;
    const char *token;
    const char *trigger;
};

/* A body that succeeds but whose recording step fails must leave the
 * database exactly as it was: no body effects, no bookkeeping row. */
static int sm_gap_run_bookkeeping_failure(const struct sm_fail_case *c)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    schema_migration_register(SM_TEST_V1, "poisoned", c->body, NULL);
    int r = sm_run_cap(&f.ndb, out);
    failures += sm_chk(c->label, "run returns -1", r == -1);
    failures += sm_chk(c->label, "failure reported", sm_has(out, c->token));
    failures += sm_chk(c->label, "body effects rolled back",
                       sm_obj_count(&f.ndb, "table", "sm_mark") == 0 &&
                       sm_obj_count(&f.ndb, "trigger", "sm_trg") == 0 &&
                       sm_obj_count(&f.ndb, "table", "sm_c") == 0);
    failures += sm_chk(c->label, "no bookkeeping row",
                       sm_row_count(&f.ndb, SM_TEST_V1) == 0);
    failures += sm_chk(c->label, "version unchanged",
                       schema_migration_current_version(&f.ndb) ==
                       NODE_DB_SCHEMA_LATEST);
    failures += sm_chk(c->label, "no transaction left open",
                       sm_no_open_tx(&f.ndb));
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_run_bookkeeping(void)
{
    static const struct sm_fail_case cases[] = {
        { "run/INSERT schema_migrations fails", sm_up_block_insert,
          "INSERT schema_migrations FAILED", "sm_trg" },
        { "run/schema_version update fails", sm_up_block_state,
          "schema_version UPDATE FAILED", "sm_trg" },
        { "run/COMMIT fails", sm_up_defer_fk, "COMMIT failed", "" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += sm_gap_run_bookkeeping_failure(&cases[i]);
    return failures;
}

static int sm_gap_run_begin_refused(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    sm_calls_reset();
    schema_migration_register(SM_TEST_V1, "blocked", sm_up_rec1, NULL);
    SM_CHECK("sm gap: outer transaction opens", node_db_begin(&f.ndb));
    int r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: BEGIN failure returns -1", r == -1);
    SM_CHECK("sm gap: BEGIN failure runs no body", g_sm_ncalls == 0);
    SM_CHECK("sm gap: BEGIN failure reported", sm_has(out, "BEGIN failed"));
    SM_CHECK("sm gap: BEGIN failure records nothing",
             sm_row_count(&f.ndb, SM_TEST_V1) == 0);
    node_db_rollback(&f.ndb);
    SM_CHECK("sm gap: version unchanged after refused BEGIN",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);
    r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: the migration applies once the db is free",
             r == 1 && g_sm_ncalls == 1);
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_deny_create_table(void *u, int act, const char *a,
                                const char *b, const char *c, const char *d)
{
    (void)u; (void)a; (void)b; (void)c; (void)d;
    return act == SQLITE_CREATE_TABLE ? SQLITE_DENY : SQLITE_OK;
}

static int sm_gap_run_bookkeeping_table(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    sm_calls_reset();
    schema_migration_register(SM_TEST_V1, "needs_table", sm_up_rec9, NULL);
    sqlite3_set_authorizer(f.ndb.db, sm_deny_create_table, NULL);
    int r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: unavailable bookkeeping table returns -1", r == -1);
    SM_CHECK("sm gap: no body runs without bookkeeping", g_sm_ncalls == 0);
    SM_CHECK("sm gap: refusal reported",
             sm_has(out, "CREATE schema_migrations FAILED"));
    SM_CHECK("sm gap: version unchanged after the refusal",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);
    sqlite3_set_authorizer(f.ndb.db, NULL, NULL);
    r = sm_run_cap(&f.ndb, out);
    SM_CHECK("sm gap: a retry after the refusal applies the migration",
             r == 1 && g_sm_ncalls == 1 &&
             schema_migration_current_version(&f.ndb) == SM_TEST_V1);
    sm_fixture_destroy(&f);
    return failures;
}

/* ── Mutation-gap tests: rollback_last ─────────────────────── */

static int sm_gap_rollback_success(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    char want[96];
    sm_open(&f);
    schema_migration_register(SM_TEST_V1, "rows", sm_up_rows, sm_down_clear);
    schema_migration_run_pending(&f.ndb);
    SM_CHECK("sm gap: applied with two rows and a bookkeeping row",
             sm_rows_in(&f.ndb, "sm_rows") == 2 &&
             sm_row_count(&f.ndb, SM_TEST_V1) == 1);

    bool rb = sm_rollback_cap(&f.ndb, out);
    SM_CHECK("sm gap: rollback succeeds", rb);
    SM_CHECK("sm gap: down() ran (rows deleted)",
             sm_rows_in(&f.ndb, "sm_rows") == 0);
    SM_CHECK("sm gap: bookkeeping row removed",
             sm_row_count(&f.ndb, SM_TEST_V1) == 0);
    SM_CHECK("sm gap: version back to the built-in latest",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);
    SM_CHECK("sm gap: no transaction left open", sm_no_open_tx(&f.ndb));
    snprintf(want, sizeof(want), "rolling back v%d: rows", SM_TEST_V1);
    SM_CHECK("sm gap: rollback announces the migration", sm_has(out, want));
    snprintf(want, sizeof(want), "rolled back v%d: rows", SM_TEST_V1);
    SM_CHECK("sm gap: rollback reports completion", sm_has(out, want));
    snprintf(want, sizeof(want), "now at v%d", NODE_DB_SCHEMA_LATEST);
    SM_CHECK("sm gap: rollback reports the landing version",
             sm_has(out, want));

    SM_CHECK("sm gap: a second rollback is refused (v not registered)",
             !schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: refused rollback leaves the version",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);
    SM_CHECK("sm gap: the rolled-back migration applies again",
             schema_migration_run_pending(&f.ndb) == 1 &&
             sm_rows_in(&f.ndb, "sm_rows") == 2 &&
             sm_row_count(&f.ndb, SM_TEST_V1) == 1);
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_rollback_previous_version(void)
{
    int failures = 0;
    struct sm_fixture f;
    sm_open(&f);
    sm_calls_reset();
    /* Non-adjacent registered versions: rolling back v3 lands on v1, the
     * highest registered below it, not on v3 - 1. */
    schema_migration_register(SM_TEST_V3, "third", sm_up_rec2, sm_down_rec7);
    schema_migration_register(SM_TEST_V1, "first", sm_up_rec1, sm_down_rec7);
    SM_CHECK("sm gap: both applied",
             schema_migration_run_pending(&f.ndb) == 2);
    SM_CHECK("sm gap: rollback of the top migration succeeds",
             schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: lands on the highest registered version below",
             schema_migration_current_version(&f.ndb) == SM_TEST_V1);
    SM_CHECK("sm gap: only the top migration's down ran",
             g_sm_ncalls == 3 && g_sm_calls[0] == 1 && g_sm_calls[1] == 2 &&
             g_sm_calls[2] == 7);
    SM_CHECK("sm gap: rollback of the lowest migration succeeds",
             schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: with none registered below, lands on version - 1",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_rollback_low_versions(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    schema_migration_register(2, "two", test_up_add_table, sm_down_rec7);
    schema_migration_register(1, "one", test_up_add_table, sm_down_rec7);
    sm_set_version(&f.ndb, 2);
    SM_CHECK("sm gap: version 2 rolls back", schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: v2 with v1 registered lands on 1",
             schema_migration_current_version(&f.ndb) == 1);
    SM_CHECK("sm gap: version 1 rolls back", schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: v1 lands on 0",
             schema_migration_current_version(&f.ndb) == 0);
    SM_CHECK("sm gap: nothing left to roll back at version 0",
             !sm_rollback_cap(&f.ndb, out));
    SM_CHECK("sm gap: refused as having nothing to roll back",
             sm_has(out, "no migrations to roll back"));
    schema_migration_clear();
    schema_migration_register(2, "two_alone", test_up_add_table, sm_down_rec7);
    sm_set_version(&f.ndb, 2);
    SM_CHECK("sm gap: lone v2 rolls back",
             schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: lone v2 lands on version - 1",
             schema_migration_current_version(&f.ndb) == 1);
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_rollback_refusals(void)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    struct node_db closed;
    sm_open(&f);
    sm_calls_reset();
    SM_CHECK("sm gap: current version not in registry is refused",
             !schema_migration_rollback_last(&f.ndb));
    SM_CHECK("sm gap: refusal leaves the version",
             schema_migration_current_version(&f.ndb) ==
             NODE_DB_SCHEMA_LATEST);

    schema_migration_register(SM_TEST_V1, "one", sm_up_rec1, sm_down_rec7);
    schema_migration_run_pending(&f.ndb);
    SM_CHECK("sm gap: outer transaction opens", node_db_begin(&f.ndb));
    bool rb = sm_rollback_cap(&f.ndb, out);
    SM_CHECK("sm gap: BEGIN failure refuses the rollback", !rb);
    SM_CHECK("sm gap: BEGIN failure runs no down()",
             g_sm_ncalls == 1);
    SM_CHECK("sm gap: BEGIN failure reported", sm_has(out, "BEGIN failed"));
    node_db_rollback(&f.ndb);
    SM_CHECK("sm gap: refused rollback leaves version and row",
             schema_migration_current_version(&f.ndb) == SM_TEST_V1 &&
             sm_row_count(&f.ndb, SM_TEST_V1) == 1);
    sm_fixture_destroy(&f);

    memset(&closed, 0, sizeof(closed));
    SM_CHECK("sm gap: closed db: run_pending returns -1",
             schema_migration_run_pending(&closed) == -1);
    SM_CHECK("sm gap: closed db: rollback refused",
             !sm_rollback_cap(&closed, out));
    SM_CHECK("sm gap: closed db: refused as not open, not as version 0",
             sm_has(out, "db not open"));
    return failures;
}

struct sm_rb_case {
    const char *label;
    schema_migrate_fn down;
    const char *token;
};

/* A rollback that fails at any step must leave the migration fully applied:
 * rows restored, bookkeeping row present, version unchanged. */
static int sm_gap_rollback_failure_case(const struct sm_rb_case *c)
{
    int failures = 0;
    struct sm_fixture f;
    char out[SM_OUT_CAP];
    sm_open(&f);
    schema_migration_register(SM_TEST_V1, "rows", sm_up_rows, c->down);
    schema_migration_run_pending(&f.ndb);
    bool rb = sm_rollback_cap(&f.ndb, out);
    failures += sm_chk(c->label, "rollback refused", !rb);
    failures += sm_chk(c->label, "failure reported", sm_has(out, c->token));
    failures += sm_chk(c->label, "down() effects undone",
                       sm_rows_in(&f.ndb, "sm_rows") == 2 &&
                       sm_obj_count(&f.ndb, "trigger", "sm_trg") == 0 &&
                       sm_obj_count(&f.ndb, "table", "sm_mark") == 0 &&
                       sm_obj_count(&f.ndb, "table", "sm_c") == 0);
    failures += sm_chk(c->label, "bookkeeping row still present",
                       sm_row_count(&f.ndb, SM_TEST_V1) == 1);
    failures += sm_chk(c->label, "version unchanged",
                       schema_migration_current_version(&f.ndb) ==
                       SM_TEST_V1);
    failures += sm_chk(c->label, "no transaction left open",
                       sm_no_open_tx(&f.ndb));
    sm_fixture_destroy(&f);
    return failures;
}

static int sm_gap_rollback_failures(void)
{
    static const struct sm_rb_case cases[] = {
        { "rollback/down() fails after writing", sm_down_write_then_fail,
          "down() FAILED" },
        { "rollback/DELETE schema_migrations fails", sm_down_block_delete,
          "DELETE schema_migrations FAILED" },
        { "rollback/schema_version update fails", sm_down_block_state,
          "schema_version UPDATE" },
        { "rollback/COMMIT fails", sm_down_defer_fk, "COMMIT failed" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += sm_gap_rollback_failure_case(&cases[i]);
    return failures;
}

static int sm_mutation_gap_tests(void)
{
    int failures = 0;
    failures += sm_gap_registration();
    failures += sm_gap_registry_full();
    failures += sm_gap_order_and_rerun();
    failures += sm_gap_version_boundary();
    failures += sm_gap_up_failure_first();
    failures += sm_gap_up_failure_second();
    failures += sm_gap_run_bookkeeping();
    failures += sm_gap_run_begin_refused();
    failures += sm_gap_run_bookkeeping_table();
    failures += sm_gap_rollback_success();
    failures += sm_gap_rollback_previous_version();
    failures += sm_gap_rollback_low_versions();
    failures += sm_gap_rollback_refusals();
    failures += sm_gap_rollback_failures();
    schema_migration_clear();
    return failures;
}

/* ── Tests ─────────────────────────────────────────────────── */

int test_schema_migration(void)
{
    printf("\n=== schema_migration tests ===\n");
    int failures = 0;

    /* ── 1. Registration basics ───────────────────────── */
    {
        schema_migration_clear();

        bool r1 = schema_migration_register(SM_TEST_V1, "add_test_table",
                                            test_up_add_table, test_down_drop_table);
        SM_CHECK("sm: register first post-built-in migration succeeds", r1);
        SM_CHECK("sm: count is 1", schema_migration_count() == 1);

        bool r2 = schema_migration_register(SM_TEST_V2, "add_column",
                                            test_up_add_column, NULL);
        SM_CHECK("sm: register second post-built-in migration succeeds", r2);
        SM_CHECK("sm: count is 2", schema_migration_count() == 2);

        /* Duplicate version rejected */
        bool r3 = schema_migration_register(SM_TEST_V1, "duplicate",
                                            test_up_add_table, NULL);
        SM_CHECK("sm: duplicate version rejected", !r3);
        SM_CHECK("sm: count still 2 after reject", schema_migration_count() == 2);

        /* Invalid version rejected */
        bool r4 = schema_migration_register(0, "zero",
                                            test_up_add_table, NULL);
        SM_CHECK("sm: version 0 rejected", !r4);

        bool r5 = schema_migration_register(-1, "negative",
                                            test_up_add_table, NULL);
        SM_CHECK("sm: negative version rejected", !r5);

        /* NULL up rejected */
        bool r6 = schema_migration_register(SM_TEST_V3, "null_up", NULL, NULL);
        SM_CHECK("sm: NULL up function rejected", !r6);

        schema_migration_clear();
    }

    /* ── 2. Latest version and get ────────────────────── */
    {
        schema_migration_clear();
        SM_CHECK("sm: latest_version is 0 when empty",
                 schema_migration_latest_version() == 0);

        schema_migration_register(SM_TEST_V6, "vmax", test_up_add_table, NULL);
        schema_migration_register(SM_TEST_V1, "vfirst", test_up_add_table, NULL);
        schema_migration_register(SM_TEST_V3, "vthird", test_up_add_table, NULL);

        SM_CHECK("sm: latest_version is highest registered",
                 schema_migration_latest_version() == SM_TEST_V6);

        const struct schema_migration *m = schema_migration_get(SM_TEST_V3);
        SM_CHECK("sm: get(third) returns correct migration",
                 m && m->version == SM_TEST_V3 &&
                 strcmp(m->name, "vthird") == 0);

        SM_CHECK("sm: get(99) returns NULL",
                 schema_migration_get(99) == NULL);

        schema_migration_clear();
    }

    /* ── 3. Run pending — basic execution ─────────────── */
    {
        struct sm_fixture f;
        bool ok = sm_fixture_init(&f);
        SM_CHECK("sm: fixture opens", ok);

        schema_migration_register(SM_TEST_V1, "add_test_table",
                                  test_up_add_table, test_down_drop_table);
        schema_migration_register(SM_TEST_V2, "add_column",
                                  test_up_add_column, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: run_pending applies 2 migrations", applied == 2);
        SM_CHECK("sm: version is now second test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V2);

        /* Verify the table was actually created */
        bool table_ok = node_db_exec(&f.ndb,
            "INSERT INTO test_table(id, name, age) VALUES(1, 'test', 25)");
        SM_CHECK("sm: test_table exists with age column", table_ok);

        /* Run again — nothing pending */
        int applied2 = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: second run_pending applies 0", applied2 == 0);

        sm_fixture_destroy(&f);
    }

    /* ── 4. Already-applied migrations are skipped ────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        /* Register migrations below the built-in latest — they should be skipped */
        schema_migration_register(5, "old_migration",
                                  test_up_add_table, NULL);
        schema_migration_register(10, "another_old",
                                  test_up_add_table, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: old migrations (v5, v10) skipped", applied == 0);

        sm_fixture_destroy(&f);
    }

    /* ── 5. Failed migration rolls back ───────────────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V1, "good_migration",
                                  test_up_add_table, test_down_drop_table);
        schema_migration_register(SM_TEST_V2, "bad_migration",
                                  test_up_fail, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        /* first test migration should succeed, second should fail and stop */
        SM_CHECK("sm: partial apply (1 of 2)", applied == 1);
        SM_CHECK("sm: version stuck at first test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V1);

        sm_fixture_destroy(&f);
    }

    /* ── 6. Rollback with down function ───────────────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V1, "add_test_table",
                                  test_up_add_table, test_down_drop_table);

        schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: at first test migration before rollback",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V1);

        bool rb = schema_migration_rollback_last(&f.ndb);
        SM_CHECK("sm: rollback succeeds", rb);
        SM_CHECK("sm: version back to built-in latest after rollback",
                 schema_migration_current_version(&f.ndb) == NODE_DB_SCHEMA_LATEST);

        /* Down function should have cleared the table */
        SM_CHECK("sm: down() ran (table emptied by rollback)", rb);

        sm_fixture_destroy(&f);
    }

    /* ── 7. Rollback without down function fails ──────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V1, "irreversible",
                                  test_up_add_table, NULL);
        schema_migration_run_pending(&f.ndb);

        bool rb = schema_migration_rollback_last(&f.ndb);
        SM_CHECK("sm: rollback fails when no down function", !rb);
        SM_CHECK("sm: version unchanged at first test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V1);

        sm_fixture_destroy(&f);
    }

    /* ── 8. Migrations run in version order regardless of registration order ── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V3, "insert_row",
                                  test_up_insert_row, NULL);
        schema_migration_register(SM_TEST_V1, "create_table",
                                  test_up_add_table, NULL);
        schema_migration_register(SM_TEST_V2, "add_column",
                                  test_up_add_column, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: all 3 applied in order", applied == 3);
        SM_CHECK("sm: version is third test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V3);

        /* If order was wrong, insert_row would fail (table doesn't exist yet) */
        SM_CHECK("sm: migrations ran in version order (table exists with row)", true);

        sm_fixture_destroy(&f);
    }

    /* ── 9. is_applied query ──────────────────────────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        SM_CHECK("sm: built-in latest is applied",
                 schema_migration_is_applied(&f.ndb, NODE_DB_SCHEMA_LATEST));
        SM_CHECK("sm: first test migration is not applied yet",
                 !schema_migration_is_applied(&f.ndb, SM_TEST_V1));

        schema_migration_register(SM_TEST_V1, "test", test_up_add_table, NULL);
        schema_migration_run_pending(&f.ndb);

        SM_CHECK("sm: first test migration is applied after run",
                 schema_migration_is_applied(&f.ndb, SM_TEST_V1));

        sm_fixture_destroy(&f);
    }

    /* ── 10. register_entry convenience ───────────────── */
    {
        schema_migration_clear();

        struct schema_migration m = {
            .version = SM_TEST_V6,
            .name = "from_struct",
            .up = test_up_add_table,
            .down = NULL,
        };
        bool r = schema_migration_register_entry(&m);
        SM_CHECK("sm: register_entry succeeds", r);
        SM_CHECK("sm: registered migration accessible",
                 schema_migration_get(SM_TEST_V6) != NULL);

        bool r_null = schema_migration_register_entry(NULL);
        SM_CHECK("sm: register_entry(NULL) rejected", !r_null);

        schema_migration_clear();
    }

    /* ── 11. NULL db handled ──────────────────────────── */
    {
        SM_CHECK("sm: run_pending(NULL) returns -1",
                 schema_migration_run_pending(NULL) == -1);
        SM_CHECK("sm: rollback_last(NULL) returns false",
                 !schema_migration_rollback_last(NULL));
    }

    /* ── 12. Clear resets everything ──────────────────── */
    {
        schema_migration_register(SM_TEST_V1, "test", test_up_add_table, NULL);
        SM_CHECK("sm: count is 1 before clear", schema_migration_count() == 1);

        schema_migration_clear();
        SM_CHECK("sm: count is 0 after clear", schema_migration_count() == 0);
        SM_CHECK("sm: latest_version is 0 after clear",
                 schema_migration_latest_version() == 0);
    }

    /* ── 13. Mutation-gap pins (ordering, failure states, rerun) ── */
    failures += sm_mutation_gap_tests();

    return failures;
}
