/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for stage_anchor (engine/jobs/src/stage_anchor.c).
 *
 * stage_anchor_upstream_cursors_to() aligns upstream reducer stage cursors
 * (header_admit .. utxo_apply) to a trusted anchor target, with utxo_apply
 * capped by coins_applied_height when that durable frontier is present.
 * It was recently churned (commit 392f7256d) and had zero coverage. The
 * load-bearing invariants this test pins:
 *
 *   - ATOMIC advance: every upstream cursor that is BEHIND the target ends
 *     up exactly AT the target after one anchor call, except utxo_apply when
 *     coins_applied_height caps it lower.
 *   - FORWARD-ONLY monotonicity: a cursor already AT or ABOVE the target is
 *     NEVER rewound — anchoring to a lower value is a no-op for that cursor.
 *   - IDEMPOTENT re-anchor: anchoring twice to the same target leaves every
 *     cursor unchanged on the second call.
 *   - P2 CAP: utxo_apply is never anchored above coins_applied_height.
 *
 * Only the real public API is used: stage_anchor_upstream_cursors_to() to
 * advance, stage_set_named_cursor_if_behind() to prime, and the public
 * stage_cursor_persisted() reader (jobs/stage_helpers.h) to observe.
 *
 * Parallel-runner safe: each block opens its OWN uniquely-named on-disk DB,
 * unlinks it before and after, and never touches global node state. The
 * progress_store recursive tx-lock used by the anchor self-inits via
 * pthread_once, so no progress_store_open() is required. */

#include "jobs/stage_anchor.h"
#include "jobs/stage_helpers.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "test/test_core.h"
#include "util/stage.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SA_CHECK(name, expr) do { \
    printf("stage_anchor: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* The exact upstream set stage_anchor advances, mirrored here so the test
 * can prime and observe each one through the public API. Kept in the SAME
 * order as stage_anchor.c. */
static const char *const SA_UPSTREAM[] = {
    "header_admit",
    "validate_headers",
    "body_fetch",
    "body_persist",
    "script_validate",
    "proof_validate",
    "utxo_apply",
};
#define SA_N (sizeof(SA_UPSTREAM) / sizeof(SA_UPSTREAM[0]))

/* Open a fresh on-disk DB with just the stage_cursor table. */
static sqlite3 *sa_open(const char *path)
{
    unlink(path);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return NULL;
    if (!stage_table_ensure(db)) { sqlite3_close(db); return NULL; }
    return db;
}

static uint64_t sa_read(sqlite3 *db, const char *name)
{
    /* Public read path used by every stage and by stage_anchor itself. */
    return stage_cursor_persisted(db, name, "test_stage_anchor");
}

static bool sa_set_coins_applied(sqlite3 *db, int32_t height)
{
    if (!progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, height);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    return ok;
}

/* cursor_read_contract, part 1: a malformed stage_cursor schema must come
 * back as an error, never as a missing row. Closes and unlinks the DB so
 * part 2 can reopen a valid schema at the same path. Each helper carries
 * its own local failure count, which test_stage_anchor sums. */
static int sa_check_cursor_read_schema_error(const char *fixture_dir)
{
    int failures = 0;
    char path[256];
    (void)snprintf(path, sizeof(path), "%s/test_stage_cursor_read_contract.db", fixture_dir);
    unlink(path);
    sqlite3 *db = NULL;
    SA_CHECK("cursor_read_contract: sqlite open",
             sqlite3_open(path, &db) == SQLITE_OK);
    SA_CHECK("cursor_read_contract: create malformed table",
             sqlite3_exec(db,
                "CREATE TABLE stage_cursor(name TEXT PRIMARY KEY,"
                " bad INTEGER)",
                NULL, NULL, NULL) == SQLITE_OK);

    struct stage_cursor_read_result bad =
        stage_cursor_read_persisted(db, "header_admit",
                                    "test_stage_anchor");
    SA_CHECK("cursor_read_contract: schema error is not ok",
             !bad.ok && !bad.found && bad.cursor == 0);

    sqlite3_close(db);
    unlink(path);
    return failures;
}

/* cursor_read_contract, part 2: on a valid schema a missing row reads as
 * {ok, !found, 0} and a set row round-trips its cursor value. */
static int sa_check_cursor_read_missing_and_found_rows(const char *fixture_dir)
{
    int failures = 0;
    char path[256];
    (void)snprintf(path, sizeof(path), "%s/test_stage_cursor_read_contract.db", fixture_dir);
    sqlite3 *db = sa_open(path);
    SA_CHECK("cursor_read_contract: reopen valid schema", db != NULL);

    struct stage_cursor_read_result missing =
        stage_cursor_read_persisted(db, "missing_stage",
                                    "test_stage_anchor");
    SA_CHECK("cursor_read_contract: missing row is ok zero",
             missing.ok && !missing.found && missing.cursor == 0);

    SA_CHECK("cursor_read_contract: set row",
             stage_set_named_cursor_if_behind(db, "header_admit", 77));
    struct stage_cursor_read_result found =
        stage_cursor_read_persisted(db, "header_admit",
                                    "test_stage_anchor");
    SA_CHECK("cursor_read_contract: found row returns cursor",
             found.ok && found.found && found.cursor == 77);

    sqlite3_close(db);
    unlink(path);
    return failures;
}

/* ATOMIC advance: prime every upstream cursor below the target, anchor
 * once, and require every one of them to land exactly on the target. */
static int sa_check_anchor_atomic_advance(const char *fixture_dir)
{
    int failures = 0;
    char path[256];
    (void)snprintf(path, sizeof(path), "%s/test_stage_anchor_advance.db", fixture_dir);
    sqlite3 *db = sa_open(path);
    SA_CHECK("db open", db != NULL);

    /* Prime cursors at staggered values, all strictly below 5000.
     * Indices 0..6 → 100, 200, ..., 700. */
    for (size_t i = 0; i < SA_N; i++) {
        bool ok = stage_set_named_cursor_if_behind(
            db, SA_UPSTREAM[i], (uint64_t)((i + 1) * 100));
        SA_CHECK("prime behind cursor", ok);
    }

    bool ok = stage_anchor_upstream_cursors_to(db, 5000, "test",
                                               "atomic-advance", false);
    SA_CHECK("anchor advance returns true", ok);

    bool all_at_target = true;
    for (size_t i = 0; i < SA_N; i++)
        if (sa_read(db, SA_UPSTREAM[i]) != 5000) all_at_target = false;
    SA_CHECK("all behind cursors advanced to target", all_at_target);

    sqlite3_close(db);
    unlink(path);
    return failures;
}

/* FORWARD-ONLY, part 1: prime script_validate above the target and every
 * other cursor below it, anchor, then check the above-target cursor is
 * untouched and each below-target cursor advanced exactly to the target. */
static int sa_check_anchor_with_one_cursor_above_target(sqlite3 *db,
                                                        uint64_t target,
                                                        uint64_t high,
                                                        uint64_t low)
{
    int failures = 0;
    bool ok = stage_set_named_cursor_if_behind(db, "script_validate", high);
    SA_CHECK("prime high cursor", ok);
    for (size_t i = 0; i < SA_N; i++) {
        if (i == 4 /* script_validate */) continue;
        stage_set_named_cursor_if_behind(db, SA_UPSTREAM[i], low);
    }

    ok = stage_anchor_upstream_cursors_to(db, target, "test",
                                          "forward-only", false);
    SA_CHECK("anchor with one-above returns true", ok);

    SA_CHECK("above-target cursor NOT rewound",
             sa_read(db, "script_validate") == high);

    bool others_advanced = true;
    for (size_t i = 0; i < SA_N; i++) {
        if (i == 4) continue;
        if (sa_read(db, SA_UPSTREAM[i]) != target) others_advanced = false;
    }
    SA_CHECK("below-target cursors advanced to target", others_advanced);
    return failures;
}

/* FORWARD-ONLY, part 2: runs after part 1 on the same DB. */
static int sa_check_anchor_below_all_cursors_is_noop(sqlite3 *db,
                                                     uint64_t target,
                                                     uint64_t high)
{
    int failures = 0;
    /* Anchor to a value BELOW every current cursor → pure no-op. */
    bool ok = stage_anchor_upstream_cursors_to(db, 50, "test", "below-all", false);
    SA_CHECK("anchor below-all returns true", ok);
    SA_CHECK("high cursor still high after below-all anchor",
             sa_read(db, "script_validate") == high);
    bool none_rewound = true;
    for (size_t i = 0; i < SA_N; i++) {
        if (i == 4) continue;
        if (sa_read(db, SA_UPSTREAM[i]) != target) none_rewound = false;
    }
    SA_CHECK("no cursor rewound by below-all anchor", none_rewound);
    return failures;
}

/* IDEMPOTENT: anchor twice to the same target; the second call must leave
 * every cursor unchanged. */
static int sa_check_anchor_reanchor_is_idempotent(sqlite3 *db)
{
    int failures = 0;
    bool ok = stage_anchor_upstream_cursors_to(db, 4242, "test",
                                               "first-anchor", false);
    SA_CHECK("first anchor returns true", ok);
    bool first_at_target = true;
    for (size_t i = 0; i < SA_N; i++)
        if (sa_read(db, SA_UPSTREAM[i]) != 4242) first_at_target = false;
    SA_CHECK("first anchor set all cursors", first_at_target);

    ok = stage_anchor_upstream_cursors_to(db, 4242, "test",
                                          "re-anchor", false);
    SA_CHECK("re-anchor returns true", ok);
    bool unchanged = true;
    for (size_t i = 0; i < SA_N; i++)
        if (sa_read(db, SA_UPSTREAM[i]) != 4242) unchanged = false;
    SA_CHECK("re-anchor to same target left cursors unchanged",
             unchanged);
    return failures;
}

/* IDEMPOTENT, outer-transaction half: runs after
 * sa_check_anchor_reanchor_is_idempotent on the same DB. */
static int sa_check_reanchor_joins_outer_transaction(sqlite3 *db)
{
    int failures = 0;
    /* A larger atomic cutover may already own the SQLite transaction. An
     * idempotent re-anchor must remain a pure read/no-op and must not try to
     * nest the standalone cursor writer's BEGIN. */
    bool outer_open = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL,
                                   NULL) == SQLITE_OK;
    bool ok = outer_open && stage_anchor_upstream_cursors_to(
        db, 4242, "test", "outer-transaction-noop", true);
    bool outer_still_open = sqlite3_get_autocommit(db) == 0;
    bool outer_rolled_back = sqlite3_exec(db, "ROLLBACK", NULL, NULL,
                                          NULL) == SQLITE_OK;
    SA_CHECK("same-target re-anchor joins outer transaction as no-op",
             ok && outer_still_open && outer_rolled_back);
    return failures;
}

/* P2 CAP setup: prime staggered cursors, stamp coins_applied_height=700,
 * then anchor to 5000. */
static int sa_check_coins_cap_prime_and_anchor(sqlite3 *db)
{
    int failures = 0;
    bool ok = true;
    for (size_t i = 0; i < SA_N; i++)
        ok = ok && stage_set_named_cursor_if_behind(
            db, SA_UPSTREAM[i], (uint64_t)((i + 1) * 100));
    SA_CHECK("coins_cap: prime cursors", ok);
    SA_CHECK("coins_cap: stamp coins_applied_height=700",
             sa_set_coins_applied(db, 700));

    ok = stage_anchor_upstream_cursors_to(db, 5000, "test",
                                          "coins-cap", false);
    SA_CHECK("coins_cap: anchor returns true", ok);
    return failures;
}

/* P2 CAP verification: runs after sa_check_coins_cap_prime_and_anchor on
 * the same DB. */
static int sa_check_coins_cap_caps_dependent_cursors(sqlite3 *db)
{
    int failures = 0;
    /* The coins-INDEPENDENT stages (header_admit/validate_headers/body_fetch)
     * track the header/body frontier and advance to the requested target.
     * The coins-DEPENDENT stages — body_persist (the created_outputs index
     * builder), script_validate, proof_validate, utxo_apply — are capped at
     * coins_applied_height (700): they consume each other's per-height
     * outputs, so jumping any of them past the coins frontier without
     * producing the intervening rows/index manufactures the upstream
     * hole/prevout-gap that wedges the tip at the snapshot seed. */
    const char *coin_dep[] = { "body_persist", "script_validate",
                               "proof_validate", "utxo_apply" };
    bool non_coin_stages_at_target = true;
    for (size_t i = 0; i < SA_N; i++) {
        bool is_coin_dep = false;
        for (size_t j = 0; j < sizeof(coin_dep) / sizeof(coin_dep[0]); j++)
            if (strcmp(SA_UPSTREAM[i], coin_dep[j]) == 0)
                is_coin_dep = true;
        if (is_coin_dep)
            continue;
        if (sa_read(db, SA_UPSTREAM[i]) != 5000)
            non_coin_stages_at_target = false;
    }
    SA_CHECK("coins_cap: non-coin cursors advanced",
             non_coin_stages_at_target);
    bool coin_dep_capped = true;
    for (size_t j = 0; j < sizeof(coin_dep) / sizeof(coin_dep[0]); j++)
        if (sa_read(db, coin_dep[j]) != 700)
            coin_dep_capped = false;
    SA_CHECK("coins_cap: coins-dependent cursors capped at coins frontier",
             coin_dep_capped);
    return failures;
}


/* ------------------------------------------------------------------------
 * Mutation-gap cases: the log-frontier cap itself (so this group runs it, not
 * only the frontier_cap group), and the refusals of the anchor entry point.
 * ------------------------------------------------------------------------ */

static bool sa_exec(sqlite3 *db, const char *sql)
{
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);  // raw-sql-ok:test-seed
    if (rc != SQLITE_OK)
        printf("stage_anchor: seed SQL failed rc=%d: %s\n", rc,
               sqlite3_errmsg(db));
    return rc == SQLITE_OK;
}

static bool sa_make_log(sqlite3 *db, const char *table)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s(height INTEGER PRIMARY KEY)",
             table);
    return sa_exec(db, sql);
}

/* Rows lo..hi inclusive, skipping `skip` (pass -1 for none). */
static bool sa_put_rows(sqlite3 *db, const char *table, int lo, int hi,
                        int skip)
{
    char sql[512];
    for (int h = lo; h <= hi; h++) {
        if (h == skip)
            continue;
        snprintf(sql, sizeof(sql), "INSERT INTO %s(height) VALUES(%d)",
                 table, h);
        if (!sa_exec(db, sql))
            return false;
    }
    return true;
}

static bool sa_cap(sqlite3 *db, const char *table, uint64_t cursor,
                   uint64_t requested, bool exempt, uint64_t *out)
{
    return stage_anchor_cap_target_at_log_frontier(db, table, cursor,
                                                   requested, exempt, out);
}

static bool sa_no_open_statements(sqlite3 *db)
{
    return sqlite3_next_stmt(db, NULL) == NULL;
}

static sqlite3 *sa_fresh(const char *fixture_dir, const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", fixture_dir, name);
    return sa_open(path);
}

/* A table that exists but whose `height` column raises at read time, so the
 * cap's probe prepares fine and then fails in sqlite3_step. */
static bool g_sa_boom;

static void sa_boom_fn(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc;
    if (g_sa_boom)
        sqlite3_result_error(ctx, "sa_boom: injected read failure", -1);
    else
        sqlite3_result_value(ctx, argv[0]);
}

static bool sa_make_broken_log(sqlite3 *db, const char *table)
{
    char sql[512];
    g_sa_boom = false;
    if (sqlite3_create_function(db, "sa_boom", 1,
                                SQLITE_UTF8 | SQLITE_DETERMINISTIC |
                                    SQLITE_INNOCUOUS,
                                NULL, sa_boom_fn, NULL, NULL) != SQLITE_OK)
        return false;
    snprintf(sql, sizeof(sql),
             "CREATE TABLE %s(x INTEGER, height INTEGER GENERATED ALWAYS "
             "AS (sa_boom(x)) VIRTUAL)", table);
    if (!sa_exec(db, sql))
        return false;
    snprintf(sql, sizeof(sql), "INSERT INTO %s(x) VALUES(1)", table);
    if (!sa_exec(db, sql))
        return false;
    g_sa_boom = true;  /* every later read of `height` now fails */
    return true;
}

/* The cap on a log with a hole inside the jump, a rowless cursor, a fresh
 * log, and the pass-through and exemption prongs. */
static int sa_case_cap_hole(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_cap_hole.db");
    SA_CHECK("cap hole: db open", db != NULL);
    if (!db)
        return failures;
    bool seeded = sa_make_log(db, "sa_hole_log") &&
                  sa_put_rows(db, "sa_hole_log", 100, 120, 110);
    SA_CHECK("cap hole: seeded", seeded);
    uint64_t capped = 0;
    SA_CHECK("cap hole: hole inside the jump caps at the hole",
             sa_cap(db, "sa_hole_log", 100, 121, false, &capped) &&
             capped == 110);
    SA_CHECK("cap hole: rowless cursor caps at the cursor",
             sa_cap(db, "sa_hole_log", 99, 121, false, &capped) &&
             capped == 99);
    SA_CHECK("cap hole: seed-exempt jumps over the hole",
             sa_cap(db, "sa_hole_log", 100, 121, true, &capped) &&
             capped == 121);
    SA_CHECK("cap hole: request at the cursor passes through",
             sa_cap(db, "sa_hole_log", 105, 105, false, &capped) &&
             capped == 105);
    SA_CHECK("cap hole: no statement left open", sa_no_open_statements(db));
    sqlite3_close(db);
    return failures;
}

/* A log with rows only at or above the request has nothing below to tear. */
static int sa_case_cap_fresh_and_flat(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_cap_flat.db");
    SA_CHECK("cap flat: db open", db != NULL);
    if (!db)
        return failures;
    bool seeded = sa_make_log(db, "sa_high_log") &&
                  sa_put_rows(db, "sa_high_log", 200, 201, -1) &&
                  sa_make_log(db, "sa_flat_log") &&
                  sa_put_rows(db, "sa_flat_log", 100, 120, -1) &&
                  sa_make_log(db, "t") && sa_put_rows(db, "t", 1, 4, 3);
    SA_CHECK("cap flat: seeded", seeded);
    uint64_t capped = 0;
    SA_CHECK("cap flat: no row below the request, full jump",
             sa_cap(db, "sa_high_log", 10, 50, false, &capped) &&
             capped == 50);
    SA_CHECK("cap flat: contiguous log caps at its first rowless height",
             sa_cap(db, "sa_flat_log", 100, 500, false, &capped) &&
             capped == 121);
    SA_CHECK("cap flat: INT64_MAX is an accepted request",
             sa_cap(db, "sa_flat_log", 100, (uint64_t)INT64_MAX, false,
                    &capped) && capped == 121);
    SA_CHECK("cap flat: a request past INT64_MAX is refused, untouched",
             !sa_cap(db, "sa_flat_log", 100, (uint64_t)INT64_MAX + 1, false,
                     &capped) && capped == (uint64_t)INT64_MAX + 1);
    SA_CHECK("cap flat: one-character table name is honoured",
             sa_cap(db, "t", 1, 10, false, &capped) && capped == 3);
    SA_CHECK("cap flat: no statement left open", sa_no_open_statements(db));
    sqlite3_close(db);
    return failures;
}

/* Invalid arguments are refused and leave the output at the request. */
static int sa_case_cap_bad_args(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_cap_args.db");
    SA_CHECK("cap args: db open", db != NULL);
    if (!db)
        return failures;
    uint64_t capped = 0;
    SA_CHECK("cap args: NULL out refused",
             !sa_cap(db, "sa_hole_log", 1, 9, false, NULL));
    capped = 0;
    SA_CHECK("cap args: NULL db refused, out set to the request",
             !sa_cap(NULL, "sa_hole_log", 1, 77, false, &capped) &&
             capped == 77);
    capped = 0;
    SA_CHECK("cap args: NULL table refused, out set to the request",
             !sa_cap(db, NULL, 1, 78, false, &capped) && capped == 78);
    capped = 0;
    SA_CHECK("cap args: empty table refused, out set to the request",
             !sa_cap(db, "", 1, 79, false, &capped) && capped == 79);
    sqlite3_close(db);
    return failures;
}

/* A probe that fails mid-step is an error, never a quiet full jump. */
static int sa_case_cap_probe_failure(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_cap_broken.db");
    SA_CHECK("cap broken: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("cap broken: broken table made",
             sa_make_broken_log(db, "sa_broken_log"));
    uint64_t capped = 0;
    SA_CHECK("cap broken: failing probe is refused, out at the request",
             !sa_cap(db, "sa_broken_log", 5, 50, false, &capped) &&
             capped == 50);
    SA_CHECK("cap broken: request at the cursor never scans",
             sa_cap(db, "sa_broken_log", 50, 50, false, &capped) &&
             capped == 50);
    SA_CHECK("cap broken: no statement left open", sa_no_open_statements(db));
    g_sa_boom = false;
    sqlite3_close(db);
    return failures;
}

/* The table-existence probe failing in step (database locked by another
 * connection) is an error, not "no table". */
static int sa_case_cap_locked_database(const char *fixture_dir)
{
    int failures = 0;
    char path[256];
    snprintf(path, sizeof(path), "%s/sa_cap_locked.db", fixture_dir);
    sqlite3 *db = sa_open(path);
    sqlite3 *other = NULL;
    SA_CHECK("cap locked: db open", db != NULL);
    if (!db)
        return failures;
    bool ready = sa_exec(db, "PRAGMA journal_mode=DELETE") &&
                 sa_make_log(db, "sa_locked_log") &&
                 sa_put_rows(db, "sa_locked_log", 1, 5, -1) &&
                 sa_exec(db, "SELECT count(*) FROM sqlite_master");
    SA_CHECK("cap locked: seeded", ready);
    bool locked = sqlite3_open(path, &other) == SQLITE_OK &&
                  sa_exec(other, "BEGIN EXCLUSIVE");
    SA_CHECK("cap locked: other connection holds the exclusive lock", locked);
    uint64_t capped = 0;
    SA_CHECK("cap locked: probe failure is refused, out at the request",
             !sa_cap(db, "sa_locked_log", 1, 9, false, &capped) &&
             capped == 9);
    if (other) {
        sa_exec(other, "ROLLBACK");
        sqlite3_close(other);
    }
    SA_CHECK("cap locked: no statement left open", sa_no_open_statements(db));
    sqlite3_close(db);
    return failures;
}

/* A table name too long for the probe SQL is refused, not scanned empty. */
static int sa_case_cap_long_name(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_cap_long.db");
    SA_CHECK("cap long: db open", db != NULL);
    if (!db)
        return failures;
    char name[300];
    memset(name, 'a', 260);
    name[260] = '\0';
    SA_CHECK("cap long: long-named log seeded",
             sa_make_log(db, name) && sa_put_rows(db, name, 1, 5, -1));
    uint64_t capped = 0;
    SA_CHECK("cap long: overlong probe SQL is refused",
             !sa_cap(db, name, 1, 9, false, &capped) && capped == 9);
    sqlite3_close(db);
    return failures;
}

static void *sa_trylock_thread(void *arg)
{
    bool *got = arg;
    *got = progress_store_tx_trylock();
    if (*got)
        progress_store_tx_unlock();
    return NULL;
}

/* After the cap returns, the progress-store lock is free for other threads. */
static int sa_case_cap_releases_lock(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_cap_lock.db");
    SA_CHECK("cap lock: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("cap lock: log seeded",
             sa_make_log(db, "sa_lock_log") &&
             sa_put_rows(db, "sa_lock_log", 1, 5, -1));
    uint64_t capped = 0;
    SA_CHECK("cap lock: cap runs",
             sa_cap(db, "sa_lock_log", 1, 9, false, &capped));
    bool got = false;
    pthread_t th;
    bool started = pthread_create(&th, NULL, sa_trylock_thread, &got) == 0;
    SA_CHECK("cap lock: thread started", started);
    if (started)
        pthread_join(th, NULL);
    SA_CHECK("cap lock: another thread can take the lock", got);
    sqlite3_close(db);
    return failures;
}

static bool sa_all_at(sqlite3 *db, size_t from, size_t to, uint64_t want)
{
    for (size_t i = from; i < to; i++)
        if (sa_read(db, SA_UPSTREAM[i]) != want)
            return false;
    return true;
}

/* A NULL owner is accepted: the log tag falls back to a default. */
static int sa_case_upstream_null_owner(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_up_owner.db");
    SA_CHECK("owner: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("owner: NULL owner and NULL reason anchor",
             stage_anchor_upstream_cursors_to(db, 100, NULL, NULL, false));
    SA_CHECK("owner: every cursor reached the target",
             sa_all_at(db, 0, SA_N, 100));
    sqlite3_close(db);
    return failures;
}

/* coins_applied_height = 0 is a real frontier: dependent stages are held at
 * 0 and the call still succeeds. */
static int sa_case_upstream_zero_frontier(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_up_zero.db");
    SA_CHECK("zero frontier: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("zero frontier: stamped", sa_set_coins_applied(db, 0));
    SA_CHECK("zero frontier: anchor succeeds",
             stage_anchor_upstream_cursors_to(db, 500, "test", "zero", false));
    SA_CHECK("zero frontier: independent stages reach the target",
             sa_all_at(db, 0, 3, 500));
    SA_CHECK("zero frontier: dependent stages stay at 0",
             sa_all_at(db, 3, SA_N, 0));
    sqlite3_close(db);
    return failures;
}

/* A negative frontier is malformed: refused, and the stages from the first
 * coins-dependent one onward are not moved. */
static int sa_case_upstream_negative_frontier(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_up_neg.db");
    SA_CHECK("negative frontier: db open", db != NULL);
    if (!db)
        return failures;
    bool seeded = progress_meta_table_ensure(db) &&
                  sa_exec(db, "INSERT OR REPLACE INTO progress_meta(key, value)"
                              " VALUES('coins_applied_height',"
                              " x'ffffffffffffffff')");
    SA_CHECK("negative frontier: seeded", seeded);
    SA_CHECK("negative frontier: anchor refused",
             !stage_anchor_upstream_cursors_to(db, 500, "test", "neg", false));
    SA_CHECK("negative frontier: dependent stages not moved",
             sa_all_at(db, 3, SA_N, 0));
    sqlite3_close(db);
    return failures;
}

/* An unreadable coins frontier is refused rather than treated as absent. */
static int sa_case_upstream_unreadable_frontier(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_up_badmeta.db");
    SA_CHECK("bad meta: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("bad meta: wrong-schema progress_meta",
             sa_exec(db, "CREATE TABLE progress_meta(foo INTEGER)"));
    SA_CHECK("bad meta: anchor refused",
             !stage_anchor_upstream_cursors_to(db, 500, "test", "bad", false));
    SA_CHECK("bad meta: dependent stages not moved",
             sa_all_at(db, 3, SA_N, 0));
    sqlite3_close(db);
    return failures;
}

/* The frontier table cannot be ensured (an index owns its name): refused. */
static int sa_case_upstream_frontier_schema_blocked(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_up_blocked.db");
    SA_CHECK("blocked meta: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("blocked meta: index squats on the table name",
             sa_exec(db, "CREATE INDEX progress_meta ON stage_cursor(name)"));
    SA_CHECK("blocked meta: anchor refused",
             !stage_anchor_upstream_cursors_to(db, 500, "test", "blk", false));
    SA_CHECK("blocked meta: dependent stages not moved",
             sa_all_at(db, 3, SA_N, 0));
    sqlite3_close(db);
    return failures;
}

/* A cap probe failing on one stage's log refuses the whole call and does not
 * advance that stage's cursor. */
static int sa_case_upstream_frontier_cap_error(const char *fixture_dir)
{
    int failures = 0;
    sqlite3 *db = sa_fresh(fixture_dir, "sa_up_capfail.db");
    SA_CHECK("cap error: db open", db != NULL);
    if (!db)
        return failures;
    SA_CHECK("cap error: header_admit_log is broken",
             sa_make_broken_log(db, "header_admit_log"));
    SA_CHECK("cap error: anchor refused",
             !stage_anchor_upstream_cursors_to(db, 100, "test", "cap", false));
    SA_CHECK("cap error: the failing stage did not move",
             sa_read(db, "header_admit") == 0);
    g_sa_boom = false;
    sqlite3_close(db);
    return failures;
}

/* A cursor that cannot be written (read-only store) refuses the call. */
static int sa_case_upstream_cursor_write_failure(const char *fixture_dir)
{
    int failures = 0;
    char path[256];
    snprintf(path, sizeof(path), "%s/sa_up_ro.db", fixture_dir);
    sqlite3 *db = sa_open(path);
    SA_CHECK("read-only: db open", db != NULL);
    if (!db)
        return failures;
    sqlite3_close(db);
    sqlite3 *ro = NULL;
    SA_CHECK("read-only: reopen read-only",
             sqlite3_open_v2(path, &ro, SQLITE_OPEN_READONLY, NULL) ==
                 SQLITE_OK);
    if (ro) {
        SA_CHECK("read-only: anchor refused when a cursor cannot advance",
                 !stage_anchor_upstream_cursors_to(ro, 100, "test", "ro",
                                                   false));
        SA_CHECK("read-only: cursor unchanged", sa_read(ro, "header_admit") == 0);
        sqlite3_close(ro);
    }
    unlink(path);
    return failures;
}

static int sa_gap_cases(const char *fixture_dir)
{
    int failures = 0;
    failures += sa_case_cap_hole(fixture_dir);
    failures += sa_case_cap_fresh_and_flat(fixture_dir);
    failures += sa_case_cap_bad_args(fixture_dir);
    failures += sa_case_cap_probe_failure(fixture_dir);
    failures += sa_case_cap_locked_database(fixture_dir);
    failures += sa_case_cap_long_name(fixture_dir);
    failures += sa_case_cap_releases_lock(fixture_dir);
    failures += sa_case_upstream_null_owner(fixture_dir);
    failures += sa_case_upstream_zero_frontier(fixture_dir);
    failures += sa_case_upstream_negative_frontier(fixture_dir);
    failures += sa_case_upstream_unreadable_frontier(fixture_dir);
    failures += sa_case_upstream_frontier_schema_blocked(fixture_dir);
    failures += sa_case_upstream_frontier_cap_error(fixture_dir);
    failures += sa_case_upstream_cursor_write_failure(fixture_dir);
    return failures;
}

int test_stage_anchor(void)
{
    printf("\n=== stage_anchor tests ===\n");
    int failures = 0;
    char fixture_dir[192];
    test_make_tmpdir(fixture_dir, sizeof(fixture_dir), "stage_anchor", "databases");

    /* ── Typed cursor reader distinguishes missing row from schema error ─ */
    failures += sa_check_cursor_read_schema_error(fixture_dir);
    failures += sa_check_cursor_read_missing_and_found_rows(fixture_dir);

    /* ── ATOMIC advance of multiple behind cursors to the target ──── */
    failures += sa_check_anchor_atomic_advance(fixture_dir);

    /* ── FORWARD-ONLY: a cursor at/above target is NEVER rewound ──── */
    {
        char path[256];
        (void)snprintf(path, sizeof(path), "%s/test_stage_anchor_norewind.db", fixture_dir);
        sqlite3 *db = sa_open(path);

        /* Seed one cursor ABOVE the future target and the rest below it. */
        const uint64_t target = 3000;
        const uint64_t high   = 9000;   /* above target → must not rewind */
        const uint64_t low    = 1000;   /* below target → advances        */

        failures += sa_check_anchor_with_one_cursor_above_target(db, target,
                                                                high, low);
        failures += sa_check_anchor_below_all_cursors_is_noop(db, target,
                                                             high);

        sqlite3_close(db);
        unlink(path);
    }

    /* ── IDEMPOTENT re-anchor to the same target is a no-op ───────── */
    {
        /* Under ./test-tmp, not the checkout root: this block's raw BEGIN
         * IMMEDIATE / ROLLBACK holds an open rollback journal for longer
         * than the other blocks' single autocommit writes, so a kill or
         * interrupted run between the BEGIN and the final unlink() used to
         * strand test_stage_anchor_idem.db-journal in the repo root. */
        char dir[192];
        test_make_tmpdir(dir, sizeof(dir), "stage_anchor", "idem");
        char path[256];
        snprintf(path, sizeof(path), "%s/stage_anchor_idem.db", dir);
        sqlite3 *db = sa_open(path);

        failures += sa_check_anchor_reanchor_is_idempotent(db);
        failures += sa_check_reanchor_joins_outer_transaction(db);

        sqlite3_close(db);
        test_cleanup_tmpdir(dir);
    }

    /* ── P2: utxo_apply never advances past coins_applied_height ──── */
    {
        char path[256];
        (void)snprintf(path, sizeof(path), "%s/test_stage_anchor_coins_cap.db", fixture_dir);
        sqlite3 *db = sa_open(path);
        SA_CHECK("coins_cap: db open", db != NULL);

        failures += sa_check_coins_cap_prime_and_anchor(db);
        failures += sa_check_coins_cap_caps_dependent_cursors(db);

        sqlite3_close(db);
        unlink(path);
    }

    /* ── Bad-arg guards: NULL db is a hard failure (false) ────────── */
    {
        SA_CHECK("NULL db returns false",
                 !stage_anchor_upstream_cursors_to(NULL, 1, "test", "null", false));
    }

    failures += sa_gap_cases(fixture_dir);

    test_cleanup_tmpdir(fixture_dir);
    if (failures == 0) {
        printf("=== stage_anchor tests: ALL PASS ===\n\n");
    } else {
        printf("=== stage_anchor tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
