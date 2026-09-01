/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_lcc_write_rules — Log-Cursor Contiguity write rules at the single
 * cursor-write chokepoint. See util/stage_lcc.h and
 * docs/work/fail-safe-architecture.md §0c Design B.
 *
 * Proves the wedge-prevention contract:
 *   1. a contiguous raise is ACCEPTED and persists,
 *   2. a raise over a ROWLESS hole is REFUSED and does NOT persist,
 *   3. an interior-hole raise is REFUSED,
 *   4. a trusted-base install exempts heights below the base,
 *   5. a DELETE clamps the cursor to the surviving frontier.
 *
 * Drives the real public API (stage_set_named_cursor{,_if_behind},
 * stage_cursor_clamp_to) against a temp sqlite store carrying one synthetic
 * height-keyed `<stage>_log`, so it exercises the guard exactly as the fold
 * does — no fixtures, no live datadir. */

#include "storage/progress_store.h"
#include "util/stage.h"
#include "util/stage_lcc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LCC_CHECK(name, expr) do { \
    printf("lcc_write_rules: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* The stage under test: a plausible stage name whose derived log table is
 * "foldstage_log". Using a private name keeps the test independent of the real
 * stages' schemas. */
#define LCC_STAGE "foldstage"

static bool exec_ok(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("[lcc] exec failed: %s (%s)\n", err ? err : "?", sql);
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) sqlite3_free(err);
    return true;
}

/* Insert a contiguous run of log rows for heights [lo, hi). */
static bool insert_rows(sqlite3 *db, uint64_t lo, uint64_t hi)
{
    for (uint64_t h = lo; h < hi; h++) {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO \"" LCC_STAGE "_log\"(height,ok) "
                 "VALUES(%llu,1)", (unsigned long long)h);
        if (!exec_ok(db, sql))
            return false;
    }
    return true;
}

static uint64_t read_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name=?1",
                           -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    uint64_t v = 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

struct lcc_batch_step_state {
    sqlite3 *db;
    const char *stage_name;
    int64_t skip_height;
};

static job_result_t lcc_batch_step(struct stage_step_ctx *ctx)
{
    struct lcc_batch_step_state *s = ctx ? ctx->user : NULL;
    if (!s || !s->db || !s->stage_name)
        return JOB_FATAL;
    if ((int64_t)ctx->cursor_in != s->skip_height) {
        char sql[192];
        snprintf(sql, sizeof sql,
                 "INSERT INTO \"%s_log\"(height,ok) VALUES(%llu,1)",
                 s->stage_name, (unsigned long long)ctx->cursor_in);
        if (!exec_ok(s->db, sql))
            return JOB_FATAL;
    }
    ctx->cursor_out = ctx->cursor_in + 1;
    return JOB_ADVANCED;
}

int test_lcc_write_rules(void);
int test_lcc_write_rules(void)
{
    int failures = 0;
    printf("\n=== Log-Cursor Contiguity write rules ===\n");

    sqlite3 *db = NULL;
    /* Private temp file DB (WAL not needed); the guard only needs stage_cursor
     * + progress_meta + a height-keyed stage log. */
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        printf("lcc_write_rules: open... FAIL\n");
        return 1;
    }

    bool schema_ok =
        stage_table_ensure(db) &&
        progress_meta_table_ensure(db) &&
        exec_ok(db, "CREATE TABLE \"" LCC_STAGE "_log\"("
                    "height INTEGER PRIMARY KEY, ok INTEGER NOT NULL)");
    LCC_CHECK("schema", schema_ok);

    /* Enforcement is OFF by default: the chokepoint must ALLOW even an
     * incoherent raise (so enabling the guard can never brick an existing
     * boot). The predicate still computes the verdict. */
    LCC_CHECK("enforcement OFF by default",
              !stage_lcc_enforcement_enabled(db));
    char err[192];
    LCC_CHECK("OFF: predicate flags rowless 0->3 as incoherent",
              !stage_lcc_check_raise(db, LCC_STAGE, 0, 3, err, sizeof err));
    LCC_CHECK("OFF: chokepoint ALLOWS the incoherent raise 0->3",
              stage_set_named_cursor(db, LCC_STAGE, 3) &&
              read_cursor(db, LCC_STAGE) == 3);
    /* Reset the cursor and turn enforcement ON for the rest of the test. */
    LCC_CHECK("reset cursor to 0",
              stage_cursor_clamp_to(db, LCC_STAGE, 0) &&
              read_cursor(db, LCC_STAGE) == 0);
    LCC_CHECK("enable enforcement", stage_lcc_set_enforcement_in_tx(db, true));
    LCC_CHECK("enforcement now ON", stage_lcc_enforcement_enabled(db));

    /* Rows for [0,5) exist. A raise 0 -> 5 covers exactly those heights. */
    LCC_CHECK("seed rows [0,5)", insert_rows(db, 0, 5));
    LCC_CHECK("contiguous raise 0->5 ACCEPTED",
              stage_set_named_cursor(db, LCC_STAGE, 5));
    LCC_CHECK("cursor persisted at 5", read_cursor(db, LCC_STAGE) == 5);

    /* Direct guard predicate: a fully-backed span is coherent. */
    LCC_CHECK("check_raise 0->5 true",
              stage_lcc_check_raise(db, LCC_STAGE, 0, 5, err, sizeof err));

    /* Rowless hole: rows 5,6 are absent, so a raise 5 -> 7 must be REFUSED and
     * must NOT move the persisted cursor. This is the borrowed-seed wedge made
     * unwritable. */
    LCC_CHECK("check_raise 5->7 over rowless hole REFUSED",
              !stage_lcc_check_raise(db, LCC_STAGE, 5, 7, err, sizeof err));
    LCC_CHECK("refusal names first gap height=5",
              strstr(err, "height=5") != NULL);
    LCC_CHECK("rowless raise 5->7 does NOT persist (chokepoint)",
              !stage_set_named_cursor(db, LCC_STAGE, 7));
    LCC_CHECK("cursor still 5 after refused raise",
              read_cursor(db, LCC_STAGE) == 5);
    LCC_CHECK("set_named_cursor_if_behind also refuses rowless raise",
              !stage_set_named_cursor_if_behind(db, LCC_STAGE, 7));
    LCC_CHECK("cursor still 5 after refused if_behind",
              read_cursor(db, LCC_STAGE) == 5);

    /* Fill the covering rows; the same raise now becomes coherent. */
    LCC_CHECK("fill rows [5,7)", insert_rows(db, 5, 7));
    LCC_CHECK("now-contiguous raise 5->7 ACCEPTED",
              stage_set_named_cursor(db, LCC_STAGE, 7));
    LCC_CHECK("cursor persisted at 7", read_cursor(db, LCC_STAGE) == 7);

    /* Interior hole: rows [7,9) exist but 9 is missing, so a raise 7 -> 11
     * (needs 7,8,9,10) has an interior hole at 9 -> REFUSED. */
    LCC_CHECK("fill rows [7,9) leave 9,10 missing", insert_rows(db, 7, 9));
    LCC_CHECK("interior-hole raise 7->11 REFUSED",
              !stage_lcc_check_raise(db, LCC_STAGE, 7, 11, err, sizeof err));
    LCC_CHECK("interior refusal names gap height=9",
              strstr(err, "height=9") != NULL);

    /* Trusted base: declare heights below 20 vetted, then a raise 7 -> 25 with
     * rows only for [20,25) is ACCEPTED (the [7,20) span is base-exempt). */
    LCC_CHECK("set trusted base = 20",
              stage_lcc_set_trusted_base_in_tx(db, 20));
    LCC_CHECK("trusted base reads back 20",
              stage_lcc_trusted_base(db) == 20);
    LCC_CHECK("rows [20,25) present", insert_rows(db, 20, 25));
    LCC_CHECK("base-exempt raise 7->25 ACCEPTED (below base rowless)",
              stage_lcc_check_raise(db, LCC_STAGE, 7, 25, err, sizeof err));
    /* But a hole ABOVE the base is still refused: raise to 27 needs rows 25,26;
     * 26 is absent. */
    LCC_CHECK("above-base hole raise 7->27 still REFUSED",
              !stage_lcc_check_raise(db, LCC_STAGE, 7, 27, err, sizeof err));

    /* DELETE-rule clamp: drive the cursor to a real frontier, delete the top
     * rows, and prove the clamp lowers the cursor to the surviving frontier so
     * no cursor is ever left above a deleted row. */
    LCC_CHECK("advance cursor to 25 for clamp test",
              stage_set_named_cursor(db, LCC_STAGE, 25));
    LCC_CHECK("cursor at 25", read_cursor(db, LCC_STAGE) == 25);
    LCC_CHECK("delete rows [22,25)",
              exec_ok(db, "DELETE FROM \"" LCC_STAGE "_log\" WHERE height >= 22"));
    LCC_CHECK("clamp to 22 lowers cursor",
              stage_cursor_clamp_to(db, LCC_STAGE, 22));
    LCC_CHECK("cursor clamped to 22", read_cursor(db, LCC_STAGE) == 22);
    LCC_CHECK("clamp is a no-op when already at/below max",
              stage_cursor_clamp_to(db, LCC_STAGE, 100) &&
              read_cursor(db, LCC_STAGE) == 22);
    /* After the delete+clamp, re-raising over the now-rowless [22,25) is
     * refused again — the delete cannot be silently re-covered. */
    LCC_CHECK("re-raise 22->25 over deleted rows REFUSED",
              !stage_set_named_cursor(db, LCC_STAGE, 25) &&
              read_cursor(db, LCC_STAGE) == 22);

    /* A non-stage cursor (no `<name>_log` table) is exempt: the guard never
     * blocks arbitrary named cursors. */
    LCC_CHECK("non-stage named cursor is exempt",
              stage_set_named_cursor(db, "some_helper_cursor", 999) &&
              read_cursor(db, "some_helper_cursor") == 999);

    /* Clear the trusted base before the batch sections. Those sections drive
     * their stages from height 0, and the base=20 left by the section above
     * would make heights [0,21) wholly base-exempt — the batch-hole case would
     * then be ALLOWED for a reason that has nothing to do with the batch commit
     * boundary it is meant to prove, and the contiguous case would pass without
     * its rows being consulted. Both batch assertions are only meaningful with
     * nothing exempted. */
    LCC_CHECK("reset trusted base to 0 for the batch sections",
              stage_lcc_set_trusted_base_in_tx(db, 0) &&
              stage_lcc_trusted_base(db) == 0);

    /* A batched stage coalesces its repeated cursor checks to the only
     * externally-visible boundary. Prove both sides: a complete range commits;
     * one missing row vetoes and rolls back the entire batch. */
    LCC_CHECK("batch: create contiguous log",
              exec_ok(db, "CREATE TABLE batchstage_log("
                          "height INTEGER PRIMARY KEY, ok INTEGER NOT NULL)"));
    struct lcc_batch_step_state good = { db, "batchstage", -1 };
    stage_t *good_stage = stage_create("batchstage", lcc_batch_step, &good);
    LCC_CHECK("batch: contiguous stage created", good_stage != NULL);
    LCC_CHECK("batch: contiguous begin", stage_batch_begin(db));
    LCC_CHECK("batch: contiguous advances twice",
              stage_run_once(good_stage, db) == JOB_ADVANCED &&
              stage_run_once(good_stage, db) == JOB_ADVANCED);
    LCC_CHECK("batch: contiguous boundary commits",
              stage_batch_end(db, true));
    LCC_CHECK("batch: contiguous cursor durable",
              read_cursor(db, "batchstage") == 2);
    stage_destroy(good_stage);

    LCC_CHECK("batch-hole: create log",
              exec_ok(db, "CREATE TABLE batchhole_log("
                          "height INTEGER PRIMARY KEY, ok INTEGER NOT NULL)"));
    struct lcc_batch_step_state hole = { db, "batchhole", 1 };
    stage_t *hole_stage = stage_create("batchhole", lcc_batch_step, &hole);
    LCC_CHECK("batch-hole: stage created", hole_stage != NULL);
    LCC_CHECK("batch-hole: begin", stage_batch_begin(db));
    LCC_CHECK("batch-hole: in-transaction cursors advance",
              stage_run_once(hole_stage, db) == JOB_ADVANCED &&
              stage_run_once(hole_stage, db) == JOB_ADVANCED);
    LCC_CHECK("batch-hole: commit boundary REFUSES the range",
              !stage_batch_end(db, true));
    LCC_CHECK("batch-hole: cursor rollback is durable",
              read_cursor(db, "batchhole") == 0 && !stage_batch_active());
    stage_destroy(hole_stage);

    sqlite3_close(db);

    if (failures == 0)
        printf("=== LCC write rules: ALL OK ===\n");
    else
        printf("=== LCC write rules: %d FAILURE(S) ===\n", failures);
    return failures;
}
