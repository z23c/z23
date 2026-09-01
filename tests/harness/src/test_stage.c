/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the stage primitive (platform/modules/util/src/stage.c).
 *
 * Coverage:
 *   - create/destroy: input validation, default cursor at 0
 *   - run_once: JOB_ADVANCED commits cursor; survives close+reopen
 *   - run_once: JOB_BLOCKED leaves cursor untouched, blocker recorded
 *   - run_once: JOB_IDLE leaves cursor untouched
 *   - run_once: JOB_ADVANCED with non-monotonic cursor_out → ERROR + rollback
 *   - "crash mid-step" simulation: the step writes to a scratch table,
 *     then signals ERROR; on next run the scratch row is absent (the
 *     framework rolled back) and the cursor is the pre-step value.
 *   - stage_set_cursor: explicit restore round-trips
 *   - stage_set_named_cursor: named cursor stamping can intentionally rewind.
 *   - cursor writers inside an open drain batch: stage_set_cursor /
 *     stage_set_named_cursor / stage_set_named_cursor_if_behind must nest as
 *     a SAVEPOINT (a second BEGIN IMMEDIATE is rejected by SQLite with
 *     "cannot start a transaction within a transaction" — the io-speedups
 *     reorg bug on the tip_finalize rewind path), mark the batch dirty so a
 *     non-advancing drain still COMMITs the rewind, and roll back with it. */

#include "test/test_core.h"
#include "util/blocker.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define STG_CHECK(name, expr) do { \
    printf("stage: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Step functions for fixtures ─────────────────────────────────── */

struct ctx_advance_by_one { sqlite3 *db; int times_called; };

static job_result_t step_advance_by_one(struct stage_step_ctx *c)
{
    struct ctx_advance_by_one *u = c->user;
    u->times_called++;
    c->cursor_out = c->cursor_in + 1;
    return JOB_ADVANCED;
}

static job_result_t step_always_blocked(struct stage_step_ctx *c)
{
    blocker_init(&c->blocker, "stage-blocked-fixture", "test",
                 BLOCKER_TRANSIENT, "fixture says no");
    return JOB_BLOCKED;
}

static job_result_t step_always_idle(struct stage_step_ctx *c)
{
    (void)c;
    return JOB_IDLE;
}

static job_result_t step_advance_nonmono(struct stage_step_ctx *c)
{
    c->cursor_out = c->cursor_in;  /* contract violation */
    return JOB_ADVANCED;
}

/* Writes to a "scratch" table inside the txn, then returns ERROR. The
 * framework should roll back the scratch row AND leave the cursor at
 * its pre-step value, exactly as if the process had crashed between
 * the step body and the cursor commit. */
struct ctx_crash { sqlite3 *db; };
static job_result_t step_crash_mid(struct stage_step_ctx *c)
{
    struct ctx_crash *u = c->user;
    sqlite3_exec(u->db,
        "INSERT INTO scratch(v) VALUES (42)", NULL, NULL, NULL);
    c->cursor_out = c->cursor_in + 99;
    return JOB_FATAL;
}

/* Open a fresh in-memory DB and ensure the cursor table exists. */
static sqlite3 *open_db_with_schema(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return NULL;
    if (!stage_table_ensure(db)) { sqlite3_close(db); return NULL; }
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS scratch (v INTEGER)",
        NULL, NULL, NULL);
    return db;
}

static int64_t scratch_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM scratch", -1, &st, NULL);
    int64_t n = 0;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* Spy pre-commit hook: counts invocations and returns a settable verdict, so a
 * test can prove stage_batch_end() fires the hook BEFORE the outer COMMIT (a
 * false verdict must ROLLBACK the batch — the crash-ordering seam that keeps a
 * durable stage marker from outliving an unsynced on-disk artifact). */
static _Atomic int g_precommit_calls = 0;
static bool g_precommit_verdict = true;
static bool spy_precommit(void)
{
    atomic_fetch_add(&g_precommit_calls, 1);
    return g_precommit_verdict;
}

int test_stage(void)
{
    printf("\n=== stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── create/destroy + validation ─────────────────────────────── */
    {
        stage_t *s = stage_create("alpha", step_always_idle, NULL);
        STG_CHECK("create OK", s != NULL);
        STG_CHECK("name matches", strcmp(stage_name(s), "alpha") == 0);
        STG_CHECK("cursor starts at 0", stage_cursor(s) == 0);
        stage_destroy(s);

        STG_CHECK("create NULL name → NULL",
                  stage_create(NULL, step_always_idle, NULL) == NULL);
        STG_CHECK("create empty name → NULL",
                  stage_create("", step_always_idle, NULL) == NULL);
        STG_CHECK("create NULL step → NULL",
                  stage_create("x", NULL, NULL) == NULL);

        char too_long[STAGE_NAME_MAX + 8];
        memset(too_long, 'x', sizeof(too_long));
        too_long[sizeof(too_long) - 1] = '\0';
        STG_CHECK("create long name → NULL",
                  stage_create(too_long, step_always_idle, NULL) == NULL);

        stage_destroy(NULL);  /* must not crash */
    }

    /* ── ADVANCED commits + survives reopen ──────────────────────── */
    {
        const char *path = "test_stage_advance.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);
        STG_CHECK("db open", db != NULL);

        struct ctx_advance_by_one u = { .db = db, .times_called = 0 };
        stage_t *s = stage_create("counter", step_advance_by_one, &u);

        job_result_t r = stage_run_once(s, db);
        STG_CHECK("first run advances", r == JOB_ADVANCED);
        STG_CHECK("cursor=1 after first", stage_cursor(s) == 1);
        STG_CHECK("step invoked once", u.times_called == 1);

        /* Lane 1.1 (per-stage step latency/rate metrics): a step just ran,
         * so both fields must now be positive and equal (one sample seeds
         * the EWMA directly — see stage_record_step_timing). */
        STG_CHECK("last_step_us > 0 after first step",
                  stage_last_step_us(s) > 0);
        STG_CHECK("step_us_ewma > 0 after first step",
                  stage_step_us_ewma(s) > 0);
        STG_CHECK("step_us_ewma seeded from first sample",
                  stage_step_us_ewma(s) == stage_last_step_us(s));

        r = stage_run_once(s, db);
        STG_CHECK("second run advances", r == JOB_ADVANCED);
        STG_CHECK("cursor=2 after second", stage_cursor(s) == 2);
        STG_CHECK("last_step_us still > 0 after second step",
                  stage_last_step_us(s) > 0);
        STG_CHECK("step_us_ewma still > 0 after second step",
                  stage_step_us_ewma(s) > 0);

        STG_CHECK("advanced_count=2", stage_advanced_count(s) == 2);
        STG_CHECK("blocked_count=0",  stage_blocked_count(s) == 0);

        stage_destroy(s);
        sqlite3_close(db);

        /* Reopen and confirm the cursor persisted. We don't call
         * step here — just observe via a fresh stage handle. */
        db = open_db_with_schema(path);
        struct ctx_advance_by_one u2 = { .db = db, .times_called = 0 };
        stage_t *s2 = stage_create("counter", step_advance_by_one, &u2);

        /* Force a load via a single run; it should see cursor 2 and
         * advance to 3. */
        r = stage_run_once(s2, db);
        STG_CHECK("reopen sees persisted cursor",
                  r == JOB_ADVANCED && stage_cursor(s2) == 3);

        stage_destroy(s2);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── BLOCKED leaves cursor untouched, registers a blocker ───── */
    {
        blocker_reset_for_testing();
        const char *path = "test_stage_blocked.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);

        stage_t *s = stage_create("blocky", step_always_blocked, NULL);
        job_result_t r = stage_run_once(s, db);
        STG_CHECK("blocked returns BLOCKED", r == JOB_BLOCKED);
        STG_CHECK("cursor unchanged after BLOCKED", stage_cursor(s) == 0);
        STG_CHECK("blocked_count=1", stage_blocked_count(s) == 1);
        STG_CHECK("blocker recorded",
                  blocker_exists("stage-blocked-fixture"));
        /* Step timing is recorded for every verdict, not just ADVANCED —
         * a stage that is stuck naming the same blocker every tick still
         * needs its step latency visible. */
        STG_CHECK("last_step_us > 0 after BLOCKED step",
                  stage_last_step_us(s) > 0);

        stage_destroy(s);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── IDLE leaves cursor untouched ─────────────────────────── */
    {
        const char *path = "test_stage_idle.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);

        stage_t *s = stage_create("idler", step_always_idle, NULL);
        job_result_t r = stage_run_once(s, db);
        STG_CHECK("idle returns IDLE", r == JOB_IDLE);
        STG_CHECK("cursor unchanged after IDLE", stage_cursor(s) == 0);
        STG_CHECK("idle_count=1", stage_idle_count(s) == 1);
        STG_CHECK("last_step_us > 0 after IDLE step",
                  stage_last_step_us(s) > 0);

        stage_destroy(s);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── non-monotonic ADVANCED → ERROR + rollback ─────────────── */
    {
        const char *path = "test_stage_nonmono.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);

        /* First, get the cursor to 5. */
        struct ctx_advance_by_one u = { .db = db, .times_called = 0 };
        stage_t *s = stage_create("monocheck", step_advance_by_one, &u);
        for (int i = 0; i < 5; i++) stage_run_once(s, db);
        STG_CHECK("primed to 5", stage_cursor(s) == 5);
        stage_destroy(s);

        /* Swap in a step that claims ADVANCED but doesn't move. */
        stage_t *s2 = stage_create("monocheck", step_advance_nonmono, NULL);
        job_result_t r = stage_run_once(s2, db);
        STG_CHECK("nonmono ADVANCED → ERROR", r == JOB_FATAL);
        STG_CHECK("cursor still 5 after nonmono", stage_cursor(s2) == 5);
        stage_destroy(s2);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── crash-mid-step → rollback ─────────────────────────────── */
    {
        const char *path = "test_stage_crash.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);

        struct ctx_crash u = { .db = db };
        stage_t *s = stage_create("crasher", step_crash_mid, &u);

        STG_CHECK("scratch empty pre-run", scratch_count(db) == 0);
        job_result_t r = stage_run_once(s, db);
        STG_CHECK("ERROR returned", r == JOB_FATAL);
        STG_CHECK("cursor unchanged after crash", stage_cursor(s) == 0);
        STG_CHECK("scratch rolled back", scratch_count(db) == 0);

        stage_destroy(s);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── stage_set_cursor explicit restore ─────────────────────── */
    {
        const char *path = "test_stage_restore.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);

        stage_t *s = stage_create("restored", step_advance_by_one, NULL);
        bool ok = stage_set_cursor(s, db, 1000);
        STG_CHECK("set_cursor ok", ok);
        STG_CHECK("cursor=1000 in memory", stage_cursor(s) == 1000);
        stage_destroy(s);

        /* Reopen and confirm the persisted value via a fresh stage. */
        struct ctx_advance_by_one u = { .db = db, .times_called = 0 };
        stage_t *s2 = stage_create("restored", step_advance_by_one, &u);
        stage_run_once(s2, db);
        STG_CHECK("restored cursor visible after reload",
                  stage_cursor(s2) == 1001);

        stage_destroy(s2);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── stage_set_named_cursor exact restore/rewind ───────────── */
    {
        const char *path = "test_stage_named_restore.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);

        STG_CHECK("set_named_cursor forward ok",
                  stage_set_named_cursor(db, "named", 42));

        struct ctx_advance_by_one u = { .db = db, .times_called = 0 };
        stage_t *s = stage_create("named", step_advance_by_one, &u);
        job_result_t r = stage_run_once(s, db);
        STG_CHECK("named cursor visible after set",
                  r == JOB_ADVANCED && stage_cursor(s) == 43);
        stage_destroy(s);

        STG_CHECK("set_named_cursor rewind ok",
                  stage_set_named_cursor(db, "named", 7));

        struct ctx_advance_by_one u2 = { .db = db, .times_called = 0 };
        stage_t *s2 = stage_create("named", step_advance_by_one, &u2);
        r = stage_run_once(s2, db);
        STG_CHECK("named cursor visible after rewind",
                  r == JOB_ADVANCED && stage_cursor(s2) == 8);

        stage_destroy(s2);
        sqlite3_close(db);
        unlink(path);
    }

    /* ── batch pre-commit hook (crash-ordering seam) ─────────────── */
    {
        const char *path = "test_stage_precommit.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);
        STG_CHECK("precommit: db open", db != NULL);

        stage_batch_set_precommit_hook(spy_precommit);

        /* Permit path: hook fires on commit, batch commits, row is durable. */
        atomic_store(&g_precommit_calls, 0);
        g_precommit_verdict = true;
        STG_CHECK("precommit: batch_begin", stage_batch_begin(db));
        sqlite3_exec(db, "INSERT INTO scratch(v) VALUES (7)", NULL, NULL, NULL);
        STG_CHECK("precommit: commit end ok", stage_batch_end(db, true));
        STG_CHECK("precommit: hook fired once on commit",
                  atomic_load(&g_precommit_calls) == 1);
        STG_CHECK("precommit: committed row durable", scratch_count(db) == 1);
        STG_CHECK("precommit: batch closed after commit", !stage_batch_active());

        /* ROLLBACK never calls the hook (nothing is being made durable). */
        atomic_store(&g_precommit_calls, 0);
        STG_CHECK("precommit: batch_begin 2", stage_batch_begin(db));
        sqlite3_exec(db, "INSERT INTO scratch(v) VALUES (8)", NULL, NULL, NULL);
        STG_CHECK("precommit: rollback end ok", stage_batch_end(db, false));
        STG_CHECK("precommit: hook NOT fired on rollback",
                  atomic_load(&g_precommit_calls) == 0);
        STG_CHECK("precommit: rolled-back row absent", scratch_count(db) == 1);

        /* Veto path: hook returns false → COMMIT is refused and the batch is
         * rolled back, so the row that referenced the (would-be) unsynced
         * artifact never becomes durable. This is the ordering proof: a hook
         * that ran AFTER commit could not undo it. */
        atomic_store(&g_precommit_calls, 0);
        g_precommit_verdict = false;
        STG_CHECK("precommit: batch_begin 3", stage_batch_begin(db));
        sqlite3_exec(db, "INSERT INTO scratch(v) VALUES (9)", NULL, NULL, NULL);
        STG_CHECK("precommit: veto end returns false",
                  !stage_batch_end(db, true));
        STG_CHECK("precommit: hook fired once on veto",
                  atomic_load(&g_precommit_calls) == 1);
        STG_CHECK("precommit: vetoed row NOT durable (rolled back)",
                  scratch_count(db) == 1);
        STG_CHECK("precommit: batch closed after veto", !stage_batch_active());

        /* Un-register: subsequent commits proceed with no hook. MUST run so the
         * process-global hook does not leak into sibling test groups. */
        stage_batch_set_precommit_hook(NULL);
        g_precommit_verdict = true;
        atomic_store(&g_precommit_calls, 0);
        STG_CHECK("precommit: batch_begin 4", stage_batch_begin(db));
        sqlite3_exec(db, "INSERT INTO scratch(v) VALUES (10)", NULL, NULL, NULL);
        STG_CHECK("precommit: commit after unregister",
                  stage_batch_end(db, true));
        STG_CHECK("precommit: no hook after unregister",
                  atomic_load(&g_precommit_calls) == 0);
        STG_CHECK("precommit: row durable after unregister",
                  scratch_count(db) == 2);

        sqlite3_close(db);
        unlink(path);
    }

    /* ── cursor writers inside an open batch (io-speedups reorg bug) ──
     * Regression: the standalone cursor writers once opened an unconditional
     * BEGIN IMMEDIATE. Inside a drain batch — the tip_finalize reorg-rewind
     * path calls stage_set_cursor with the batch open — SQLite rejected the
     * nested BEGIN ("cannot start a transaction within a transaction"). They
     * must now nest as a named SAVEPOINT, enrol in the outer batch, and mark
     * it dirty so a non-advancing drain COMMITs the rewind instead of
     * rolling it back (mirrors stage_run_once's batched shape). */
    {
        const char *path = "test_stage_batch_cursor.db";
        unlink(path);
        sqlite3 *db = open_db_with_schema(path);
        STG_CHECK("batch-cursor: db open", db != NULL);

        stage_t *s = stage_create("rewinder", step_advance_by_one, NULL);

        /* Unbatched baseline: unchanged behavior (own BEGIN IMMEDIATE). */
        STG_CHECK("batch-cursor: unbatched set_cursor ok",
                  stage_set_cursor(s, db, 10));
        STG_CHECK("batch-cursor: unbatched cursor=10", stage_cursor(s) == 10);

        /* Rewind INSIDE an open batch. Pre-fix this returned false on the
         * nested BEGIN; now the savepoint nests and the write succeeds. */
        STG_CHECK("batch-cursor: batch_begin", stage_batch_begin(db));
        STG_CHECK("batch-cursor: batched set_cursor rewind ok",
                  stage_set_cursor(s, db, 4));
        STG_CHECK("batch-cursor: rewind marked batch dirty",
                  stage_batch_dirty());
        STG_CHECK("batch-cursor: batch still open after rewind",
                  stage_batch_active());

        /* The named writers must nest the same way. */
        STG_CHECK("batch-cursor: batched set_named_cursor ok",
                  stage_set_named_cursor(db, "named2", 9));
        STG_CHECK("batch-cursor: batched if_behind raise ok",
                  stage_set_named_cursor_if_behind(db, "named2", 12));
        /* No-op if_behind (already ahead): must NOT roll the batch back —
         * the outer batch has to survive to COMMIT the earlier writes. */
        STG_CHECK("batch-cursor: batched if_behind no-op ok",
                  stage_set_named_cursor_if_behind(db, "named2", 5));
        STG_CHECK("batch-cursor: batch survived no-op if_behind",
                  stage_batch_active());

        /* Commit the way a drain with advanced==0 does: the dirty flag
         * carries the rewind into the COMMIT. */
        STG_CHECK("batch-cursor: batch_end commit ok",
                  stage_batch_end(db, stage_batch_dirty()));
        STG_CHECK("batch-cursor: batch closed after commit",
                  !stage_batch_active());

        /* A rolled-back batch discards the enclosed rewind. */
        STG_CHECK("batch-cursor: batch_begin 2", stage_batch_begin(db));
        STG_CHECK("batch-cursor: batched set_cursor 2 ok",
                  stage_set_cursor(s, db, 2));
        STG_CHECK("batch-cursor: batch_end rollback ok",
                  stage_batch_end(db, false));
        STG_CHECK("batch-cursor: batch closed after rollback",
                  !stage_batch_active());
        stage_destroy(s);

        /* Durability proof: reopen and observe only the COMMITted values
         * (rewinder=4, named2=12) — the rolled-back 2 is gone. A fresh
         * stage loads the persisted cursor on its first run. */
        sqlite3_close(db);
        db = open_db_with_schema(path);
        struct ctx_advance_by_one u = { .db = db, .times_called = 0 };
        stage_t *s2 = stage_create("rewinder", step_advance_by_one, &u);
        job_result_t r = stage_run_once(s2, db);
        STG_CHECK("batch-cursor: rewound cursor durable",
                  r == JOB_ADVANCED && stage_cursor(s2) == 5);
        stage_destroy(s2);
        struct ctx_advance_by_one u2 = { .db = db, .times_called = 0 };
        stage_t *s3 = stage_create("named2", step_advance_by_one, &u2);
        r = stage_run_once(s3, db);
        STG_CHECK("batch-cursor: named raise durable",
                  r == JOB_ADVANCED && stage_cursor(s3) == 13);
        stage_destroy(s3);

        sqlite3_close(db);
        unlink(path);
    }

    /* ── result name helper ────────────────────────────────────── */
    {
        STG_CHECK("name ADVANCED",
                  strcmp(stage_result_name(JOB_ADVANCED), "advanced") == 0);
        STG_CHECK("name BLOCKED",
                  strcmp(stage_result_name(JOB_BLOCKED), "blocked") == 0);
        STG_CHECK("name IDLE",
                  strcmp(stage_result_name(JOB_IDLE), "idle") == 0);
        STG_CHECK("name ERROR",
                  strcmp(stage_result_name(JOB_FATAL), "error") == 0);
        STG_CHECK("name invalid",
                  strcmp(stage_result_name((job_result_t)99),
                         "(invalid)") == 0);
    }

    blocker_reset_for_testing();

    if (failures == 0) {
        printf("=== stage tests: ALL PASS ===\n\n");
    } else {
        printf("=== stage tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
