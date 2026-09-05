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

#include <sqlite3.h>
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

int test_stage_anchor(void)
{
    printf("\n=== stage_anchor tests ===\n");
    int failures = 0;

    /* ── Typed cursor reader distinguishes missing row from schema error ─ */
    {
        const char *path = "test_stage_cursor_read_contract.db";
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
        db = sa_open(path);
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
    }

    /* ── ATOMIC advance of multiple behind cursors to the target ──── */
    {
        const char *path = "test_stage_anchor_advance.db";
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
    }

    /* ── FORWARD-ONLY: a cursor at/above target is NEVER rewound ──── */
    {
        const char *path = "test_stage_anchor_norewind.db";
        sqlite3 *db = sa_open(path);

        /* Seed one cursor ABOVE the future target and the rest below it. */
        const uint64_t target = 3000;
        const uint64_t high   = 9000;   /* above target → must not rewind */
        const uint64_t low    = 1000;   /* below target → advances        */

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

        /* Anchor to a value BELOW every current cursor → pure no-op. */
        ok = stage_anchor_upstream_cursors_to(db, 50, "test", "below-all", false);
        SA_CHECK("anchor below-all returns true", ok);
        SA_CHECK("high cursor still high after below-all anchor",
                 sa_read(db, "script_validate") == high);
        bool none_rewound = true;
        for (size_t i = 0; i < SA_N; i++) {
            if (i == 4) continue;
            if (sa_read(db, SA_UPSTREAM[i]) != target) none_rewound = false;
        }
        SA_CHECK("no cursor rewound by below-all anchor", none_rewound);

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

        /* A larger atomic cutover may already own the SQLite transaction. An
         * idempotent re-anchor must remain a pure read/no-op and must not try to
         * nest the standalone cursor writer's BEGIN. */
        bool outer_open = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL,
                                       NULL) == SQLITE_OK;
        ok = outer_open && stage_anchor_upstream_cursors_to(
            db, 4242, "test", "outer-transaction-noop", true);
        bool outer_still_open = sqlite3_get_autocommit(db) == 0;
        bool outer_rolled_back = sqlite3_exec(db, "ROLLBACK", NULL, NULL,
                                              NULL) == SQLITE_OK;
        SA_CHECK("same-target re-anchor joins outer transaction as no-op",
                 ok && outer_still_open && outer_rolled_back);

        sqlite3_close(db);
        test_cleanup_tmpdir(dir);
    }

    /* ── P2: utxo_apply never advances past coins_applied_height ──── */
    {
        const char *path = "test_stage_anchor_coins_cap.db";
        sqlite3 *db = sa_open(path);
        SA_CHECK("coins_cap: db open", db != NULL);

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

        sqlite3_close(db);
        unlink(path);
    }

    /* ── Bad-arg guards: NULL db is a hard failure (false) ────────── */
    {
        SA_CHECK("NULL db returns false",
                 !stage_anchor_upstream_cursors_to(NULL, 1, "test", "null", false));
    }

    if (failures == 0) {
        printf("=== stage_anchor tests: ALL PASS ===\n\n");
    } else {
        printf("=== stage_anchor tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
