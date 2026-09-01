/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for nullifier_kv — the reducer's consensus shielded-nullifier
 * set as a `nullifiers` table IN progress.kv (C-3). The load-bearing
 * assertions are the (nf,pool) NAMESPACE SEPARATION (zclassicd keeps
 * distinct Sprout/Sapling maps, coins.cpp:166-180 — a single-column nf key
 * would reject legal cross-pool byte-reuse, an opposite-direction fork) and
 * the exact bounds of delete_range, the rewind primitive every cursor
 * rewind relies on (see the rewind invariant in storage/nullifier_kv.h). */

#include "test/test_core.h"

#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define NK_CHECK(name, expr) do {                                        \
    if (expr) { printf("  nullifier_kv: %s... OK\n", (name)); }          \
    else { printf("  nullifier_kv: %s... FAIL\n", (name)); failures++; } \
} while (0)

static void nk_nf(uint8_t out[32], uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = tag;
    out[1] = 0x4E;
    out[31] = 0x77;
}

static int64_t nk_count(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM nullifiers",
                           -1, &s, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

static bool nk_marker_is(sqlite3 *db, const char *want)
{
    char buf[24] = {0};
    size_t len = 0;
    bool found = false;
    size_t want_len = strlen(want);
    return progress_meta_get(db, "nullifier_kv.activation_cursor",
                             buf, sizeof(buf), &len, &found) &&
           found && len == want_len && memcmp(buf, want, want_len) == 0;
}

static bool ak_both_anchor_cursors_are(sqlite3 *db, int64_t want)
{
    int64_t sprout = -1, sapling = -1;
    bool sprout_found = false, sapling_found = false;
    return anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SPROUT, &sprout, &sprout_found) &&
           anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SAPLING, &sapling, &sapling_found) &&
           sprout_found && sapling_found &&
           sprout == want && sapling == want;
}

static bool nk_all_history_markers_are(sqlite3 *db, int64_t want)
{
    int64_t sprout = -1, sapling = -1, nf = -1;
    bool sprout_found = false, sapling_found = false, nf_found = false;
    return anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SPROUT, &sprout, &sprout_found) &&
           anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SAPLING, &sapling, &sapling_found) &&
           nullifier_kv_activation_cursor(db, &nf, &nf_found) &&
           sprout_found && sapling_found && nf_found &&
           sprout == want && sapling == want && nf == want;
}

/* The reset primitives REFUSE autocommit (they require the caller's open
 * transaction, unlike anchor_kv_reset which falls back to its own IMMEDIATE tx).
 * Run each inside its own BEGIN IMMEDIATE..COMMIT so the unit test exercises the
 * same in-tx contract the boot/refold callers hold. A refusal inside the txn
 * (e.g. a negative below-height) rolls back and returns false. */
static bool nk_reset_complete_tx(sqlite3 *db)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              nullifier_kv_reset_mark_complete_in_tx(db) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    return ok;
}

static bool nk_reset_empty_below_tx(sqlite3 *db, int64_t below_height)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              nullifier_kv_reset_mark_empty_below_in_tx(db, below_height) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    return ok;
}

static bool nk_replay_advance(sqlite3 *db, int64_t height, int64_t target)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              shielded_history_full_replay_advance_in_tx(
                  db, height, target) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    return ok;
}

int test_nullifier_kv(void);
int test_nullifier_kv(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "nullifier_kv", "main");

    NK_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    NK_CHECK("db handle", db != NULL);

    /* First adoption is atomic: if the marker insert fails, schema creation
     * rolls back too, so a crash/failure cannot leave a table that later looks
     * complete merely because it exists. */
    NK_CHECK("table absent before ensure", !nullifier_kv_table_exists(db));
    NK_CHECK("failure trigger installs",
             sqlite3_exec(db,
                 "CREATE TRIGGER fail_nf_marker BEFORE INSERT ON progress_meta "
                 "WHEN NEW.key='nullifier_kv.activation_cursor' BEGIN "
                 "SELECT RAISE(ABORT,'marker refused'); END",
                 NULL, NULL, NULL) == SQLITE_OK);
    NK_CHECK("marker failure rejects first adoption",
             !nullifier_kv_initialize_history(db, 42));
    NK_CHECK("failed adoption rolled schema back",
             !nullifier_kv_table_exists(db));
    NK_CHECK("failure trigger drops",
             sqlite3_exec(db, "DROP TRIGGER fail_nf_marker", NULL, NULL,
                          NULL) == SQLITE_OK);

    /* A precreated empty table plus absent marker models the old DDL/marker
     * crash window. Initializing at a nonzero reducer cursor must stamp the
     * unknown prefix, never infer completeness from table existence. */
    NK_CHECK("ensure_schema", nullifier_kv_ensure_schema(db));
    NK_CHECK("table present after ensure", nullifier_kv_table_exists(db));
    NK_CHECK("precreated table initializes conservative cursor",
             nullifier_kv_initialize_history(db, 42));
    NK_CHECK("nonzero adoption marker is explicit", nk_marker_is(db, "42"));
    NK_CHECK("existing marker is never overwritten",
             nullifier_kv_initialize_history(db, 99) &&
             nk_marker_is(db, "42"));
    NK_CHECK("test removes marker",
             progress_meta_delete(db, "nullifier_kv.activation_cursor"));
    {
        int64_t cursor = -1;
        bool found = true;
        NK_CHECK("strict cursor reports missing as unknown",
                 nullifier_kv_activation_cursor(db, &cursor, &found) &&
                 !found);
    }
    NK_CHECK("from-genesis adoption writes explicit zero",
             nullifier_kv_initialize_history(db, 0) && nk_marker_is(db, "0"));
    {
        int64_t cursor = -1;
        bool found = false;
        NK_CHECK("strict cursor reads explicit zero",
                 nullifier_kv_activation_cursor(db, &cursor, &found) &&
                 found && cursor == 0);
    }
    NK_CHECK("ensure_schema idempotent", nullifier_kv_ensure_schema(db));
    NK_CHECK("count empty == 0", nk_count(db) == 0);

    /* add/get round-trip: presence + revealing height. */
    uint8_t n1[32];
    nk_nf(n1, 0x11);
    NK_CHECK("add n1 sprout h=100",
             nullifier_kv_add(db, n1, NULLIFIER_POOL_SPROUT, 100));
    {
        bool found = false;
        int64_t h = -1;
        NK_CHECK("get n1 sprout ok",
                 nullifier_kv_get(db, n1, NULLIFIER_POOL_SPROUT, &found, &h));
        NK_CHECK("get n1 sprout found at h=100", found && h == 100);
    }

    /* Miss: a clean found=false, NOT a store error. */
    {
        uint8_t miss[32];
        nk_nf(miss, 0xEE);
        bool found = true;
        NK_CHECK("get miss ok (no error)",
                 nullifier_kv_get(db, miss, NULLIFIER_POOL_SPROUT,
                                  &found, NULL));
        NK_CHECK("get miss found=false", !found);
    }

    /* (nf,pool) NAMESPACE SEPARATION: the SAME 32 bytes live independently
     * in each pool — one row per pool, neither read sees the other. */
    NK_CHECK("add n1 sapling h=200",
             nullifier_kv_add(db, n1, NULLIFIER_POOL_SAPLING, 200));
    NK_CHECK("count == 2 (one row per pool)", nk_count(db) == 2);
    {
        bool fs = false, fz = false;
        int64_t hs = -1, hz = -1;
        NK_CHECK("get n1 sprout still ok",
                 nullifier_kv_get(db, n1, NULLIFIER_POOL_SPROUT, &fs, &hs));
        NK_CHECK("get n1 sapling ok",
                 nullifier_kv_get(db, n1, NULLIFIER_POOL_SAPLING, &fz, &hz));
        NK_CHECK("pools keep separate heights",
                 fs && hs == 100 && fz && hz == 200);
    }

    /* nullifier_kv_row_count: the per-pool diagnostic count backing
     * `dumpstate rom_compile`'s shielded_import.nullifier.*_imported —
     * agrees with the combined nk_count() and reports each pool
     * independently (the same (nf,pool) namespace separation above). */
    {
        int64_t sprout_n = -1, sapling_n = -1;
        NK_CHECK("row_count sprout ok",
                 nullifier_kv_row_count(db, NULLIFIER_POOL_SPROUT, &sprout_n));
        NK_CHECK("row_count sapling ok",
                 nullifier_kv_row_count(db, NULLIFIER_POOL_SAPLING,
                                        &sapling_n));
        NK_CHECK("row_count per-pool == 1 each", sprout_n == 1 &&
                 sapling_n == 1);
        NK_CHECK("row_count sum agrees with combined nk_count",
                 sprout_n + sapling_n == nk_count(db));
        NK_CHECK("row_count rejects an invalid pool",
                 !nullifier_kv_row_count(db, 2, &sprout_n));
    }

    /* INSERT OR REPLACE idempotence: re-adding the same (nf,pool) keeps ONE
     * row and takes the latest height. */
    NK_CHECK("re-add n1 sprout h=150",
             nullifier_kv_add(db, n1, NULLIFIER_POOL_SPROUT, 150));
    NK_CHECK("count still 2 after re-add", nk_count(db) == 2);
    {
        bool found = false;
        int64_t h = -1;
        NK_CHECK("re-add read ok",
                 nullifier_kv_get(db, n1, NULLIFIER_POOL_SPROUT, &found, &h));
        NK_CHECK("re-add replaced height", found && h == 150);
    }

    /* delete_range EXACT BOUNDS: rows at 5/6/7; deleting [6,6] removes only
     * the middle; deleting [5,7] removes the rest. Both bounds INCLUSIVE. */
    {
        uint8_t a[32], b[32], c[32];
        nk_nf(a, 0xA5);
        nk_nf(b, 0xB6);
        nk_nf(c, 0xC7);
        NK_CHECK("seed h=5", nullifier_kv_add(db, a, NULLIFIER_POOL_SAPLING, 5));
        NK_CHECK("seed h=6", nullifier_kv_add(db, b, NULLIFIER_POOL_SAPLING, 6));
        NK_CHECK("seed h=7", nullifier_kv_add(db, c, NULLIFIER_POOL_SAPLING, 7));
        NK_CHECK("delete [6,6]", nullifier_kv_delete_range(db, 6, 6));
        bool fa = false, fb = true, fc = false;
        NK_CHECK("h=5 survives [6,6]",
                 nullifier_kv_get(db, a, NULLIFIER_POOL_SAPLING, &fa, NULL) &&
                 fa);
        NK_CHECK("h=6 deleted by [6,6]",
                 nullifier_kv_get(db, b, NULLIFIER_POOL_SAPLING, &fb, NULL) &&
                 !fb);
        NK_CHECK("h=7 survives [6,6]",
                 nullifier_kv_get(db, c, NULLIFIER_POOL_SAPLING, &fc, NULL) &&
                 fc);
        NK_CHECK("delete [5,7]", nullifier_kv_delete_range(db, 5, 7));
        fa = fc = true;
        NK_CHECK("h=5 deleted by [5,7]",
                 nullifier_kv_get(db, a, NULLIFIER_POOL_SAPLING, &fa, NULL) &&
                 !fa);
        NK_CHECK("h=7 deleted by [5,7]",
                 nullifier_kv_get(db, c, NULLIFIER_POOL_SAPLING, &fc, NULL) &&
                 !fc);
        /* The h=100/150/200 rows from earlier sections are out of range. */
        NK_CHECK("out-of-range rows untouched", nk_count(db) == 2);
    }

    /* Assisted snapshot/reset boundary is one transaction across BOTH pools.
     * A forced marker failure must restore prior anchors, marker, and rows. */
    NK_CHECK("bounded genesis replay seeds explicit complete control",
             test_complete_genesis_shielded_replay(db));
    NK_CHECK("general reset cannot publish marker zero",
             !shielded_history_reset_to_boundary(db, 0) &&
             nk_all_history_markers_are(db, 0));
    NK_CHECK("combined reset control row added",
             nullifier_kv_add(db, n1, NULLIFIER_POOL_SAPLING, 7));
    NK_CHECK("combined reset failure trigger installs",
             sqlite3_exec(db,
                 "CREATE TRIGGER fail_nf_reset_marker BEFORE INSERT ON progress_meta "
                 "WHEN NEW.key='nullifier_kv.activation_cursor' BEGIN "
                 "SELECT RAISE(ABORT,'reset marker refused'); END",
                 NULL, NULL, NULL) == SQLITE_OK);
    NK_CHECK("combined reset marker failure rolls back",
             !shielded_history_reset_to_boundary(db, 42));
    bool retained = false;
    NK_CHECK("combined reset rollback retains nullifier row",
             nullifier_kv_get(db, n1, NULLIFIER_POOL_SAPLING,
                              &retained, NULL) && retained);
    int64_t sprout_cursor = -1, sapling_cursor = -1;
    bool sprout_found = false, sapling_found = false;
    NK_CHECK("combined reset rollback retains anchor cursors",
             anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT,
                                         &sprout_cursor, &sprout_found) &&
             anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING,
                                         &sapling_cursor, &sapling_found) &&
             sprout_found && sapling_found &&
             sprout_cursor == 0 && sapling_cursor == 0 &&
             nk_marker_is(db, "0"));
    NK_CHECK("combined reset failure trigger drops",
             sqlite3_exec(db, "DROP TRIGGER fail_nf_reset_marker",
                          NULL, NULL, NULL) == SQLITE_OK);
    const int64_t replay_target = 2;
    const int64_t replay_boundary = replay_target + 1;
    NK_CHECK("full replay starts all components positive/incomplete",
             shielded_history_begin_full_replay(db, replay_target) &&
             nk_all_history_markers_are(db, replay_boundary));
    NK_CHECK("full replay row inserted while marker remains positive",
             nullifier_kv_add(db, n1, NULLIFIER_POOL_SAPLING, 7));
    NK_CHECK("premature completion before genesis-to-target refuses",
             !shielded_history_publish_full_replay_complete(
                 db, replay_target) &&
             nk_all_history_markers_are(db, replay_boundary));
    NK_CHECK("partial replay advances genesis only",
             nk_replay_advance(db, 0, replay_target));
    NK_CHECK("partial replay still reports every component incomplete",
             nk_all_history_markers_are(db, replay_boundary));
    NK_CHECK("out-of-order replay advance refuses",
             !nk_replay_advance(db, 2, replay_target) &&
             nk_all_history_markers_are(db, replay_boundary));
    NK_CHECK("bounded replay reaches target in exact order",
             nk_replay_advance(db, 1, replay_target) &&
             nk_replay_advance(db, 2, replay_target));
    NK_CHECK("completion failure trigger installs",
             sqlite3_exec(db,
                 "CREATE TRIGGER fail_nf_complete BEFORE INSERT ON progress_meta "
                 "WHEN NEW.key='nullifier_kv.activation_cursor' BEGIN "
                 "SELECT RAISE(ABORT,'completion refused'); END",
                 NULL, NULL, NULL) == SQLITE_OK);
    NK_CHECK("failed completion keeps history incomplete",
             !shielded_history_publish_full_replay_complete(
                 db, replay_target) &&
             nk_all_history_markers_are(db, replay_boundary));
    retained = false;
    NK_CHECK("failed completion preserves rebuilt rows",
             nullifier_kv_get(db, n1, NULLIFIER_POOL_SAPLING,
                              &retained, NULL) && retained);
    NK_CHECK("completion failure trigger drops",
             sqlite3_exec(db, "DROP TRIGGER fail_nf_complete",
                          NULL, NULL, NULL) == SQLITE_OK);
    NK_CHECK("successful full replay atomically publishes all three zeros",
             shielded_history_publish_full_replay_complete(
                 db, replay_target) &&
             nk_all_history_markers_are(db, 0));
    retained = false;
    NK_CHECK("completion publication does not clear rebuilt rows",
             nullifier_kv_get(db, n1, NULLIFIER_POOL_SAPLING,
                              &retained, NULL) && retained);
    NK_CHECK("malformed activation marker installs",
             progress_meta_set(db, "nullifier_kv.activation_cursor",
                               "junk", 4));
    {
        int64_t cursor = 0;
        bool found = true;
        NK_CHECK("malformed activation marker fails closed",
                 !nullifier_kv_activation_cursor(db, &cursor, &found) &&
                 !found);
    }

    /* anchor_kv reset primitives: the two OPPOSITE marker semantics are named
     * at the call site by distinct typed entry points (Hazard #1 split). Same
     * tables, same tx, same rows cleared — they differ ONLY in the adoption
     * cursor and therefore in how a later missing root is classified. Pinning
     * both the cursor value AND the classification is the load-bearing guard:
     * the empty-below cursor is the exact marker class behind the H* wedge. */
    NK_CHECK("mark_complete stamps both anchor cursors zero",
             anchor_kv_reset_mark_complete_in_tx(db) &&
             ak_both_anchor_cursors_are(db, 0));
    {
        /* Complete (from-genesis) history: the empty sapling table resolves to
         * the protocol-empty frontier as FOUND, so an output-only fold proceeds. */
        struct incremental_merkle_tree t;
        NK_CHECK("complete history: empty sapling table folds forward (FOUND)",
                 anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &t, NULL, NULL)
                     == ANCHOR_KV_FOUND);
    }
    NK_CHECK("mark_empty_below stamps both anchor cursors at N",
             anchor_kv_reset_mark_empty_below_in_tx(db, 4242) &&
             ak_both_anchor_cursors_are(db, 4242));
    {
        /* Empty-below-N history: the same empty sapling table now fails closed
         * as HISTORY_INCOMPLETE (the wedge blocker), never a false empty root. */
        struct incremental_merkle_tree t;
        NK_CHECK("empty-below history: empty sapling table fails closed "
                 "(HISTORY_INCOMPLETE)",
                 anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &t, NULL, NULL)
                     == ANCHOR_KV_HISTORY_INCOMPLETE);
    }
    /* Argument validation is preserved from the pre-split primitive: a negative
     * below-height is refused; a zero below-height is accepted and behaves as
     * mark_complete (byte-identical to the old reset_in_tx(db, 0)). */
    NK_CHECK("mark_empty_below refuses a negative height",
             !anchor_kv_reset_mark_empty_below_in_tx(db, -1));
    NK_CHECK("mark_empty_below(0) is equivalent to mark_complete",
             anchor_kv_reset_mark_empty_below_in_tx(db, 0) &&
             ak_both_anchor_cursors_are(db, 0));

    /* nullifier_kv reset primitives: the two OPPOSITE completeness semantics are
     * named at the call site by distinct typed entry points (the exact twin of
     * the anchor_kv reset split). Same table, same in-tx contract, same rows
     * cleared — they differ ONLY in the adoption cursor they stamp, and
     * therefore in whether a pre-activation nullifier can be proven fresh. The
     * empty-below cursor is the exact marker class behind the PERMANENT
     * utxo_apply.nullifier_backfill_gap blocker. Pinning both the DELETE, the
     * cursor value, AND the classification it drives is the load-bearing guard.
     * (The malformed-marker section above left a junk cursor; the reset writes a
     * clean explicit cursor over it.) */
    {
        uint8_t rc[32];
        nk_nf(rc, 0x5E);
        NK_CHECK("reset control row present",
                 nullifier_kv_add(db, rc, NULLIFIER_POOL_SAPLING, 9) &&
                 nk_count(db) > 0);
        NK_CHECK("mark_complete clears the set and stamps cursor zero",
                 nk_reset_complete_tx(db) && nk_count(db) == 0 &&
                 nk_marker_is(db, "0"));
        {
            /* Complete (from-genesis) history: the durable cursor reads explicit
             * zero, so no pre-activation nullifier prefix is claimed unknown. */
            int64_t cursor = -1;
            bool found = false;
            NK_CHECK("complete history: activation cursor reads explicit zero",
                     nullifier_kv_activation_cursor(db, &cursor, &found) &&
                     found && cursor == 0);
        }
        NK_CHECK("mark_empty_below clears the set and stamps cursor N",
                 nullifier_kv_add(db, rc, NULLIFIER_POOL_SAPLING, 9) &&
                 nk_reset_empty_below_tx(db, 4242) && nk_count(db) == 0 &&
                 nk_marker_is(db, "4242"));
        {
            /* Empty-below-N history: the durable cursor reads the positive gap
             * boundary — the marker class the reducer fails closed on until a
             * body replay backfills [0, N). */
            int64_t cursor = -1;
            bool found = false;
            NK_CHECK("empty-below history: activation cursor reads positive N",
                     nullifier_kv_activation_cursor(db, &cursor, &found) &&
                     found && cursor == 4242);
        }
        /* Argument validation is preserved from the pre-split primitive: a
         * negative below-height is refused; a zero below-height is accepted and
         * behaves as mark_complete (byte-identical to the old reset_in_tx(0)). */
        NK_CHECK("mark_empty_below refuses a negative height",
                 !nk_reset_empty_below_tx(db, -1));
        NK_CHECK("mark_empty_below(0) is equivalent to mark_complete",
                 nk_reset_empty_below_tx(db, 0) && nk_marker_is(db, "0"));
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
