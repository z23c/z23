/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_progress_floor — the from-genesis-refold floor unlock enabler.
 *
 * Asserts the SCOPING contract of the refold_in_progress signal:
 *   - refold_in_progress == false (a NORMAL boot): reducer_frontier_floor()
 *     returns the compiled anchor and reducer_frontier_compute_hstar clamps H*
 *     UP to that anchor — byte-identical to today.
 *   - refold_in_progress == true (a from-genesis staged refold): the floor
 *     drops to 0 and H* TRACKS the true folded height below the anchor (no
 *     clamp), so a refold's below-anchor progress is reported honestly.
 * Plus the DURABLE round-trip: mark_started sets the progress.kv key + cache;
 * refresh reloads it; clear_if_crossed is a no-op below the anchor and clears
 * once the utxo_apply cursor reaches/passes it.
 *
 * The fixture lowers the compiled anchor via the test override so it can build
 * a folded prefix in a handful of rows instead of 3 million. The production
 * floor logic is identical at the real anchor. */

#include "test/test_core.h"

#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "json/json.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* src-private mirrors of the test-only hooks (the witness pattern — not in the
 * public headers). */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define RP_CHECK(name, expr) do {                                  \
    printf("refold_progress_floor: %s... ", (name));               \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* A hermetic anchor well below mainnet's 3,056,758 so the folded prefix is a
 * few rows. The production floor logic runs identically at the real anchor. */
#define TEST_ANCHOR ((int32_t)1000)

static bool build_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE stage_cursor (name TEXT PRIMARY KEY, cursor INTEGER);"
        "CREATE TABLE progress_meta (key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_refold] schema: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Stamp coins_kv proven-authority (the 3 rungs coins_kv_is_proven_authority
 * checks) so compute_hstar treats the anchor as a REAL finality floor. The new
 * phantom-anchor guard in compute_hstar drops the floor to 0 when the store is
 * NOT proven authority — correct for a fresh datadir, but the NORMAL-boot
 * sub-case below models a real seeded datadir whose H* clamps at the anchor.
 * Raw SQL (this TU has no coins_kv.h). Returns false on any SQLite error. */
static bool rp_stamp_proven_authority(sqlite3 *db, int64_t applied_height)
{
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, ah, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static void synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
}

static bool put_row(sqlite3 *db, const char *table, const char *hash_col,
                    int32_t height, const uint8_t hash[32], const char *status)
{
    char sql[256];
    bool profile_bound = strcmp(table, "script_validate_log") == 0 ||
                         strcmp(table, "proof_validate_log") == 0 ||
                         strcmp(table, "utxo_apply_log") == 0;
    const char *row_status = profile_bound ? "verified" : status;
    if (hash_col && row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok,%s) VALUES(?,?,1,?)",
                 table, hash_col);
    else if (hash_col)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok,%s) VALUES(?,1,?)", table, hash_col);
    else if (row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok) VALUES(?,?,1)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok) VALUES(?,1)", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int col = 1;
    sqlite3_bind_int64(st, col++, height);
    if (row_status)
        sqlite3_bind_text(st, col++, row_status, -1, SQLITE_STATIC);
    if (hash_col) {
        if (hash) sqlite3_bind_blob(st, col++, hash, 32, SQLITE_STATIC);
        else      sqlite3_bind_null(st, col++);
    }
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool put_chain_binding(sqlite3 *db, int32_t height,
                              const uint8_t hash[32])
{
    uint8_t parent[32];
    synth_hash(parent, height - 1);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, height);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, parent, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,x'',x'')",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, height);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* One fully-consistent ok=1 row across every stage log at height h. */
static bool put_consistent(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    synth_hash(hh, h);
    return put_chain_binding(db, h, hh)
        && put_row(db, "validate_headers_log", "hash", h, hh, NULL)
        && put_row(db, "script_validate_log", "block_hash", h, hh, "ok")
        && put_row(db, "body_persist_log", NULL, h, NULL, NULL)
        && put_row(db, "proof_validate_log", "block_hash", h, hh, NULL)
        && put_row(db, "utxo_apply_log", NULL, h, NULL, NULL)
        && put_row(db, "tip_finalize_log", NULL, h, NULL, "ok");
}

static bool set_all_cursors(sqlite3 *db, int64_t c)
{
    return set_cursor(db, "validate_headers", c)
        && set_cursor(db, "body_fetch", c)
        && set_cursor(db, "body_persist", c)
        && set_cursor(db, "proof_validate", c)
        && set_cursor(db, "script_validate", c)
        && set_cursor(db, "utxo_apply", c)
        && set_cursor(db, "tip_finalize", c);
}

/* (1) Floor + H* scoping at the lowered anchor. The folded prefix sits BELOW
 * the anchor (heights TEST_ANCHOR-5 .. TEST_ANCHOR-1, cursors at anchor). */
static int case_floor_scoping(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return 1;
    RP_CHECK("schema", build_schema(db));
    /* Real seeded datadir: proven authority so the anchor floor is honored on
     * the normal-boot sub-cases (the guard leaves refold's floor=0 untouched). */
    RP_CHECK("proven authority",
             rp_stamp_proven_authority(db, TEST_ANCHOR + 1));

    reducer_frontier_test_set_compiled_anchor(TEST_ANCHOR);

    /* Fold a contiguous prefix from genesis (height 1) that ENDS below the
     * anchor — exactly the shape a from-genesis refold produces. The prefix
     * MUST be contiguous from 1 so the floor=0 walk (which starts at 0+1=1)
     * reaches the folded tip without hitting a hole. */
    const int32_t folded_tip = TEST_ANCHOR - 1;       /* 999 */
    const int32_t folded_lo  = 1;
    bool built = true;
    for (int32_t h = folded_lo; h <= folded_tip; h++)
        built = built && put_consistent(db, h);
    RP_CHECK("below-anchor rows built", built);
    /* cursors name the next height == folded_tip+1 == TEST_ANCHOR. */
    RP_CHECK("cursors", set_all_cursors(db, folded_tip + 1));

    /* --- NORMAL boot: floor == anchor, H* clamps UP to the anchor. --- */
    refold_progress_test_set_cached(false);
    RP_CHECK("normal: floor == anchor",
             reducer_frontier_floor() == TEST_ANCHOR);
    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RP_CHECK("normal: compute ok", ok);
    /* Below-anchor folded rows are clamped away — H* never falls below the
     * finality floor on a normal boot. */
    RP_CHECK("normal: H* clamped to anchor", hstar == TEST_ANCHOR);

    /* --- REFOLD in progress: floor == 0, H* tracks the true folded tip. --- */
    refold_progress_test_set_cached(true);
    RP_CHECK("refold: floor == 0", reducer_frontier_floor() == 0);
    hstar = -1; served = -1;
    ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RP_CHECK("refold: compute ok", ok);
    /* Now the below-anchor folded prefix is reported as the true H*. */
    RP_CHECK("refold: H* tracks folded tip", hstar == folded_tip);

    /* --- back to NORMAL: byte-identical to the first pass. --- */
    refold_progress_test_set_cached(false);
    RP_CHECK("restore: floor == anchor",
             reducer_frontier_floor() == TEST_ANCHOR);
    hstar = -1; served = -1;
    ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RP_CHECK("restore: H* clamped to anchor again", ok && hstar == TEST_ANCHOR);

    reducer_frontier_test_set_compiled_anchor(-1); /* restore mainnet floor */
    refold_progress_test_set_cached(false);
    sqlite3_close(db);
    return failures;
}

/* (2) Durable round-trip on a throwaway progress.kv image: mark sets the key +
 * cache; refresh reloads; clear is a no-op below the anchor and clears at/above
 * it. Uses the REAL REDUCER_FRONTIER_TRUSTED_ANCHOR (the clear gate compares
 * against the compiled constant, not the test override). */
static int case_durable_roundtrip(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return 1;
    RP_CHECK("meta table ensure", progress_meta_table_ensure(db));

    refold_progress_test_set_cached(false);

    /* refresh on a virgin image: key absent => cache false. */
    RP_CHECK("refresh virgin ok", refold_progress_refresh(db));
    RP_CHECK("virgin: not in progress", !refold_in_progress());

    /* mark started => durable key + cache true. */
    RP_CHECK("mark started ok", refold_progress_mark_started(db));
    RP_CHECK("marked: in progress", refold_in_progress());

    /* a fresh refresh (simulating a restart) keeps it true off the durable
     * key, even after the cache is cleared by hand. */
    refold_progress_test_set_cached(false);
    RP_CHECK("refresh after restart ok", refold_progress_refresh(db));
    RP_CHECK("restart: still in progress", refold_in_progress());

    /* clear is a NO-OP while the cursor is below the anchor. */
    RP_CHECK("clear below anchor ok",
             refold_progress_clear_if_crossed(
                 db, REDUCER_FRONTIER_TRUSTED_ANCHOR - 1));
    RP_CHECK("below anchor: still in progress", refold_in_progress());

    /* clear FIRES once the cursor reaches the anchor. */
    RP_CHECK("clear at anchor ok",
             refold_progress_clear_if_crossed(
                 db, REDUCER_FRONTIER_TRUSTED_ANCHOR));
    RP_CHECK("at anchor: cleared", !refold_in_progress());

    /* and the durable key is gone: a refresh confirms false. */
    refold_progress_test_set_cached(true); /* poison the cache */
    RP_CHECK("refresh after clear ok", refold_progress_refresh(db));
    RP_CHECK("after clear: durable false", !refold_in_progress());

    refold_progress_test_set_cached(false);
    sqlite3_close(db);
    return failures;
}

static int case_dump_reports_anchor_snapshot_candidate(void)
{
    int failures = 0;
    const char *path = "/tmp/zclassic23-refold-missing-anchor.snapshot";
    unlink(path);
    setenv("ZCL_MINT_ANCHOR_OUT", path, 1);

    struct json_value dump = {0};
    RP_CHECK("dump refold state ok",
             refold_progress_dump_state_json(&dump, NULL));

    const struct json_value *src =
        json_get(&dump, "anchor_snapshot_candidate_source");
    const struct json_value *p =
        json_get(&dump, "anchor_snapshot_candidate_path");
    const struct json_value *present =
        json_get(&dump, "anchor_snapshot_candidate_stat_present");
    const struct json_value *verified =
        json_get(&dump, "anchor_snapshot_verified");
    const struct json_value *verification =
        json_get(&dump, "anchor_snapshot_verification");

    RP_CHECK("dump anchor source env",
             src && strcmp(json_get_str(src), "ZCL_MINT_ANCHOR_OUT") == 0);
    RP_CHECK("dump anchor path",
             p && strcmp(json_get_str(p), path) == 0);
    RP_CHECK("dump anchor missing",
             present && !json_get_bool(present));
    RP_CHECK("dump anchor not verified",
             verified && !json_get_bool(verified));
    RP_CHECK("dump anchor verification note",
             verification &&
             strstr(json_get_str(verification), "not checked") != NULL &&
             strstr(json_get_str(verification), "SHA3/count") != NULL);

    json_free(&dump);
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    return failures;
}

int test_refold_progress_floor(void)
{
    int failures = 0;
    failures += case_floor_scoping();
    failures += case_durable_roundtrip();
    failures += case_dump_reports_anchor_snapshot_candidate();
    if (failures == 0)
        printf("test_refold_progress_floor: ALL PASSED\n");
    else
        printf("test_refold_progress_floor: %d FAILURE(S)\n", failures);
    return failures;
}
