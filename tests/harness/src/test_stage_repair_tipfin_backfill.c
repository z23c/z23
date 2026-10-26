/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the FIX-1 tip_finalize_log hole backfill (WP-B / TIPFIN):
 * stage_repair_reducer_frontier_tipfin.c. Covers T2 (lifecycle: write,
 * witness create/bump/delete, zero deletions), T3 (real coin tear refuses
 * byte-identically), T4 (adversarial G2/G3 refusals) and T9 (the
 * panel-required exact live state: FIX-2a clamp -> simulated refill ->
 * span backfill -> arithmetic convergence -> tip_finalize clamps to C). */

#include "test/test_core.h"

#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* WP-B exports — declared in engine/jobs/src/stage_repair_reducer_frontier_
 * internal.h, which is src-local (not on the test include path); these
 * prototypes mirror it exactly. Both TUs link into the test binary. */
bool stage_reducer_frontier_try_tipfin_backfill(
    sqlite3 *db, bool apply,
    struct stage_reducer_frontier_reconcile_result *out, bool *handled);
bool stage_reducer_frontier_try_unapplied_hole_clamp(
    sqlite3 *db, bool apply,
    struct stage_reducer_frontier_reconcile_result *out, bool *handled);

enum {
    T_REFUSED_NONE = STAGE_REPAIR_TIPFIN_REFUSED_NONE,
    T_REFUSED_G2_EVIDENCE_ROW =
        STAGE_REPAIR_TIPFIN_REFUSED_G2_EVIDENCE_ROW,
    T_REFUSED_G3_MISSING_EVIDENCE =
        STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE,
    T_REFUSED_G5_BINDER_MISSING =
        STAGE_REPAIR_TIPFIN_REFUSED_G5_BINDER_MISSING,
};

#define TIPFIN_CHECK(name, expr) do { \
    printf("stage_repair_tipfin_backfill: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR
static const uint8_t TIPFIN_WITNESS_ZERO_HASH[32] = {0};

/* Distinct deterministic hashes per height (rfrl fixture convention). */
static void mk_hash(struct uint256 *h, int height)
{
    memset(h, 0, sizeof(*h));
    h->data[0] = (uint8_t)(height & 0xff);
    h->data[1] = (uint8_t)((height >> 8) & 0xff);
    h->data[2] = (uint8_t)((height >> 16) & 0xff);
    h->data[31] = 0x7c;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

/* Production-shaped schema: tip_finalize_log carries the FULL column set so
 * the production log_insert (work_delta/finalized_at columns) round-trips. */
static bool seed_schema(sqlite3 *db)
{
    return
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            "parent_hash BLOB, admitted_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB, source TEXT,"
            "bytes INTEGER, fetched_at INTEGER, ok INTEGER,"
            "fail_reason TEXT)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL,"
            "work_delta_low INTEGER NOT NULL, utxo_size_after INTEGER NOT NULL,"
            "reorg_depth INTEGER NOT NULL, finalized_at INTEGER NOT NULL,"
            "tip_hash BLOB)");
}

static bool seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_all_cursors(sqlite3 *db, int cursor)
{
    return seed_cursor(db, "validate_headers", cursor) &&
           seed_cursor(db, "body_fetch", cursor) &&
           seed_cursor(db, "body_persist", cursor) &&
           seed_cursor(db, "script_validate", cursor) &&
           seed_cursor(db, "proof_validate", cursor) &&
           seed_cursor(db, "utxo_apply", cursor) &&
           seed_cursor(db, "tip_finalize", cursor);
}

static bool put_validate(sqlite3 *db, int height, int ok_flag,
                         const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok) "
            "VALUES(?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    if (hash)
        sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 2);
    sqlite3_bind_int(st, 3, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_script(sqlite3 *db, int height, int ok_flag,
                       const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log"
            "(height,status,ok,block_hash) VALUES(?,'verified',?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    if (hash)
        sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 3);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_header(sqlite3 *db, int height, const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,admitted_at) VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_proof(sqlite3 *db, int height, int ok_flag,
                      const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO proof_validate_log"
            "(height,status,ok,block_hash) VALUES(?,'verified',?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_utxo(sqlite3 *db, int height, int ok_flag,
                     const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
        "VALUES(?,'verified',?)", -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int(st, 1, height);
        sqlite3_bind_int(st, 2, ok_flag);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!ok || sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,x'',x'')",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_simple(sqlite3 *db, const char *table, int height, int ok_flag)
{
    char sql[160];
    if (strcmp(table, "body_persist_log") == 0) {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,source,ok) "
                 "VALUES(?,'fixture',?)",
                 table);
    } else {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok) "
                 "VALUES(?,'verified',?)",
                 table);
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_tip(sqlite3 *db, int height, const char *status, int ok_flag,
                    const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            " utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(?,?,?,0,0,0,0,1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_flag);
    if (hash)
        sqlite3_bind_blob(st, 4, hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 4);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* All five upstream logs ok=1 at `height` (validate + script bound to hash). */
static bool put_upstream_ok(sqlite3 *db, int height,
                            const struct uint256 *hash)
{
    return put_validate(db, height, 1, hash) &&
           put_header(db, height, hash) &&
           put_script(db, height, 1, hash) &&
           put_simple(db, "body_persist_log", height, 1) &&
           put_proof(db, height, 1, hash) &&
           put_utxo(db, height, 1, hash);
}

static bool seed_coins_applied(sqlite3 *db, int64_t height)
{
    uint8_t blob[8];
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)((uint64_t)height >> (8 * i));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, sizeof(blob), SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    /* Stamp full coins_kv proven-authority so compute_hstar treats the baked
     * TRUSTED_ANCHOR as a REAL finality floor (these fixtures model a seeded
     * datadir). compute_hstar's phantom-anchor guard drops the floor to 0 when
     * coins_kv is NOT proven authority — correct for a fresh datadir, wrong for
     * these. Proven authority needs all three rungs: the applied_height above,
     * the migration-complete stamp, and a non-empty `coins` table. */
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }
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

static int cursor_value(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

/* (count, sum(height), sum(ok)) digest per log table + every stage cursor:
 * the "cursors and logs byte-identical" witness for refusal cases. */
#define TIPFIN_DIGEST_N (6 * 3 + 7)

static bool digest_all(sqlite3 *db, long long out[TIPFIN_DIGEST_N])
{
    static const char *const logs[] = {
        "validate_headers_log", "script_validate_log", "body_persist_log",
        "proof_validate_log",   "utxo_apply_log",      "tip_finalize_log",
    };
    static const char *const stages[] = {
        "validate_headers", "body_fetch", "body_persist", "script_validate",
        "proof_validate",   "utxo_apply", "tip_finalize",
    };
    int k = 0;
    for (size_t i = 0; i < sizeof(logs) / sizeof(logs[0]); i++) {
        char sql[160];
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*), COALESCE(SUM(height),0), "
                 "COALESCE(SUM(ok),0) FROM %s", logs[i]);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
            return false;
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            return false;
        }
        out[k++] = sqlite3_column_int64(st, 0);
        out[k++] = sqlite3_column_int64(st, 1);
        out[k++] = sqlite3_column_int64(st, 2);
        sqlite3_finalize(st);
    }
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++)
        out[k++] = cursor_value(db, stages[i]);
    return k == TIPFIN_DIGEST_N;
}

struct tip_row_view {
    bool found;
    int ok;
    char status[32];
    bool has_hash;
    struct uint256 hash;
};

static bool tip_row_at(sqlite3 *db, int height, struct tip_row_view *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, status, tip_hash FROM tip_finalize_log "
            "WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        out->found = true;
        out->ok = sqlite3_column_int(st, 0);
        const unsigned char *s = sqlite3_column_text(st, 1);
        snprintf(out->status, sizeof(out->status), "%s",
                 s ? (const char *)s : "");
        const void *blob = sqlite3_column_blob(st, 2);
        if (blob && sqlite3_column_bytes(st, 2) == 32) {
            memcpy(out->hash.data, blob, 32);
            out->has_hash = true;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static long long tip_row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    long long n = -1;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM tip_finalize_log",
                           -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool witness_at(sqlite3 *db, bool *found, int32_t *last,
                       uint32_t *total)
{
    *found = false;
    *last = -1;
    *total = 0;
    uint8_t buf[8] = {0};
    size_t n = 0;
    if (!repair_marker_have(db, REPAIR_MARKER_KIND_TIPFIN_PROGRESS,
                            REPAIR_MARKER_TIPFIN_HEIGHT, TIPFIN_WITNESS_ZERO_HASH,
                            found, buf, sizeof(buf), &n))
        return false;
    if (!*found)
        return true;
    if (n != sizeof(buf))
        return false;
    uint32_t l = 0, t = 0;
    for (int i = 0; i < 4; i++)
        l |= (uint32_t)buf[i] << (8 * i);
    for (int i = 0; i < 4; i++)
        t |= (uint32_t)buf[4 + i] << (8 * i);
    *last = (int32_t)l;
    *total = t;
    return true;
}

static bool put_tipfin_witness(sqlite3 *db, int32_t last, uint32_t total)
{
    uint8_t buf[8] = {0};
    for (int i = 0; i < 4; i++)
        buf[i] = (uint8_t)((uint32_t)last >> (8 * i));
    for (int i = 0; i < 4; i++)
        buf[4 + i] = (uint8_t)(total >> (8 * i));
    return repair_marker_note(db, REPAIR_MARKER_KIND_TIPFIN_PROGRESS,
                              REPAIR_MARKER_TIPFIN_HEIGHT,
                              TIPFIN_WITNESS_ZERO_HASH, buf, sizeof(buf));
}

static long long marker_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    long long n = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM repair_marker WHERE kind = "
            "'reducer_frontier.tipfin_backfill_repair'",
            -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool put_tipfin_marker(sqlite3 *db, int first_p,
                              const struct uint256 *binder_hash)
{
    uint8_t one = 1;
    return repair_marker_note(db, REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL,
                              first_p, binder_hash->data, &one, sizeof(one));
}

static bool tipfin_marker_is_one(sqlite3 *db, int first_p,
                                 const struct uint256 *binder_hash)
{
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool found = false;
    return repair_marker_have(db, REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL,
                              first_p, binder_hash->data, &found,
                              blob, sizeof(blob), &n) &&
           found && n == 1 && blob[0] == 1;
}

/* The read_frontier_snapshot subset the WP-B repairs consume (the tests
 * drive the exports directly, like the production reconcile would). */
static bool snapshot(sqlite3 *db,
                     struct stage_reducer_frontier_reconcile_result *out)
{
    static const char *const stages[] = {
        "validate_headers", "body_fetch", "body_persist", "script_validate",
        "proof_validate",   "utxo_apply", "tip_finalize",
    };
    memset(out, 0, sizeof(*out));
    progress_store_tx_lock();
    int32_t hstar = 0, floor = 0;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &floor);
    int32_t coins = 0;
    bool found = false;
    ok = ok && coins_kv_get_applied_height(db, &coins, &found);
    progress_store_tx_unlock();
    if (!ok)
        return false;
    out->hstar = hstar;
    out->served_floor = floor;
    out->sweep_top = floor;
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        int cursor = cursor_value(db, stages[i]);
        if (cursor > 0 && cursor - 1 > out->sweep_top)
            out->sweep_top = cursor - 1;
    }
    out->coins_applied_found = found;
    out->coins_applied_height = found ? coins : -1;
    if (!found)
        out->refused_coin_unknown = true;
    else if (coins > hstar + 1)
        out->refused_coin_tear = true;
    return true;
}

static bool open_fixture(char *dir, size_t dir_n, const char *tag,
                         int cursor_top)
{
    test_make_tmpdir(dir, dir_n, "stage_repair_tipfin_backfill", tag);
    if (!progress_store_open(dir))
        return false;
    return seed_schema(progress_store_db()) &&
           seed_all_cursors(progress_store_db(), cursor_top);
}

static void tipfin_fill_hashes(struct uint256 *h, int n)
{
    for (int i = 1; i <= n; i++)
        mk_hash(&h[i], A + i);
}

static bool tipfin_seed_upstream_range(sqlite3 *db, const struct uint256 *h,
                                       int lo, int hi)
{
    bool seeded = true;
    for (int i = lo; i <= hi; i++)
        seeded = seeded && put_upstream_ok(db, A + i, &h[i]);
    return seeded;
}

static bool tipfin_t2_tips_and_coins(sqlite3 *db, const struct uint256 *h)
{
    return put_tip(db, A + 1, "finalized", 1, &h[2]) &&
           put_tip(db, A + 5, "finalized", 1, &h[6]) &&
           put_tip(db, A + 6, "finalized", 1, &h[7]) &&
           seed_coins_applied(db, A + 6);
}

static bool tipfin_t2_seed(sqlite3 *db, struct uint256 *h)
{
    tipfin_fill_hashes(h, 7);
    return tipfin_seed_upstream_range(db, h, 1, 6) &&
           /* Binder gap mid-span: the script hash at A+4 is NULL until pass 3,
            * so G5 blocks p=A+3 and the witness record is observable. */
           put_script(db, A + 4, 1, NULL) &&
           tipfin_t2_tips_and_coins(db, h);
}

static bool tipfin_t2b_seed(sqlite3 *db, struct uint256 *h)
{
    tipfin_fill_hashes(h, 7);
    return tipfin_seed_upstream_range(db, h, 1, 6) &&
           tipfin_t2_tips_and_coins(db, h) &&
           put_tipfin_marker(db, A + 2, &h[3]);
}

static bool tipfin_t2c_seed(sqlite3 *db, struct uint256 *h)
{
    return tipfin_t2b_seed(db, h) && put_tipfin_witness(db, A + 5, 9);
}

static bool tipfin_t3_upstream(sqlite3 *db, const struct uint256 *h)
{
    /* The REAL tear: the script row is missing at A+3, strictly below
     * the coins frontier (A+5). Everything else is ok=1. */
    bool seeded = true;
    for (int i = 1; i <= 5; i++) {
        seeded = seeded && put_validate(db, A + i, 1, &h[i]) &&
                 put_header(db, A + i, &h[i]) &&
                 put_simple(db, "body_persist_log", A + i, 1) &&
                 put_proof(db, A + i, 1, &h[i]) &&
                 put_utxo(db, A + i, 1, &h[i]);
        if (i != 3)
            seeded = seeded && put_script(db, A + i, 1, &h[i]);
    }
    return seeded;
}

static bool tipfin_t3_seed(sqlite3 *db, struct uint256 *h)
{
    tipfin_fill_hashes(h, 6);
    return tipfin_t3_upstream(db, h) &&
           put_tip(db, A + 1, "finalized", 1, &h[2]) &&
           put_tip(db, A + 2, "finalized", 1, &h[3]) &&
           seed_coins_applied(db, A + 5);
}

static bool tipfin_t4_anchor_tips(sqlite3 *db, const struct uint256 *h)
{
    return put_tip(db, A + 1, "finalized", 1, &h[2]) &&
           put_tip(db, A + 4, "finalized", 1, &h[5]) &&
           seed_coins_applied(db, A + 4);
}

static bool tipfin_t4a_seed(sqlite3 *db, struct uint256 *h)
{
    tipfin_fill_hashes(h, 5);
    return tipfin_seed_upstream_range(db, h, 1, 4) &&
           put_proof(db, A + 2, 0, &h[2]) &&
           tipfin_t4_anchor_tips(db, h);
}

static bool tipfin_t4b_seed(sqlite3 *db, struct uint256 *h)
{
    tipfin_fill_hashes(h, 5);
    return tipfin_seed_upstream_range(db, h, 1, 4) &&
           put_tip(db, A + 1, "finalized", 1, &h[2]) &&
           put_tip(db, A + 2, "utxo_count_diverged", 0, NULL) &&
           put_tip(db, A + 4, "finalized", 1, &h[5]) &&
           seed_coins_applied(db, A + 4);
}

static bool tipfin_t4_fork_seed(sqlite3 *db, struct uint256 *h,
                                uint8_t flip, bool utxo_fork)
{
    tipfin_fill_hashes(h, 5);
    struct uint256 fork_hash = h[2];
    fork_hash.data[31] ^= flip;
    return tipfin_seed_upstream_range(db, h, 1, 4) &&
           (utxo_fork ? put_utxo(db, A + 2, 1, &fork_hash)
                      : put_proof(db, A + 2, 1, &fork_hash)) &&
           tipfin_t4_anchor_tips(db, h);
}

static bool tipfin_t9_seed(sqlite3 *db, struct uint256 *h, int c_at)
{
    tipfin_fill_hashes(h, 9);
    /* A+1 .. C-1: all five logs ok=1 */
    bool seeded = tipfin_seed_upstream_range(db, h, 1, 7);
    /* At C: validate + body_persist present, script/proof/utxo rowless. */
    seeded = seeded && put_header(db, c_at, &h[8]) &&
             put_validate(db, c_at, 1, &h[8]) &&
             put_simple(db, "body_persist_log", c_at, 1);
    /* tip_finalize: rows through S-1, rowless span, anchor ok=1 at C. */
    return seeded &&
           put_tip(db, A + 1, "finalized", 1, &h[2]) &&
           put_tip(db, A + 2, "finalized", 1, &h[3]) &&
           put_tip(db, c_at, "anchor", 1, &h[8]) &&
           seed_coins_applied(db, c_at);
}

static bool tipfin_t10_seed(sqlite3 *db, struct uint256 *h)
{
    tipfin_fill_hashes(h, 9);
    /* all five logs ok=1 A+1 .. A+8 */
    bool seeded = tipfin_seed_upstream_range(db, h, 1, 8);
    /* tip_finalize: rows at A+1, rowless HOLE A+2..A+4, rows A+5..A+8. */
    return seeded &&
           put_tip(db, A + 1, "finalized", 1, &h[2]) &&
           put_tip(db, A + 5, "finalized", 1, &h[6]) &&
           put_tip(db, A + 6, "finalized", 1, &h[7]) &&
           put_tip(db, A + 7, "finalized", 1, &h[8]) &&
           put_tip(db, A + 8, "finalized", 1, &h[9]) &&
           seed_coins_applied(db, A + 9);
}

/* floor < 0 skips served_floor; coins < 0 skips coins_applied_height.
 * tear_mode 0 skips the tear bit, >0 requires it, <0 requires it clear. */
static bool tipfin_snap_expect(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr,
    int hstar, int floor, int coins, int tear_mode)
{
    bool ok = snapshot(db, rr) && rr->hstar == hstar;
    if (floor >= 0)
        ok = ok && rr->served_floor == floor;
    if (coins >= 0)
        ok = ok && rr->coins_applied_height == coins;
    if (tear_mode != 0)
        ok = ok && rr->refused_coin_tear == (tear_mode > 0);
    return ok;
}

static bool tipfin_t2_dry_run(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, false, rr, handled) &&
           *handled && rr->repaired &&
           rr->tipfin_backfill_height == A + 2 &&
           tip_row_count(db) == 3 && marker_count(db) == 0;
}

static bool tipfin_t2_pass1_filled(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           *handled && rr->repaired && !rr->refused_coin_tear &&
           rr->tipfin_backfill_count == 1 &&
           rr->tipfin_backfill_height == A + 2;
}

static bool tipfin_row_matches(sqlite3 *db, int height,
                               struct tip_row_view *row, int ok_flag,
                               const char *status, const struct uint256 *hash,
                               bool require_hash_flag)
{
    bool match = tip_row_at(db, height, row) && row->found &&
                 row->ok == ok_flag;
    if (status != NULL)
        match = match && strcmp(row->status, status) == 0;
    if (require_hash_flag)
        match = match && row->has_hash;
    if (hash != NULL)
        match = match && memcmp(row->hash.data, hash->data, 32) == 0;
    return match;
}

static bool tipfin_t2_pass1_witness(sqlite3 *db, bool *found, int32_t *wlast,
                                    uint32_t *wtotal,
                                    const struct uint256 *binder)
{
    return witness_at(db, found, wlast, wtotal) && *found &&
           *wlast == A + 2 && *wtotal == 1 && marker_count(db) == 1 &&
           tipfin_marker_is_one(db, A + 2, binder);
}

static bool tipfin_t2_pass2_blocked(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           !*handled && rr->tipfin_backfill_count == 0 &&
           rr->tipfin_backfill_refused_reason == T_REFUSED_G5_BINDER_MISSING;
}

static bool tipfin_t2_pass2_witness(sqlite3 *db, bool *found, int32_t *wlast,
                                    uint32_t *wtotal)
{
    return witness_at(db, found, wlast, wtotal) && *found &&
           *wlast == A + 2 && *wtotal == 1 &&
           tip_row_count(db) == 4;
}

static bool tipfin_backfill_span(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled,
    int count, int height)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           *handled && rr->tipfin_backfill_count == count &&
           rr->tipfin_backfill_height == height;
}

static bool tipfin_t2_pass3_rows(sqlite3 *db, const struct uint256 *h,
                                 struct tip_row_view *row)
{
    return tipfin_row_matches(db, A + 3, row, 1, NULL, &h[4], false) &&
           tipfin_row_matches(db, A + 4, row, 1, NULL, &h[5], false);
}

static bool tipfin_witness_gone(sqlite3 *db, bool *found, int32_t *wlast,
                                uint32_t *wtotal)
{
    return witness_at(db, found, wlast, wtotal) && !*found;
}

static bool tipfin_t2_span_done(sqlite3 *db, bool *found, int32_t *wlast,
                                uint32_t *wtotal)
{
    return tipfin_witness_gone(db, found, wlast, wtotal) &&
           marker_count(db) == 1;
}

static bool tipfin_t2_intact(sqlite3 *db, struct tip_row_view *row)
{
    return tip_row_count(db) == 6 &&
           tipfin_row_matches(db, A + 1, row, 1, "finalized", NULL, false) &&
           tipfin_row_matches(db, A + 5, row, 1, "finalized", NULL, false) &&
           cursor_value(db, "tip_finalize") == A + 7 &&
           cursor_value(db, "script_validate") == A + 7;
}

static bool tipfin_backfill_idle(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           !*handled &&
           rr->tipfin_backfill_refused_reason == T_REFUSED_NONE;
}

static bool tipfin_marker_blocks(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           !*handled && !rr->repaired &&
           rr->tipfin_backfill_marker_seen &&
           rr->tipfin_backfill_refused_reason ==
               STAGE_REPAIR_TIPFIN_REFUSED_G7_MARKER_SEEN &&
           rr->tipfin_backfill_count == 0 &&
           tip_row_count(db) == 3 && marker_count(db) == 1;
}

static bool tipfin_refused_at(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled,
    int reason, int height, int log)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           !*handled &&
           rr->tipfin_backfill_refused_reason == reason &&
           rr->tipfin_backfill_refused_height == height &&
           rr->tipfin_backfill_refused_log == log;
}

static bool tipfin_refused_absent(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled,
    struct tip_row_view *row, int reason, int height, int log)
{
    return tipfin_refused_at(db, rr, handled, reason, height, log) &&
           tip_row_at(db, height, row) && !row->found;
}

static bool tipfin_fork_refused(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled,
    struct tip_row_view *row, int log)
{
    return tipfin_snap_expect(db, rr, A + 1, -1, -1, 0) &&
           stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           !*handled &&
           rr->tipfin_backfill_refused_reason ==
               T_REFUSED_G3_MISSING_EVIDENCE &&
           rr->tipfin_backfill_refused_log == log &&
           tip_row_at(db, A + 2, row) && !row->found;
}

static bool tipfin_clamp_at(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled,
    int script_at, int proof_at)
{
    return stage_reducer_frontier_try_unapplied_hole_clamp(
               db, true, rr, handled) &&
           cursor_value(db, "script_validate") == script_at &&
           cursor_value(db, "proof_validate") == proof_at;
}

static bool tipfin_digest_same(sqlite3 *db,
                               long long before[TIPFIN_DIGEST_N],
                               long long after[TIPFIN_DIGEST_N])
{
    return digest_all(db, after) &&
           memcmp(before, after,
                  sizeof(long long) * (size_t)TIPFIN_DIGEST_N) == 0;
}

static bool tipfin_t9_refill(sqlite3 *db, int c_at, const struct uint256 *h)
{
    return put_script(db, c_at, 1, &h[8]) && put_proof(db, c_at, 1, &h[8]);
}

static bool tipfin_t9_reconcile_ok(sqlite3 *db, struct main_state *ms,
                                   struct stage_reducer_frontier_reconcile_result *fin,
                                   int c_at)
{
    return stage_reducer_frontier_reconcile_light(db, ms, fin) &&
           !fin->refused_coin_tear &&
           cursor_value(db, "tip_finalize") == c_at;
}

static bool tipfin_hstar_matches(bool okc, int32_t hs, int32_t sf,
                                 int want_hs, int want_sf)
{
    return okc && hs == want_hs && sf == want_sf;
}

static bool tipfin_t10_filled(sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *rr, bool *handled)
{
    return stage_reducer_frontier_try_tipfin_backfill(
               db, true, rr, handled) &&
           *handled && rr->repaired &&
           rr->tipfin_backfill_count == 3 &&
           rr->tipfin_backfill_height == A + 4;
}

static bool tipfin_t10_rows(sqlite3 *db, const struct uint256 *h,
                            struct tip_row_view *row)
{
    return tipfin_row_matches(db, A + 2, row, 1, "finalize_backfill",
                              &h[3], false) &&
           tipfin_row_matches(db, A + 3, row, 1, NULL, &h[4], false) &&
           tipfin_row_matches(db, A + 4, row, 1, NULL, &h[5], false);
}

static bool tipfin_t10_intact(sqlite3 *db, struct tip_row_view *row)
{
    return tip_row_count(db) == 8 &&
           tipfin_row_matches(db, A + 5, row, 1, "finalized", NULL, false) &&
           cursor_value(db, "tip_finalize") == A + 9;
}

int test_stage_repair_tipfin_backfill(void);
int test_stage_repair_tipfin_backfill(void)
{
    printf("\n=== stage_repair_tipfin_backfill tests ===\n");
    int failures = 0;

    {
        struct stage_reducer_frontier_reconcile_result rr;
        memset(&rr, 0, sizeof(rr));
        rr.refused_coin_tear = true;
        rr.coins_applied_found = true;
        rr.coins_applied_height = A + 8;
        rr.tipfin_backfill_refused_reason =
            STAGE_REPAIR_TIPFIN_REFUSED_G5_BINDER_MISSING;
        rr.tipfin_backfill_refused_height = A + 8;
        TIPFIN_CHECK("pending-forward G5 classifier at coins frontier",
                     stage_repair_tipfin_refusal_is_pending_forward(&rr));

        rr.tipfin_backfill_refused_height = A + 7;
        TIPFIN_CHECK("below-coins G5 stays hard refusal",
                     !stage_repair_tipfin_refusal_is_pending_forward(&rr));

        rr.tipfin_backfill_refused_reason =
            STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE;
        rr.tipfin_backfill_refused_height = A + 8;
        TIPFIN_CHECK("pending-forward G3 classifier at coins frontier",
                     stage_repair_tipfin_refusal_is_pending_forward(&rr));

        rr.tipfin_backfill_refused_reason =
            STAGE_REPAIR_TIPFIN_REFUSED_G2_EVIDENCE_ROW;
        TIPFIN_CHECK("evidence rows never classify pending-forward",
                     !stage_repair_tipfin_refusal_is_pending_forward(&rr));
    }

    /* ── T2 — lifecycle: write, witness create/bump/delete, no deletes ── */
    {
        char dir[256];
        TIPFIN_CHECK("T2 setup", open_fixture(dir, sizeof(dir), "t2", A + 7));
        sqlite3 *db = progress_store_db();

        struct uint256 h[8];
        bool seeded = tipfin_t2_seed(db, h);
        TIPFIN_CHECK("T2 seed", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        bool handled = false;
        TIPFIN_CHECK("T2 snapshot torn",
                     tipfin_snap_expect(db, &rr, A + 1, A + 6, -1, 1));

        /* Dry run: reports the repair, mutates nothing. */
        TIPFIN_CHECK("T2 dry-run reports without mutating",
                     tipfin_t2_dry_run(db, &rr, &handled));

        /* Pass 1: backfills A+2, blocks at the A+4 binder gap. */
        bool found = false;
        int32_t wlast = -1;
        uint32_t wtotal = 0;
        TIPFIN_CHECK("T2 snapshot pass1", snapshot(db, &rr));
        handled = false;
        TIPFIN_CHECK("T2 pass1 backfills first hole",
                     tipfin_t2_pass1_filled(db, &rr, &handled));
        struct tip_row_view row;
        TIPFIN_CHECK("T2 pass1 row hash-bound to h(p+1)",
                     tipfin_row_matches(db, A + 2, &row, 1,
                                        "finalize_backfill", &h[3], true));
        TIPFIN_CHECK("T2 pass1 witness created + marker recorded",
                     tipfin_t2_pass1_witness(db, &found, &wlast, &wtotal,
                                             &h[3]));

        /* Pass 2: binder still missing at A+4 — zero progress, named G5. */
        TIPFIN_CHECK("T2 snapshot pass2",
                     tipfin_snap_expect(db, &rr, A + 2, -1, -1, 1));
        handled = false;
        TIPFIN_CHECK("T2 pass2 blocked on missing binder",
                     tipfin_t2_pass2_blocked(db, &rr, &handled));
        TIPFIN_CHECK("T2 pass2 witness untouched",
                     tipfin_t2_pass2_witness(db, &found, &wlast, &wtotal));

        /* Pass 3: binder restored — span completes, witness deleted. */
        TIPFIN_CHECK("T2 restore binder", put_script(db, A + 4, 1, &h[4]));
        TIPFIN_CHECK("T2 snapshot pass3",
                     tipfin_snap_expect(db, &rr, A + 2, -1, -1, 0));
        handled = false;
        TIPFIN_CHECK("T2 pass3 completes span",
                     tipfin_backfill_span(db, &rr, &handled, 2, A + 4));
        TIPFIN_CHECK("T2 pass3 rows hash-bound",
                     tipfin_t2_pass3_rows(db, h, &row));
        TIPFIN_CHECK("T2 pass3 witness deleted on span completion",
                     tipfin_t2_span_done(db, &found, &wlast, &wtotal));

        /* Zero deletions: 3 original rows + 3 backfilled, originals intact,
         * and the repair wrote no cursor. */
        TIPFIN_CHECK("T2 zero deletions, originals + cursors intact",
                     tipfin_t2_intact(db, &row));

        /* Healed: the coin-tear refusal clears arithmetically. */
        TIPFIN_CHECK("T2 post-heal pass reports no tear",
                     tipfin_snap_expect(db, &rr, A + 6, -1, -1, -1));
        handled = false;
        TIPFIN_CHECK("T2 post-heal backfill not applicable",
                     tipfin_backfill_idle(db, &rr, &handled));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── T2b — one-shot marker blocks a repeated span start ── */
    {
        char dir[256];
        TIPFIN_CHECK("T2b setup", open_fixture(dir, sizeof(dir), "t2b", A + 7));
        sqlite3 *db = progress_store_db();

        struct uint256 h[8];
        bool seeded = tipfin_t2b_seed(db, h);
        TIPFIN_CHECK("T2b seed pre-existing marker", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        bool handled = false;
        TIPFIN_CHECK("T2b snapshot torn",
                     tipfin_snap_expect(db, &rr, A + 1, -1, -1, 1));
        TIPFIN_CHECK("T2b marker refuses repeated span",
                     tipfin_marker_blocks(db, &rr, &handled));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── T2c — stale witness must not bypass the one-shot marker ── */
    {
        char dir[256];
        TIPFIN_CHECK("T2c setup", open_fixture(dir, sizeof(dir), "t2c", A + 7));
        sqlite3 *db = progress_store_db();

        struct uint256 h[8];
        bool seeded = tipfin_t2c_seed(db, h);
        TIPFIN_CHECK("T2c seed stale witness + marker", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        bool handled = false;
        TIPFIN_CHECK("T2c snapshot torn",
                     tipfin_snap_expect(db, &rr, A + 1, -1, -1, 1));
        TIPFIN_CHECK("T2c stale witness restarts G7 marker gate",
                     tipfin_marker_blocks(db, &rr, &handled));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── T3 — real coin tear (hole strictly below coins): refuse ── */
    {
        char dir[256];
        TIPFIN_CHECK("T3 setup", open_fixture(dir, sizeof(dir), "t3", A + 6));
        sqlite3 *db = progress_store_db();

        struct uint256 h[7];
        bool seeded = tipfin_t3_seed(db, h);
        TIPFIN_CHECK("T3 seed", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        TIPFIN_CHECK("T3 snapshot pins at the tear",
                     tipfin_snap_expect(db, &rr, A + 2, -1, -1, 1));

        long long before[TIPFIN_DIGEST_N], after[TIPFIN_DIGEST_N];
        TIPFIN_CHECK("T3 digest before", digest_all(db, before));

        bool handled = false;
        TIPFIN_CHECK("T3 backfill refuses, names the binding log",
                     tipfin_refused_at(db, &rr, &handled,
                                       T_REFUSED_G3_MISSING_EVIDENCE, A + 3,
                                       STAGE_REPAIR_TIPFIN_LOG_SCRIPT_VALIDATE));

        /* FIX-2a must NOT clamp: the hole is strictly below the coins
         * frontier — the unapplied-hole clamp floor. */
        struct stage_reducer_frontier_reconcile_result rr2;
        bool handled2 = false;
        TIPFIN_CHECK("T3 snapshot for clamp", snapshot(db, &rr2));
        TIPFIN_CHECK("T3 FIX-2a does not clamp below the frontier",
                     tipfin_clamp_at(db, &rr2, &handled2, A + 6, A + 6));

        TIPFIN_CHECK("T3 cursors and logs byte-identical",
                     tipfin_digest_same(db, before, after));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── T4 — adversarial: G3 (proof ok=0) and G2 (evidence row) ── */
    {
        char dir[256];
        TIPFIN_CHECK("T4a setup",
                     open_fixture(dir, sizeof(dir), "t4a", A + 5));
        sqlite3 *db = progress_store_db();

        struct uint256 h[6];
        bool seeded = tipfin_t4a_seed(db, h);
        TIPFIN_CHECK("T4a seed", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        TIPFIN_CHECK("T4a snapshot",
                     tipfin_snap_expect(db, &rr, A + 1, -1, -1, 1));

        long long before[TIPFIN_DIGEST_N], after[TIPFIN_DIGEST_N];
        TIPFIN_CHECK("T4a digest before", digest_all(db, before));
        bool handled = false;
        struct tip_row_view row;
        TIPFIN_CHECK("T4a G3 refuses on proof ok=0",
                     tipfin_refused_absent(
                         db, &rr, &handled, &row,
                         T_REFUSED_G3_MISSING_EVIDENCE, A + 2,
                         STAGE_REPAIR_TIPFIN_LOG_PROOF_VALIDATE));
        TIPFIN_CHECK("T4a byte-identical",
                     tipfin_digest_same(db, before, after));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }
    {
        char dir[256];
        TIPFIN_CHECK("T4b setup",
                     open_fixture(dir, sizeof(dir), "t4b", A + 5));
        sqlite3 *db = progress_store_db();

        struct uint256 h[6];
        bool seeded = tipfin_t4b_seed(db, h);
        TIPFIN_CHECK("T4b seed", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        TIPFIN_CHECK("T4b snapshot",
                     tipfin_snap_expect(db, &rr, A + 1, -1, -1, 1));

        long long before[TIPFIN_DIGEST_N], after[TIPFIN_DIGEST_N];
        TIPFIN_CHECK("T4b digest before", digest_all(db, before));
        bool handled = false;
        struct tip_row_view row;
        TIPFIN_CHECK("T4b G2 refuses on the ok=0 evidence row",
                     tipfin_refused_at(db, &rr, &handled,
                                       T_REFUSED_G2_EVIDENCE_ROW, A + 2,
                                       STAGE_REPAIR_TIPFIN_LOG_TIP_FINALIZE));
        TIPFIN_CHECK("T4b evidence row never overwritten",
                     tipfin_row_matches(db, A + 2, &row, 0,
                                        "utxo_count_diverged", NULL, false));
        TIPFIN_CHECK("T4b byte-identical",
                     tipfin_digest_same(db, before, after));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    {
        char dir[256];
        TIPFIN_CHECK("T4c proof-fork setup",
                     open_fixture(dir, sizeof(dir), "t4c_proof_fork", A + 5));
        sqlite3 *db = progress_store_db();
        struct uint256 h[6];
        bool seeded = tipfin_t4_fork_seed(db, h, 0x5au, false);
        TIPFIN_CHECK("T4c proof-fork seed", seeded);
        struct stage_reducer_frontier_reconcile_result rr;
        bool handled = false;
        struct tip_row_view row;
        TIPFIN_CHECK("T4c forked proof cannot authorize backfill",
                     tipfin_fork_refused(
                         db, &rr, &handled, &row,
                         STAGE_REPAIR_TIPFIN_LOG_PROOF_VALIDATE));
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    {
        char dir[256];
        TIPFIN_CHECK("T4d UTXO-fork setup",
                     open_fixture(dir, sizeof(dir), "t4d_utxo_fork", A + 5));
        sqlite3 *db = progress_store_db();
        struct uint256 h[6];
        bool seeded = tipfin_t4_fork_seed(db, h, 0xa5u, true);
        TIPFIN_CHECK("T4d UTXO-fork seed", seeded);
        struct stage_reducer_frontier_reconcile_result rr;
        bool handled = false;
        struct tip_row_view row;
        TIPFIN_CHECK("T4d forked UTXO cannot authorize backfill",
                     tipfin_fork_refused(
                         db, &rr, &handled, &row,
                         STAGE_REPAIR_TIPFIN_LOG_UTXO_APPLY));
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── T9 — panel-required exact live state ──
     * tip_finalize rowless span [S..C-1] + anchor ok=1 at C; script+proof
     * rowless at C == coins_applied; utxo rows through C-1; cursors at
     * C+2001. FIX-2a clamps script/proof; after a simulated refill at C the
     * backfill heals the span to C-1 (boundary written with both binders),
     * H* converges to C-1, the tear clears arithmetically, and the existing
     * reconcile clamps tip_finalize to C. S = A+3, C = A+8. */
    {
        const int C = A + 8;
        char dir[256];
        TIPFIN_CHECK("T9 setup",
                     open_fixture(dir, sizeof(dir), "t9", C + 2001));
        sqlite3 *db = progress_store_db();

        struct uint256 h[10];
        bool seeded = tipfin_t9_seed(db, h, C);
        TIPFIN_CHECK("T9 seed", seeded);

        struct stage_reducer_frontier_reconcile_result rr;
        TIPFIN_CHECK("T9 snapshot matches the live pin",
                     tipfin_snap_expect(db, &rr, A + 2, C, C, 1));

        /* Step 1 — FIX-2a clamps script/proof to the unapplied hole at C. */
        bool handled = false;
        TIPFIN_CHECK("T9 FIX-2a clamps script/proof to C",
                     tipfin_clamp_at(db, &rr, &handled, C, C));

        /* Step 2 — boundary ordering: before the refill at C, the backfill
         * stops at C-2 (G5 needs the script binder at C). */
        TIPFIN_CHECK("T9 snapshot pre-refill",
                     tipfin_snap_expect(db, &rr, A + 2, -1, -1, 1));
        handled = false;
        TIPFIN_CHECK("T9 pre-refill pass stops below the boundary",
                     tipfin_backfill_span(db, &rr, &handled, 4, C - 2));

        /* Step 3 — simulated forward script/proof refill at C. */
        TIPFIN_CHECK("T9 simulated refill at C", tipfin_t9_refill(db, C, h));

        /* Step 4 — the boundary p=C-1 is written with both binders. */
        TIPFIN_CHECK("T9 snapshot at boundary",
                     tipfin_snap_expect(db, &rr, C - 2, -1, -1, 1));
        handled = false;
        TIPFIN_CHECK("T9 boundary backfilled after refill",
                     tipfin_backfill_span(db, &rr, &handled, 1, C - 1));
        struct tip_row_view row;
        TIPFIN_CHECK("T9 boundary row carries the dual binder hash",
                     tipfin_row_matches(db, C - 1, &row, 1,
                                        "finalize_backfill", &h[8], true));
        bool found = false;
        int32_t wlast = -1;
        uint32_t wtotal = 0;
        TIPFIN_CHECK("T9 witness deleted when the span exhausts",
                     tipfin_witness_gone(db, &found, &wlast, &wtotal));

        /* Step 5 — H* converges to C-1; the tear clears ARITHMETICALLY. */
        TIPFIN_CHECK("T9 hstar converges, tear clears",
                     tipfin_snap_expect(db, &rr, C - 1, -1, -1, -1));

        /* Step 6 — the existing reconcile clamps tip_finalize to C.
         * OWN-frame (task #31, corrected): the clamp band is [hstar, hstar+1]
         * capped at coins_applied's own NEXT-frame value; hstar = C-1,
         * coins_applied = C (=> applied through C-1, so the transition row at
         * C-1 — which serves C — is fully backed), so the served-tip claim is
         * C. The step_finalize resting state IS cursor == coins_applied (it
         * writes row C-1 and advances to C); clamping one lower made the
         * reconcile fight the step on every pass (the live rewind-churn
         * livelock: cur=hstar+1 clamped to hstar, re-finalized, repeat, until
         * the churn gate refused and fed the escalator). Seed-anchor
         * candidacy does not depend on the one-lower clamp: the durable
         * trusted-base declaration vets an ABSENT first row above the base
         * (reducer_trusted_anchor's allow_rowless_first path), and
         * stage_repair_preserve_trusted_base_transition keeps a completed
         * first transition above the base from being rewound at all. */
        struct main_state ms;
        main_state_init(&ms);
        struct stage_reducer_frontier_reconcile_result fin;
        TIPFIN_CHECK("T9 reconcile clamps tip_finalize to C (served tip)",
                     tipfin_t9_reconcile_ok(db, &ms, &fin, C));
        main_state_free(&ms);

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── T10 — tip_finalize-ONLY rowless hole, NO coin tear (the 16:40-flip
     * live pin class). Every upstream log (incl. utxo_apply) is ok=1 through
     * the range and coins is AHEAD (coins_applied == utxo_apply frontier + 1,
     * so NO coin tear), yet a rowless span mid tip_finalize_log caps H* at the
     * slowest log while served_floor sits ABOVE it. The forward reducer cannot
     * re-fill it (a cursor rewind trips utxo_count_diverged / the churn gate).
     * Pre-fix the backfill's coin-tear-ONLY gate returned handled=false and the
     * pin held forever; post-fix the relaxed gate re-emits the hash-bound rows
     * and H* climbs to served_floor. ── */
    {
        char dir[256];
        TIPFIN_CHECK("T10 setup", open_fixture(dir, sizeof(dir), "t10", A + 9));
        sqlite3 *db = progress_store_db();

        struct uint256 h[10];
        bool seeded = tipfin_t10_seed(db, h);
        TIPFIN_CHECK("T10 seed", seeded);

        /* H* pins at the hole even though served_floor is far above it, and
         * there is NO coin tear (coins A+9 == utxo_apply frontier A+8 + 1). */
        int32_t hs = 0, sf = 0;
        progress_store_tx_lock();
        bool okc = reducer_frontier_compute_hstar(db, &hs, &sf);
        progress_store_tx_unlock();
        TIPFIN_CHECK("T10 H* pins at the hole, served_floor ahead",
                     tipfin_hstar_matches(okc, hs, sf, A + 1, A + 8));

        /* Model the production no-tear snapshot (read_frontier_snapshot uses the
         * utxo_apply OWN frontier for the tear, not the tip_finalize-pinned H*,
         * so this rowless hole is NOT a coin tear). */
        struct stage_reducer_frontier_reconcile_result rr;
        memset(&rr, 0, sizeof(rr));
        rr.hstar = hs;
        rr.served_floor = sf;
        rr.sweep_top = sf;
        rr.coins_applied_found = true;
        rr.coins_applied_height = A + 9;
        rr.refused_coin_tear = false;   /* the whole point: no tear */
        rr.tip_finalize_cursor_before = A + 9;
        rr.tip_finalize_cursor_after = A + 9;

        bool handled = false;
        TIPFIN_CHECK("T10 backfill fills the no-tear hole (pre-fix: handled=false)",
                     tipfin_t10_filled(db, &rr, &handled));

        struct tip_row_view row;
        TIPFIN_CHECK("T10 filled rows are hash-bound finalize_backfill",
                     tipfin_t10_rows(db, h, &row));

        /* H* climbs to served_floor: the log is now contiguous ok=1. */
        progress_store_tx_lock();
        okc = reducer_frontier_compute_hstar(db, &hs, &sf);
        progress_store_tx_unlock();
        TIPFIN_CHECK("T10 H* climbs to served_floor after the fill",
                     tipfin_hstar_matches(okc, hs, sf, A + 8, A + 8));

        /* Originals intact (insert-only, non-destructive): 5 seeded + 3 filled. */
        TIPFIN_CHECK("T10 zero deletions, originals intact",
                     tipfin_t10_intact(db, &row));

        /* Re-run is a benign no-op: contiguous now, nothing to fill. */
        handled = false;
        memset(&rr, 0, sizeof(rr));
        rr.hstar = A + 8;
        rr.served_floor = A + 8;
        rr.coins_applied_found = true;
        rr.coins_applied_height = A + 9;
        rr.refused_coin_tear = false;
        TIPFIN_CHECK("T10 healed log is not applicable (served_floor==hstar)",
                     tipfin_backfill_idle(db, &rr, &handled));

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    printf("stage_repair_tipfin_backfill: %d failures\n", failures);
    return failures;
}
