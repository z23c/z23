/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the stale reorg-residue tip_finalize verdict replacement
 * (stage_reducer_frontier_purge_stale_reorg_tipfin), wired into the L1
 * reconcile (stage_repair_reducer_frontier.c).
 *
 * Coin tear is measured against utxo_apply's own contiguous ok=1 log prefix:
 * refused_coin_tear = coins_applied > utxo_apply_contig + 1. Coins leading the
 * global H* is pipeline depth, not a tear.
 *
 * Scenario: a depth-2 reorg at R leaves tip_finalize_log[R] = ok=0
 * reorg_detected; R+1,R+2 are absent from every value-checked log except
 * header_admit; utxo_apply is solid through R, coins_applied == R+1. The
 * residue caps H* at R-1 but is not a coin tear.
 *
 * GREEN   - header_admit present at R+1 and its cursor past R+1: the residue
 *           is replaced in place (never deleted; served_floor preserved) with
 *           an ok=1 'finalize_backfill' row carrying hash(R+1); H* lifts to R
 *           and the refill clamps the column to R+1; coins untouched.
 * REWOUND - header_admit at R+1 but its cursor == R+1 (replay territory): not
 *           replaced.
 * RED     - header_admit absent at R+1: not replaced, H* stays at R-1; the
 *           refill re-derives the column without touching coins.
 */

#include "test/test_core.h"

#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RR_CHECK(name, expr) do { \
    printf("reorg_residue_tipfin_replace: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

/* Distinct deterministic per-height hashes (rfrl/tipfin fixture convention). */
static void mk_hash(struct uint256 *h, int height)
{
    memset(h, 0, sizeof(*h));
    h->data[0] = (uint8_t)(height & 0xff);
    h->data[1] = (uint8_t)((height >> 8) & 0xff);
    h->data[2] = (uint8_t)((height >> 16) & 0xff);
    h->data[31] = 0x5a;
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

/* tip_finalize_log carries the full production column set. */
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

static bool put_simple(sqlite3 *db, const char *table, int height, int ok_flag)
{
    char sql[160];
    if (strcmp(table, "body_persist_log") == 0)
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,source,ok) "
                 "VALUES(?,'fixture',?)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok) "
                 "VALUES(?,'verified',?)", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
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
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
            "VALUES(?,'verified',?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* All five upstream value-checked logs ok=1 at `height`. */
static bool put_upstream_ok(sqlite3 *db, int height, const struct uint256 *hash)
{
    return put_validate(db, height, 1, hash) &&
           put_script(db, height, 1, hash) &&
           put_simple(db, "body_persist_log", height, 1) &&
           put_proof(db, height, 1, hash) &&
           put_utxo(db, height, 1, hash);
}

static bool put_tip(sqlite3 *db, int height, const char *status, int ok_flag,
                    int reorg_depth, const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            " utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(?,?,?,0,0,0,?,1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_flag);
    sqlite3_bind_int(st, 4, reorg_depth);
    if (hash)
        sqlite3_bind_blob(st, 5, hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 5);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_header_admit(sqlite3 *db, int height,
                             const struct uint256 *hash,
                             const struct uint256 *parent_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    if (parent_hash)
        sqlite3_bind_blob(st, 3, parent_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 3);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
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
    /* Stamp coins_kv proven-authority (applied_height, migration stamp,
     * non-empty coins) so compute_hstar keeps the anchor as a real floor. */
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

struct tip_view {
    bool found;
    int ok;
    char status[40];
    bool has_hash;
    struct uint256 hash;
};

static bool tip_at(sqlite3 *db, int height, struct tip_view *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, status, tip_hash FROM tip_finalize_log WHERE height=?",
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

/* Read H*, served_floor and coins as the L1 reconcile snapshot does. `tear`
 * compares coins_applied to utxo_apply's own contiguous ok=1 prefix, not H*,
 * so pipeline depth is never read as a tear. */
static bool snapshot(sqlite3 *db, int *hstar, int *served_floor,
                     int *coins_applied, bool *tear)
{
    progress_store_tx_lock();
    int32_t hs = 0, sf = 0;
    bool ok = reducer_frontier_compute_hstar(db, &hs, &sf);
    int32_t coins = 0;
    bool found = false;
    ok = ok && coins_kv_get_applied_height(db, &coins, &found);
    int32_t ua_contig = hs;
    ok = ok && reducer_frontier_log_frontier(db, "utxo_apply_log",
                                             "utxo_apply", &ua_contig);
    progress_store_tx_unlock();
    if (!ok)
        return false;
    *hstar = hs;
    *served_floor = sf;
    *coins_applied = found ? coins : -1;
    /* PRODUCTION tear basis: utxo_apply's own applied frontier, not H*. */
    *tear = found && coins > ua_contig + 1;
    return true;
}

static bool seed_wedge_residue_row(sqlite3 *db, int R,
                                   const struct uint256 *h,
                                   const char *tip_status)
{
    /* R: upstream logs ok=1; tip_finalize is the stale ok=0 residue
     * with reorg_depth=2. */
    return put_upstream_ok(db, R, &h[R - A]) &&
           put_tip(db, R, tip_status, 0, 2, &h[R - A + 1]);
}

static bool seed_wedge_header_admits(sqlite3 *db, int R,
                                     const struct uint256 *h,
                                     bool admit_at_gap)
{
    /* R+1, R+2: the column gap — validate..tip_finalize ALL absent (nothing
     * seeded). header_admit DOES carry them (real parent-linked blocks). */
    /* header_admit for every real height A+1 .. R+2. */
    bool ok = true;
    for (int x = A + 1; x <= R + 2; x++) {
        if (x == R + 1 && !admit_at_gap)
            continue;  /* RED control: starve FIX-A's lookahead binder */
        ok = ok && put_header_admit(db, x, &h[x - A], &h[x - A - 1]);
    }
    return ok;
}

static bool seed_wedge_cursors(sqlite3 *db, int R, int top_cursor)
{
    /* Cursors: upstream all high; utxo_apply at the gap (R+1 unapplied). */
    return seed_cursor(db, "validate_headers", top_cursor) &&
           seed_cursor(db, "header_admit", top_cursor) &&
           seed_cursor(db, "body_fetch", top_cursor) &&
           seed_cursor(db, "body_persist", top_cursor) &&
           seed_cursor(db, "script_validate", top_cursor) &&
           seed_cursor(db, "proof_validate", top_cursor) &&
           seed_cursor(db, "utxo_apply", R + 1) &&
           seed_cursor(db, "tip_finalize", top_cursor) &&
           seed_coins_applied(db, R + 1);
}

/* Seed the wedge: ok=0 reorg_detected at R, a column gap at R+1,R+2,
 * header_admit present through R+2 unless !admit_at_gap, coins_applied =
 * utxo_apply cursor = R+1, upper cursors high. */
static bool seed_wedge_with_tip_status(sqlite3 *db, int R, int top_cursor,
                                       bool admit_at_gap,
                                       const char *tip_status)
{
    struct uint256 h[8];
    for (int i = 0; i <= 7; i++)
        mk_hash(&h[i], A + i);
    /* A+1 .. A+(R-A): all five value-checked logs + tip_finalize ok=1
     * (contiguous finalized prefix below the residue). The residue is at R. */
    bool ok = true;
    for (int x = A + 1; x < R; x++) {
        ok = ok && put_upstream_ok(db, x, &h[x - A]);
        /* tip_finalize finalized row carries lookahead hash(x+1). */
        ok = ok && put_tip(db, x, "finalized", 1, 0, &h[x - A + 1]);
    }
    ok = ok && seed_wedge_residue_row(db, R, h, tip_status);
    ok = ok && seed_wedge_header_admits(db, R, h, admit_at_gap);
    ok = ok && seed_wedge_cursors(db, R, top_cursor);
    return ok;
}

static bool seed_wedge(sqlite3 *db, int R, int top_cursor, bool admit_at_gap)
{
    return seed_wedge_with_tip_status(db, R, top_cursor, admit_at_gap,
                                      "reorg_detected");
}

static int run_red_pin_check(sqlite3 *db, int R)
{
    int failures = 0;
    int hstar = 0, sf = 0, coins = 0;
    bool tear = false;
    /* The residue pins H* at R-1; coins lead it but utxo_apply's own log
     * is solid through R, so this is not a tear. */
    RR_CHECK("RED snapshot pins H* at R-1 with NO coin tear (vs utxo_apply)",
             snapshot(db, &hstar, &sf, &coins, &tear) &&
             hstar == R - 1 && coins == R + 1 && !tear);
    return failures;
}

/* RED control: header_admit absent at the gap, so the residue row is not
 * replaced and H* stays at R-1; the refill re-derives the column without
 * touching coins. */
static int run_red_case(int R, int top_cursor)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir),
                     "reorg_residue_tipfin_replace", "red");
    RR_CHECK("RED open", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    RR_CHECK("RED schema", seed_schema(db));
    RR_CHECK("RED seed (no header_admit at gap)",
             seed_wedge(db, R, top_cursor, /*admit_at_gap=*/false));

    failures += run_red_pin_check(db, R);

    struct main_state ms;
    main_state_init(&ms);
    struct stage_reducer_frontier_reconcile_result rr;
    /* The lookahead binder fails before the row is counted, so the
     * residue is neither found nor replaced and H* is not lifted. */
    RR_CHECK("RED reconcile: residue NOT replaced, no tear refusal",
             stage_reducer_frontier_reconcile_light(db, &ms, &rr) &&
             !rr.refused_coin_tear &&
             rr.reorg_residue_tipfin_found == 0 &&
             rr.reorg_residue_tipfin_replaced == 0 &&
             rr.lowest_reorg_residue_tipfin == -1);
    struct tip_view row;
    RR_CHECK("RED residue row untouched (still ok=0 reorg_detected)",
             tip_at(db, R, &row) && row.found && row.ok == 0 &&
             strcmp(row.status, "reorg_detected") == 0);
    /* H* unchanged at R-1 (residue still caps it). */
    int hstar2 = 0, sf2 = 0, coins2 = 0;
    bool tear2 = false;
    RR_CHECK("RED H* still pinned at R-1 (residue not replaced)",
             snapshot(db, &hstar2, &sf2, &coins2, &tear2) &&
             hstar2 == R - 1 && !tear2);
    /* Downstream heal: upstream cursors clamp back to re-walk the
     * unfinalized column; forward-only, nothing deleted. */
    RR_CHECK("RED downstream refill clamps the column (no refusal)",
             rr.repaired &&
             cursor_value(db, "validate_headers") == R + 2 &&
             cursor_value(db, "tip_finalize") == R);
    /* COINS UNTOUCHED even without FIX-A: utxo_apply cursor and
     * coins_applied are never rewound by the downstream refill. */
    RR_CHECK("RED utxo_apply + coins UNCHANGED at R+1 (no coin rewind)",
             cursor_value(db, "utxo_apply") == R + 1 && coins2 == R + 1);
    main_state_free(&ms);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* REWOUND: the header_admit row at R+1 exists but the cursor is rewound
 * to R+1, so it is replay territory and not a lookahead binder. */
static int run_rewound_case(int R, int top_cursor)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir),
                     "reorg_residue_tipfin_replace", "rewound");
    RR_CHECK("REWOUND open", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    RR_CHECK("REWOUND schema", seed_schema(db));
    RR_CHECK("REWOUND seed with header_admit row at gap",
             seed_wedge(db, R, top_cursor, /*admit_at_gap=*/true));
    RR_CHECK("REWOUND force header_admit cursor to gap",
             seed_cursor(db, "header_admit", R + 1) &&
             cursor_value(db, "header_admit") == R + 1);

    struct main_state ms;
    main_state_init(&ms);
    struct stage_reducer_frontier_reconcile_result rr;
    RR_CHECK("REWOUND reconcile refuses row at header_admit cursor",
             stage_reducer_frontier_reconcile_light(db, &ms, &rr) &&
             rr.reorg_residue_tipfin_found == 0 &&
             rr.reorg_residue_tipfin_replaced == 0 &&
             rr.lowest_reorg_residue_tipfin == -1);
    struct tip_view row;
    RR_CHECK("REWOUND residue row untouched",
             tip_at(db, R, &row) && row.found && row.ok == 0 &&
             strcmp(row.status, "reorg_detected") == 0);
    RR_CHECK("REWOUND header_admit cursor remains at replay point",
             cursor_value(db, "header_admit") == R + 1);
    main_state_free(&ms);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Reconcile the residue: the verdict is replaced in place, never deleted. */
static int run_green_reconcile(sqlite3 *db, int R, struct main_state *ms,
        struct stage_reducer_frontier_reconcile_result *rr)
{
    int failures = 0;
    long long rows_before = tip_row_count(db);

    struct uint256 admit_next;  /* hash(R+1) the replacement must carry */
    mk_hash(&admit_next, R + 1);

    main_state_init(ms);
    RR_CHECK("GREEN reconcile replaces residue + clears the tear",
             stage_reducer_frontier_reconcile_light(db, ms, rr) &&
             !rr->refused_coin_tear &&
             rr->reorg_residue_tipfin_replaced == 1 &&
             rr->reorg_residue_tipfin_found == 1 &&
             rr->lowest_reorg_residue_tipfin == R &&
             rr->repaired);

    /* The residue verdict is REPLACED in place — same height, fresh ok=1
     * 'finalize_backfill' carrying the lookahead hash(R+1); NEVER deleted
     * (row count unchanged), served_floor preserved. */
    struct tip_view fixed;
    RR_CHECK("GREEN residue REPLACED in place -> ok=1 finalize_backfill",
             tip_at(db, R, &fixed) && fixed.found && fixed.ok == 1 &&
             strcmp(fixed.status, "finalize_backfill") == 0 &&
             fixed.has_hash &&
             memcmp(fixed.hash.data, admit_next.data, 32) == 0);
    RR_CHECK("GREEN no tip_finalize row deleted (replace, not delete)",
             tip_row_count(db) == rows_before);
    return failures;
}

/* Post-reconcile: H* lifts to R and the column clamps; coins are untouched. */
static int run_green_clamp_checks(
        sqlite3 *db, int R,
        const struct stage_reducer_frontier_reconcile_result *rr)
{
    int failures = 0;
    /* H* lifted to R; the column clamps to the header_admit hole R+1. */
    int hstar2 = 0, sf2 = 0, coins2 = 0;
    bool tear2 = false;
    RR_CHECK("GREEN H* lifted to R, tear cleared arithmetically",
             snapshot(db, &hstar2, &sf2, &coins2, &tear2) &&
             hstar2 == R && !tear2);
    RR_CHECK("GREEN validate_headers clamped to the column hole R+1",
             rr->clamped_validate_headers &&
             cursor_value(db, "validate_headers") == R + 1);
    RR_CHECK("GREEN body_fetch + body_persist cascade to R+1",
             cursor_value(db, "body_fetch") == R + 1 &&
             cursor_value(db, "body_persist") == R + 1);
    /* tip_finalize's cursor is the served tip: R+1, backed by the replaced
     * ok=1 row at R; upstream column cursors stay at R+1. */
    RR_CHECK("GREEN tip_finalize clamped to the served tip R+1",
             cursor_value(db, "tip_finalize") == R + 1);

    /* COINS UNTOUCHED: utxo_apply cursor and coins_applied unchanged —
     * no coin rewind, no double-apply. */
    RR_CHECK("GREEN utxo_apply cursor UNCHANGED at R+1 (no coin rewind)",
             cursor_value(db, "utxo_apply") == R + 1);
    RR_CHECK("GREEN coins_applied UNCHANGED at R+1",
             coins2 == R + 1);
    return failures;
}

/* GREEN: header_admit present at the gap. The residue is replaced, H*
 * lifts to R, and the column clamps to R+1; coins are untouched. */
static int run_green_case(int R, int top_cursor)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir),
                     "reorg_residue_tipfin_replace", "green");
    RR_CHECK("GREEN open", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    RR_CHECK("GREEN schema", seed_schema(db));
    RR_CHECK("GREEN seed THE wedge",
             seed_wedge(db, R, top_cursor, /*admit_at_gap=*/true));

    int hstar = 0, sf = 0, coins = 0;
    bool tear = false;
    /* H* capped at R-1 by the ok=0 residue; coins at R+1 are not a tear. */
    RR_CHECK("GREEN snapshot reproduces the live pin (H*=R-1, no tear)",
             snapshot(db, &hstar, &sf, &coins, &tear) &&
             hstar == R - 1 && coins == R + 1 && !tear);
    struct tip_view residue;
    RR_CHECK("GREEN residue row present ok=0 reorg_detected before fix",
             tip_at(db, R, &residue) && residue.found &&
             residue.ok == 0 &&
             strcmp(residue.status, "reorg_detected") == 0);

    struct main_state ms;
    struct stage_reducer_frontier_reconcile_result rr;
    failures += run_green_reconcile(db, R, &ms, &rr);
    failures += run_green_clamp_checks(db, R, &rr);

    /* Idempotent: a second reconcile finds nothing to replace and holds
     * the clamped column (no re-pin, no re-tear). */
    struct stage_reducer_frontier_reconcile_result rr2;
    RR_CHECK("GREEN second reconcile is a stable no-replace",
             stage_reducer_frontier_reconcile_light(db, &ms, &rr2) &&
             !rr2.refused_coin_tear &&
             rr2.reorg_residue_tipfin_replaced == 0 &&
             cursor_value(db, "utxo_apply") == R + 1);
    main_state_free(&ms);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* One non-residue status: the guarded ok=0 row must stay unreplaced. */
static int run_nonresidue_case(int R, int top_cursor, const char *status)
{
    int failures = 0;
    char dir[256];
    char suffix[64];
    snprintf(suffix, sizeof(suffix), "nonresidue-%s", status);
    test_make_tmpdir(dir, sizeof(dir),
                     "reorg_residue_tipfin_replace", suffix);
    RR_CHECK("NONRESIDUE open", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    RR_CHECK("NONRESIDUE schema", seed_schema(db));
    RR_CHECK("NONRESIDUE seed guarded status",
             seed_wedge_with_tip_status(db, R, top_cursor,
                                        /*admit_at_gap=*/true, status));

    long long rows_before = tip_row_count(db);
    struct main_state ms;
    main_state_init(&ms);
    struct stage_reducer_frontier_reconcile_result rr;
    RR_CHECK("NONRESIDUE reconcile leaves guarded status unreplaced",
             stage_reducer_frontier_reconcile_light(db, &ms, &rr) &&
             rr.reorg_residue_tipfin_found == 0 &&
             rr.reorg_residue_tipfin_replaced == 0 &&
             rr.lowest_reorg_residue_tipfin == -1);

    struct tip_view row;
    RR_CHECK("NONRESIDUE row remains ok=0 with original status",
             tip_at(db, R, &row) && row.found && row.ok == 0 &&
             strcmp(row.status, status) == 0);
    RR_CHECK("NONRESIDUE no tip_finalize row deleted or replaced",
             tip_row_count(db) == rows_before);
    main_state_free(&ms);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_reorg_residue_tipfin_replace(void);
int test_reorg_residue_tipfin_replace(void)
{
    printf("\n=== reorg_residue_tipfin_replace tests ===\n");
    int failures = 0;

    const int R = A + 3;            /* residue height */
    const int top_cursor = A + 100; /* upper stages far ahead of the gap */

    failures += run_red_case(R, top_cursor);
    failures += run_rewound_case(R, top_cursor);
    failures += run_green_case(R, top_cursor);

    /* ── NEGATIVE GUARD — ok=0 tip_finalize rows that represent a real
     * upstream/precondition failure are NOT reorg residue. They must stay
     * ok=0 even when the header-admit binder exists, or the repair would
     * rewrite a real blocker into ok=1 finalize_backfill. ── */
    static const char *const non_residue_statuses[] = {
        "upstream_failed",
        "precondition_failed",
    };
    for (size_t i = 0;
         i < sizeof(non_residue_statuses) / sizeof(non_residue_statuses[0]);
         i++) {
        const char *status = non_residue_statuses[i];
        failures += run_nonresidue_case(R, top_cursor, status);
    }

    printf("reorg_residue_tipfin_replace: %d failures\n", failures);
    return failures;
}
