/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for FIX-A — the stale reorg-residue tip_finalize verdict replacement
 * (stage_repair_reducer_frontier_purge.c::
 *  stage_reducer_frontier_purge_stale_reorg_tipfin), wired into the L1
 * reconcile (stage_repair_reducer_frontier.c).
 *
 * SEMANTICS CHANGE (coin-tear is now measured vs utxo_apply's OWN log):
 * read_frontier_snapshot used to read refused_coin_tear = (coins_applied >
 * hstar + 1), where hstar is the global MIN over ALL stage logs INCLUDING the
 * slowest (tip_finalize). That was a FALSE-POSITIVE generator: coins_applied
 * tracks the utxo_apply cursor by construction (co-committed in one BEGIN
 * IMMEDIATE), so coins leading the global MIN H* is just PIPELINE DEPTH
 * (tip_finalize, the LAST stage, lagging) — not a tear. The fix measures the
 * tear against utxo_apply's OWN contiguous ok=1 log prefix (utxo_apply_contig,
 * read via reducer_frontier_log_frontier("utxo_apply_log","utxo_apply")):
 * refused_coin_tear = (coins_applied > utxo_apply_contig + 1). A REAL tear is
 * coins applied ABOVE utxo_apply's own solid log (a hole/ok=0 below the
 * cursor); this reorg-residue scenario has utxo_apply SOLID ok=1 through R, so
 * it is NO LONGER a coin tear at all.
 *
 * THE LIVE #1 WEDGE (proven on ~/.zclassic-c23-wedgecopy progress.kv): a
 * depth-2 reorg at h=R left tip_finalize_log[R] = ok=0 reorg_detected, while
 * the contiguous heights R+1,R+2 are ABSENT from EVERY value-checked log
 * (a "column gap"). header_admit_log HAS R+1,R+2 (real parent-linked
 * blocks). Upper cursors sit far above; utxo_apply cursor == coins_applied
 * == R+1 (coins applied THROUGH R; R+1 unapplied). utxo_apply's OWN log is
 * contiguous ok=1 through R, so utxo_apply_contig == R and
 * coins_applied(R+1) > utxo_apply_contig(R)+1 is FALSE => NO coin tear.
 *
 * The ok=0 row at R still caps the global H* at R-1 (it is the slowest log),
 * which is the residue the chain must shed to make forward progress — but it
 * is NOT a coin tear and no longer drives a refusal. The reconcile now
 * proceeds straight to the downstream heal in BOTH controls.
 *
 * GREEN — header_admit present at R+1 and header_admit cursor past R+1:
 * FIX-A's lookahead binder succeeds, so it REPLACES the residue verdict in
 * place (never deletes — served_floor preserved) with a fresh ok=1
 * 'finalize_backfill' row carrying hash(R+1); H* lifts to R and the existing
 * header_admit-keyed refill clamps validate_headers/body_fetch/body_persist
 * (and tip_finalize) to the column hole R+1; coins/utxo_apply are untouched.
 *
 * REWOUND — header_admit present at R+1 but cursor == R+1: this is replay
 * territory after a forward-fork rewind, not trusted evidence. The residue row
 * is NOT replaced until header_admit re-admits the canonical child and advances
 * past R+1.
 *
 * RED — header_admit ABSENT at R+1: FIX-A's lookahead binder gate fails before
 * the row is counted as replaceable, so the residue row is NOT replaced and H*
 * stays pinned at R-1. With the false coin-tear gone the reconcile no longer
 * early-returns; it falls through to the downstream refill, which SAFELY
 * re-derives the still-unfinalized column WITHOUT touching coins:
 * validate_headers clamps to the lowest header_admit-evidenced rowless hole
 * (R+2), body_fetch/body_persist re-walk from R, and tip_finalize clamps to
 * the H*+1 floor R (re-finalizing from R re-evaluates the residue). utxo_apply
 * and coins_applied stay at R+1 (no coin rewind). The RED control therefore
 * still asserts the REAL gate that distinguishes FIX-A: residue REPLACED iff
 * header_admit is present at the gap (GREEN) and NOT replaced when absent
 * (RED) — it just no longer asserts the (false) coin-tear refusal, which the
 * semantics change correctly removed.
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

/* Production-shaped schema: tip_finalize_log carries the FULL column set so
 * the production log_insert round-trips (matches tipfin fixture). */
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
    /* Stamp full coins_kv proven-authority so compute_hstar treats the baked
     * TRUSTED_ANCHOR as a REAL finality floor (this fixture models a seeded
     * datadir). compute_hstar's phantom-anchor guard drops the floor to 0 when
     * coins_kv is NOT proven authority — correct for a fresh datadir, wrong
     * here. Needs all three rungs: applied_height above, the migration stamp,
     * and a non-empty `coins` table. */
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

/* Read H-star, served_floor, coins, tear off the durable store the way the
 * L1 reconcile snapshot does — used to assert the pin BEFORE the reconcile.
 * `tear` follows the PRODUCTION semantics: coins_applied vs utxo_apply's OWN
 * contiguous ok=1 log prefix (reducer_frontier_log_frontier), NOT the global
 * MIN H* — so legitimate pipeline depth (tip_finalize lagging) is never read
 * as a tear. */
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

/* Seed THE wedge: contiguous ok=1 through R-? , an ok=0 reorg_detected row
 * at R, a column gap (validate..tip_finalize absent) at R+1,R+2,
 * header_admit present at every real height incl. R+1,R+2, coins_applied =
 * R+1, upper cursors high, utxo_apply cursor = R+1.  `admit_gap` controls the
 * RED-before control: when false, header_admit is NOT seeded at R+1 (FIX-A
 * gate-2 fails, residue stays). */
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
    /* R: the five value-checked logs are ok=1 (R is below the reorg point —
     * already covered by coins), but tip_finalize is the STALE ok=0
     * residue candidate with reorg_depth=2. */
    ok = ok && put_upstream_ok(db, R, &h[R - A]) &&
         put_tip(db, R, tip_status, 0, 2, &h[R - A + 1]);
    /* R+1, R+2: the column gap — validate..tip_finalize ALL absent (nothing
     * seeded). header_admit DOES carry them (real parent-linked blocks). */
    /* header_admit for every real height A+1 .. R+2. */
    for (int x = A + 1; x <= R + 2; x++) {
        if (x == R + 1 && !admit_at_gap)
            continue;  /* RED control: starve FIX-A's lookahead binder */
        ok = ok && put_header_admit(db, x, &h[x - A], &h[x - A - 1]);
    }
    /* Cursors: upstream all high; utxo_apply at the gap (R+1 unapplied). */
    ok = ok && seed_cursor(db, "validate_headers", top_cursor) &&
         seed_cursor(db, "header_admit", top_cursor) &&
         seed_cursor(db, "body_fetch", top_cursor) &&
         seed_cursor(db, "body_persist", top_cursor) &&
         seed_cursor(db, "script_validate", top_cursor) &&
         seed_cursor(db, "proof_validate", top_cursor) &&
         seed_cursor(db, "utxo_apply", R + 1) &&
         seed_cursor(db, "tip_finalize", top_cursor) &&
         seed_coins_applied(db, R + 1);
    return ok;
}

static bool seed_wedge(sqlite3 *db, int R, int top_cursor, bool admit_at_gap)
{
    return seed_wedge_with_tip_status(db, R, top_cursor, admit_at_gap,
                                      "reorg_detected");
}

int test_reorg_residue_tipfin_replace(void);
int test_reorg_residue_tipfin_replace(void)
{
    printf("\n=== reorg_residue_tipfin_replace tests ===\n");
    int failures = 0;

    const int R = A + 3;            /* residue height */
    const int top_cursor = A + 100; /* upper stages far ahead of the gap */

    /* ── RED control — header_admit ABSENT at the gap (R+1): FIX-A's
     * gate-2 (lookahead binder) fails, so the residue row is NOT replaced
     * (replaced==0) and the global H* stays pinned at R-1. This is still the
     * load-bearing distinction FIX-A draws: residue replaced iff header_admit
     * is present at the gap. With the semantics change the (false) coin-tear
     * is gone, so the reconcile no longer early-returns on a refusal — it
     * falls through to the downstream refill, which SAFELY re-derives the
     * unfinalized column WITHOUT rewinding coins. ── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir),
                         "reorg_residue_tipfin_replace", "red");
        RR_CHECK("RED open", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        RR_CHECK("RED schema", seed_schema(db));
        RR_CHECK("RED seed (no header_admit at gap)",
                 seed_wedge(db, R, top_cursor, /*admit_at_gap=*/false));

        int hstar = 0, sf = 0, coins = 0;
        bool tear = false;
        /* The residue still pins H* at R-1 (it is the slowest log), and coins
         * lead it — but vs utxo_apply's OWN solid log (contiguous ok=1 through
         * R) this is NOT a tear: coins_applied(R+1) > utxo_apply_contig(R)+1 is
         * false. The pin is real; the tear is not. */
        RR_CHECK("RED snapshot pins H* at R-1 with NO coin tear (vs utxo_apply)",
                 snapshot(db, &hstar, &sf, &coins, &tear) &&
                 hstar == R - 1 && coins == R + 1 && !tear);

        struct main_state ms;
        main_state_init(&ms);
        struct stage_reducer_frontier_reconcile_result rr;
        /* No false coin-tear refusal; FIX-A's gate-2 (lookahead binder
         * header_admit at R+1) fails BEFORE the row is even counted, so the
         * residue is neither found-as-replaceable nor replaced — it stays ok=0
         * and H* is not lifted. The reconcile heals the column downstream
         * instead. (found/lowest both 0/-1: the binder gate runs ahead of the
         * found++ counter; see stage_repair_reducer_frontier_purge.c.) */
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
        /* Downstream heal (no refusal early-return): the upstream cursors
         * clamp back to re-walk the still-unfinalized column. validate_headers
         * clamps to the lowest header_admit-evidenced rowless hole (R+2 — R+1
         * has no header_admit in RED); body_fetch/body_persist re-walk from R;
         * tip_finalize clamps to the H*+1 floor R (re-finalizing from R
         * re-evaluates the residue). All forward-only, INSERT-OR-REPLACE
         * cursors — nothing deleted. */
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
    }

    /* ── REWOUND guard — header_admit_log at R+1 exists, but the durable
     * header_admit cursor was rewound TO R+1. That row is stale replay
     * territory until header_admit advances past it, so FIX-A must not use it
     * as a lookahead binder. This models a forward-fork
     * recovery after header_admit clamped from far-ahead stale rows. ── */
    {
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
    }

    /* ── GREEN — THE wedge with header_admit present at the gap. There is no
     * coin tear (utxo_apply's own log is solid through R), but the ok=0
     * residue at R still caps the global H* at R-1 and blocks forward
     * finalization. FIX-A replaces the residue verdict, H* lifts to R, the
     * existing header_admit-keyed refill clamps the column to R+1,
     * coins/utxo_apply are untouched. Driven through the REAL L1 entry
     * point. ── */
    {
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
        /* Reproduces the live pin: H* capped at R-1 by the ok=0 residue, coins
         * one ahead at R+1 — but NO coin tear vs utxo_apply's own solid log
         * (utxo_apply_contig == R). The residue is the H* cap, not a tear. */
        RR_CHECK("GREEN snapshot reproduces the live pin (H*=R-1, no tear)",
                 snapshot(db, &hstar, &sf, &coins, &tear) &&
                 hstar == R - 1 && coins == R + 1 && !tear);
        struct tip_view residue;
        RR_CHECK("GREEN residue row present ok=0 reorg_detected before fix",
                 tip_at(db, R, &residue) && residue.found &&
                 residue.ok == 0 &&
                 strcmp(residue.status, "reorg_detected") == 0);
        long long rows_before = tip_row_count(db);

        struct uint256 admit_next;  /* hash(R+1) the replacement must carry */
        mk_hash(&admit_next, R + 1);

        struct main_state ms;
        main_state_init(&ms);
        struct stage_reducer_frontier_reconcile_result rr;
        RR_CHECK("GREEN reconcile replaces residue + clears the tear",
                 stage_reducer_frontier_reconcile_light(db, &ms, &rr) &&
                 !rr.refused_coin_tear &&
                 rr.reorg_residue_tipfin_replaced == 1 &&
                 rr.reorg_residue_tipfin_found == 1 &&
                 rr.lowest_reorg_residue_tipfin == R &&
                 rr.repaired);

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

        /* H* lifted to R; the column clamps to the header_admit hole R+1. */
        int hstar2 = 0, sf2 = 0, coins2 = 0;
        bool tear2 = false;
        RR_CHECK("GREEN H* lifted to R, tear cleared arithmetically",
                 snapshot(db, &hstar2, &sf2, &coins2, &tear2) &&
                 hstar2 == R && !tear2);
        RR_CHECK("GREEN validate_headers clamped to the column hole R+1",
                 rr.clamped_validate_headers &&
                 cursor_value(db, "validate_headers") == R + 1);
        RR_CHECK("GREEN body_fetch + body_persist cascade to R+1",
                 cursor_value(db, "body_fetch") == R + 1 &&
                 cursor_value(db, "body_persist") == R + 1);
        /* OWN-frame (task #31, corrected): tip_finalize's cursor is the
         * served tip height; with H* = R and coins applied through R the
         * served-tip claim is R+1 — backed by the just-replaced ok=1
         * transition row at R and exactly where the forward step rests
         * (the upstream column cursors stay NEXT-frame at R+1). */
        RR_CHECK("GREEN tip_finalize clamped to the served tip R+1",
                 cursor_value(db, "tip_finalize") == R + 1);

        /* COINS UNTOUCHED: utxo_apply cursor and coins_applied unchanged —
         * no coin rewind, no double-apply. */
        RR_CHECK("GREEN utxo_apply cursor UNCHANGED at R+1 (no coin rewind)",
                 cursor_value(db, "utxo_apply") == R + 1);
        RR_CHECK("GREEN coins_applied UNCHANGED at R+1",
                 coins2 == R + 1);

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
    }

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
    }

    printf("reorg_residue_tipfin_replace: %d failures\n", failures);
    return failures;
}
