/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * T10/T11 (WP-F / FIX-5): reducer_frontier_reconcile_light condition-layer
 * witness channel + peer-gate visibility, proven through the REAL condition
 * engine (condition_engine_tick), never by calling detect/remedy directly.
 *
 * T10 — H*-only witness + TL-1 REFRESH-ONLY progress channel. The witness
 *   still clears ONLY on a real advance of the provable frontier H*
 *   (reducer_frontier_compute_hstar) — a backfill record bump is NOT a
 *   clear-edge. But TL-1 decouples the witness CLEAR from the attempt-budget
 *   REFRESH: when the witness is still false yet the remedy is making durable,
 *   resumable progress (a chunked backfill spanning more rounds than
 *   max_attempts), condition.progressing() RESETS the budget so a converging
 *   repair is never false-paged. So:
 *     T10a — a backfill record that ADVANCES every round (durable progress)
 *       REFRESHES the budget: across >5 rounds with H* frozen it must NOT page
 *       and must stay currently_active (TL-1 — converging repair not wedged).
 *     T10b — a FROZEN record (pure churn, no advance) returns progressing()=
 *       false, so the budget STILL exhausts at max_attempts=5 and pages
 *       (EV_OPERATOR_NEEDED path intact — a genuinely stuck node still pages).
 *     T10c — never-stuck-invariant-3: the at-detect H* baseline is captured
 *       ONCE at the rising edge, not re-stamped every detect-true tick, so a
 *       sustained detect-true episode whose H* climbs by 1 each round CLEARS
 *       the witness (never accrues a false page).
 *
 * T11 — peer-gate bypass: peers present but none ahead used to idle the
 *   ENTIRE L1 layer silently. A pending refused_coin_tear (durable internal
 *   evidence) must now bypass the gate with ONE transition-logged WARN;
 *   the same peer state with no tear must suppress exactly as today.
 *
 * Fixture is a trimmed copy of test_reducer_frontier_reconcile_light.c's. */

#include "platform/time_compat.h"
#include "test/test_core.h"

#include "conditions/reducer_frontier_reconcile_light.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "framework/condition.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "net/connman.h"
#include "net/net.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Mirrors engine/reducer/conditions/src/reducer_frontier_reconcile_light.c ZCL_TESTING
 * hooks that are src-private (the test_utxo_apply_stage.c delta-internal
 * mirror pattern). The post-remedy hook stands in for the TIPFIN backfill
 * bumping its progress record during the remedy. */
void reducer_frontier_reconcile_light_test_set_post_remedy_hook(
    void (*fn)(void));
int reducer_frontier_reconcile_light_test_bypass_warns(void);
bool reducer_frontier_reconcile_light_test_progressing(void);
void reducer_frontier_reconcile_light_test_snapshot_insert_baseline(void);
void reducer_frontier_reconcile_light_test_note_coin_insert_result(int inserted);

#define RRW_CHECK(name, expr) do { \
    printf("reducer_reconcile_witness: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR
#define COND_NAME "reducer_frontier_reconcile_light"

struct rrw_fixture {
    char dir[256];
    struct main_state ms;
    struct uint256 hashes[4];
    struct block_index *idx[4];
};

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

static bool seed_schema(sqlite3 *db)
{
    return
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            "parent_hash BLOB, admitted_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
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
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "tip_hash BLOB)");
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

static bool put_hash_log(sqlite3 *db, const char *table, const char *hash_col,
                         int height, int ok_flag, const struct uint256 *hash)
{
    char sql[192];
    if (strcmp(table, "validate_headers_log") == 0) {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,ok,%s) VALUES(?,?,?)",
                 table, hash_col);
    } else {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok,%s) "
                 "VALUES(?,'verified',?,?)",
                 table, hash_col);
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_simple_log(sqlite3 *db, const char *table, int height,
                           int ok_flag)
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

static bool put_utxo_log(sqlite3 *db, int height, int ok_flag,
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

/* Seed a REAL coin tear: poke an ok=0 row into utxo_apply_log at height K.
 * The coin-tear test now compares coins_applied against utxo_apply's OWN
 * contiguous ok=1 log prefix (reducer_frontier_log_frontier on
 * "utxo_apply_log"/"utxo_apply"), so an ok=0 row at K (overwriting the ok=1
 * row setup_fixture wrote) terminates that prefix at K-1. With coins_applied
 * set above K, `coins_applied > utxo_apply_contig + 1` is TRUE — a genuine
 * tear of coins above the solid applied log, NOT a tip_finalize-lag false
 * positive. Status 'verified' (default) is intentional: it must NOT be
 * 'value_overflow' (the maybe_repair_value_overflow trigger), so this remains
 * a plain applied-log hole that no pre-refusal repair claims, and the L1 flow
 * reaches the terminal coin-tear refusal that drives the witness machinery. */
static bool poke_utxo_apply_hole(sqlite3 *db, int height)
{
    return put_simple_log(db, "utxo_apply_log", height, 0);
}

static bool put_tip_log(sqlite3 *db, int height, int ok_flag,
                        const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,tip_hash) VALUES(?,'finalized',?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_upstream_ok(sqlite3 *db, int height,
                            const struct uint256 *hash)
{
    return put_hash_log(db, "validate_headers_log", "hash", height, 1, hash) &&
           put_hash_log(db, "script_validate_log", "block_hash", height, 1,
                        hash) &&
           put_simple_log(db, "body_persist_log", height, 1) &&
           put_hash_log(db, "proof_validate_log", "block_hash", height, 1,
                        hash) &&
           put_utxo_log(db, height, 1, hash);
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
    return ok;
}

/* Write/bump the tipfin_backfill.progress record exactly as the TIPFIN
 * backfill does: [last_backfilled_height i32 LE][total u32 LE]. */
static bool set_tipfin_progress(sqlite3 *db, int v)
{
    uint8_t blob[8] = {0};
    for (int i = 0; i < 4; i++)
        blob[i] = (uint8_t)((uint32_t)v >> (8 * i));
    uint32_t total = 1;
    for (int i = 0; i < 4; i++)
        blob[4 + i] = (uint8_t)(total >> (8 * i));
    static const uint8_t zero_hash[32] = {0};
    return repair_marker_note(db, REPAIR_MARKER_KIND_TIPFIN_PROGRESS,
                              REPAIR_MARKER_TIPFIN_HEIGHT, zero_hash,
                              blob, sizeof(blob));
}

static bool set_tipfin_progress_malformed(sqlite3 *db, int v)
{
    uint8_t blob[4] = {
        (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16),
        (uint8_t)(v >> 24)
    };
    static const uint8_t zero_hash[32] = {0};
    return repair_marker_note(db, REPAIR_MARKER_KIND_TIPFIN_PROGRESS,
                              REPAIR_MARKER_TIPFIN_HEIGHT, zero_hash,
                              blob, sizeof(blob));
}

static struct block_index *insert_index(struct main_state *ms,
                                        struct uint256 *hash,
                                        int height,
                                        struct block_index *prev,
                                        unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = (uint8_t)((height >> 16) & 0xff);
    hash->data[31] = 0x7b;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = status;
    bi->nFile = -1;
    bi->nDataPos = 0;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height - A + 1));
    return bi;
}

static bool stamp_coins_kv_migration(sqlite3 *db);

static bool setup_fixture(struct rrw_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir),
                     "reducer_reconcile_witness", tag);
    if (!progress_store_open(fx->dir))
        return false;
    if (!seed_schema(progress_store_db()))
        return false;
    if (!seed_all_cursors(progress_store_db(), A + 4))
        return false;

    main_state_init(&fx->ms);
    fx->idx[1] = insert_index(&fx->ms, &fx->hashes[1], A + 1, NULL,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    fx->idx[2] = insert_index(&fx->ms, &fx->hashes[2], A + 2,
                              fx->idx[1], BLOCK_HAVE_DATA);
    fx->idx[3] = insert_index(&fx->ms, &fx->hashes[3], A + 3,
                              fx->idx[2],
                              BLOCK_VALID_TREE | BLOCK_HAVE_DATA |
                              BLOCK_FAILED_VALID);
    if (!fx->idx[1] || !fx->idx[2] || !fx->idx[3])
        return false;

    if (!put_header_admit(progress_store_db(), A + 1, &fx->hashes[1], NULL) ||
        !put_header_admit(progress_store_db(), A + 2, &fx->hashes[2],
                          &fx->hashes[1]) ||
        !put_header_admit(progress_store_db(), A + 3, &fx->hashes[3],
                          &fx->hashes[2]))
        return false;

    if (!put_upstream_ok(progress_store_db(), A + 1, &fx->hashes[1]) ||
        !put_upstream_ok(progress_store_db(), A + 2, &fx->hashes[2]) ||
        !put_upstream_ok(progress_store_db(), A + 3, &fx->hashes[3]))
        return false;
    if (!put_tip_log(progress_store_db(), A + 1, 1, &fx->hashes[1]))
        return false;
    if (!seed_coins_applied(progress_store_db(), A + 2))
        return false;
    return stamp_coins_kv_migration(progress_store_db());
}

static void teardown_fixture(struct rrw_fixture *fx)
{
    main_state_free(&fx->ms);
    progress_store_close();
    test_cleanup_tmpdir(fx->dir);
}

static const struct json_value *rrw_json_condition(
    const struct json_value *root,
    const char *name)
{
    const struct json_value *conditions = json_get(root, "conditions");
    if (!conditions || !name)
        return NULL;
    for (size_t i = 0; i < json_size(conditions); i++) {
        const struct json_value *cond = json_at(conditions, i);
        const struct json_value *n = json_get(cond, "name");
        if (n && strcmp(json_get_str(n), name) == 0)
            return cond;
    }
    return NULL;
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

/* T10 post-remedy hook: the TIPFIN backfill repairs a batch DURING the
 * remedy and bumps its progress record; the engine's immediate post-remedy
 * witness re-check then sees the bump. */
static int g_bump_progress = 100;
static void bump_tipfin_record(void)
{
    g_bump_progress++;
    (void)set_tipfin_progress(progress_store_db(), g_bump_progress);
}

/* ── T10c climb-fixture helpers (never-stuck-invariant-3) ─────────────────
 * A fixture where detect stays TRUE via a persistent coin tear while H*
 * genuinely CLIMBS one height per round. The tear is kept "high" (coins
 * applied far above utxo_apply's own contiguous frontier), and utxo_apply is
 * the SLOWEST stage (the global MIN that pins H*); filling utxo_apply one
 * height at a time between ticks climbs H* by 1 while the tear (and thus
 * detect) persists. coins are kept so far above that no pre-refusal repair can
 * heal the tear, so the remedy refuses (FAILED) without mutating H* — the only
 * H* movement is the test's own between-tick fill. */
static void synth_hash_h(struct uint256 *h, int height)
{
    memset(h, 0, sizeof(*h));
    h->data[0] = (uint8_t)(height & 0xff);
    h->data[1] = (uint8_t)((height >> 8) & 0xff);
    h->data[2] = (uint8_t)((height >> 16) & 0xff);
    h->data[31] = 0x7c;
}

/* Stamp coins_kv proven-authority (the rungs coins_kv_is_proven_authority
 * checks) so compute_hstar treats REDUCER_FRONTIER_TRUSTED_ANCHOR as a REAL
 * finality floor — otherwise the phantom-anchor guard drops the floor to 0 and
 * the gap below the anchor pins H*=0 (it could not climb). coins_applied_height
 * is set separately by seed_coins_applied. */
static bool stamp_coins_kv_migration(sqlite3 *db)
{
    static const uint8_t dummy_txid[32] = {0x74};
    if (!coins_kv_ensure_schema(db) ||
        !coins_kv_add(db, dummy_txid, 0, 0, A, false, NULL, 0))
        return false;
    uint8_t one = 1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Build the climb fixture. Every stage EXCEPT utxo_apply is ok=1 contiguous
 * A+1..A+top (so they never bind below utxo_apply); utxo_apply is ok=1 ONLY at
 * A+1 (holes A+2..A+top — the climbing stage). coins_applied sits at A+top+4
 * (a persistent tear). No block_index is needed: active_chain_height reads
 * MAX(tip_finalize ok=1)=A+top, so the peer gate passes with zero peers. */
static bool setup_climb_fixture(struct rrw_fixture *fx, const char *tag, int top)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir),
                     "reducer_reconcile_witness", tag);
    if (!progress_store_open(fx->dir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!seed_schema(db))
        return false;
    if (!seed_all_cursors(db, A + top + 8))
        return false;
    main_state_init(&fx->ms);

    for (int h = A + 1; h <= A + top; h++) {
        struct uint256 hh;
        synth_hash_h(&hh, h);
        if (!put_header_admit(db, h, &hh, NULL))
            return false;
        if (!put_hash_log(db, "validate_headers_log", "hash", h, 1, &hh))
            return false;
        if (!put_hash_log(db, "script_validate_log", "block_hash", h, 1, &hh))
            return false;
        if (!put_simple_log(db, "body_persist_log", h, 1))
            return false;
        if (!put_hash_log(db, "proof_validate_log", "block_hash", h, 1,
                          &hh))
            return false;
        if (!put_tip_log(db, h, 1, &hh))
            return false;
    }
    /* utxo_apply: only A+1 ok=1; A+2..A+top are holes (the climbing stage). */
    struct uint256 first_hash;
    synth_hash_h(&first_hash, A + 1);
    if (!put_utxo_log(db, A + 1, 1, &first_hash))
        return false;
    /* Tear far above the climb so no pre-refusal repair can heal it. */
    if (!seed_coins_applied(db, A + top + 4))
        return false;
    if (!stamp_coins_kv_migration(db))
        return false;
    return true;
}

int test_reducer_reconcile_witness(void);
int test_reducer_reconcile_witness(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== reducer_reconcile_witness (FIX-5) tests ===\n");
    int failures = 0;

    /* ── T10a: ADVANCING record REFRESHES the budget (TL-1) ──────────── */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T10a: setup tear fixture", setup_fixture(&fx, "t10_bump"));
        sqlite3 *db = progress_store_db();
        /* REAL coin tear: a real utxo_apply hole at K=A+2 with
         * coins_applied=A+3 > K — `coins_applied > utxo_apply_contig + 1` is
         * TRUE so the tear fires and the remedy refuses (COND_REMEDY_FAILED)
         * every round. H* stays pinned at the hole (A+1) the whole time — the
         * witness NEVER clears (H* is the sole clear predicate). But the
         * post-remedy hook ADVANCES the tipfin backfill record every round,
         * which is durable, resumable progress: TL-1's progressing() channel
         * REFRESHES the attempt budget so a converging multi-round repair is
         * never false-paged. Across 8 rounds (> max_attempts=5) it must stay
         * active and NOT page. */
        RRW_CHECK("T10a: poke real utxo_apply hole at K=A+2",
                  poke_utxo_apply_hole(db, A + 2));
        RRW_CHECK("T10a: seed coins_applied above the hole (tear)",
                  seed_coins_applied(db, A + 3));
        RRW_CHECK("T10a: backfill record present before first tick",
                  set_tipfin_progress(db, 100));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();
        g_bump_progress = 100;
        reducer_frontier_reconcile_light_test_set_post_remedy_hook(
            bump_tipfin_record);

        /* 8 rounds (> max_attempts=5): each tick detects, remedies (hook
         * ADVANCES the record, impl refuses the tear), and the post-remedy
         * progressing() sees the record advance and resets attempts to 0. So no
         * round pages even though H* never moves and the witness never clears. */
        for (int i = 0; i < 8; i++) {
            reducer_frontier_reconcile_light_test_clear_backoff();
            condition_engine_tick();
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(COND_NAME, &snap);
        RRW_CHECK("T10a: advancing record REFRESHES the budget — stays active, "
                  "never pages across >5 rounds (TL-1)",
                  got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 8 &&
                  snap.currently_active &&
                  snap.attempts < 5 &&
                  snap.last_outcome == COND_REMEDY_FAILED &&
                  !snap.operator_needed_emitted);

        reducer_frontier_reconcile_light_test_set_post_remedy_hook(NULL);
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── T10b: frozen record exhausts the budget and pages ───────────── */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T10b: setup tear fixture",
                  setup_fixture(&fx, "t10_frozen"));
        sqlite3 *db = progress_store_db();
        /* REAL coin tear: the tear is now measured against utxo_apply's OWN
         * contiguous ok=1 log prefix, so seed a real utxo_apply hole at K=A+2
         * with coins_applied=A+3 > K — `coins_applied > utxo_apply_contig + 1`
         * is TRUE so the tear genuinely fires (and, the record being frozen,
         * the budget exhausts and pages). */
        RRW_CHECK("T10b: poke real utxo_apply hole at K=A+2",
                  poke_utxo_apply_hole(db, A + 2));
        RRW_CHECK("T10b: seed coins_applied above the hole (tear)",
                  seed_coins_applied(db, A + 3));
        /* Record present but FROZEN: presence alone must never witness —
         * only movement (or an absent<->present transition) does. */
        RRW_CHECK("T10b: frozen backfill record present",
                  set_tipfin_progress(db, 42));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        for (int i = 0; i < 5; i++) {
            reducer_frontier_reconcile_light_test_clear_backoff();
            condition_engine_tick();
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(COND_NAME, &snap);
        RRW_CHECK("T10b: frozen record -> attempts hit max and page "
                  "(EV_OPERATOR_NEEDED path intact)",
                  got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 5 &&
                  snap.currently_active &&
                  snap.attempts >= 5 &&
                  snap.last_outcome == COND_REMEDY_FAILED &&
                  snap.operator_needed_emitted);

        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── T10b2: malformed TIPFIN progress is diagnostic-absent ─────── */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T10b2: setup tear fixture",
                  setup_fixture(&fx, "t10_malformed"));
        sqlite3 *db = progress_store_db();
        RRW_CHECK("T10b2: poke real utxo_apply hole at K=A+2",
                  poke_utxo_apply_hole(db, A + 2));
        RRW_CHECK("T10b2: seed coins_applied above the hole (tear)",
                  seed_coins_applied(db, A + 3));
        RRW_CHECK("T10b2: malformed 4-byte progress record present",
                  set_tipfin_progress_malformed(db, 77));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();
        reducer_frontier_reconcile_light_test_clear_backoff();
        condition_engine_tick();

        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        bool ok = condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            ok ? rrw_json_condition(&dump, COND_NAME) : NULL;
        const struct json_value *detail = cond ? json_get(cond, "detail") : NULL;
        ok = ok && detail &&
             json_get_int(json_get(
                 detail, "tipfin_backfill_present_at_detect")) == 0 &&
             json_get_int(json_get(
                 detail, "tipfin_backfill_progress_at_detect")) == -1;
        RRW_CHECK("T10b2: malformed progress treated as absent", ok);
        json_free(&dump);

        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── T10b3: inserted-coin progress is edge-triggered ───────────── */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T10b3: setup progress callback fixture",
                  setup_fixture(&fx, "t10_insert_edge"));

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        reducer_frontier_reconcile_light_test_snapshot_insert_baseline();

        reducer_frontier_reconcile_light_test_note_coin_insert_result(7);
        bool first = reducer_frontier_reconcile_light_test_progressing();
        bool stale_repeat = reducer_frontier_reconcile_light_test_progressing();

        reducer_frontier_reconcile_light_test_note_coin_insert_result(0);
        bool no_insert = reducer_frontier_reconcile_light_test_progressing();

        reducer_frontier_reconcile_light_test_note_coin_insert_result(3);
        bool second_insert = reducer_frontier_reconcile_light_test_progressing();

        RRW_CHECK("T10b3: inserted coins refresh once per remedy result",
                  first && !stale_repeat && !no_insert && second_insert &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 3);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        teardown_fixture(&fx);
    }

    /* ── T10c: H* baseline captured ONCE at the rising edge (inv-3) ──── */
    {
        /* never-stuck-invariant-3: the old detect re-stamped g_hstar_at_detect
         * on EVERY detect-true tick, so a sustained detect-true episode that
         * climbs H* one hole at a time could never witness the climb (the
         * baseline tracked H* up), accrued attempts, and false-paged. With the
         * rising-edge capture the baseline is frozen at episode start, so any
         * genuine H* climb clears the witness. Here detect stays true via a
         * persistent tear while the test fills utxo_apply one height per round
         * between ticks (H* climbs by 1 each round). The remedy refuses the tear
         * (FAILED) without mutating H*, so the only H* movement is the fill.
         * Expectation: the witness CLEARS repeatedly (never a false page) across
         * 8 rounds (> max_attempts=5). The OLD re-stamp bug would page at 5. */
        const int top = 10;
        struct rrw_fixture fx;
        RRW_CHECK("T10c: setup climb fixture",
                  setup_climb_fixture(&fx, "t10_climb", top));
        sqlite3 *db = progress_store_db();

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        for (int round = 1; round <= 8; round++) {
            reducer_frontier_reconcile_light_test_clear_backoff();
            condition_engine_tick();
            /* Between ticks: fill the next utxo_apply hole so H* climbs by 1.
             * utxo_apply is the global MIN, so its contiguous frontier == H*. */
            struct uint256 filled_hash;
            synth_hash_h(&filled_hash, A + 1 + round);
            (void)put_utxo_log(db, A + 1 + round, 1, &filled_hash);
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(COND_NAME, &snap);
        RRW_CHECK("T10c: climbing H* clears the witness, never pages "
                  "(baseline captured once at the rising edge)",
                  got &&
                  snap.cleared_count >= 3 &&
                  snap.attempts < 5 &&
                  !snap.operator_needed_emitted);

        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── T11a: peers-not-ahead + pending tear -> gate BYPASS ─────────── */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T11a: setup tear fixture",
                  setup_fixture(&fx, "t11_bypass"));
        sqlite3 *db = progress_store_db();
        /* REAL coin tear: the tear is now measured against utxo_apply's OWN
         * contiguous ok=1 log prefix, so seed a real utxo_apply hole at K=A+2
         * with coins_applied=A+3 > K — `coins_applied > utxo_apply_contig + 1`
         * is TRUE so the tear (and the peer-gate bypass) genuinely fires. */
        RRW_CHECK("T11a: poke real utxo_apply hole at K=A+2",
                  poke_utxo_apply_hole(db, A + 2));
        RRW_CHECK("T11a: seed coins_applied above the hole (tear)",
                  seed_coins_applied(db, A + 3));

        /* One peer, NOT ahead: starting_height == local finalized height
         * (A+1). peer_lag_allows_repair refuses this — pre-FIX-5 the whole
         * L1 layer idled here silently. */
        struct connman cm;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memset(&p1, 0, sizeof(p1));
        p1.id = 1;
        p1.starting_height = A + 1;
        p1.state = PEER_ACTIVE;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(COND_NAME, &snap);
        RRW_CHECK("T11a: detect activates via bypass and remedy runs",
                  got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 1 &&
                  snap.currently_active &&
                  snap.last_outcome == COND_REMEDY_FAILED);
        RRW_CHECK("T11a: bypass WARN emitted once",
                  reducer_frontier_reconcile_light_test_bypass_warns() == 1);

        /* Second tick: still bypassing, but the WARN is transition-logged —
         * no repeat. */
        reducer_frontier_reconcile_light_test_clear_backoff();
        condition_engine_tick();
        RRW_CHECK("T11a: second tick keeps detecting",
                  reducer_frontier_reconcile_light_test_remedy_calls() == 2);
        RRW_CHECK("T11a: bypass WARN still exactly once",
                  reducer_frontier_reconcile_light_test_bypass_warns() == 1);

        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── T11b: same peer state, NO tear -> gate suppresses as today ──── */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T11b: setup plain repair fixture",
                  setup_fixture(&fx, "t11_suppress"));
        sqlite3 *db = progress_store_db();

        struct connman cm;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memset(&p1, 0, sizeof(p1));
        p1.id = 1;
        p1.starting_height = A + 1;
        p1.state = PEER_ACTIVE;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();
        reducer_frontier_reconcile_light_test_clear_backoff();
        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(COND_NAME, &snap);
        RRW_CHECK("T11b: gate suppresses the plain cursor-churn class",
                  got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 0 &&
                  !snap.currently_active &&
                  reducer_frontier_reconcile_light_test_bypass_warns() == 0);
        RRW_CHECK("T11b: no repair mutation while suppressed",
                  cursor_value(db, "body_fetch") == A + 4 &&
                  cursor_value(db, "tip_finalize") == A + 4);

        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── P2: the purge clamps script/proof cursors to the hole it makes ──
     * A 1-block reorg can
     * leave rows at h describing the invalidated block; the reconcile apply
     * pass purged them (rowless holes in script_validate_log /
     * proof_validate_log) but left the script_validate / proof_validate
     * cursors ABOVE h — the refill scan keys on the body_persist_log anchor
     * row the same pass deleted, so it read no hole and no stage ever
     * re-derived the rows (H* frozen 3 h at 3166988). Live shape: h ==
     * coins_applied == hstar+1 (NO coin tear), cursors above h. The purge
     * must now clamp both cursors to h in the SAME apply pass, atomically
     * with the deletes (stage_repair_reducer_frontier_purge.c). */
    {
        struct rrw_fixture fx;
        RRW_CHECK("P2: setup fixture", setup_fixture(&fx, "p2_purge_clamp"));
        sqlite3 *db = progress_store_db();
        /* progress.kv reopens per fixture; drop the dry-run detect memo so a
         * reused db pointer cannot replay a prior fixture's clean result. */
        stage_reducer_frontier_reset_detect_memo_for_testing();
        /* Anchor floor (the T10c precedent): without the coins_kv
         * proven-authority stamp the phantom-anchor guard drops the H* floor
         * to 0 and the purge window [hstar+1, hstar+8192] misses A+2. */
        RRW_CHECK("P2: coins_kv proven-authority stamped",
                  stamp_coins_kv_migration(db));

        /* The purge judges rows against the ACTIVE chain at their height. */
        RRW_CHECK("P2: active chain installs",
                  active_chain_move_window_tip(&fx.ms.chain_active,
                                               fx.idx[3]));

        /* Reorg residue at h=A+2 (== coins_applied == hstar+1): rewrite the
         * validate/script rows with the invalidated block's hash, ok=0 (the
         * tip_fork_stale verdict shape). The hashless body_persist / proof
         * rows at A+2 are transitively stale; the purge deletes them too. */
        struct uint256 stale;
        memset(&stale, 0, sizeof(stale));
        stale.data[0] = 0x41;
        stale.data[31] = 0x1b;
        RRW_CHECK("P2: seed stale validate row at A+2",
                  put_hash_log(db, "validate_headers_log", "hash", A + 2, 0,
                               &stale));
        RRW_CHECK("P2: seed stale script row at A+2",
                  put_hash_log(db, "script_validate_log", "block_hash", A + 2,
                               0, &stale));

        struct stage_reducer_frontier_reconcile_result dry;
        RRW_CHECK("P2: dry-run succeeds",
                  stage_reducer_frontier_reconcile_light_needed(db, &fx.ms,
                                                                &dry));
        RRW_CHECK("P2: dry-run finds the residue and the would-be clamp",
                  dry.noncanonical_found >= 1 &&
                  dry.noncanonical_purged == 0 &&
                  dry.lowest_noncanonical == A + 2 &&
                  dry.clamped_script_validate &&
                  dry.clamped_proof_validate);
        RRW_CHECK("P2: dry-run mutates no cursor",
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4);

        struct stage_reducer_frontier_reconcile_result rr;
        RRW_CHECK("P2: apply succeeds",
                  stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RRW_CHECK("P2: apply purges the residue rows",
                  rr.noncanonical_purged >= 2 && rr.repaired &&
                  rr.clamped_script_validate && rr.clamped_proof_validate);
        /* THE regression: the SAME apply pass that deleted the rows leaves
         * no script/proof cursor above the now-rowless height A+2. */
        RRW_CHECK("P2: script/proof cursors clamped to the purged height",
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 2);
        RRW_CHECK("P2: utxo_apply cursor untouched (coins-floor rule)",
                  cursor_value(db, "utxo_apply") == A + 4);

        sqlite3_stmt *st = NULL;
        int rows_left = -1;
        if (sqlite3_prepare_v2(db,
                "SELECT"
                " (SELECT COUNT(*) FROM validate_headers_log WHERE height=?1)"
                " + (SELECT COUNT(*) FROM script_validate_log WHERE height=?1)"
                " + (SELECT COUNT(*) FROM body_persist_log WHERE height=?1)"
                " + (SELECT COUNT(*) FROM proof_validate_log WHERE height=?1)",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, A + 2);
            if (sqlite3_step(st) == SQLITE_ROW)
                rows_left = sqlite3_column_int(st, 0);
        }
        sqlite3_finalize(st);
        RRW_CHECK("P2: purged height is fully rowless", rows_left == 0);

        /* Stages re-run from the clamped cursors: they rewrite canonical
         * ok=1 rows at A+2 and walk back up. Simulate that, then assert the
         * dry-run reports no remaining script/proof hole or residue. */
        RRW_CHECK("P2: stages re-derive canonical rows at A+2",
                  put_upstream_ok(db, A + 2, &fx.hashes[2]) &&
                  seed_cursor(db, "validate_headers", A + 4) &&
                  seed_cursor(db, "body_fetch", A + 4) &&
                  seed_cursor(db, "body_persist", A + 4) &&
                  seed_cursor(db, "script_validate", A + 4) &&
                  seed_cursor(db, "proof_validate", A + 4));

        struct stage_reducer_frontier_reconcile_result dry2;
        RRW_CHECK("P2: post-re-derive dry-run succeeds",
                  stage_reducer_frontier_reconcile_light_needed(db, &fx.ms,
                                                                &dry2));
        RRW_CHECK("P2: no remaining script/proof hole or residue",
                  dry2.noncanonical_found == 0 &&
                  dry2.lowest_script_validate_refill_hole == -1 &&
                  dry2.lowest_proof_validate_refill_hole == -1 &&
                  !dry2.clamped_script_validate &&
                  !dry2.clamped_proof_validate &&
                  !dry2.refused_coin_tear);

        teardown_fixture(&fx);
    }

    /* ── T12: same-height churn exhausts the budget and ARMS the escalator ──
     * FIX-1: a backfill record that never advances past its high-water baseline
     * (a same-height rewind->re-derive cycle) is churn, not progress:
     * progressing() must NOT refresh, so the budget exhausts, the CRITICAL
     * condition pages, and the sticky escalator (the always-terminating remedy
     * ladder) auto-arms on the unresolved-CRITICAL backlog. Pre-FIX-1 the record
     * transition re-refreshed the budget every cycle so max_attempts was never
     * reached and the escalator never armed (the silent-wedge bug). */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T12: setup tear fixture", setup_fixture(&fx, "t12_arm"));
        sqlite3 *db = progress_store_db();
        RRW_CHECK("T12: poke real utxo_apply hole at K=A+2",
                  poke_utxo_apply_hole(db, A + 2));
        RRW_CHECK("T12: seed coins_applied above the hole (tear)",
                  seed_coins_applied(db, A + 3));
        /* A record that re-derives back to the SAME height every round: seeded
         * at 100, never climbs above it — the degenerate same-height churn. */
        RRW_CHECK("T12: backfill record present, pinned at one height",
                  set_tipfin_progress(db, 100));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sticky_escalator_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        for (int i = 0; i < 5; i++) {
            /* Re-write the record to the SAME height each round (a rewind that
             * re-derives back to where it was) — never above the high-water. */
            (void)set_tipfin_progress(db, 100);
            reducer_frontier_reconcile_light_test_clear_backoff();
            condition_engine_tick();
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(COND_NAME, &snap);
        RRW_CHECK("T12: same-height churn does NOT refresh — budget exhausts "
                  "and pages",
                  got &&
                  snap.currently_active &&
                  snap.attempts >= 5 &&
                  snap.operator_needed_emitted &&
                  condition_engine_get_unresolved_critical_count() == 1);

        /* The exhausted CRITICAL backlog auto-arms the always-terminating
         * remedy ladder on its next drive. */
        sticky_escalator_test_reset();
        (void)sticky_escalator_test_drive(
            0, (int64_t)platform_time_wall_unix());
        RRW_CHECK("T12: budget exhaustion arms the sticky escalator",
                  sticky_escalator_test_armed());

        sticky_escalator_test_reset();
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── T13: a rewind BELOW the high-water then a re-advance to a
     *   previously-seen height does NOT refresh progressing() (FIX-1) ────────
     * Drives progressing() directly. The old code re-baselined the record to
     * the CURRENT (rewound-low) value whenever ANY signal refreshed, so a
     * subsequent re-advance to a height it had ALREADY reached refreshed again —
     * churn forever. The high-water baseline is raised, never lowered, so the
     * re-advance to a seen height returns false. */
    {
        struct rrw_fixture fx;
        RRW_CHECK("T13: setup fixture", setup_fixture(&fx, "t13_highwater"));
        sqlite3 *db = progress_store_db();

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        reducer_frontier_reconcile_light_test_snapshot_insert_baseline();

        /* R1: record present at its peak (200) — genuine forward progress. */
        RRW_CHECK("T13: seed record at the peak", set_tipfin_progress(db, 200));
        bool p1 = reducer_frontier_reconcile_light_test_progressing();

        /* R2: rewind the record low (150), but an inserted-coin result refreshes
         * this round — the OLD code re-baselined the record DOWN to 150 here. */
        RRW_CHECK("T13: rewind record below the peak",
                  set_tipfin_progress(db, 150));
        reducer_frontier_reconcile_light_test_note_coin_insert_result(5);
        bool p2 = reducer_frontier_reconcile_light_test_progressing();

        /* R3: re-advance to 160 — above the rewound 150 but still BELOW the 200
         * high-water. OLD: 160 > 150 -> refresh (churn). NEW: 160 <= 200 -> no
         * refresh, and no insert this round, H* flat -> false. */
        RRW_CHECK("T13: re-advance below the high-water",
                  set_tipfin_progress(db, 160));
        reducer_frontier_reconcile_light_test_note_coin_insert_result(0);
        bool p3 = reducer_frontier_reconcile_light_test_progressing();

        RRW_CHECK("T13: peak + insert refresh, but a re-advance to a seen height "
                  "does not (high-water baseline)",
                  p1 && p2 && !p3 &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 2);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        teardown_fixture(&fx);
    }

    printf("reducer_reconcile_witness: %d failures\n", failures);
    return failures;
}
