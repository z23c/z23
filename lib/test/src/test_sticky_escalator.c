/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_sticky_escalator — the targeted_rederive rung's real curative surface.
 *
 * The rung calls the reducer-frontier reconcile APPLY pass
 * (stage_reducer_frontier_reconcile_light) directly — the same entry the
 * reducer_frontier_reconcile_light Condition's remedy uses, WITHOUT the
 * Condition's peer gate (connman_max_peer_height reads static handshake
 * starting_height, so near tip it reads "no peer ahead" forever and the
 * recomputed repair is discarded — leaving H* pinned with a
 * rowless script/proof hole below it). Proven here through the REAL ladder
 * (note_stall -> retry -> targeted_rederive) over a synthetic progress.kv:
 *
 *   T1 — actionable rowless script+proof hole at coins_applied: the rung
 *        reports repaired, clamps script/proof cursors to the hole and
 *        tip_finalize to H*, deletes no log rows, and HOLDS the rung
 *        (PROGRESSING + repair-hold memo) so the ladder does not cascade
 *        into the reindex rung while the stages consume the clamp.
 *   T2 — fully-consistent store: the rung reports no-op (repaired=0) and the
 *        ladder honestly advances to the next rung, zero cursor writes.
 *
 * Fixture shape mirrors test_stage_repair_script_refill.c Part A (synthetic
 * rows at the mainnet trusted anchor A). */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "coins/undo.h"

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "storage/boot_auto_reindex.h"
#include "storage/boot_auto_refold.h"
#include "storage/progress_store.h"
#include "storage/seal_kv.h"
#include "util/blocker.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SE_CHECK(name, expr) do { \
    printf("sticky_escalator: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

/* The compiled-anchor floor is network-derived; this fixture seeds rows at
 * MAINNET heights (A+1..) so the floor must be pinned to the mainnet anchor A
 * for compute_hstar (the test_stage_repair_script_refill.c pattern). Restored
 * to -1 (production default) before return. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* ── Fixture: synthetic progress.kv at the mainnet trusted anchor ───────── */

struct se_fixture {
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool put_body_fetch_ok(sqlite3 *db, int height,
                              const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO body_fetch_log"
            "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
            "VALUES(?,?,'disk',0,1,1,NULL)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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

static bool delete_height(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE height=?", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok) return false;
    /* Stamp full coins_kv proven-authority so compute_hstar honors the baked
     * TRUSTED_ANCHOR floor (the test_stage_repair_script_refill.c fixture
     * models a seeded datadir whose H* clamps at the anchor). */
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {  // raw-sql-ok:test-seed
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
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

/* Total rows across every reducer log — the "no log row is ever deleted"
 * invariant witness. */
static int64_t total_log_rows(sqlite3 *db)
{
    static const char *const tables[] = {
        "header_admit_log", "validate_headers_log", "body_fetch_log",
        "body_persist_log", "script_validate_log", "proof_validate_log",
        "utxo_apply_log", "tip_finalize_log",
    };
    int64_t total = 0;
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[96];
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", tables[i]);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) != SQLITE_ROW) {  // raw-sql-ok:test-readback
            sqlite3_finalize(st);
            return -1;
        }
        total += sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return total;
}

static struct block_index *insert_index(struct main_state *ms,
                                        struct uint256 *hash,
                                        int height,
                                        struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = (uint8_t)((height >> 16) & 0xff);
    hash->data[31] = 0x5e;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    /* VALID_SCRIPTS and no HAVE_DATA: the block-index flag reconcile pass
     * has nothing to set or clear, so cursor assertions stay isolated. */
    bi->nStatus = BLOCK_VALID_SCRIPTS;
    bi->nFile = -1;
    bi->nDataPos = 0;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height - A + 1));
    return bi;
}

static bool setup_fixture(struct se_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "sticky_escalator", tag);
    if (!progress_store_open(fx->dir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!seed_schema(db))
        return false;
    if (!seed_all_cursors(db, A + 4))
        return false;

    main_state_init(&fx->ms);
    fx->idx[1] = insert_index(&fx->ms, &fx->hashes[1], A + 1, NULL);
    fx->idx[2] = insert_index(&fx->ms, &fx->hashes[2], A + 2, fx->idx[1]);
    fx->idx[3] = insert_index(&fx->ms, &fx->hashes[3], A + 3, fx->idx[2]);
    if (!fx->idx[1] || !fx->idx[2] || !fx->idx[3])
        return false;

    if (!put_header_admit(db, A + 1, &fx->hashes[1], NULL) ||
        !put_header_admit(db, A + 2, &fx->hashes[2], &fx->hashes[1]) ||
        !put_header_admit(db, A + 3, &fx->hashes[3], &fx->hashes[2]))
        return false;

    for (int i = 1; i <= 3; i++) {
        if (!put_upstream_ok(db, A + i, &fx->hashes[i]) ||
            !put_body_fetch_ok(db, A + i, &fx->hashes[i]))
            return false;
    }
    if (!put_tip_log(db, A + 1, 1, &fx->hashes[1]))
        return false;
    if (!seed_coins_applied(db, A + 2))
        return false;
    return true;
}

static void teardown_fixture(struct se_fixture *fx)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    sticky_escalator_test_reset();
    stage_reducer_frontier_reset_detect_memo_for_testing();
    main_state_free(&fx->ms);
    progress_store_close();
    test_cleanup_tmpdir(fx->dir);
}

/* Seed a self-valid RATIFIED seal at grid point g into the fixture's seal ring
 * (mirrors test_seal_kv.c's insert+ratify), so the resnapshot rung's
 * nearest-verified-base probe (seal_kv_newest_ratified) finds a base. */
static bool seed_ratified_seal(sqlite3 *db, int32_t g)
{
    if (!seal_kv_ensure_schema(db))
        return false;
    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = g;
    for (int i = 0; i < 32; i++) {
        r.block_hash[i]         = (uint8_t)(g + i + 1);
        r.coins_sha3[i]         = (uint8_t)(g + i + 0x40);
        r.anchor_window_sha3[i] = (uint8_t)(g + i + 0x80);
    }
    r.utxo_count = (int64_t)g * 7 + 11;
    r.supply     = (int64_t)g * 1000000 + 333;
    r.sealed_at  = 1700000000 + g;

    progress_store_tx_lock();
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = seal_kv_insert_candidate_in_tx(db, &r);
    sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    if (!ok)
        return false;

    struct seal_record at;
    bool found = false;
    int slot = -1;
    if (!seal_kv_get_at_height(db, g, &at, &found, &slot) || !found)
        return false;
    progress_store_tx_lock();
    bool mok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    if (mok) mok = seal_kv_mark_ratified_in_tx(db, slot, &at);
    sqlite3_exec(db, mok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    return mok;
}

/* Seed a ratified seal slot whose stored bytes no longer match their own
 * self_sha3: write the serialized record directly into ring slot 0 with one
 * block_hash byte flipped AFTER serialization, so seal_read_slot computes
 * self_ok=0 and the ring reports no valid ratified seal. Used by T20 to prove a
 * corrupt seal is never selected as a re-entry base. */
static bool seed_corrupt_ratified_seal(sqlite3 *db, int32_t g)
{
    if (!seal_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return false;
    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = g;
    for (int i = 0; i < 32; i++) {
        r.block_hash[i]         = (uint8_t)(g + i + 1);
        r.coins_sha3[i]         = (uint8_t)(g + i + 0x40);
        r.anchor_window_sha3[i] = (uint8_t)(g + i + 0x80);
    }
    r.utxo_count = (int64_t)g * 7 + 11;
    r.supply     = (int64_t)g * 1000000 + 333;
    r.ratified   = 1;
    r.sealed_at  = 1700000000 + g;

    uint8_t blob[SEAL_RECORD_BYTES];
    if (!seal_serialize(&r, blob))
        return false;
    blob[5] ^= 0xff;  /* tamper: self_sha3 no longer covers the stored content */

    if (!progress_meta_set(db, SEAL_SLOT_KEY_PREFIX "0", blob, sizeof(blob)))
        return false;
    uint8_t head[8] = {0};
    return progress_meta_set(db, SEAL_HEAD_KEY, head, sizeof(head));
}

/* ── T7 fixture: a synthetic never-clearing condition ────────────────────
 * detect() always fires, witness() never clears — the shape of a condition
 * that stays "active" forever under its own remedy/cooldown schedule
 * (e.g. download_queue_starved), used to prove the belt-and-suspenders
 * auto-arm severity gate below. */
static bool se_t7_detect(void)
{
    return true;
}

static enum condition_remedy_result se_t7_remedy(void)
{
    return COND_REMEDY_OK;
}

static bool se_t7_witness(int64_t target_at_detect)
{
    (void)target_at_detect;
    return false;
}

/* A rung action that ALWAYS reports PROGRESSING — so the only thing that can
 * move the ladder off this rung within its (unlapsed) witness window is the
 * livelock backstop (STICKY_LIVELOCK_MAX_PASSES zero-progress passes). */
static enum sticky_rung_result se_always_progressing(void)
{
    return STICKY_RUNG_PROGRESSING;
}

int test_sticky_escalator(void);
int test_sticky_escalator(void)
{
    printf("\n=== sticky_escalator tests ===\n");
    int failures = 0;

    blocker_module_init();
    /* Pin the network-derived compiled-anchor floor to the mainnet anchor A:
     * the fixtures seed rows at A+1.. (see the refill test's rationale). */
    reducer_frontier_test_set_compiled_anchor(A);

    /* T0 — a callback already queued when shutdown begins must be inert. The
     * live incident armed auto_reindex_request from such a stale recovery tick
     * while node.db/event teardown was in progress, immediately before SIGSEGV. */
    {
        thread_registry_reset_for_test();
        sticky_escalator_test_reset();
        sticky_escalator_note_stall("test_shutdown_barrier");
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        thread_registry_request_shutdown();
        SE_CHECK("T0: shutdown blocks an already-armed recovery dispatch",
                 sticky_escalator_test_drive(0, t0 + 31) ==
                     STICKY_RUNG_RETRY);
        sticky_escalator_test_reset();
        sticky_escalator_note_stall("test_shutdown_late_note");
        SE_CHECK("T0: shutdown ignores a late stall notification",
                 !sticky_escalator_test_armed());
        thread_registry_reset_for_test();
        sticky_escalator_test_reset();
    }

    /* T1 — actionable rowless script+proof hole at coins_applied: driving the
     * real ladder into the targeted_rederive rung applies the reconcile clamp
     * (no peer gate) and holds the rung while the stages would consume it. */
    {
        struct se_fixture fx;
        SE_CHECK("T1: setup fixture", setup_fixture(&fx, "t1_hole"));
        sqlite3 *db = progress_store_db();

        /* The live 3166989 shape: purge left script/proof rowless at the
         * coins frontier while their cursors sit above it. */
        SE_CHECK("T1: punch rowless hole at h0 = coins_applied",
                 delete_height(db, "script_validate_log", A + 2) &&
                 delete_height(db, "proof_validate_log", A + 2) &&
                 delete_height(db, "utxo_apply_log", A + 2) &&
                 delete_height(db, "utxo_apply_log", A + 3) &&
                 seed_cursor(db, "utxo_apply", A + 2));

        int64_t rows_before = total_log_rows(db);

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();

        sticky_escalator_note_stall("test_rowless_hole");
        SE_CHECK("T1: ladder armed by note_stall",
                 sticky_escalator_test_armed());

        /* note_stall stamps the rung-entered clock with the REAL wall time,
         * so the injected drive times are anchored on it. Injected tip 0
         * never satisfies the progress margin (entry is -1 or a real H*). */
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T1: retry rung holds within its window",
                 sticky_escalator_test_drive(0, t0 + 1) == STICKY_RUNG_RETRY);
        SE_CHECK("T1: retry window lapse advances to targeted_rederive",
                 sticky_escalator_test_drive(0, t0 + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T1: targeted_rederive applies the reconcile and holds",
                 sticky_escalator_test_drive(0, t0 + 32) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T1: script/proof cursors clamped to the hole, tip to the "
                 "coins-backed served tip",
                 cursor_value(db, "script_validate") == A + 2 &&
                 cursor_value(db, "proof_validate") == A + 2 &&
                 cursor_value(db, "tip_finalize") == A + 2);
        SE_CHECK("T1: utxo cursor untouched + no log rows deleted",
                 cursor_value(db, "utxo_apply") == A + 2 &&
                 total_log_rows(db) == rows_before);
        /* The next pass finds nothing NEW actionable (cursors already at the
         * hole); the repair-hold memo keeps the rung instead of cascading
         * into the reindex rung on the very next tick. */
        SE_CHECK("T1: repair-hold memo keeps the rung after the clamp",
                 sticky_escalator_test_drive(0, t0 + 40) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T1: ladder still armed (episode clears only on H* climb)",
                 sticky_escalator_test_armed());

        teardown_fixture(&fx);
    }

    /* T2 — fully-consistent store: nothing actionable. The rung reports the
     * honest no-op and the ladder advances to the next rung, zero writes. */
    {
        struct se_fixture fx;
        SE_CHECK("T2: setup fixture", setup_fixture(&fx, "t2_clean"));
        sqlite3 *db = progress_store_db();

        /* Complete the tip column, move coins one above H*, and park the
         * OWN-frame tip_finalize cursor AT H* (A+3, the served tip) so every
         * cursor already equals its reconcile target: no clamp, no purge, no
         * backfill — the honest no-op shape. */
        SE_CHECK("T2: complete tip rows + coins frontier + served tip cursor",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));

        int64_t rows_before = total_log_rows(db);

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();

        sticky_escalator_note_stall("test_clean_store");
        int64_t t1 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T2: retry rung holds within its window",
                 sticky_escalator_test_drive(0, t1 + 1) == STICKY_RUNG_RETRY);
        SE_CHECK("T2: retry window lapse advances to targeted_rederive",
                 sticky_escalator_test_drive(0, t1 + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T2: no-op rederive honestly advances the ladder",
                 sticky_escalator_test_drive(0, t1 + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T2: zero cursor writes + no log rows deleted",
                 cursor_value(db, "script_validate") == A + 4 &&
                 cursor_value(db, "proof_validate") == A + 4 &&
                 cursor_value(db, "utxo_apply") == A + 4 &&
                 cursor_value(db, "tip_finalize") == A + 3 &&
                 total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* T3 — cold-import window: active-chain state exists, but genesis-side
     * block data is not readable from this datadir. Runtime escalation must
     * NOT arm auto_reindex_request, because the next boot would only consume
     * and refuse the impossible replay-from-blocks verb. */
    {
        struct se_fixture fx;
        SE_CHECK("T3: setup fixture", setup_fixture(&fx, "t3_cold_import"));
        sqlite3 *db = progress_store_db();

        SE_CHECK("T3: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        sticky_escalator_set_datadir(fx.dir);

        sticky_escalator_note_stall("test_cold_import_window");
        int64_t t2 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T3: retry window advances to targeted_rederive",
                 sticky_escalator_test_drive(0, t2 + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T3: no-op rederive advances to resnapshot",
                 sticky_escalator_test_drive(0, t2 + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T3: resnapshot stub advances to reindex",
                 sticky_escalator_test_drive(0, t2 + 33) ==
                     STICKY_RUNG_REINDEX);
        SE_CHECK("T3: unexecutable reindex escalates deeper",
                 sticky_escalator_test_drive(0, t2 + 34) ==
                     STICKY_RUNG_SELF_MINT_REFOLD);
        SE_CHECK("T3: no auto-reindex marker written",
                 !boot_auto_reindex_pending(fx.dir));

        sticky_escalator_set_datadir(NULL);
        teardown_fixture(&fx);
    }

    /* T4 — episode clears via tip progress with a PENDING (non-terminal)
     * reindex marker whose anchor the tip has progressed PAST:
     * withdraw_stale_reindex_request() (called from clear_episode) must
     * remove it so it does not outlive its episode and force a needless
     * reindex-chainstate rebuild on the next boot (a residue that can block
     * `make deploy-dev` with "pending crash-only
     * auto-reindex request anchor=<h>" after the stall had already
     * self-resolved). No progress-store fixture is needed: the cached H*
     * (reducer_frontier_provable_tip_set) drives observe_tip(), so the clear
     * fires on the very first drive call, before any rung dispatch. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "sticky_escalator", "t4_withdraw");
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        sticky_escalator_set_datadir(dir);

        SE_CHECK("T4: plant a pending (non-terminal) reindex request",
                 boot_auto_reindex_request(dir, 900) == 1 &&
                 boot_auto_reindex_pending(dir));

        sticky_escalator_note_stall("test_t4_withdraw");
        int64_t t4 = (int64_t)platform_time_wall_time_t();
        /* tip_at_rung was stamped from the cached H*=1000 at arm time; inject
         * a tip 2 past it (STICKY_PROGRESS_MARGIN) so THIS drive call clears
         * the episode. */
        SE_CHECK("T4: tip progress clears the episode",
                 sticky_escalator_test_drive(1002, t4 + 1) ==
                     STICKY_RUNG_RETRY &&
                 !sticky_escalator_test_armed());
        SE_CHECK("T4: stale reindex marker withdrawn (tip 1002 > anchor 900)",
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        sticky_escalator_set_datadir(NULL);
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        test_cleanup_tmpdir(dir);
    }

    /* T5 — episode clears via tip progress, but the tip has NOT progressed
     * past the pending marker's anchor: the marker must be left alone (the
     * request may still describe a real anchor the next boot legitimately
     * needs to consume). */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "sticky_escalator", "t5_keep");
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        sticky_escalator_set_datadir(dir);

        SE_CHECK("T5: plant a pending reindex request ABOVE the clearing tip",
                 boot_auto_reindex_request(dir, 1500) == 1 &&
                 boot_auto_reindex_pending(dir));

        sticky_escalator_note_stall("test_t5_keep");
        int64_t t5 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T5: tip progress still clears the episode (H* climbed)",
                 sticky_escalator_test_drive(1002, t5 + 1) ==
                     STICKY_RUNG_RETRY &&
                 !sticky_escalator_test_armed());
        SE_CHECK("T5: marker retained (tip 1002 has not passed anchor 1500)",
                 boot_auto_reindex_pending(dir));

        sticky_escalator_set_datadir(NULL);
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        test_cleanup_tmpdir(dir);
    }

    /* T6 — a TERMINAL marker (budget exhausted, operator already paged) must
     * never be touched by episode clearing — only the operator or a fresh,
     * strictly-higher-anchor episode may replace it (PRESERVE the
     * cross-boot budget / terminal-state semantics documented on
     * boot_auto_reindex_request / boot_auto_reindex_mark_terminal). */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "sticky_escalator", "t6_terminal");
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        sticky_escalator_set_datadir(dir);

        SE_CHECK("T6: plant a TERMINAL reindex marker",
                 boot_auto_reindex_mark_terminal(dir, 900) &&
                 boot_auto_reindex_is_terminal(dir) &&
                 !boot_auto_reindex_pending(dir));

        sticky_escalator_note_stall("test_t6_terminal");
        int64_t t6 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T6: tip progress clears the episode",
                 sticky_escalator_test_drive(1002, t6 + 1) ==
                     STICKY_RUNG_RETRY &&
                 !sticky_escalator_test_armed());
        SE_CHECK("T6: terminal marker left untouched",
                 boot_auto_reindex_is_terminal(dir));

        sticky_escalator_set_datadir(NULL);
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        test_cleanup_tmpdir(dir);
    }

    /* T7 — belt-and-suspenders auto-arm (apply_drive's own
     * condition_engine_get_unresolved_critical_count() check, reached with NO
     * explicit sticky_escalator_note_stall) must only respond to an
     * unresolved CRITICAL condition, never a WARN-severity one that owns its
     * own bounded remedy/cooldown — e.g. download_queue_starved
     * (COND_WARN) can stay active for hours on a healthy, tip-synced node and
     * must not silently re-arm this path every few minutes. */
    {
        static struct condition c_t7_warn = {
            .name = "t7_warn_only",
            .severity = COND_WARN,
            .poll_secs = 1,
            .backoff_secs = 0,
            .max_attempts = 1,
            .detect = se_t7_detect,
            .remedy = se_t7_remedy,
            .witness = se_t7_witness,
            .witness_window_secs = 60,
        };
        condition_engine_reset_for_testing();
        sticky_escalator_test_reset();
        sticky_escalator_test_set_pending_work(1);
        reducer_frontier_provable_tip_reset();

        SE_CHECK("T7: register a WARN-only unresolved condition",
                 condition_register(&c_t7_warn));
        condition_engine_tick();
        condition_engine_tick(); /* attempts reaches max_attempts=1: exhausted */
        SE_CHECK("T7: plain unresolved count sees the WARN backlog",
                 condition_engine_get_unresolved_count() == 1);
        SE_CHECK("T7: CRITICAL-scoped count does not",
                 condition_engine_get_unresolved_critical_count() == 0);

        int64_t t7 = (int64_t)platform_time_wall_time_t();
        sticky_escalator_test_drive(0, t7);
        SE_CHECK("T7: a WARN-only backlog must NOT auto-arm the ladder",
                 !sticky_escalator_test_armed());

        condition_engine_reset_for_testing();
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* T8 — the same belt-and-suspenders path DOES auto-arm for an unresolved
     * CRITICAL condition (the class it was built for — e.g.
     * reducer_frontier_reconcile_light). Confirms T7 is a severity filter, not
     * an accidental full disablement of the auto-arm path. */
    {
        static struct condition c_t8_critical = {
            .name = "t8_critical",
            .severity = COND_CRITICAL,
            .poll_secs = 1,
            .backoff_secs = 0,
            .max_attempts = 1,
            .detect = se_t7_detect,
            .remedy = se_t7_remedy,
            .witness = se_t7_witness,
            .witness_window_secs = 60,
        };
        condition_engine_reset_for_testing();
        sticky_escalator_test_reset();
        sticky_escalator_test_set_pending_work(1);
        reducer_frontier_provable_tip_reset();

        SE_CHECK("T8: register a CRITICAL unresolved condition",
                 condition_register(&c_t8_critical));
        condition_engine_tick();
        condition_engine_tick();
        SE_CHECK("T8: CRITICAL-scoped count sees it",
                 condition_engine_get_unresolved_critical_count() == 1);

        int64_t t8 = (int64_t)platform_time_wall_time_t();
        sticky_escalator_test_drive(0, t8);
        SE_CHECK("T8: an unresolved CRITICAL backlog DOES auto-arm the ladder",
                 sticky_escalator_test_armed());

        sticky_escalator_test_reset();
        sticky_escalator_test_set_pending_work(0);
        sticky_escalator_test_drive(0, t8 + 1);
        SE_CHECK("T8: a CRITICAL backlog at a caught-up tip does NOT auto-arm",
                 !sticky_escalator_test_armed());

        condition_engine_reset_for_testing();
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* ── T9/T10: the widen_peers rung ───────────────────────────────────────
     * A hermetic connman with directly-injected p2p_node entries (never
     * started — no sockets/threads), mirroring
     * test_connman_addnode_fallback.c's add_test_peer, so
     * connman_outbound_healthy_count() reflects exactly the peers we
     * inject. g_connect_only forces connman_kick_seed_discovery /
     * connman_kick_onion_seeds to no-op (both check it — lib/net/src/
     * connman.c) so the rung's real dispatch never touches DNS/onion
     * network I/O in-test; the dispatch itself is observed via the
     * sticky_escalator_test_widen_kicks() counter, not its side effects. */

    /* T9 — peers below the widen-peers floor: driving the real ladder all
     * the way down (retry -> targeted_rederive -> resnapshot -> reindex ->
     * self_mint_refold -> widen_peers, the same unexecutable-reindex shape
     * as T3) must NOT report NOT_IMPLEMENTED at widen_peers: it dispatches
     * connman_kick_seed_discovery (+ onion, zero outbound) and HOLDS the
     * rung for its witness window, same shape as T1's real curative rung. */
    {
        extern bool g_connect_only; /* lib/net/src/connman.c */
        bool saved_connect_only = g_connect_only;
        g_connect_only = true; /* force kick_* no-ops: no DNS/onion I/O */

        chain_params_select(CHAIN_MAIN);
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        SE_CHECK("T9: connman_init",
                 connman_init(&cm, chain_params_get(), &sigs));
        /* One healthy outbound peer — below STICKY_WIDEN_PEERS_MIN_HEALTHY
         * (3), but NOT zero, so the seed kick fires without the onion
         * peer-of-last-resort kick. */
        cm.manager.nodes = zcl_calloc(4, sizeof(*cm.manager.nodes),
                                      "test_sticky_widen_nodes");
        cm.manager.nodes_cap = 4;
        struct net_address addr;
        memset(&addr, 0, sizeof(addr));
        net_address_init(&addr);
        addr.svc.addr.ip[10] = 0xff;
        addr.svc.addr.ip[11] = 0xff;
        addr.svc.addr.ip[12] = 203;
        addr.svc.addr.ip[13] = 0;
        addr.svc.addr.ip[14] = 113;
        addr.svc.addr.ip[15] = 5;
        addr.svc.port = 8033;
        struct p2p_node *peer = p2p_node_create(
            &cm.manager, ZCL_INVALID_SOCKET, &addr, "widen-test", false);
        SE_CHECK("T9: inject one healthy outbound peer", peer != NULL);
        if (peer) {
            peer->state = PEER_HANDSHAKE_COMPLETE;
            peer->disconnect = false;
            peer->services = NODE_NETWORK;
            peer->starting_height = 100;
            cm.manager.nodes[cm.manager.num_nodes++] = peer;
        }
        SE_CHECK("T9: exactly one healthy outbound peer counted",
                 connman_outbound_healthy_count(&cm) == 1);

        struct se_fixture fx;
        SE_CHECK("T9: setup fixture", setup_fixture(&fx, "t9_widen"));
        sqlite3 *db = progress_store_db();
        SE_CHECK("T9: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        sticky_escalator_set_datadir(fx.dir); /* unexecutable -> escalates */

        sticky_escalator_note_stall("test_widen_below_floor");
        int64_t t9 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T9: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t9 + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T9: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t9 + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T9: resnapshot stub -> reindex",
                 sticky_escalator_test_drive(0, t9 + 33) ==
                     STICKY_RUNG_REINDEX);
        SE_CHECK("T9: unexecutable reindex -> self_mint_refold",
                 sticky_escalator_test_drive(0, t9 + 34) ==
                     STICKY_RUNG_SELF_MINT_REFOLD);
        /* Entering the widen_peers rung does not dispatch it — the rung
         * action runs on the NEXT drive. So no kick has fired yet here. */
        SE_CHECK("T9: self_mint_refold stub -> widen_peers (not yet dispatched)",
                 sticky_escalator_test_drive(0, t9 + 35) ==
                     STICKY_RUNG_WIDEN_PEERS &&
                 sticky_escalator_test_widen_kicks() == 0);
        /* First dispatch of the rung: it kicks seed discovery and HOLDS the
         * rung within its witness window — never NOT_IMPLEMENTED (which would
         * have advanced instead of holding). */
        SE_CHECK("T9: widen_peers dispatches the real kick and HOLDS",
                 sticky_escalator_test_drive(0, t9 + 36) ==
                     STICKY_RUNG_WIDEN_PEERS &&
                 sticky_escalator_test_widen_kicks() == 1);
        /* Thrash guard: re-driving within the kick cooldown holds the rung
         * WITHOUT re-dispatching the discovery kick. */
        SE_CHECK("T9: thrash guard: re-drive within cooldown did NOT re-kick",
                 sticky_escalator_test_drive(0, t9 + 50) ==
                     STICKY_RUNG_WIDEN_PEERS &&
                 sticky_escalator_test_widen_kicks() == 1);

        sticky_escalator_set_datadir(NULL);
        teardown_fixture(&fx);
        connman_free(&cm);
        g_connect_only = saved_connect_only;
    }

    /* T10 — peers already at/above the floor when the ladder reaches
     * widen_peers: nothing for THIS rung to widen, so it must honestly
     * FAIL (not hold, not NOT_IMPLEMENTED) and advance straight to
     * rebootstrap without dispatching any kick. */
    {
        extern bool g_connect_only;
        bool saved_connect_only = g_connect_only;
        g_connect_only = true;

        chain_params_select(CHAIN_MAIN);
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        SE_CHECK("T10: connman_init",
                 connman_init(&cm, chain_params_get(), &sigs));
        cm.manager.nodes = zcl_calloc(4, sizeof(*cm.manager.nodes),
                                      "test_sticky_widen_healthy_nodes");
        cm.manager.nodes_cap = 4;
        for (uint8_t i = 0; i < 3; i++) {
            struct net_address addr;
            memset(&addr, 0, sizeof(addr));
            net_address_init(&addr);
            addr.svc.addr.ip[10] = 0xff;
            addr.svc.addr.ip[11] = 0xff;
            addr.svc.addr.ip[12] = 203;
            addr.svc.addr.ip[13] = 0;
            addr.svc.addr.ip[14] = 113;
            addr.svc.addr.ip[15] = (uint8_t)(10 + i);
            addr.svc.port = 8033;
            struct p2p_node *peer = p2p_node_create(
                &cm.manager, ZCL_INVALID_SOCKET, &addr, "widen-test", false);
            if (peer) {
                peer->state = PEER_HANDSHAKE_COMPLETE;
                peer->disconnect = false;
                peer->services = NODE_NETWORK;
                peer->starting_height = 100;
                cm.manager.nodes[cm.manager.num_nodes++] = peer;
            }
        }
        SE_CHECK("T10: three healthy outbound peers counted (at floor)",
                 connman_outbound_healthy_count(&cm) == 3);

        struct se_fixture fx;
        SE_CHECK("T10: setup fixture", setup_fixture(&fx, "t10_healthy"));
        sqlite3 *db = progress_store_db();
        SE_CHECK("T10: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        sticky_escalator_set_datadir(fx.dir);

        sticky_escalator_note_stall("test_widen_already_healthy");
        int64_t t10 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T10: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t10 + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T10: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t10 + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T10: resnapshot stub -> reindex",
                 sticky_escalator_test_drive(0, t10 + 33) ==
                     STICKY_RUNG_REINDEX);
        SE_CHECK("T10: unexecutable reindex -> self_mint_refold",
                 sticky_escalator_test_drive(0, t10 + 34) ==
                     STICKY_RUNG_SELF_MINT_REFOLD);
        SE_CHECK("T10: self_mint_refold stub -> widen_peers",
                 sticky_escalator_test_drive(0, t10 + 35) ==
                     STICKY_RUNG_WIDEN_PEERS);
        SE_CHECK("T10: already-healthy widen_peers advances immediately "
                 "to rebootstrap (FAILED, not a hold)",
                 sticky_escalator_test_drive(0, t10 + 36) ==
                     STICKY_RUNG_REBOOTSTRAP);
        SE_CHECK("T10: no kick dispatched — nothing to widen",
                 sticky_escalator_test_widen_kicks() == 0);

        sticky_escalator_set_datadir(NULL);
        teardown_fixture(&fx);
        connman_free(&cm);
        g_connect_only = saved_connect_only;
    }

    /* ── T11: self_mint_refold ARMS the from-anchor refold; the TERMINAL rung
     * triggers the (suppressed) self-respawn that consumes it ────────────────
     * The stub rungs are now real: self_mint_refold arms boot_auto_refold
     * (witnessed via boot_auto_refold_pending) WITHOUT respawning, so the
     * cheaper widen_peers/rebootstrap rungs still get a turn; the terminal
     * refold_from_anchor rung then pulls the restart trigger. The anchor-artifact
     * gate is forced present and the real shutdown/respawn syscalls suppressed. */
    {
        struct se_fixture fx;
        SE_CHECK("T11: setup fixture", setup_fixture(&fx, "t11_refold_arm"));
        sqlite3 *db = progress_store_db();
        SE_CHECK("T11: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        sticky_escalator_set_datadir(fx.dir);
        sticky_escalator_test_set_refold_artifact_available(1);
        sticky_escalator_test_set_suppress_refold_restart(true);

        SE_CHECK("T11: no refold armed before the ladder runs",
                 !boot_auto_refold_pending(fx.dir));

        sticky_escalator_note_stall("test_refold_arm");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T11: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T11: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T11: resnapshot (no base) -> reindex",
                 sticky_escalator_test_drive(0, t + 33) == STICKY_RUNG_REINDEX);
        SE_CHECK("T11: unexecutable reindex -> self_mint_refold",
                 sticky_escalator_test_drive(0, t + 34) ==
                     STICKY_RUNG_SELF_MINT_REFOLD);
        /* self_mint_refold arms the durable refold and advances (arm persists). */
        SE_CHECK("T11: self_mint_refold arms the refold + advances to widen_peers",
                 sticky_escalator_test_drive(0, t + 35) ==
                     STICKY_RUNG_WIDEN_PEERS &&
                 boot_auto_refold_pending(fx.dir));
        SE_CHECK("T11: widen_peers (no connman) -> rebootstrap",
                 sticky_escalator_test_drive(0, t + 36) ==
                     STICKY_RUNG_REBOOTSTRAP);
        SE_CHECK("T11: rebootstrap -> terminal refold_from_anchor",
                 sticky_escalator_test_drive(0, t + 37) ==
                     STICKY_RUNG_REFOLD_FROM_ANCHOR);
        /* Terminal rung sees the pending arm, requests the (suppressed) respawn,
         * and HOLDS within its witness window — the refold stays armed and the
         * ladder is still driving (never-give-up). */
        SE_CHECK("T11: terminal refold requests respawn and holds (armed)",
                 sticky_escalator_test_drive(0, t + 38) ==
                     STICKY_RUNG_REFOLD_FROM_ANCHOR &&
                 boot_auto_refold_pending(fx.dir) &&
                 sticky_escalator_test_armed());

        sticky_escalator_set_datadir(NULL);
        reducer_frontier_provable_tip_reset();
        teardown_fixture(&fx);
    }

    /* ── T12: resnapshot detects the nearest SELF-VERIFIED rewind base ───────
     * With NO base it names the typed blocker resnapshot_no_base and advances.
     * With a ratified seal reachable AND the stage_rederive_range primitive now
     * LINKED into this build (pillar2's universal re-derive), it invokes that
     * in-process consumer from the base; on the degenerate range this minimal
     * fixture presents (no observable tip above the base) the consumer refuses
     * honestly and the rung advances to the durable reindex rung — naming
     * neither no_base (a base WAS found) nor no_consumer (a consumer IS linked).
     * Either way it advances — never a borrowed-state snapshot pull, never a
     * faked "done". Witnessed via the typed blocker registry. */
    {
        struct se_fixture fx;
        SE_CHECK("T12: setup fixture", setup_fixture(&fx, "t12_resnapshot_base"));
        sqlite3 *db = progress_store_db();
        SE_CHECK("T12: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(NULL, NULL, &fx.ms);

        /* Sub-case A: no seal, no artifact -> resnapshot names no_base. */
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        blocker_clear("sticky_escalator.resnapshot_no_base");
        blocker_clear("sticky_escalator.resnapshot_no_consumer");
        sticky_escalator_note_stall("test_resnapshot_no_base");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T12A: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T12A: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T12A: resnapshot (no base) names no_base + advances to reindex",
                 sticky_escalator_test_drive(0, t + 33) == STICKY_RUNG_REINDEX &&
                 blocker_exists("sticky_escalator.resnapshot_no_base") &&
                 !blocker_exists("sticky_escalator.resnapshot_no_consumer"));

        /* Sub-case B: seed a ratified seal -> resnapshot finds the base and,
         * with the real stage_rederive_range consumer now linked (weak symbol
         * resolves to the pillar2 primitive), invokes it from that base. The
         * consumer refuses the degenerate [1000, no-tip] range and the rung
         * advances to reindex — no_base is NOT named (base found) and
         * no_consumer is NOT named (consumer linked). */
        SE_CHECK("T12B: seed a ratified seal at a grid point",
                 seed_ratified_seal(db, 1000));
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        blocker_clear("sticky_escalator.resnapshot_no_base");
        blocker_clear("sticky_escalator.resnapshot_no_consumer");
        sticky_escalator_note_stall("test_resnapshot_base_found");
        int64_t t2 = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T12B: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t2 + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T12B: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t2 + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T12B: resnapshot finds the seal base, invokes the linked "
                 "re-derive consumer, advances",
                 sticky_escalator_test_drive(0, t2 + 33) == STICKY_RUNG_REINDEX &&
                 !blocker_exists("sticky_escalator.resnapshot_no_consumer") &&
                 !blocker_exists("sticky_escalator.resnapshot_no_base"));

        blocker_clear("sticky_escalator.resnapshot_no_base");
        blocker_clear("sticky_escalator.resnapshot_no_consumer");
        teardown_fixture(&fx);
    }

    /* ── T13: episode clear withdraws a stale armed refold ───────────────────
     * A pending (non-terminal) auto_refold_request whose anchor the tip has
     * progressed past is withdrawn on episode clear (mirrors T4 for the reindex
     * marker) so a self-resolved stall does not force a needless from-anchor
     * refold on the next boot — the auto-terminating-remedy invariant. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "sticky_escalator", "t13_refold_withdraw");
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        sticky_escalator_set_datadir(dir);

        SE_CHECK("T13: plant a pending (non-terminal) refold request",
                 boot_auto_refold_request(dir, 900) == 1 &&
                 boot_auto_refold_pending(dir));

        sticky_escalator_note_stall("test_t13_refold_withdraw");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T13: tip progress clears the episode",
                 sticky_escalator_test_drive(1002, t + 1) == STICKY_RUNG_RETRY &&
                 !sticky_escalator_test_armed());
        SE_CHECK("T13: stale refold marker withdrawn (tip 1002 > anchor 900)",
                 !boot_auto_refold_pending(dir) &&
                 !boot_auto_refold_is_terminal(dir));

        sticky_escalator_set_datadir(NULL);
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        test_cleanup_tmpdir(dir);
    }

    /* ── T14: flat-H* repair churn advances the rung (FIX-3) ──────────────────
     * A targeted_rederive whose reconcile keeps reporting repaired (a cursor is
     * re-raised above the same rowless hole every tick — the fold re-advancing
     * while the hole pins H*) must NOT hold its whole window: after
     * STICKY_REDERIVE_MAX_FLAT_REPAIRS flat repairs (H* never lifts past the
     * rung-entry baseline) the rung FAILs so the ladder advances to resnapshot
     * instead of looping on a repair that will never clear H*. */
    {
        struct se_fixture fx;
        SE_CHECK("T14: setup fixture", setup_fixture(&fx, "t14_flat_churn"));
        sqlite3 *db = progress_store_db();

        /* Same live 3166989 shape as T1: rowless script/proof hole at the coins
         * frontier with the utxo cursor parked at it. */
        SE_CHECK("T14: punch rowless hole at h0 = coins_applied",
                 delete_height(db, "script_validate_log", A + 2) &&
                 delete_height(db, "proof_validate_log", A + 2) &&
                 delete_height(db, "utxo_apply_log", A + 2) &&
                 delete_height(db, "utxo_apply_log", A + 3) &&
                 seed_cursor(db, "utxo_apply", A + 2));

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        stage_reducer_frontier_reset_detect_memo_for_testing();

        /* Pin observe_tip() to the flat frontier so the rung-entry baseline
         * (g_tip_at_rung) equals the pinned H* and the flat check fires. */
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(A + 1);

        sticky_escalator_note_stall("test_flat_repair_churn");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T14: retry window lapse advances to targeted_rederive",
                 sticky_escalator_test_drive(0, t + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);

        /* Each dispatch: re-raise the cursors above the rowless hole (the fold's
         * re-advance) so the reconcile re-clamps and reports repaired with H*
         * still pinned at A+1. The first N-1 flat repairs HOLD the rung; the
         * Nth FAILs and advances — all inside the rung's 60 s window (t+32..),
         * so only the flat-repair cap, not the window, can advance it. */
        for (int i = 1; i < STICKY_REDERIVE_MAX_FLAT_REPAIRS; i++) {
            SE_CHECK("T14: re-raise cursors above the hole",
                     seed_cursor(db, "script_validate", A + 4) &&
                     seed_cursor(db, "proof_validate", A + 4) &&
                     seed_cursor(db, "tip_finalize", A + 3));
            SE_CHECK("T14: flat repair holds the rung",
                     sticky_escalator_test_drive(0, t + 31 + i) ==
                         STICKY_RUNG_TARGETED_REDERIVE);
        }
        SE_CHECK("T14: re-raise cursors above the hole (final)",
                 seed_cursor(db, "script_validate", A + 4) &&
                 seed_cursor(db, "proof_validate", A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));
        SE_CHECK("T14: Nth flat repair FAILs and advances to resnapshot "
                 "(not a loop)",
                 sticky_escalator_test_drive(
                     0, t + 31 + STICKY_REDERIVE_MAX_FLAT_REPAIRS) ==
                     STICKY_RUNG_RESNAPSHOT);

        reducer_frontier_provable_tip_reset();
        teardown_fixture(&fx);
    }
    /* ── T15: ladder-livelock backstop ──────────────────────────────────
     * A rung that returns PROGRESSING every pass while the observed tip stays
     * frozen is spinning without advancing. The per-episode assertion must
     * FORCE-advance it after STICKY_LIVELOCK_MAX_PASSES zero-progress passes —
     * even though the rung's own 30s witness window has NOT lapsed. We drive
     * all passes strictly inside that window so ONLY the backstop can move the
     * ladder, isolating it from the window mechanism. */
    {
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        /* Custom RETRY action that never yields — window would hold it forever. */
        sticky_escalator_register_rung(STICKY_RUNG_RETRY, se_always_progressing);

        sticky_escalator_note_stall("test_livelock_backstop");
        SE_CHECK("T15: armed at retry", sticky_escalator_test_armed());
        int64_t t = (int64_t)platform_time_wall_time_t();

        /* MAX passes, each within the 30s retry window, tip frozen at 500:
         * held on retry (window not lapsed, cap not yet reached). */
        enum sticky_rung r = STICKY_RUNG_RETRY;
        for (int i = 1; i <= STICKY_LIVELOCK_MAX_PASSES; i++)
            r = sticky_escalator_test_drive(500, t + i);
        SE_CHECK("T15: holds on retry up to the cap (window not lapsed)",
                 r == STICKY_RUNG_RETRY);
        SE_CHECK("T15: no force-advance before the cap",
                 sticky_escalator_test_livelock_force_advances() == 0);

        /* The (cap+1)-th zero-progress pass trips the backstop → force-advance
         * to the next rung, still inside the retry window. */
        r = sticky_escalator_test_drive(500, t + STICKY_LIVELOCK_MAX_PASSES + 1);
        SE_CHECK("T15: backstop force-advances off retry within the window",
                 r == STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T15: exactly one force-advance recorded",
                 sticky_escalator_test_livelock_force_advances() == 1);

        sticky_escalator_register_rung(STICKY_RUNG_RETRY, NULL);
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* ── T16: a climbing tip resets the backstop ─────────────────────────
     * Even a sub-margin (1-block) climb each pass is forward cursor movement,
     * so the no-progress counter never reaches the cap and the backstop never
     * fires — the rung is held by its own window, not force-advanced. */
    {
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        sticky_escalator_register_rung(STICKY_RUNG_RETRY, se_always_progressing);

        sticky_escalator_note_stall("test_livelock_climb");
        int64_t t = (int64_t)platform_time_wall_time_t();
        /* Climb by 1 each pass — below STICKY_PROGRESS_MARGIN (2) so the
         * episode never CLEARS, but each pass is genuine cursor movement. */
        enum sticky_rung r = STICKY_RUNG_RETRY;
        for (int i = 1; i <= STICKY_LIVELOCK_MAX_PASSES + 3; i++)
            r = sticky_escalator_test_drive(500 + i, t + i);
        SE_CHECK("T16: climbing tip keeps the rung (backstop not tripped)",
                 r == STICKY_RUNG_RETRY);
        SE_CHECK("T16: no force-advance while the tip climbs",
                 sticky_escalator_test_livelock_force_advances() == 0);

        sticky_escalator_register_rung(STICKY_RUNG_RETRY, NULL);
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* ── T17: a PERMANENT sync-domain blocker HOLDS the ladder ───────────────
     * The defect class this guards against: a shielded-history-less node
     * holding two
     * permanent utxo_apply blockers (anchor_backfill_gap + nullifier_backfill_
     * gap) with the escalator churning resnapshot -> reindex against a cause NO
     * rung can cure. With the blocker registered, the ladder must NOT advance
     * off its rung (or dispatch a destructive one) — it HOLDS and surfaces the
     * hold state, re-checking each cadence. */
    {
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        blocker_reset_for_testing();

        struct blocker_record perm;
        SE_CHECK("T17: init permanent utxo_apply blocker",
                 blocker_init(&perm, "utxo_apply.anchor_backfill_gap",
                              "utxo_apply", BLOCKER_PERMANENT,
                              "shielded anchor history incomplete (test)"));
        SE_CHECK("T17: register the permanent blocker",
                 blocker_set(&perm) == 0);

        sticky_escalator_note_stall("test_permanent_hold");
        SE_CHECK("T17: armed at retry", sticky_escalator_test_armed());
        int64_t t = (int64_t)platform_time_wall_time_t();
        /* Past the retry window: WITHOUT the hold this advances to
         * targeted_rederive (T1). The permanent-blocker hold keeps it on retry
         * and dispatches nothing. tip==entry (1000) so no episode clear. */
        SE_CHECK("T17: permanent blocker HOLDS the ladder on retry (no advance)",
                 sticky_escalator_test_drive(1000, t + 31) == STICKY_RUNG_RETRY);
        SE_CHECK("T17: held-by-permanent state surfaced",
                 sticky_escalator_test_held_by_permanent());
        SE_CHECK("T17: the hold fired",
                 sticky_escalator_test_permanent_hold_fires() >= 1);
        /* Far past EVERY rung window: still held on retry — never reaches a
         * destructive resnapshot/reindex/refold rung. */
        SE_CHECK("T17: still held far past every rung window",
                 sticky_escalator_test_drive(1000, t + 5000) ==
                     STICKY_RUNG_RETRY &&
                 sticky_escalator_test_held_by_permanent());

        blocker_reset_for_testing();
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* ── T18: a TRANSIENT blocker does NOT hold escalation ───────────────────
     * A transient blocker (even in the sync domain) is the EXPECTED shape during
     * a normal stall — the shallower rungs' remedies are exactly what should
     * run. Only PERMANENT holds; advancement must be unchanged. */
    {
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        blocker_reset_for_testing();

        struct blocker_record tr;
        SE_CHECK("T18: init transient utxo_apply blocker",
                 blocker_init(&tr, "utxo_apply.body_read_failed", "utxo_apply",
                              BLOCKER_TRANSIENT, "transient body read (test)"));
        SE_CHECK("T18: register the transient blocker",
                 blocker_set(&tr) == 0);

        sticky_escalator_note_stall("test_transient_no_hold");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T18: transient blocker does NOT hold — retry advances normally",
                 sticky_escalator_test_drive(1000, t + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T18: not held by permanent",
                 !sticky_escalator_test_held_by_permanent());
        SE_CHECK("T18: no hold fired",
                 sticky_escalator_test_permanent_hold_fires() == 0);

        blocker_reset_for_testing();
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* ── T19: clearing the permanent blocker RESUMES escalation ──────────────
     * The hold must release the moment the blocker clears/retires — the ladder
     * resumes advancing on the normal cadence, no restart needed. */
    {
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(1000);
        blocker_reset_for_testing();

        struct blocker_record perm;
        SE_CHECK("T19: register a permanent utxo_apply blocker",
                 blocker_init(&perm, "utxo_apply.nullifier_backfill_gap",
                              "utxo_apply", BLOCKER_PERMANENT,
                              "nullifier history incomplete (test)") &&
                 blocker_set(&perm) == 0);

        sticky_escalator_note_stall("test_hold_then_clear");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T19: held on retry while the blocker is active",
                 sticky_escalator_test_drive(1000, t + 31) == STICKY_RUNG_RETRY &&
                 sticky_escalator_test_held_by_permanent());

        /* Owner-gated clear (a backfill completed / operator cleared it). */
        blocker_clear("utxo_apply.nullifier_backfill_gap");
        SE_CHECK("T19: after clear, the ladder resumes advancing",
                 sticky_escalator_test_drive(1000, t + 62) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T19: hold state released",
                 !sticky_escalator_test_held_by_permanent());

        /* An UNRELATED permanent blocker must NOT re-hold the sync ladder. */
        struct blocker_record other;
        SE_CHECK("T19: register an unrelated permanent blocker",
                 blocker_init(&other, "consensus_bundle_export.write_failed",
                              "consensus_bundle_export", BLOCKER_PERMANENT,
                              "unrelated export fault (test)") &&
                 blocker_set(&other) == 0);
        SE_CHECK("T19: unrelated permanent blocker does NOT hold sync recovery",
                 !sticky_escalator_test_held_by_permanent());
        /* targeted_rederive has no db/ms here -> FAILs and advances honestly,
         * proving the unrelated blocker did not freeze the ladder. */
        SE_CHECK("T19: ladder still advances past the unrelated blocker",
                 sticky_escalator_test_drive(1000, t + 63) ==
                     STICKY_RUNG_RESNAPSHOT &&
                 !sticky_escalator_test_held_by_permanent());

        blocker_reset_for_testing();
        sticky_escalator_test_reset();
        reducer_frontier_provable_tip_reset();
    }

    /* ── T20: a CORRUPT seal is skipped, never a re-entry base ──────────────
     * A ratified seal sits in the ring below the frontier, but its stored bytes
     * no longer match their own self_sha3. resnapshot must refuse it exactly as
     * it refuses an absent one — name resnapshot_no_base and leave every body
     * cursor untouched. The negative half of the re-entry-depth proof: recovery
     * never rewinds onto state it cannot self-verify. */
    {
        struct se_fixture fx;
        SE_CHECK("T20: setup fixture", setup_fixture(&fx, "t20_corrupt_seal"));
        sqlite3 *db = progress_store_db();
        SE_CHECK("T20: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));
        SE_CHECK("T20: seed a CORRUPT ratified seal below the frontier",
                 seed_corrupt_ratified_seal(db, A + 3));

        struct seal_record got;
        bool found = true;
        SE_CHECK("T20: ring reports NO valid ratified seal (slot skipped)",
                 seal_kv_newest_ratified(db, &got, &found) && !found);

        int sc_before = cursor_value(db, "script_validate");
        int pv_before = cursor_value(db, "proof_validate");
        int bf_before = cursor_value(db, "body_fetch");

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        blocker_reset_for_testing();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(A + 10);

        sticky_escalator_note_stall("test_corrupt_seal_no_base");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T20: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T20: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        (void)sticky_escalator_test_drive(0, t + 33);
        SE_CHECK("T20: resnapshot names no_base (corrupt seal not a base)",
                 blocker_exists("sticky_escalator.resnapshot_no_base"));
        SE_CHECK("T20: no cursor rewound onto the corrupt seal",
                 cursor_value(db, "script_validate") == sc_before &&
                 cursor_value(db, "proof_validate") == pv_before &&
                 cursor_value(db, "body_fetch") == bf_before);

        blocker_reset_for_testing();
        reducer_frontier_provable_tip_reset();
        teardown_fixture(&fx);
    }

    /* ── T21: re-entry DEPTH — a reachable seal makes recovery O(delta) ─────
     * T12B proves resnapshot finds a ratified base and invokes the re-derive
     * consumer. This pins the property that matters for recovery COST: with an
     * observable tip above a valid seal, the body cursors rewind to the SEAL
     * height, not down to the compiled anchor A. Recovery is O(tip - seal), not
     * O(tip - anchor) — the difference between a delta refold and a full
     * chain refold. */
    {
        struct se_fixture fx;
        SE_CHECK("T21: setup fixture", setup_fixture(&fx, "t21_seal_reentry"));
        sqlite3 *db = progress_store_db();
        SE_CHECK("T21: make rederive rung an honest no-op",
                 put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                 put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                 seed_coins_applied(db, A + 4) &&
                 seed_cursor(db, "tip_finalize", A + 3));
        SE_CHECK("T21: seed a VALID ratified seal at A+3",
                 seed_ratified_seal(db, A + 3));

        struct seal_record got;
        bool found = false;
        SE_CHECK("T21: ring reports the ratified seal at A+3",
                 seal_kv_newest_ratified(db, &got, &found) && found &&
                 got.height == A + 3);

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        blocker_reset_for_testing();
        stage_reducer_frontier_reset_detect_memo_for_testing();
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(A + 10); /* tip well above the seal */

        sticky_escalator_note_stall("test_seal_reentry_depth");
        int64_t t = (int64_t)platform_time_wall_time_t();
        SE_CHECK("T21: retry -> targeted_rederive",
                 sticky_escalator_test_drive(0, t + 31) ==
                     STICKY_RUNG_TARGETED_REDERIVE);
        SE_CHECK("T21: no-op rederive -> resnapshot",
                 sticky_escalator_test_drive(0, t + 32) ==
                     STICKY_RUNG_RESNAPSHOT);
        (void)sticky_escalator_test_drive(0, t + 33);
        SE_CHECK("T21: a reachable base means no_base is NOT named",
                 !blocker_exists("sticky_escalator.resnapshot_no_base"));
        SE_CHECK("T21: re-entered at the SEAL (A+3), not the compiled anchor",
                 cursor_value(db, "script_validate") == A + 3 &&
                 cursor_value(db, "proof_validate") == A + 3 &&
                 cursor_value(db, "body_fetch") == A + 3 &&
                 cursor_value(db, "script_validate") != A);
        SE_CHECK("T21: resnapshot dispatched exactly once",
                 sticky_escalator_test_rung_dispatches(
                     STICKY_RUNG_RESNAPSHOT) == 1);

        /* A supervisor poll while the fold is still below its pre-rewind
         * frontier must HOLD without dispatching the destructive range rewind
         * again.  This is the live custody sawtooth regression: before the fix,
         * every five-second poll re-entered the same seal and the wallet money
         * snapshot oscillated CURRENT -> STALE forever. */
        SE_CHECK("T21: catch-up poll holds on resnapshot",
                 sticky_escalator_test_drive(A + 9, t + 34) ==
                     STICKY_RUNG_RESNAPSHOT);
        SE_CHECK("T21: catch-up poll does not redispatch the rewind",
                 sticky_escalator_test_rung_dispatches(
                     STICKY_RUNG_RESNAPSHOT) == 1);

        /* Regaining the exact pre-rewind frontier is sufficient.  Waiting for
         * two newer blocks would wrongly push a completed repair into reindex
         * on a quiet chain. */
        SE_CHECK("T21: regaining entry frontier clears the episode",
                 sticky_escalator_test_drive(A + 10, t + 35) ==
                     STICKY_RUNG_RETRY &&
                 !sticky_escalator_test_armed());
        SE_CHECK("T21: completion still records one rewind dispatch",
                 sticky_escalator_test_rung_dispatches(
                     STICKY_RUNG_RESNAPSHOT) == 1);

        blocker_reset_for_testing();
        reducer_frontier_provable_tip_reset();
        teardown_fixture(&fx);
    }

    reducer_frontier_test_set_compiled_anchor(-1); /* restore production floor */

    printf("sticky_escalator: %d failures\n", failures);
    return failures;
}
