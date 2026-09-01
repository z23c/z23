/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Unit tests for Wave S S-9 tip_finalize stage. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "json/json.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/reducer_frontier.h"
#include "util/boot_scan.h"
/* src-private: the current-tip-missing observe helper under test (Task A #11). */
#include "../../../engine/jobs/src/tip_finalize_stage_observe.h"
/* src-private: the incremental utxo_apply SUM cache under differential KAT. */
#include "../../../engine/jobs/src/tip_finalize_log_store.h"
/* src-private: the durable-cursor hydrate seam under the cross-txn crash-window
 * clamp test (tip_finalize.uv_cursor_gap cure). */
#include "../../../engine/jobs/src/tip_finalize_stage_durable.h"
#include "services/consensus_state_publication_cas.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Source-private exact trusted-anchor evidence predicate under type KAT. */
int tip_finalize_trusted_anchor_at(sqlite3 *db, int height,
                                   const struct uint256 *block_hash);

#define TF_CHECK(name, expr) do { \
    printf("tip_finalize: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Test-only override of the compiled SHA3-checkpoint floor — lets H* track the
 * synthetic sub-checkpoint heights instead of clamping up to the mainnet
 * anchor (3,056,758). Forward-declared (defined ZCL_TESTING-only in
 * reducer_frontier.c); the same pattern test_refold_progress_floor.c uses. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

enum tf_fail_kind {
    TF_FAIL_NONE = 0,
    TF_FAIL_REORG,
    TF_FAIL_PRECONDITION,
    TF_FAIL_UTXO_COUNT,
};

struct synth_chain_tf {
    struct block_index *blocks;
    struct uint256     *hashes;
    int n;
    int upstream_fail_height;
    enum tf_fail_kind fail_kind;
};

static int mkdir_p_tf(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void synthetic_hash(struct uint256 *out, int h)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0xa0 + h);
}

static bool synth_chain_tf_build(struct synth_chain_tf *sc, int n)
{
    sc->blocks = calloc((size_t)n, sizeof(struct block_index));
    sc->hashes = calloc((size_t)n, sizeof(struct uint256));
    if (!sc->blocks || !sc->hashes) return false;
    for (int i = 0; i < n; i++) {
        synthetic_hash(&sc->hashes[i], i);
        block_index_init(&sc->blocks[i]);
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nVersion = 4;
        sc->blocks[i].nTime = (uint32_t)(1700005000u + (uint32_t)i);
        sc->blocks[i].nBits = 0x1f07ffff;
        sc->blocks[i].nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        arith_uint256_set_u64(&sc->blocks[i].nChainWork,
                              (uint64_t)i + 1);
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    if (sc->fail_kind == TF_FAIL_PRECONDITION && n > 2)
        sc->blocks[2].nStatus = BLOCK_VALID_SCRIPTS;
    if (sc->fail_kind == TF_FAIL_REORG && n > 2)
        sc->blocks[2].pprev = NULL;
    sc->n = n;
    return true;
}

static void synth_chain_tf_free(struct synth_chain_tf *sc)
{
    free(sc->blocks);
    free(sc->hashes);
    memset(sc, 0, sizeof(*sc));
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool seed_utxo_apply(sqlite3 *db, int n, int upstream_fail_height)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height               INTEGER PRIMARY KEY,"
        "  status               TEXT    NOT NULL,"
        "  ok                   INTEGER NOT NULL,"
        "  spent_count          INTEGER NOT NULL,"
        "  added_count          INTEGER NOT NULL,"
        "  total_value_delta    INTEGER NOT NULL,"
        "  first_failure_kind   TEXT,"
        "  first_failure_detail BLOB,"
        "  applied_at           INTEGER NOT NULL"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log "
        "(height, status, ok, spent_count, added_count, "
        " total_value_delta, applied_at) "
        "VALUES (?, ?, ?, 1, 2, 1, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        int ok = (h == upstream_fail_height) ? 0 : 1;
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_text(st, 2, ok ? "verified" : "value_overflow",
                          -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, ok);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);

    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('utxo_apply', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_coins_applied_height(sqlite3 *db, int32_t height)
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

static bool stamp_proven_authority_tf(sqlite3 *db, int32_t applied_height)
{
    if (!seed_coins_applied_height(db, applied_height))
        return false;
    static const uint8_t dummy_txid[32] = {0x71};
    if (!coins_kv_ensure_schema(db) ||
        !coins_kv_add(db, dummy_txid, 0, 0, 0, false, NULL, 0))
        return false;
    uint8_t one = 1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1,
                      SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Seed a script_validate_log row (the reducer's authoritative script verdict)
 * with an explicit ok and block_hash, so the tip_finalize hash-guarded fallback
 * can be exercised: a matching hash + ok=1 heals a drifted block_index bit; a
 * mismatched hash (stale orphan row) or ok=0 must be rejected. */
static bool seed_script_log(sqlite3 *db, int height, int ok,
                            const struct uint256 *block_hash)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB)"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, validated_at, block_hash) "
        "VALUES (?, 'verified', ?, 1, 0, 1, ?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok);
    if (block_hash)
        sqlite3_bind_blob(st, 3, block_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 3);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

/* Seed a stage_cursor row to `cursor` for `name`. */
static bool seed_cursor_tf(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES(?, ?, 1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Seed a simple (height, status, ok) *_log for h in [0, n) at ok=1, plus its
 * cursor at n. body_persist_log uses (height, source, ok); the others use
 * (height, status, ok). Mirrors the per-stage schema the reducer reads. */
static bool seed_simple_log_tf(sqlite3 *db, const char *table,
                               const char *cursor_name, int n)
{
    char ddl[256];
    bool body = strcmp(table, "body_persist_log") == 0;
    snprintf(ddl, sizeof(ddl),
        "CREATE TABLE IF NOT EXISTS %s ("
        "  height INTEGER PRIMARY KEY, %s TEXT, ok INTEGER NOT NULL)",
        table, body ? "source" : "status");
    if (!exec_sql(db, ddl))
        return false;
    char ins[256];
    snprintf(ins, sizeof(ins),
        "INSERT OR REPLACE INTO %s(height, %s, ok) VALUES(?, %s, 1)",
        table, body ? "source" : "status",
        body ? "'fixture'" : "'verified'");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, ins, -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    return seed_cursor_tf(db, cursor_name, n);
}

static bool seed_proof_log_tf(sqlite3 *db, struct synth_chain_tf *sc, int n)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "block_hash BLOB)"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
    return seed_cursor_tf(db, "proof_validate", n);
}

/* Seed validate_headers_log (height, hash, ok) for h in [0, n) at ok=1 with
 * the synthetic chain hash, plus its cursor at n. The reducer reads .hash for
 * the C3 hash-agreement check. */
static bool seed_validate_headers_tf(sqlite3 *db, struct synth_chain_tf *sc,
                                     int n)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER)"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height, hash, ok, validated_at) VALUES(?, ?, 1, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
    return seed_cursor_tf(db, "validate_headers", n);
}

static bool seed_hash_authority_tf(sqlite3 *db, struct synth_chain_tf *sc,
                                   int n)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,parent_hash BLOB,"
        "admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "height INTEGER PRIMARY KEY,branch_hash BLOB NOT NULL,"
        "spent_blob BLOB NOT NULL,added_blob BLOB NOT NULL)"))
        return false;
    sqlite3_stmt *header = NULL;
    sqlite3_stmt *delta = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &header, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,X'',X'')",
            -1, &delta, NULL) != SQLITE_OK) {
        sqlite3_finalize(header);
        sqlite3_finalize(delta);
        return false;
    }
    bool ok = true;
    for (int h = 0; ok && h < n; h++) {
        sqlite3_bind_int(header, 1, h);
        sqlite3_bind_blob(header, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (h > 0)
            sqlite3_bind_blob(header, 3, sc->hashes[h - 1].data, 32,
                              SQLITE_STATIC);
        else
            sqlite3_bind_null(header, 3);
        sqlite3_bind_int(delta, 1, h);
        sqlite3_bind_blob(delta, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        ok = sqlite3_step(header) == SQLITE_DONE &&
             sqlite3_step(delta) == SQLITE_DONE;
        sqlite3_reset(header);
        sqlite3_clear_bindings(header);
        sqlite3_reset(delta);
        sqlite3_clear_bindings(delta);
    }
    sqlite3_finalize(header);
    sqlite3_finalize(delta);
    return ok;
}

static bool set_utxo_branch_tf(sqlite3 *db, int height,
                               const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE utxo_apply_delta SET branch_hash=? WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

/* Seed ALL upstream reducer logs (validate_headers, script_validate,
 * body_persist, proof_validate) ok=1 for h in [0, n), so the MIN-fold in
 * reducer_frontier_compute_hstar can actually reach the synthetic frontier
 * instead of being pinned to the anchor by an unseeded cursor=0 log. The
 * harness's tf_setup already seeds utxo_apply + the tip_finalize stage; this
 * fills the remaining four logs (with matching synthetic hashes, so the C3
 * hash-agreement check between validate_headers and script_validate passes).
 * H* then equals MIN over all six contiguous ok=1 prefixes. */
static bool seed_upstream_logs_tf(sqlite3 *db, struct synth_chain_tf *sc, int n)
{
    if (!seed_validate_headers_tf(db, sc, n) ||
        !seed_hash_authority_tf(db, sc, n))
        return false;
    for (int h = 0; h < n; h++)
        if (!seed_script_log(db, h, 1, &sc->hashes[h]))
            return false;
    if (!seed_cursor_tf(db, "script_validate", n))
        return false;
    return seed_simple_log_tf(db, "body_persist_log", "body_persist", n) &&
           seed_proof_log_tf(db, sc, n);
}

/* Re-derive H* directly from the durable state, under the progress lock the
 * reducer requires — the value the cache MUST mirror at steady state. */
static int32_t compute_hstar_now(sqlite3 *db)
{
    int32_t hs = -999, sf = 0;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, &hs, &sf);
    progress_store_tx_unlock();
    return ok ? hs : -999;
}

static bool log_row_at(sqlite3 *db, int height, int *out_ok,
                       char *out_status, size_t status_size,
                       int *out_reorg_depth, int64_t *out_utxo_size)
{
    *out_ok = -1;
    if (out_status && status_size) out_status[0] = 0;
    if (out_reorg_depth) *out_reorg_depth = -1;
    if (out_utxo_size) *out_utxo_size = -2;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, reorg_depth, utxo_size_after "
        "FROM tip_finalize_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_status && status_size)
            snprintf(out_status, status_size, "%s", (const char *)txt);
        if (out_reorg_depth)
            *out_reorg_depth = sqlite3_column_int(st, 2);
        if (out_utxo_size)
            *out_utxo_size = sqlite3_column_int64(st, 3);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

static bool log_tip_hash_at(sqlite3 *db, int height, struct uint256 *out)
{
    uint256_set_null(out);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT tip_hash FROM tip_finalize_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (blob && n == 32) {
            memcpy(out->data, blob, 32);
            found = true;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static bool seed_tip_anchor_tf(sqlite3 *db, int height,
                               const struct uint256 *hash)
{
    if (!hash)
        return false;
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height           INTEGER PRIMARY KEY,"
        "  status           TEXT    NOT NULL,"
        "  ok               INTEGER NOT NULL,"
        "  work_delta_high  INTEGER NOT NULL,"
        "  work_delta_low   INTEGER NOT NULL,"
        "  utxo_size_after  INTEGER NOT NULL,"
        "  reorg_depth      INTEGER NOT NULL,"
        "  finalized_at     INTEGER NOT NULL,"
        "  tip_hash         BLOB"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO tip_finalize_log "
        "(height, status, ok, work_delta_high, work_delta_low, "
        " utxo_size_after, reorg_depth, finalized_at, tip_hash) "
        "VALUES(?, 'anchor', 1, 0, 0, -1, 0, 1, ?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static uint64_t cursor_at(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    uint64_t out = 0;
    if (sqlite3_prepare_v2(db,
        "SELECT cursor FROM stage_cursor WHERE name = ?",
        -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)
        out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

static bool fake_utxo_count(int height_after, int64_t *out_count, void *user)
{
    struct synth_chain_tf *sc = user;
    if (sc && sc->fail_kind == TF_FAIL_UTXO_COUNT && height_after == 2) {
        *out_count = 99;
        return true;
    }
    *out_count = height_after;
    return true;
}

static int tf_setup(const char *tag, int log_rows,
                    enum tf_fail_kind fail_kind,
                    int upstream_fail_height,
                    char *dir_out, size_t dir_out_size,
                    struct main_state *ms, struct synth_chain_tf *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "tip_finalize", tag);
    mkdir_p_tf("./test-tmp");
    mkdir_p_tf(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(sc, 0, sizeof(*sc));
    sc->fail_kind = fail_kind;
    sc->upstream_fail_height = upstream_fail_height;
    memset(ms, 0, sizeof(*ms));
    main_state_init(ms);
    if (!synth_chain_tf_build(sc, log_rows + 1)) return 2;
    for (int i = 0; i <= log_rows; i++) {
        if (!block_map_insert(&ms->map_block_index, sc->blocks[i].phashBlock,
                              &sc->blocks[i]))
            return 2;
    }
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[log_rows]);
    if (fail_kind == TF_FAIL_REORG && ms->chain_active.chain) {
        for (int i = 0; i <= log_rows; i++)
            ms->chain_active.chain[i] = &sc->blocks[i];
        ms->chain_active.height = log_rows;
    }

    if (!seed_utxo_apply(progress_store_db(), log_rows,
                         upstream_fail_height))
        return 3;
    if (!seed_upstream_logs_tf(progress_store_db(), sc, log_rows))
        return 3;
    if (!tip_finalize_stage_init(ms)) return 4;
    tip_finalize_stage_set_utxo_counter(fake_utxo_count, sc);
    return 0;
}

static void tf_teardown(const char *dir, struct main_state *ms,
                        struct synth_chain_tf *sc)
{
    tip_finalize_stage_shutdown();
    main_state_free(ms);
    synth_chain_tf_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* Minimal non-null step for a bare tip_finalize stage_t handle used to drive
 * the durable-cursor hydrate seam directly (no full stage lifecycle needed). */
static job_result_t uv_gap_dummy_step(struct stage_step_ctx *c)
{
    (void)c;
    return JOB_IDLE;
}

static int64_t tf_count_rows(sqlite3 *db, const char *table)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

int test_tip_finalize_stage(void);
int test_tip_finalize_stage(void)
{
    printf("\n=== tip_finalize_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* uv_cursor_gap crash-window clamp (Lane C root-cause fix).
     *
     * The reorg unwind commits the utxo_apply cursor rewind in one txn
     * (utxo_apply_delta_reorg.c) while tip_finalize's own cursor is rewound in
     * a SEPARATE, LATER txn (rewind_cursor_if_active_chain_reorged). A kill-9
     * between those two durable commits persists tip_finalize_cursor >
     * utxo_apply_cursor. On the next open, hydrate must clamp the tip_finalize
     * CURSOR down to the utxo_apply frontier (restoring the step_finalize
     * invariant tip_finalize <= utxo_apply) WITHOUT deleting a tip_finalize_log
     * row — otherwise step_finalize wedges forever on tip_finalize.uv_cursor_gap.
     * Pre-fix this case is RED (cursor stays at 5). */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "uv_gap_clamp");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        bool ok_setup = progress_store_open(dir);
        sqlite3 *db = progress_store_db();

        /* Durable crash-window image: tip_finalize cursor ahead (5) of the
         * rewound utxo_apply cursor (0), plus two surviving finalized-log rows
         * that the clamp must preserve. */
        ok_setup = ok_setup && exec_sql(db,
            "CREATE TABLE IF NOT EXISTS stage_cursor(name TEXT PRIMARY KEY,"
            " cursor INTEGER NOT NULL, updated_at INTEGER NOT NULL)");
        ok_setup = ok_setup && exec_sql(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('utxo_apply',0,1)");
        ok_setup = ok_setup && exec_sql(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('tip_finalize',5,1)");
        struct uint256 h2, h3;
        synthetic_hash(&h2, 2);
        synthetic_hash(&h3, 3);
        ok_setup = ok_setup && seed_tip_anchor_tf(db, 2, &h2);
        ok_setup = ok_setup && seed_tip_anchor_tf(db, 3, &h3);
        TF_CHECK("uv_gap_clamp: setup", ok_setup);

        /* The inversion is durably present before hydrate runs. */
        TF_CHECK("uv_gap_clamp: durable inversion present pre-hydrate",
                 cursor_at(db, "tip_finalize") == 5 &&
                 cursor_at(db, "utxo_apply") == 0);
        int64_t rows_before = tf_count_rows(db, "tip_finalize_log");

        stage_t *s = stage_create("tip_finalize", uv_gap_dummy_step, NULL);
        TF_CHECK("uv_gap_clamp: stage created", s != NULL);
        TF_CHECK("uv_gap_clamp: hydrate returns ok",
                 tip_finalize_stage_hydrate_cursor_from_store(db, s,
                                                              "uv_gap_test"));

        /* GREEN: cursor clamped to the upstream frontier; invariant restored;
         * log rows untouched. */
        TF_CHECK("uv_gap_clamp: tip_finalize cursor clamped to utxo_apply",
                 cursor_at(db, "tip_finalize") == 0);
        TF_CHECK("uv_gap_clamp: tip_finalize <= utxo_apply after clamp",
                 cursor_at(db, "tip_finalize") <= cursor_at(db, "utxo_apply"));
        TF_CHECK("uv_gap_clamp: tip_finalize_log rows preserved (none deleted)",
                 rows_before == 2 &&
                 tf_count_rows(db, "tip_finalize_log") == rows_before);

        if (s) stage_destroy(s);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("authority_guard: setup",
                 tf_setup("authority_guard", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("authority_guard: seeded from restored tip",
                 active_chain_height(&ms.chain_active) == 3);
        TF_CHECK("authority_guard: raw low-level tip write succeeds",
                 active_chain_move_window_tip(&ms.chain_active, &sc.blocks[1]));
        TF_CHECK("authority_guard: public height unchanged",
                 active_chain_height(&ms.chain_active) == 3);
        TF_CHECK("authority_guard: reducer height unchanged",
                 tip_finalize_stage_last_height() == 3);
        TF_CHECK("authority_guard: public tip unchanged",
                 active_chain_tip(&ms.chain_active) == &sc.blocks[3]);
        TF_CHECK("authority_guard: cache records raw local write",
                 active_chain_cached_tip(&ms.chain_active) == &sc.blocks[1]);
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "stale_cursor");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 6);
        for (int i = 0; ok_setup && i <= 5; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[5]);
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 3, -1);
        ok_setup = ok_setup &&
            seed_coins_applied_height(progress_store_db(), 3);
        ok_setup = ok_setup &&
            seed_tip_anchor_tf(progress_store_db(), 2, &sc.hashes[2]);
        ok_setup = ok_setup && exec_sql(progress_store_db(),
            "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
            "VALUES('tip_finalize', 2, 1)");
        ok_setup = ok_setup && tip_finalize_stage_init(&ms);
        tip_finalize_stage_set_utxo_counter(fake_utxo_count, &sc);
        TF_CHECK("stale_cursor: setup", ok_setup);
        /* The raw active-chain window is at 5, but coins_applied_height=3
         * means coins are applied only through 2. Startup must keep the
         * served authority at the durable coin-backed tip and must not turn
         * the overextended window into a new anchor. */
        TF_CHECK("stale_cursor: cursor remains durable coin-backed tip",
                 tip_finalize_stage_cursor() == 2);
        TF_CHECK("stale_cursor: header_admit not anchored from active tip",
                 cursor_at(progress_store_db(), "header_admit") == 0);
        TF_CHECK("stale_cursor: validate_headers not anchored from active tip",
                 cursor_at(progress_store_db(), "validate_headers") == 0);
        TF_CHECK("stale_cursor: body_fetch not anchored from active tip",
                 cursor_at(progress_store_db(), "body_fetch") == 0);
        TF_CHECK("stale_cursor: body_persist not anchored from active tip",
                 cursor_at(progress_store_db(), "body_persist") == 0);
        TF_CHECK("stale_cursor: script_validate not anchored from active tip",
                 cursor_at(progress_store_db(), "script_validate") == 0);
        TF_CHECK("stale_cursor: proof_validate not anchored from active tip",
                 cursor_at(progress_store_db(), "proof_validate") == 0);
        TF_CHECK("stale_cursor: utxo_apply remains at coins frontier",
                 cursor_at(progress_store_db(), "utxo_apply") == 3);
        TF_CHECK("stale_cursor: public height remains coin-backed tip",
                 active_chain_height(&ms.chain_active) == 2);
        TF_CHECK("stale_cursor: public tip resolves to coin-backed block",
                 active_chain_tip(&ms.chain_active) == &sc.blocks[2]);
        TF_CHECK("stale_cursor: raw window remains overextended",
                 active_chain_cached_tip(&ms.chain_active) == &sc.blocks[5]);
        int row_ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("stale_cursor: high anchor not written",
                 !log_row_at(progress_store_db(), 5, &row_ok, status,
                             sizeof(status), &depth, &utxos));
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("repair_replay: setup",
                 tf_setup("repair_replay", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("repair_replay: public starts at restored tip",
                 active_chain_height(&ms.chain_active) == 3);
        TF_CHECK("repair_replay: force cursor below authority",
                 exec_sql(progress_store_db(),
                    "INSERT OR REPLACE INTO stage_cursor"
                    "(name, cursor, updated_at) "
                    "VALUES('tip_finalize', 1, 1)"));
        TF_CHECK("repair_replay: lower row replays",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("repair_replay: cursor advanced",
                 tip_finalize_stage_cursor() == 2);
        TF_CHECK("repair_replay: public height did not regress",
                 active_chain_height(&ms.chain_active) == 3);
        TF_CHECK("repair_replay: authority height did not regress",
                 tip_finalize_stage_last_height() == 3);
        TF_CHECK("repair_replay: local window may rewind for replay",
                 active_chain_cached_tip(&ms.chain_active) == &sc.blocks[2]);
        int row_ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("repair_replay: replay row written",
                 log_row_at(progress_store_db(), 1, &row_ok, status,
                            sizeof(status), &depth, &utxos));
        TF_CHECK("repair_replay: replay row finalized",
                 row_ok == 1 && strcmp(status, "finalized") == 0);
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("happy: setup",
                 tf_setup("happy", 3, TF_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        TF_CHECK("happy: authority seeded from restored tip",
                 active_chain_height(&ms.chain_active) == 3);
        TF_CHECK("happy: drains 3", tip_finalize_stage_drain(100) == 3);
        TF_CHECK("happy: cursor at 3", tip_finalize_stage_cursor() == 3);
        TF_CHECK("happy: finalized_total == 3",
                 tip_finalize_stage_finalized_total() == 3);
        TF_CHECK("happy: work_added_low == 3",
                 tip_finalize_stage_total_work_added_low() == 3);
        for (int h = 0; h < 3; h++) {
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            log_row_at(progress_store_db(), h, &ok, status, sizeof(status),
                       &depth, &utxos);
            TF_CHECK("happy: row ok=1", ok == 1);
            TF_CHECK("happy: row status finalized",
                     strcmp(status, "finalized") == 0);
            TF_CHECK("happy: row reorg_depth=0", depth == 0);
            TF_CHECK("happy: utxo size matches delta",
                     utxos == (int64_t)h + 1);
        }
        TF_CHECK("happy: next step IDLE",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        tf_teardown(dir, &ms, &sc);
    }

    /* A durable upstream hole is hidden behind the derived contiguous-success
     * frontier: tip_finalize stops before the missing row and publishes no
     * downstream failure. Refilling the row raises that frontier and resumes
     * immediately. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("upstream_log_hole: setup",
                 tf_setup("upstream_hole", 3, TF_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        /* utxo_apply's cursor is already at 3 (tf_setup's seed); delete its
         * row at height=1 to simulate the torn-invariant residue. */
        TF_CHECK("upstream_log_hole: delete row at height=1 below the floor",
                 exec_sql(progress_store_db(),
                          "DELETE FROM utxo_apply_log WHERE height=1"));
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        TF_CHECK("upstream_log_hole: h=0 advances, holds at the hole",
                 tip_finalize_stage_drain(100) == 1);
        TF_CHECK("upstream_log_hole: cursor held at the hole (1)",
                 tip_finalize_stage_cursor() == 1);
        TF_CHECK("upstream_log_hole: stays JOB_IDLE, never JOB_BLOCKED",
                 tip_finalize_stage_step_once() == JOB_IDLE);

        struct blocker_snapshot uh_snaps[16];
        int uh_n = blocker_snapshot_all(uh_snaps, 16);
        bool uh_found = false, uh_fields_ok = false;
        for (int k = 0; k < uh_n; k++) {
            if (strcmp(uh_snaps[k].id, "tip_finalize.upstream_log_hole") ==
                0) {
                uh_found = true;
                uh_fields_ok = strstr(uh_snaps[k].reason, "utxo_apply_log") &&
                               strstr(uh_snaps[k].reason, "height=1") &&
                               uh_snaps[k].class == BLOCKER_DEPENDENCY;
                break;
            }
        }
        TF_CHECK("upstream_log_hole: derived frontier hides the torn row",
                 !uh_found);
        TF_CHECK("upstream_log_hole: no stale blocker fields escape",
                 !uh_fields_ok);

        int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("upstream_log_hole: no terminal row written at the hole",
                 !log_row_at(progress_store_db(), 1, &ok, status,
                             sizeof(status), &depth, &utxos));

        TF_CHECK("upstream_log_hole: refill the row (healer simulation)",
                 exec_sql(progress_store_db(),
                          "INSERT OR REPLACE INTO utxo_apply_log "
                          "(height, status, ok, spent_count, added_count, "
                          " total_value_delta, applied_at) "
                          "VALUES (1, 'verified', 1, 1, 2, 1, 1)"));
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        TF_CHECK("upstream_log_hole: resumes once the row is refilled",
                 tip_finalize_stage_drain(100) == 2);
        TF_CHECK("upstream_log_hole: cursor advanced to tip (3)",
                 tip_finalize_stage_cursor() == 3);
        TF_CHECK("upstream_log_hole: blocker cleared on resolve",
                 !blocker_exists("tip_finalize.upstream_log_hole"));
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("checkpoint_evidence: setup",
                 tf_setup("checkpoint_evidence", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("checkpoint_evidence: relabel complete upstream tuple",
                 exec_sql(progress_store_db(),
                     "UPDATE script_validate_log SET status='checkpoint_fold' "
                     "WHERE height=0;"
                     "UPDATE proof_validate_log SET status='checkpoint_fold' "
                     "WHERE height=0;"
                     "UPDATE utxo_apply_log SET status='checkpoint_fold' "
                     "WHERE height=0"));
        TF_CHECK("checkpoint_evidence: cannot finalize",
                 tip_finalize_stage_step_once() == JOB_BLOCKED);
        TF_CHECK("checkpoint_evidence: cursor stays before contained row",
                 tip_finalize_stage_cursor() == 0);
        TF_CHECK("checkpoint_evidence: names causal blocker",
                 blocker_exists("tip_finalize.validation_evidence"));
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("forked_utxo_evidence: setup",
                 tf_setup("forked_utxo_evidence",3,TF_FAIL_NONE,-1,
                          dir,sizeof(dir),&ms,&sc)==0);
        struct uint256 fork=sc.hashes[0];
        fork.data[31]^=0x5au;
        TF_CHECK("forked_utxo_evidence: corrupt branch receipt",
                 set_utxo_branch_tf(progress_store_db(),0,&fork));
        TF_CHECK("forked_utxo_evidence: cannot finalize",
                 tip_finalize_stage_step_once()==JOB_BLOCKED&&
                 tip_finalize_stage_cursor()==0&&
                 blocker_exists("tip_finalize.validation_evidence"));
        tf_teardown(dir,&ms,&sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        int row_ok = -1;
        char status[32];
        TF_CHECK("anchor_storage: setup",
                 tf_setup("anchor_storage", 4, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("anchor_storage: seed trusted height",
                 tip_finalize_stage_seed_anchor(3, sc.hashes[3].data, true));
        TF_CHECK("anchor_storage: isolate anchor-only authority",
                 exec_sql(progress_store_db(),
                     "UPDATE utxo_apply_log SET status='anchor' WHERE height=3;"
                     "DELETE FROM script_validate_log WHERE height=3;"
                     "DELETE FROM proof_validate_log WHERE height=3"));
        TF_CHECK("anchor_storage: numeric-prefix TEXT height fixture",
                 exec_sql(progress_store_db(),
                     "UPDATE progress_meta SET value=CAST('3x' AS TEXT) "
                     "WHERE key='" REDUCER_TRUSTED_BASE_HEIGHT_KEY "'"));
        TF_CHECK("anchor_storage: malformed authority refuses seed atomically",
                 !tip_finalize_stage_seed_anchor(
                     4, sc.hashes[3].data, true) &&
                 !log_row_at(progress_store_db(), 4, &row_ok,
                             status, sizeof(status), NULL, NULL));
        TF_CHECK("anchor_storage: TEXT height authority fails closed",
                 tip_finalize_trusted_anchor_at(
                     progress_store_db(), 3, &sc.hashes[3]) == -1);
        uint8_t high_bit_height[8] = {0, 0, 0, 0, 0, 0, 0, 0x80};
        TF_CHECK("anchor_storage: high-bit BLOB height fixture",
                 progress_meta_set(
                     progress_store_db(), REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                     high_bit_height, sizeof(high_bit_height)));
        TF_CHECK("anchor_storage: high-bit authority refuses seed atomically",
                 !tip_finalize_stage_seed_anchor(
                     4, sc.hashes[3].data, true) &&
                 !log_row_at(progress_store_db(), 4, &row_ok,
                             status, sizeof(status), NULL, NULL));
        uint8_t trusted_height[8] = {3, 0, 0, 0, 0, 0, 0, 0};
        TF_CHECK("anchor_storage: exact BLOB height restores authority",
                 progress_meta_set(
                     progress_store_db(), REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                     trusted_height, sizeof(trusted_height)) &&
                 tip_finalize_trusted_anchor_at(
                     progress_store_db(), 3, &sc.hashes[3]) == 1);
        TF_CHECK("anchor_storage: REAL hash fixture",
                 exec_sql(progress_store_db(),
                     "UPDATE progress_meta SET value=1.25 WHERE key='"
                     REDUCER_TRUSTED_BASE_HASH_KEY "'"));
        TF_CHECK("anchor_storage: REAL hash authority fails closed",
                 tip_finalize_trusted_anchor_at(
                     progress_store_db(), 3, &sc.hashes[3]) == -1);
        TF_CHECK("anchor_storage: exact BLOB hash restores authority",
                 progress_meta_set(
                     progress_store_db(), REDUCER_TRUSTED_BASE_HASH_KEY,
                     sc.hashes[3].data, sizeof(sc.hashes[3].data)) &&
                 tip_finalize_trusted_anchor_at(
                     progress_store_db(), 3, &sc.hashes[3]) == 1);
        TF_CHECK("anchor_storage: TEXT ok cannot authorize",
                 exec_sql(progress_store_db(),
                     "UPDATE tip_finalize_log SET ok=CAST('1x' AS TEXT) "
                     "WHERE height=3") &&
                 tip_finalize_trusted_anchor_at(
                     progress_store_db(), 3, &sc.hashes[3]) == 0);
        TF_CHECK("anchor_storage: TEXT hash cannot authorize",
                 exec_sql(progress_store_db(),
                     "UPDATE tip_finalize_log SET ok=1,"
                     "tip_hash=CAST(tip_hash AS TEXT) WHERE height=3") &&
                 tip_finalize_trusted_anchor_at(
                     progress_store_db(), 3, &sc.hashes[3]) == 0);
        tf_teardown(dir, &ms, &sc);
    }

    /* Live-frontier no-skip (task #30 root cause): every chain_set_active_tip re-anchors the JUST-PUBLISHED
     * tip via set_authoritative_tip. The old height+1 anchor target bumped
     * the cursor past the pending tip→tip+1 transition, so each new block
     * could only be published when ITS successor arrived — the served tip
     * trailed the network by one full inter-block interval (the alternating
     * finalized/anchor lattice in tip_finalize_log). This block pins:
     * (a) the self re-anchor is a cursor no-op, (b) the successor publishes
     * on FIRST arrival, (c) the resolver returns a self-consistent pair in
     * the advance→anchor crash window, (d) a stale re-commit never
     * downgrades a finalized row to an anchor row. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "noskip");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 5);
        /* Block 4 exists in the synth chain but has NOT "arrived" yet —
         * keep it out of the map so the most-work candidate is the tip. */
        for (int i = 0; ok_setup && i <= 3; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]);
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 3, -1);
        ok_setup = ok_setup &&
            seed_upstream_logs_tf(progress_store_db(), &sc, 3);
        ok_setup = ok_setup && tip_finalize_stage_init(&ms);
        tip_finalize_stage_set_utxo_counter(fake_utxo_count, &sc);
        TF_CHECK("noskip: setup", ok_setup);
        TF_CHECK("noskip: drains to the tip", tip_finalize_stage_drain(100) == 3);
        TF_CHECK("noskip: cursor at tip", tip_finalize_stage_cursor() == 3);

        /* (a) The live-path re-anchor of the self-published tip. */
        tip_finalize_stage_set_authoritative_tip(3, sc.hashes[3].data);
        TF_CHECK("noskip: self re-anchor does not bump the cursor",
                 tip_finalize_stage_cursor() == 3);
        int row_ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("noskip: anchor row written at tip",
                 log_row_at(progress_store_db(), 3, &row_ok, status,
                            sizeof(status), &depth, &utxos));
        TF_CHECK("noskip: anchor row ok",
                 row_ok == 1 && strcmp(status, "anchor") == 0);
        TF_CHECK("noskip: idle while successor absent",
                 tip_finalize_stage_step_once() == JOB_IDLE);

        /* (b) Successor arrives: map + utxo witness, ONE step publishes it. */
        ok_setup = block_map_insert(&ms.map_block_index,
                                    sc.blocks[4].phashBlock, &sc.blocks[4]);
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 4, -1);
        ok_setup = ok_setup &&
            seed_upstream_logs_tf(progress_store_db(), &sc, 4);
        TF_CHECK("noskip: successor arrival setup", ok_setup);
        TF_CHECK("noskip: successor publishes on FIRST arrival",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("noskip: cursor advanced", tip_finalize_stage_cursor() == 4);
        TF_CHECK("noskip: successor is the published tip",
                 tip_finalize_stage_last_height() == 4);
        TF_CHECK("noskip: anchor row upgraded to finalized",
                 log_row_at(progress_store_db(), 3, &row_ok, status,
                            sizeof(status), &depth, &utxos) &&
                 row_ok == 1 && strcmp(status, "finalized") == 0);

        /* (c) Crash-window resolver: cursor=4, no row at 4 yet (the next
         * trusted-tip anchor has not landed). The naive cursor-1 raw read
         * would pair (3, hash(4)) — the splice-class poisoned pair; the
         * resolver must return (4, hash(4)). */
        int rh = -1; uint8_t rhash[32];
        TF_CHECK("noskip: resolver finds a durable tip",
                 tip_finalize_stage_resolve_durable_tip(progress_store_db(),
                                                        &rh, rhash));
        TF_CHECK("noskip: resolver pair is self-consistent",
                 rh == 4 && memcmp(rhash, sc.hashes[4].data, 32) == 0);

        /* (c') CAS frontier capture over the SAME finalized lattice. This is
         * exactly the live -install-consensus-bundle refusal state: the durable
         * tip resolves to 4 (a `finalized` row at H binds tip H+1) while H* is
         * 3 (the deepest finalized ROW). The pre-fix capture demanded
         * durable_h == H* and REFUSED (frontier_unknown); the corrected capture
         * binds H* with H*'s OWN hash, which is (3, hash(3)). */
        {
            int32_t cf_h = -999; uint8_t cf_hash[32];
            int32_t hs = -999, sf = -999;
            progress_store_tx_lock();
            bool hs_ok = reducer_frontier_compute_hstar(progress_store_db(),
                                                        &hs, &sf);
            progress_store_tx_unlock();
            TF_CHECK("noskip: H* is 3 while durable tip is 4 (lattice +1)",
                     hs_ok && hs == 3 && rh == hs + 1);
            TF_CHECK("noskip: CAS capture SUCCEEDS when durable leads H* by one",
                     consensus_state_publication_cas_capture_frontier(
                         &cf_h, cf_hash));
            TF_CHECK("noskip: CAS capture binds (H*, hash-of-H*)",
                     cf_h == 3 &&
                     memcmp(cf_hash, sc.hashes[3].data, 32) == 0);
        }

        /* (d) A stale authority re-commit of an already-finalized height
         * must not downgrade the finalized row (it carries the successor
         * hash block_hash_at reads) and must not move the cursor. */
        tip_finalize_stage_set_authoritative_tip(3, sc.hashes[3].data);
        TF_CHECK("noskip: stale re-commit keeps the finalized row",
                 log_row_at(progress_store_db(), 3, &row_ok, status,
                            sizeof(status), &depth, &utxos) &&
                 row_ok == 1 && strcmp(status, "finalized") == 0);
        TF_CHECK("noskip: stale re-commit keeps the cursor",
                 tip_finalize_stage_cursor() == 4);

        /* (e) Genuine-unknown refusal: with the finalized log wiped, H*'s hash
         * is unresolvable, so capture must REFUSE (return false) and LOG_ERROR
         * every number — never a blind refusal. */
        TF_CHECK("noskip: wipe tip_finalize_log for uncomputable-frontier case",
                 exec_sql(progress_store_db(),
                          "DELETE FROM tip_finalize_log"));
        {
            int32_t cf_h = -999; uint8_t cf_hash[32];
            TF_CHECK("noskip: CAS capture REFUSES on an uncomputable frontier",
                     !consensus_state_publication_cas_capture_frontier(
                         &cf_h, cf_hash));
        }
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* AUTHORITY PAIR SELF-CONSISTENCY (height-splice class):
         * after a finalize PUBLISH the served pair must be the tip block's
         * OWN (height, hash) — active_chain_tip()->nHeight ==
         * active_chain_height(). A step path that publishes
         * (next_h, hash(next_h+1)) leaves the authority height one BELOW
         * the block its own hash resolves to; accept_block_header's
         * label-trust install then turned that pair into a -1 header-graph
         * splice on a tip re-delivery. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("authority_pair: setup",
                 tf_setup("authority_pair", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("authority_pair: drains 3",
                 tip_finalize_stage_drain(100) == 3);
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        TF_CHECK("authority_pair: tip resolves to the served block",
                 tip == &sc.blocks[3]);
        TF_CHECK("authority_pair: height label == tip block's own height",
                 tip != NULL &&
                 active_chain_height(&ms.chain_active) == tip->nHeight);
        TF_CHECK("authority_pair: published authority did not regress",
                 tip_finalize_stage_last_height() == 3);
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* A boot-time active-chain window may sit ahead of the coins frontier
         * after a torn/overextended restore. The generic active-tip re-anchor
         * must not turn that window into served finality: only a height whose
         * coins are applied through H may become the tip_finalize authority. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize",
                        "authority_coin_cap");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 5);
        for (int i = 0; ok_setup && i <= 4; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[4]);
        ok_setup = ok_setup &&
            seed_tip_anchor_tf(progress_store_db(), 2, &sc.hashes[2]) &&
            seed_cursor_tf(progress_store_db(), "tip_finalize", 2) &&
            /* utxo_apply stage cursor is co-committed with coins_applied_height
             * in production (utxo_apply_stage.c); seed it consistently (== 3)
             * so the boot-open clamp (tip_finalize <= utxo_apply) sees a
             * realistic frontier and does not fire on an unseeded-cursor
             * fixture. The coin-frontier cap under test still holds tip at 2. */
            seed_cursor_tf(progress_store_db(), "utxo_apply", 3) &&
            seed_coins_applied_height(progress_store_db(), 3);
        ok_setup = ok_setup && tip_finalize_stage_init(&ms);
        TF_CHECK("authority_coin_cap: setup", ok_setup);
        TF_CHECK("authority_coin_cap: boot publishes durable coin-backed tip",
                 tip_finalize_stage_last_height() == 2);
        int row_ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("authority_coin_cap: high anchor absent after init",
                 !log_row_at(progress_store_db(), 4, &row_ok, status,
                             sizeof(status), &depth, &utxos));

        tip_finalize_stage_set_authoritative_tip(4, sc.hashes[4].data);
        TF_CHECK("authority_coin_cap: high re-anchor does not publish",
                 tip_finalize_stage_last_height() == 2);
        TF_CHECK("authority_coin_cap: high re-anchor writes no anchor",
                 !log_row_at(progress_store_db(), 4, &row_ok, status,
                             sizeof(status), &depth, &utxos));
        TF_CHECK("authority_coin_cap: cursor remains durable tip",
                 tip_finalize_stage_cursor() == 2);
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("reorg: setup",
                 tf_setup("reorg", 3, TF_FAIL_REORG, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        TF_CHECK("reorg: first finalizes",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("reorg: second logs and advances",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("reorg: counter == 1",
                 tip_finalize_stage_reorg_detected_total() == 1);
        int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        log_row_at(progress_store_db(), 1, &ok, status, sizeof(status),
                   &depth, &utxos);
        TF_CHECK("reorg: h=1 ok=0", ok == 0);
        TF_CHECK("reorg: h=1 status",
                 strcmp(status, "reorg_detected") == 0);
        TF_CHECK("reorg: depth > 0", depth > 0);
        TF_CHECK("reorg: cursor advances to 2",
                 tip_finalize_stage_cursor() == 2);
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("reorg_replay: setup",
                 tf_setup("reorg_replay", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("reorg_replay: initial drain",
                 tip_finalize_stage_drain(100) == 3);
        TF_CHECK("reorg_replay: cursor at old tip",
                 tip_finalize_stage_cursor() == 3);

        sc.hashes[2].data[0] = 0xf2;
        sc.hashes[3].data[0] = 0xf3;
        sc.blocks[2].pprev = &sc.blocks[1];
        sc.blocks[3].pprev = &sc.blocks[2];
        arith_uint256_set_u64(&sc.blocks[2].nChainWork, 20);
        arith_uint256_set_u64(&sc.blocks[3].nChainWork, 30);
        TF_CHECK("reorg_replay: installs coherent fork",
                 active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]));

        TF_CHECK("reorg_replay: rewinds and replays fork block",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("reorg_replay: cursor is fork+1",
                 tip_finalize_stage_cursor() == 2);
        TF_CHECK("reorg_replay: counter increments",
                 tip_finalize_stage_reorg_detected_total() == 1);
        int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        struct uint256 logged;
        log_row_at(progress_store_db(), 1, &ok, status, sizeof(status),
                   &depth, &utxos);
        TF_CHECK("reorg_replay: row rewritten ok", ok == 1);
        TF_CHECK("reorg_replay: row rewritten finalized",
                 strcmp(status, "finalized") == 0);
        TF_CHECK("reorg_replay: row hash updated",
                 log_tip_hash_at(progress_store_db(), 1, &logged) &&
                 uint256_eq(&logged, sc.blocks[2].phashBlock));
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* SAFETY / NO-FALSE-REORG (the rejected chain-extender rung regression).
         * The rung admitted a pprev-less body at tip+1 into the window on weak
         * "unique have-data, non-failed body" criteria; tip_finalize then read
         * that NULL-pprev lookahead as new_tip and false-marked the good tip
         * below it ok=0 reorg_detected (tip_finalize_stage.c:429), incrementing
         * reorg_detected_total and skipping the cursor past a perfectly valid
         * height. The shipped extender REFUSES a pprev-less successor, so the
         * good tip idles on a missing lookahead (safe) instead of being
         * false-reorged. This proves all three: (1) the extender keeps the
         * severed body OUT of the window; (2) with it out, tip_finalize does NOT
         * reorg the good tip; (3) contrast — if the severed body IS forced into
         * the window slot (what the rung did), tip_finalize DOES reorg, so the
         * extender's refusal is the load-bearing guard. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "no_false_reorg");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 5);
        /* SEVER block 4's parent link: a genuinely unverifiable-parent body. */
        sc.blocks[4].pprev = NULL;
        /* Blocks 0..3 are the good, pprev-linked chain; block 4 (severed) lives
         * in the map as the ONLY candidate for the height-4 lookahead. */
        for (int i = 0; ok_setup && i <= 4; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]);
        ms.pindex_best_header = &sc.blocks[4];
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 4, -1);
        ok_setup = ok_setup &&
            seed_upstream_logs_tf(progress_store_db(), &sc, 4);
        ok_setup = ok_setup && tip_finalize_stage_init(&ms);
        tip_finalize_stage_set_utxo_counter(fake_utxo_count, &sc);
        TF_CHECK("no_false_reorg: setup", ok_setup);

        /* Finalize the good heights 0,1,2 (lookaheads 1,2,3 are all linked); the
         * severed height-4 body idles height 3, so the drain stops at 3. */
        TF_CHECK("no_false_reorg: drains the good prefix",
                 tip_finalize_stage_drain(100) == 3);
        TF_CHECK("no_false_reorg: cursor at the good tip",
                 tip_finalize_stage_cursor() == 3);

        /* (1) The extender must NOT pull the severed height-4 body into the
         * window — active_chain_at(4) stays empty. */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index,
                                             ms.pindex_best_header, 4);
        TF_CHECK("no_false_reorg: severed tip+1 body kept out of the window",
                 active_chain_at(&ms.chain_active, 4) == NULL);

        /* (2) With the severed body out, finalizing the good tip idles on a
         * missing lookahead — NOT reorg_detected. */
        uint64_t reorgs_before = tip_finalize_stage_reorg_detected_total();
        TF_CHECK("no_false_reorg: good tip idles, not reorged",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        TF_CHECK("no_false_reorg: reorg counter did not increment",
                 tip_finalize_stage_reorg_detected_total() == reorgs_before);
        {
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            TF_CHECK("no_false_reorg: no verdict row written at the good tip",
                     !log_row_at(progress_store_db(), 3, &ok, status,
                                 sizeof(status), &depth, &utxos));
        }

        /* (3) CONTRAST — force the severed body into the window slot (what the
         * rung did). Now tip_finalize DOES false-detect a reorg on the good tip,
         * proving the extender's refusal above is the load-bearing guard. */
        TF_CHECK("no_false_reorg: window has room for the forced slot",
                 ms.chain_active.capacity > 4);
        if (ms.chain_active.capacity > 4) {
            ms.chain_active.chain[4] = &sc.blocks[4];
            ms.chain_active.height = 4;
            TF_CHECK("no_false_reorg: forced severed lookahead DOES reorg",
                     tip_finalize_stage_step_once() == JOB_ADVANCED);
            TF_CHECK("no_false_reorg: forced-in reorg increments the counter",
                     tip_finalize_stage_reorg_detected_total() ==
                     reorgs_before + 1);
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            TF_CHECK("no_false_reorg: forced-in marks the good tip "
                     "reorg_detected",
                     log_row_at(progress_store_db(), 3, &ok, status,
                                sizeof(status), &depth, &utxos) &&
                     ok == 0 && strcmp(status, "reorg_detected") == 0);
        }
        tf_teardown(dir, &ms, &sc);
    }

    /* A snapshot/refold boot can already have a durable, coherent tip_finalize
     * frontier before the first coordinator step. Public RPC must not serve the
     * unpublished H* sentinel (0) while waiting for a later stage tick. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        reducer_frontier_test_set_compiled_anchor(0);
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "provable_tip_init");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 4);
        for (int i = 0; ok_setup && i <= 3; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]);
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 3, -1);
        ok_setup = ok_setup &&
            seed_upstream_logs_tf(progress_store_db(), &sc, 3);
        ok_setup = ok_setup &&
            stamp_proven_authority_tf(progress_store_db(), 3);
        ok_setup = ok_setup &&
            seed_tip_anchor_tf(progress_store_db(), 2, &sc.hashes[2]);
        ok_setup = ok_setup &&
            seed_cursor_tf(progress_store_db(), "tip_finalize", 2);
        reducer_frontier_provable_tip_reset();
        TF_CHECK("provable_tip_init: setup", ok_setup);
        TF_CHECK("provable_tip_init: cache starts unpublished",
                 reducer_frontier_provable_tip_cached() == 0);
        TF_CHECK("provable_tip_init: external height uses durable witness",
                 reducer_frontier_external_tip_height() == 2);
        TF_CHECK("provable_tip_init: init warms from durable frontier",
                 ok_setup && tip_finalize_stage_init(&ms));
        TF_CHECK("provable_tip_init: durable H* published without step",
                 reducer_frontier_provable_tip_cached() == 2);
        TF_CHECK("provable_tip_init: cache mirrors compute_hstar",
                 reducer_frontier_provable_tip_cached() ==
                    compute_hstar_now(progress_store_db()));
        tf_teardown(dir, &ms, &sc);
        reducer_frontier_test_set_compiled_anchor(-1);
    }

    /* Phase 0.2 — the EXTERNAL provable-tip cache (H*) MIRRORS compute_hstar at
     * steady state and is LOWERED at the reorg-rewind chokepoint. Lower the
     * compiled-anchor floor so H* reflects the synthetic heights (without the
     * override compute_hstar clamps the cache up to the mainnet checkpoint).
     *
     * tf_setup only seeds utxo_apply; reducer_frontier_compute_hstar MIN-folds
     * over SIX logs (validate_headers, script_validate, body_persist,
     * proof_validate, utxo_apply, tip_finalize), so the other four must be
     * seeded too or H* = MIN(...) stays pinned to the anchor (0) by their
     * unseeded cursor=0 logs (the original RED assertion's defect). We seed all
     * four ok=1 with matching synthetic hashes so the C3 hash-agreement check
     * passes and H* can reach the real synthetic frontier. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        reducer_frontier_test_set_compiled_anchor(0);
        TF_CHECK("provable_tip: setup",
                 tf_setup("provable_tip", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("provable_tip: seed upstream reducer logs to the frontier",
                 seed_upstream_logs_tf(progress_store_db(), &sc, 3));

        /* Drain the clean prefix: every upstream log + tip_finalize now reaches
         * a contiguous ok=1 prefix of 2 (rows at heights 1 and 2 above the
         * anchor 0), so H* = MIN over all six = 2. The cache must equal it. */
        TF_CHECK("provable_tip: first advance takes baseline proof",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        boot_scan_reset_for_testing();
        TF_CHECK("provable_tip: adjacent advances fast-forward H*",
                 tip_finalize_stage_drain(100) == 2);
        TF_CHECK("provable_tip: fast-forward scans no historical frontier rows",
                 boot_scan_value("reducer_frontier.contiguity_rows") == 0);
        /* The O(1)-per-finalize ratchet: neither the H* watermark nor the
         * utxo_apply SUM re-derives from durable rows on an adjacent advance —
         * the full fold and the full SUM stay untouched, and each finalize takes
         * exactly one fast-path bump. This is span-independent (0 rows scanned),
         * so per-finalize work does NOT scale with (cursor - anchor). */
        TF_CHECK("provable_tip: no full H* recompute in the fast-forward drain",
                 boot_scan_value("reducer_frontier.hstar_full_recompute") == 0);
        TF_CHECK("provable_tip: SUM cache O(1) — no full SUM in the drain",
                 boot_scan_value("reducer_frontier.utxo_sum_full_recompute") == 0);
        TF_CHECK("provable_tip: one fast-path advance per finalized block",
                 boot_scan_value("reducer_frontier.hstar_fastpath") == 2);
        int32_t hstar_real = compute_hstar_now(progress_store_db());
        TF_CHECK("provable_tip: real H* reaches the synthetic frontier",
                 hstar_real == 2);
        TF_CHECK("provable_tip: cache mirrors compute_hstar exactly",
                 reducer_frontier_provable_tip_cached() == hstar_real);

        /* Capture the proven pre-reorg tip (== the real H* == 2). */
        int32_t pre_reorg = reducer_frontier_provable_tip_cached();
        TF_CHECK("provable_tip: pre-reorg cache equals the real tip",
                 pre_reorg == 2);

        /* Pin a deterministic frontier floor BELOW the old tip: utxo_apply's
         * row at height 2 becomes ok=0, so its contiguous ok=1 prefix caps at 1.
         * This makes the post-rewind H* (and the recompute) settle at 1
         * regardless of any same-step re-advance — the rewind LOWERING is then
         * observable and stable, not transient. */
        TF_CHECK("provable_tip: cap utxo_apply frontier at height 1",
                 exec_sql(progress_store_db(),
                    "UPDATE utxo_apply_log SET ok=0, status='value_overflow' "
                    "WHERE height=2"));

        /* Install a coherent higher-work fork that diverges below the tip. Clear
         * BLOCK_HAVE_DATA on the fork's lookahead (block[2]) so that after the
         * reorg rewinds the tip_finalize cursor it HOLDS (have_data_missing,
         * JOB_IDLE) instead of immediately re-finalizing — the ONLY refresh that
         * runs is the reorg-rewind one, so the assertion isolates that site. */
        sc.hashes[2].data[0] = 0xf2;
        sc.hashes[3].data[0] = 0xf3;
        sc.blocks[2].pprev = &sc.blocks[1];
        sc.blocks[3].pprev = &sc.blocks[2];
        sc.blocks[2].nStatus = BLOCK_VALID_SCRIPTS;  /* HAVE_DATA cleared */
        arith_uint256_set_u64(&sc.blocks[2].nChainWork, 20);
        arith_uint256_set_u64(&sc.blocks[3].nChainWork, 30);
        TF_CHECK("provable_tip: installs coherent fork",
                 active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]));

        uint64_t reorgs_before = tip_finalize_stage_reorg_detected_total();
        /* The step detects the reorg and rewinds the tip_finalize cursor (3->1),
         * lowering the cache at the rewind chokepoint, then holds (the fork
         * lookahead's body is absent). The step result is IDLE; what matters is
         * the rewind fired and lowered the proven tip. */
        tip_finalize_stage_step_once();
        TF_CHECK("provable_tip: reorg rewind fired",
                 tip_finalize_stage_reorg_detected_total() == reorgs_before + 1);

        int32_t post_reorg = reducer_frontier_provable_tip_cached();
        TF_CHECK("provable_tip: reorg STRICTLY LOWERED the cached tip",
                 post_reorg < pre_reorg);
        TF_CHECK("provable_tip: lowered cache still mirrors compute_hstar",
                 post_reorg == compute_hstar_now(progress_store_db()));
        TF_CHECK("provable_tip: lowered cache holds at/above the anchor",
                 post_reorg >= 0);

        /* Shutdown resets the served-tip cache to the "not yet published"
         * sentinel, which the accessor serves as 0 (the honest pre-publish
         * provable height) — NOT the baked finality anchor. The next finalize
         * advance republishes the true H*. */
        tf_teardown(dir, &ms, &sc);
        TF_CHECK("provable_tip: shutdown reset cache to 0 (unpublished sentinel)",
                 reducer_frontier_provable_tip_cached() == 0);
        reducer_frontier_test_set_compiled_anchor(-1); /* restore mainnet floor */
    }

    /* Phase 0.3 — the O(1) H* fast path (tf_advance_provable_tip) can NEVER
     * publish a height whose consensus receipts name a block other than the one
     * being finalized. The fast path itself reads no rows: it bumps the
     * watermark on the sole condition cached == next_h - 1. What makes that safe
     * is the finalize gate ABOVE it — tip_finalize_full_evidence_at() requires
     * header_admit.hash, validate_headers.hash, utxo_apply_delta.branch_hash,
     * script_validate.block_hash and proof_validate.block_hash to ALL equal the
     * selected block's hash, with ok=1 + VERIFIED evidence. That is a STRICTER
     * binding than the fold's own C3 hash-agreement check (which only demands
     * the rows agree with EACH OTHER, and exempts a NULL nullable witness).
     *
     * These are the 2026-07-27 one-block-fork shapes at h=3,195,363: a verdict
     * row left hash-bound to the LOSING block while a different block is
     * canonical. Each must hold the cursor AND the published height, and the
     * cache must stay equal to the full recompute — proving the cheap path
     * cannot report a height the node is refusing to apply. */
    {
        static const struct {
            const char *tag;
            const char *name;
            const char *forge;      /* the losing-branch / weak-evidence row */
        } k_refuse[] = {
            { "coins_binding", "utxo_apply_delta.branch_hash names the loser",
              "UPDATE utxo_apply_delta SET branch_hash="
              "x'ee00000000000000000000000000000000000000000000000000000000000000' "
              "WHERE height=4" },
            { "proof_binding", "proof_validate verdict hash-bound to the loser",
              "UPDATE proof_validate_log SET block_hash="
              "x'ee00000000000000000000000000000000000000000000000000000000000000' "
              "WHERE height=4" },
            { "weak_evidence", "utxo_apply ok=1 without VERIFIED evidence",
              "UPDATE utxo_apply_log SET status='checkpoint' WHERE height=4" },
        };
        for (size_t i = 0; i < sizeof(k_refuse) / sizeof(k_refuse[0]); i++) {
            char dir[256]; struct main_state ms; struct synth_chain_tf sc;
            char label[192];
            reducer_frontier_test_set_compiled_anchor(0);
            snprintf(label, sizeof(label), "fastpath_binding[%s]: setup",
                     k_refuse[i].tag);
            TF_CHECK(label, tf_setup(k_refuse[i].tag, 5, TF_FAIL_NONE, -1,
                                     dir, sizeof(dir), &ms, &sc) == 0);
            /* Finalize the clean prefix up to h=3 so the cache sits at exactly
             * next_h - 1 == 3 — the ONE state that arms the fast path. */
            snprintf(label, sizeof(label),
                     "fastpath_binding[%s]: clean prefix finalizes 4 heights",
                     k_refuse[i].tag);
            TF_CHECK(label, tip_finalize_stage_drain(4) == 4);
            snprintf(label, sizeof(label),
                     "fastpath_binding[%s]: fast path ARMED (cache == next_h-1)",
                     k_refuse[i].tag);
            TF_CHECK(label, reducer_frontier_provable_tip_cached() == 3 &&
                            tip_finalize_stage_cursor() == 4);

            snprintf(label, sizeof(label), "fastpath_binding[%s]: forge %s",
                     k_refuse[i].tag, k_refuse[i].name);
            TF_CHECK(label, exec_sql(progress_store_db(), k_refuse[i].forge));

            job_result_t r = tip_finalize_stage_step_once();
            snprintf(label, sizeof(label),
                     "fastpath_binding[%s]: step is BLOCKED, not ADVANCED",
                     k_refuse[i].tag);
            TF_CHECK(label, r == JOB_BLOCKED);
            snprintf(label, sizeof(label),
                     "fastpath_binding[%s]: cursor held at 4", k_refuse[i].tag);
            TF_CHECK(label, tip_finalize_stage_cursor() == 4);
            snprintf(label, sizeof(label),
                     "fastpath_binding[%s]: published height NOT bumped to 4",
                     k_refuse[i].tag);
            TF_CHECK(label, reducer_frontier_provable_tip_cached() == 3);
            snprintf(label, sizeof(label),
                     "fastpath_binding[%s]: cache still == full recompute",
                     k_refuse[i].tag);
            TF_CHECK(label, reducer_frontier_provable_tip_cached() ==
                            compute_hstar_now(progress_store_db()));
            tf_teardown(dir, &ms, &sc);
            reducer_frontier_test_set_compiled_anchor(-1);
        }
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("precondition: setup",
                 tf_setup("precondition", 3, TF_FAIL_PRECONDITION, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        /* block[2] lacks BLOCK_HAVE_DATA -> finalizing height 1 sees a
         * TRANSIENT have_data_missing lookahead. Height 0 finalizes; the
         * stage then HOLDS at height 1 (JOB_IDLE) instead of stranding it by
         * advancing the cursor past an un-finalized height (the live
         * 3134304<->3134302 oscillation). */
        TF_CHECK("precondition: drains only height 0 (holds at 1)",
                 tip_finalize_stage_drain(100) == 1);
        TF_CHECK("precondition: cursor held at 1 (not advanced past)",
                 tip_finalize_stage_cursor() == 1);
        TF_CHECK("precondition: successor_pending counter fired",
                 tip_finalize_stage_successor_pending_total() == 1);
        TF_CHECK("precondition: genuine-fork counter NOT fired",
                 tip_finalize_stage_precondition_failed_total() == 0);
        int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("precondition: NO junk row written at h=1",
                 log_row_at(progress_store_db(), 1, &ok, status,
                            sizeof(status), &depth, &utxos) == false);
        /* CS-F1 WARN-storm throttle: repeated holds on the UNCHANGED
         * (height,reason) pair are counted (precondition_repeat_count in the
         * native dumpstate output) instead of re-logging the WARN every idle tick. */
        TF_CHECK("precondition: repeat hold stays IDLE",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        TF_CHECK("precondition: repeat hold stays IDLE x2",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        {
            struct json_value v;
            json_init(&v);
            char buf[1536];
            bool dumped = tip_finalize_dump_state_json(&v, NULL);
            size_t n = dumped ? json_write(&v, buf, sizeof(buf)) : 0;
            TF_CHECK("precondition: repeat count == 2 in dump",
                     n > 0 && n < sizeof(buf) &&
                     strstr(buf, "\"precondition_repeat_count\":2") != NULL);
            TF_CHECK("precondition: dump records blocked height",
                     strstr(buf, "\"last_precondition_height\":1") != NULL);
            TF_CHECK("precondition: dump records blocked reason",
                     strstr(buf, "\"last_precondition_reason\":"
                             "\"have_data_missing\"") != NULL);
            json_free(&v);
        }
        /* Land the successor body: block[2] now has HAVE_DATA, so BOTH height 1
         * (lookahead = block[2]) and height 2 (lookahead = the always-ready
         * block[3]) become finalizable. The held frontier drains forward two
         * blocks; cursor lands at 3 (utxo_apply_log has rows only through 2). */
        sc.blocks[2].nStatus |= BLOCK_HAVE_DATA;
        TF_CHECK("precondition: drains 1 and 2 once successor lands",
                 tip_finalize_stage_drain(100) == 2 &&
                 tip_finalize_stage_cursor() == 3);
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* INVALIDATED SUCCESSOR HOLD.  Reproduce the physical-node race where
         * chain[] has already retreated below block[2], but the durable
         * finalized-hash table can still resolve block[2]'s FAILED map owner.
         * The generous best-header scan must not re-expose it, and the
         * tip-finalize self-heal must not use it as the lookahead witness.
         * Doing either would run post-finalize for the invalidated block,
         * remove its resurrected transactions, and oscillate on every tick. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("failed_successor: setup",
                 tf_setup("failed_successor", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("failed_successor: finalize clean height 0",
                 tip_finalize_stage_drain(1) == 1 &&
                 tip_finalize_stage_cursor() == 1);
        sc.blocks[2].nStatus |= BLOCK_FAILED_VALID;
        ms.pindex_best_header = &sc.blocks[3];
        TF_CHECK("failed_successor: retreat active window below failed block",
                 active_chain_move_window_tip(&ms.chain_active,
                                              &sc.blocks[1]));
        TF_CHECK("failed_successor: durable-hash candidate holds",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        TF_CHECK("failed_successor: cursor remains before invalidated successor",
                 tip_finalize_stage_cursor() == 1);
        TF_CHECK("failed_successor: failed block not re-exposed in chain window",
                 active_chain_at(&ms.chain_active, 2) == NULL);
        TF_CHECK("failed_successor: successor_pending counter fired",
                 tip_finalize_stage_successor_pending_total() == 1);
        {
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            TF_CHECK("failed_successor: no finalized junk row at held height",
                     log_row_at(progress_store_db(), 1, &ok, status,
                                sizeof(status), &depth, &utxos) == false);
            struct json_value v;
            json_init(&v);
            char buf[1536];
            bool dumped = tip_finalize_dump_state_json(&v, NULL);
            size_t n = dumped ? json_write(&v, buf, sizeof(buf)) : 0;
            TF_CHECK("failed_successor: dump names block_failed",
                     n > 0 && n < sizeof(buf) &&
                     strstr(buf, "\"last_precondition_reason\":"
                                 "\"block_failed\"") != NULL);
            json_free(&v);
        }
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* HEADER-ONLY CANONICAL-SUCCESSOR FINALIZE (deadlock-cure step 3).
         * The precondition hold above (best_header unset) proves tip_finalize
         * HOLDS at height 1 when the lookahead successor block[2] is body-
         * missing. Here the SAME fixture, but with pindex_best_header SET so
         * block[2] is a CANONICAL header successor (BLOCK_VALID_SCRIPTS >=
         * BLOCK_VALID_HEADER, strictly greater work, on the best-header
         * ancestry). tip_finalize must NOT freeze: it finalizes height 1 on
         * block[2]'s HEADER witness (no body/script gate on block[2]) and the
         * frontier then cascades to the synthetic tip. This is the live 3162166
         * wedge in miniature — the have-data window stalls at the body frontier
         * (block[1]) and the successor is resolvable ONLY via the best-header
         * self-heal, exercising the new header-chain lookahead resolution. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("header_witness: setup",
                 tf_setup("header_witness", 3, TF_FAIL_PRECONDITION, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        ms.pindex_best_header = &sc.blocks[3];
        TF_CHECK("header_witness: drains PAST the body-missing successor",
                 tip_finalize_stage_drain(100) == 3);
        TF_CHECK("header_witness: cursor advanced to the frontier",
                 tip_finalize_stage_cursor() == 3);
        TF_CHECK("header_witness: header-witness finalize fired exactly once",
                 tip_finalize_stage_header_witness_total() == 1);
        TF_CHECK("header_witness: total finalized == 3 (heights 0,1,2)",
                 tip_finalize_stage_finalized_total() == 3);
        TF_CHECK("header_witness: NOT counted as a successor-pending hold",
                 tip_finalize_stage_successor_pending_total() == 0);
        /* The header-only row at height 1 uses the LOOKAHEAD convention
         * (status "finalized", tip_hash == hash(block[2])) — NOT an anchor row —
         * so the reorg-rewind scan checks it normally (no blind spot). */
        {
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            TF_CHECK("header_witness: h=1 is a normal lookahead 'finalized' row",
                     log_row_at(progress_store_db(), 1, &ok, status,
                                sizeof(status), &depth, &utxos) &&
                     ok == 1 && strcmp(status, "finalized") == 0);
            struct uint256 th;
            TF_CHECK("header_witness: h=1 row carries hash(block[2]) (lookahead)",
                     log_tip_hash_at(progress_store_db(), 1, &th) &&
                     uint256_eq(&th, sc.blocks[2].phashBlock));
        }
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* NEGATIVE GUARD: a RESOLVABLE successor that is NOT a canonical header
         * successor (here block[2] carries EQUAL — not strictly greater — work)
         * must STILL HOLD. No header-witness finalize, no DB row, cursor frozen.
         * Guards against a regression that finalizes on a lighter/non-canonical
         * N+1 (which would let H* climb past the real most-work chain). */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("header_witness_neg: setup",
                 tf_setup("header_witness_neg", 3, TF_FAIL_PRECONDITION, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        ms.pindex_best_header = &sc.blocks[3];
        /* block[2] no longer strictly heavier than its parent block[1]. */
        sc.blocks[2].nChainWork = sc.blocks[1].nChainWork;
        TF_CHECK("header_witness_neg: finalizes only h0, holds at 1",
                 tip_finalize_stage_drain(100) == 1);
        TF_CHECK("header_witness_neg: cursor held at 1",
                 tip_finalize_stage_cursor() == 1);
        TF_CHECK("header_witness_neg: NO header-witness finalize",
                 tip_finalize_stage_header_witness_total() == 0);
        TF_CHECK("header_witness_neg: counted as a successor-pending hold",
                 tip_finalize_stage_successor_pending_total() == 1);
        {
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            TF_CHECK("header_witness_neg: NO junk row written at h=1",
                     log_row_at(progress_store_db(), 1, &ok, status,
                                sizeof(status), &depth, &utxos) == false);
        }
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* FORK-LOOKAHEAD GUARD: best_header can rescue a missing N+1 only when
         * that header is the direct child of the already-finalized N. A
         * higher-work header fork whose parent hash differs from active N is a
         * reorg candidate, not a successor witness. tip_finalize must HOLD
         * without writing a height-keyed reorg_detected row; otherwise stale
         * ok=0 residue caps H* after the window later catches up. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("header_witness_fork_guard: setup",
                 tf_setup("header_witness_fork_guard", 3,
                          TF_FAIL_PRECONDITION, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("header_witness_fork_guard: collapse window to body frontier",
                 active_chain_move_window_tip(&ms.chain_active, &sc.blocks[1]));

        struct block_index fork_blocks[4];
        struct uint256 fork_hashes[4];
        for (int i = 1; i <= 3; i++) {
            block_index_init(&fork_blocks[i]);
            uint256_set_null(&fork_hashes[i]);
            fork_hashes[i].data[0] = (uint8_t)(0xe0 + i);
            fork_hashes[i].data[1] = (uint8_t)i;
            fork_blocks[i].hashBlock = fork_hashes[i];
            fork_blocks[i].phashBlock = &fork_hashes[i];
            fork_blocks[i].nHeight = i;
            fork_blocks[i].nVersion = 4;
            fork_blocks[i].nTime = (uint32_t)(1700010000u + (uint32_t)i);
            fork_blocks[i].nBits = 0x1f07ffff;
            fork_blocks[i].nStatus = BLOCK_VALID_HEADER;  /* header-only */
            arith_uint256_set_u64(&fork_blocks[i].nChainWork,
                                  (uint64_t)100 + (uint64_t)i);
        }
        fork_blocks[1].pprev = &sc.blocks[0];
        fork_blocks[2].pprev = &fork_blocks[1];
        fork_blocks[3].pprev = &fork_blocks[2];
        for (int i = 1; i <= 3; i++)
            block_index_build_skip(&fork_blocks[i]);
        ms.pindex_best_header = &fork_blocks[3];

        TF_CHECK("header_witness_fork_guard: finalizes only h0, holds at 1",
                 tip_finalize_stage_drain(100) == 1);
        TF_CHECK("header_witness_fork_guard: cursor held at 1",
                 tip_finalize_stage_cursor() == 1);
        TF_CHECK("header_witness_fork_guard: no header-witness finalize",
                 tip_finalize_stage_header_witness_total() == 0);
        TF_CHECK("header_witness_fork_guard: no reorg row/counter",
                 tip_finalize_stage_reorg_detected_total() == 0);
        {
            int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
            TF_CHECK("header_witness_fork_guard: NO junk row written at h=1",
                     log_row_at(progress_store_db(), 1, &ok, status,
                                sizeof(status), &depth, &utxos) == false);
        }
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* The block_index BLOCK_VALID_SCRIPTS mirror drifted CLEAR for the
         * lookahead (block[2]) — the live 3134954 wedge. The reducer's
         * hash-bound script_validate_log proves the scripts WERE validated, so
         * the gate trusts the log, finalizes past it, and heals the bit. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("script_log_heal: setup",
                 tf_setup("script_log_heal", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sc.blocks[2].nStatus = BLOCK_HAVE_DATA;  /* VALID_SCRIPTS cleared */
        TF_CHECK("script_log_heal: seed matching ok=1 row",
                 seed_script_log(progress_store_db(), 2, 1,
                                 sc.blocks[2].phashBlock));
        TF_CHECK("script_log_heal: drains all 3 via authoritative log",
                 tip_finalize_stage_drain(100) == 3);
        TF_CHECK("script_log_heal: cursor at 3",
                 tip_finalize_stage_cursor() == 3);
        TF_CHECK("script_log_heal: drifted bit healed on block[2]",
                 (sc.blocks[2].nStatus & BLOCK_VALID_MASK) >=
                     BLOCK_VALID_SCRIPTS);
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* REORG SAFETY: a stale ok=1 row left by an orphaned block that once
         * held height 2 carries a DIFFERENT block_hash. The height-keyed log
         * must NOT be trusted — finalizing the active (unvalidated) block here
         * would be a consensus break. The gate rejects the mismatch and holds. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("script_log_stale_reorg: setup",
                 tf_setup("script_log_stale", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sc.blocks[2].nStatus = BLOCK_HAVE_DATA;  /* VALID_SCRIPTS cleared */
        struct uint256 wrong; uint256_set_null(&wrong); wrong.data[0] = 0x11;
        TF_CHECK("script_log_stale_reorg: seed mismatched-hash ok=1 row",
                 seed_script_log(progress_store_db(), 2, 1, &wrong));
        TF_CHECK("script_log_stale_reorg: finalizes only h0, holds at 1",
                 tip_finalize_stage_drain(100) == 1);
        TF_CHECK("script_log_stale_reorg: cursor held at 1 (no false finalize)",
                 tip_finalize_stage_cursor() == 1);
        TF_CHECK("script_log_stale_reorg: block[2] bit NOT healed",
                 (sc.blocks[2].nStatus & BLOCK_VALID_MASK) <
                     BLOCK_VALID_SCRIPTS);
        tf_teardown(dir, &ms, &sc);
    }

    {
        /* ok=0 must never heal even with a matching hash: a recorded script
         * FAILURE is authoritative too — finalizing over it is forbidden. */
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("script_log_ok0: setup",
                 tf_setup("script_log_ok0", 3, TF_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sc.blocks[2].nStatus = BLOCK_HAVE_DATA;  /* VALID_SCRIPTS cleared */
        TF_CHECK("script_log_ok0: seed matching-hash ok=0 row",
                 seed_script_log(progress_store_db(), 2, 0,
                                 sc.blocks[2].phashBlock));
        TF_CHECK("script_log_ok0: finalizes only h0, holds at 1",
                 tip_finalize_stage_drain(100) == 1);
        TF_CHECK("script_log_ok0: cursor held at 1",
                 tip_finalize_stage_cursor() == 1);
        /* NEVER-LIE keystone: the SERVED tip is never published past the
         * cursor's advance over a non-finalizable height. update_last_advance
         * is called ONLY on the ok=1 finalized-publish path (tip_finalize_stage.c
         * ~471-494); the script-fail HOLD here takes JOB_IDLE and never publishes.
         * The last legitimately-served tip is the restored seed (blocks[3], h=3),
         * which init published; h=0 finalized but the publish guard
         * (published_before=3, 1>=3 false) kept it off the served tip, and h=1
         * holds. So the served tip MUST stay at 3 (the last ok=1 state) and MUST
         * NOT track the cursor (which holds at 1). Exact-equality, mutation-
         * sensitive: any publish from the ok=0 / hold path would drop it to <=1. */
        TF_CHECK("script_log_ok0: served tip stays at last ok=1 finalize (h=3)",
                 tip_finalize_stage_last_height() == 3);
        TF_CHECK("script_log_ok0: served tip not bumped to the held cursor",
                 tip_finalize_stage_last_height() !=
                     (int64_t)tip_finalize_stage_cursor());
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("utxo_count: setup",
                 tf_setup("utxo_count", 3, TF_FAIL_UTXO_COUNT, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        TF_CHECK("utxo_count: drains 3", tip_finalize_stage_drain(100) == 3);
        TF_CHECK("utxo_count: counter == 1",
                 tip_finalize_stage_utxo_count_diverged_total() == 1);
        int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        log_row_at(progress_store_db(), 1, &ok, status, sizeof(status),
                   &depth, &utxos);
        TF_CHECK("utxo_count: h=1 ok=0", ok == 0);
        TF_CHECK("utxo_count: h=1 status",
                 strcmp(status, "utxo_count_diverged") == 0);
        TF_CHECK("utxo_count: live count recorded", utxos == 99);
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("upstream_failed: setup",
                 tf_setup("upstream", 3, TF_FAIL_NONE, 2, dir, sizeof(dir),
                          &ms, &sc) == 0);
        TF_CHECK("upstream_failed: drains only the proven prefix",
                 tip_finalize_stage_drain(100) == 2);
        TF_CHECK("upstream_failed: failed row is not republished",
                 tip_finalize_stage_upstream_failed_total() == 0 &&
                 tip_finalize_stage_cursor() == 2);
        int ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        log_row_at(progress_store_db(), 2, &ok, status, sizeof(status),
                   &depth, &utxos);
        TF_CHECK("upstream_failed: no downstream h=2 row",
                 ok == -1 && status[0] == '\0');
        tf_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("idle: setup",
                 tf_setup("idle", 3, TF_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        sqlite3_exec(progress_store_db(),
            "UPDATE stage_cursor SET cursor=1 WHERE name='utxo_apply'",
            NULL, NULL, NULL);
        TF_CHECK("idle: advances one", tip_finalize_stage_drain(100) == 1);
        TF_CHECK("idle: next step IDLE",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        TF_CHECK("idle: cursor stays 1", tip_finalize_stage_cursor() == 1);
        tf_teardown(dir, &ms, &sc);
    }

    {
        TF_CHECK("guard: step_once with no init returns IDLE",
                 tip_finalize_stage_step_once() == JOB_IDLE);
        TF_CHECK("guard: init(NULL) rejected",
                 !tip_finalize_stage_init(NULL));
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        TF_CHECK("dump: setup",
                 tf_setup("dump", 2, TF_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        tip_finalize_stage_drain(100);
        struct json_value v;
        json_init(&v);
        TF_CHECK("dump: returns true",
                 tip_finalize_dump_state_json(&v, NULL));
        char buf[2048];   /* headroom: dump grew step-latency/rate fields
                            * (lane 1.1, engine/jobs/include/jobs/stage_helpers.h
                            * stage_dump_counters()) */
        size_t n = json_write(&v, buf, sizeof(buf));
        TF_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        TF_CHECK("dump: stage_name",
                 strstr(buf, "\"stage_name\":\"tip_finalize\"") != NULL);
        TF_CHECK("dump: cursor=2", strstr(buf, "\"cursor\":2") != NULL);
        TF_CHECK("dump: finalized_total=2",
                 strstr(buf, "\"finalized_total\":2") != NULL);
        TF_CHECK("dump: precondition_repeat_count=0",
                 strstr(buf, "\"precondition_repeat_count\":0") != NULL);
        TF_CHECK("dump: last_precondition_height=-1",
                 strstr(buf, "\"last_precondition_height\":-1") != NULL);
        TF_CHECK("dump: last_precondition_reason empty",
                 strstr(buf, "\"last_precondition_reason\":\"\"") != NULL);
        /* Lane 1.1 (per-stage step latency/rate metrics) — see the matching
         * block in test_utxo_apply_stage.c for the full rationale. */
        TF_CHECK("dump: last_step_us key present",
                 strstr(buf, "\"last_step_us\":") != NULL);
        TF_CHECK("dump: step_us_ewma key present",
                 strstr(buf, "\"step_us_ewma\":") != NULL);
        TF_CHECK("dump: steps_per_sec_ewma key present",
                 strstr(buf, "\"steps_per_sec_ewma\":") != NULL);
        TF_CHECK("dump: last_step_us > 0",
                 json_get_int(json_get(&v, "last_step_us")) > 0);
        TF_CHECK("dump: step_us_ewma > 0",
                 json_get_int(json_get(&v, "step_us_ewma")) > 0);
        json_free(&v);
        tf_teardown(dir, &ms, &sc);
    }

    /* TASK #31 — seed-anchor cursor unification: tip_finalize_stage_seed_anchor
     * stamps the tip_finalize cursor to the seeded tip's OWN height H (the
     * served-tip convention), NEVER H+1. A cursor of H+1 would claim the
     * unfinalized H→H+1 transition and skip it forever (the cursor is
     * monotonic) — one late block per cold-import/snapshot seed: block H+1
     * could only publish when H+2 arrived. This pins that the seed cursor is H
     * and the very next arriving block (H+1) publishes on its FIRST step. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "seed_no_late_block");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        /* Synth chain 0..4. The seeded tip is H=3; block 4 (H+1) has NOT
         * arrived yet (kept out of the map until the second phase). */
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 5);
        for (int i = 0; ok_setup && i <= 3; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]);
        /* Upstream applied through H=3 (next-height cursor == 4). */
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 4, -1);
        ok_setup = ok_setup && tip_finalize_stage_init(&ms);
        tip_finalize_stage_set_utxo_counter(fake_utxo_count, &sc);
        TF_CHECK("seed_no_late_block: setup", ok_setup);

        /* The cold-import/snapshot seed of the durable served tip at H=3. */
        TF_CHECK("seed_no_late_block: seed_anchor at H succeeds",
                 tip_finalize_stage_seed_anchor(3, sc.hashes[3].data, true));
        /* THE INVARIANT: the tip_finalize cursor floor is H (3), never H+1. */
        TF_CHECK("seed_no_late_block: tip_finalize cursor == served-tip H",
                 tip_finalize_stage_cursor() == 3);
        int row_ok = -1, depth = -1; int64_t utxos = -1; char status[32];
        TF_CHECK("seed_no_late_block: anchor row written at H",
                 log_row_at(progress_store_db(), 3, &row_ok, status,
                            sizeof(status), &depth, &utxos) &&
                 row_ok == 1 && strcmp(status, "anchor") == 0);
        /* The seed's utxo_apply trust stamp is INSERT OR IGNORE: the real
         * 'verified' verdict row at H (pre-written by seed_utxo_apply above)
         * must survive the seed un-clobbered. */
        {
            sqlite3_stmt *st = NULL;
            char ua_status[32] = ""; int ua_ok = -1;
            TF_CHECK("seed_no_late_block: real utxo_apply row at H survives",
                     sqlite3_prepare_v2(progress_store_db(),
                         "SELECT status, ok FROM utxo_apply_log "
                         "WHERE height = 3", -1, &st, NULL) == SQLITE_OK &&
                     sqlite3_step(st) == SQLITE_ROW &&
                     (snprintf(ua_status, sizeof(ua_status), "%s",
                               sqlite3_column_text(st, 0)) > 0) &&
                     (ua_ok = sqlite3_column_int(st, 1)) == 1 &&
                     strcmp(ua_status, "verified") == 0);
            if (st) sqlite3_finalize(st);
        }
        /* The boot resolver returns the seeded tip self-consistently from the
         * served-tip cursor (no +1, no -1 splice). */
        int rh = -1; uint8_t rhash[32];
        TF_CHECK("seed_no_late_block: resolver returns the seeded tip",
                 tip_finalize_stage_resolve_durable_tip(progress_store_db(),
                                                        &rh, rhash) &&
                 rh == 3 && memcmp(rhash, sc.hashes[3].data, 32) == 0);
        /* No successor yet → the stage idles (it does NOT regress or spin). */
        TF_CHECK("seed_no_late_block: idle while successor absent",
                 tip_finalize_stage_step_once() == JOB_IDLE);

        /* Block H+1 (=4) ARRIVES: map + utxo witness. Under the served-tip
         * cursor it publishes on the FIRST step — no late block. Under the old
         * H+1 stamp the cursor would already be 4 and this transition skipped,
         * so block 4 would wait for block 5. */
        ok_setup = block_map_insert(&ms.map_block_index,
                                    sc.blocks[4].phashBlock, &sc.blocks[4]);
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 5, -1);
        TF_CHECK("seed_no_late_block: successor arrival setup", ok_setup);
        TF_CHECK("seed_no_late_block: H+1 publishes on FIRST arrival",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("seed_no_late_block: cursor advanced to H+1",
                 tip_finalize_stage_cursor() == 4);
        TF_CHECK("seed_no_late_block: H+1 is the published tip",
                 tip_finalize_stage_last_height() == 4);
        tf_teardown(dir, &ms, &sc);
    }

    /* TASK #31, second member — the COLD-IMPORT row gap: on a real import
     * the utxo_apply cursor is seeded to H+1 with NO log rows at all (the
     * coins arrived inside the verified chainstate; utxo_apply never
     * re-applies ≤H). step_finalize at cursor H consumes the utxo_apply row
     * AT H, so without the seed's own trust stamp the stage idles forever on
     * uv_row_missing when upstream has applied through
     * the live tip while tip_finalize holds at the seed. This pins that the
     * seed itself supplies the row and the first live successor publishes. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_tf sc;
        bool ok_setup = true;
        test_fmt_tmpdir(dir, sizeof(dir), "tip_finalize", "seed_cold_import_row_gap");
        mkdir_p_tf("./test-tmp");
        mkdir_p_tf(dir);
        ok_setup = ok_setup && progress_store_open(dir);
        memset(&sc, 0, sizeof(sc));
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        ok_setup = ok_setup && synth_chain_tf_build(&sc, 5);
        for (int i = 0; ok_setup && i <= 3; i++)
            ok_setup = block_map_insert(&ms.map_block_index,
                                        sc.blocks[i].phashBlock,
                                        &sc.blocks[i]);
        ok_setup = ok_setup &&
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]);
        /* The cold-import shape: utxo_apply cursor at H+1 with ZERO rows
         * (seed_utxo_apply with n=0 creates the table + cursor only). */
        ok_setup = ok_setup && seed_utxo_apply(progress_store_db(), 0, -1);
        ok_setup = ok_setup && exec_sql(progress_store_db(),
            "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
            "VALUES('utxo_apply', 4, 1)");
        ok_setup = ok_setup &&
            stamp_proven_authority_tf(progress_store_db(), 4);
        ok_setup = ok_setup && tip_finalize_stage_init(&ms);
        /* Production never wires the utxo counter (test-only seam) — and on
         * a cold import sums-through(H) sees only the zero-delta anchor row,
         * so a wired counter would false-diverge. NULL also clears the
         * previous case's seam (its user pointer is out of scope). */
        tip_finalize_stage_set_utxo_counter(NULL, NULL);
        TF_CHECK("seed_cold_import_row_gap: setup", ok_setup);

        TF_CHECK("seed_cold_import_row_gap: seed_anchor at H succeeds",
                 tip_finalize_stage_seed_anchor(3, sc.hashes[3].data, true));
        /* THE PIN: the seed supplied its own utxo_apply trust row at H. */
        {
            sqlite3_stmt *st = NULL;
            char ua_status[32] = ""; int ua_ok = -1;
            TF_CHECK("seed_cold_import_row_gap: seed stamps utxo_apply row at H",
                     sqlite3_prepare_v2(progress_store_db(),
                         "SELECT status, ok FROM utxo_apply_log "
                         "WHERE height = 3", -1, &st, NULL) == SQLITE_OK &&
                     sqlite3_step(st) == SQLITE_ROW &&
                     (snprintf(ua_status, sizeof(ua_status), "%s",
                               sqlite3_column_text(st, 0)) > 0) &&
                     (ua_ok = sqlite3_column_int(st, 1)) == 1 &&
                     strcmp(ua_status, "anchor") == 0);
            if (st) sqlite3_finalize(st);
        }
        /* No successor yet → idle (and NOT uv_row_missing-pinned). */
        TF_CHECK("seed_cold_import_row_gap: idle while successor absent",
                 tip_finalize_stage_step_once() == JOB_IDLE);

        /* The first live block H+1 (=4) arrives: index entry + its OWN
         * apply verdict row + cursor → 5 (exactly what the live reducer
         * writes). The stage must publish it on the FIRST step. */
        ok_setup = block_map_insert(&ms.map_block_index,
                                    sc.blocks[4].phashBlock, &sc.blocks[4]);
        /* added-spent must equal the counter's count-after(5)==5: the seed
         * anchor row at 3 contributes (0,0), so this live row carries the
         * whole delta. (In production the counter seam is never wired.) */
        ok_setup = ok_setup && exec_sql(progress_store_db(),
            "INSERT OR REPLACE INTO utxo_apply_log "
            "(height, status, ok, spent_count, added_count, "
            " total_value_delta, applied_at) "
            "VALUES (4, 'verified', 1, 0, 5, 5, 1)");
        ok_setup = ok_setup && exec_sql(progress_store_db(),
            "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
            "VALUES('utxo_apply', 5, 1)");
        ok_setup = ok_setup &&
            stamp_proven_authority_tf(progress_store_db(), 5);
        TF_CHECK("seed_cold_import_row_gap: successor arrival setup", ok_setup);
        TF_CHECK("seed_cold_import_row_gap: H+1 publishes on FIRST arrival",
                 tip_finalize_stage_step_once() == JOB_ADVANCED);
        TF_CHECK("seed_cold_import_row_gap: cursor advanced to H+1",
                 tip_finalize_stage_cursor() == 4);
        TF_CHECK("seed_cold_import_row_gap: H+1 is the published tip",
                 tip_finalize_stage_last_height() == 4);
        tf_teardown(dir, &ms, &sc);
    }

    /* Task A #11 — current-tip-missing names a typed blocker. Previously this
     * anomaly (the block finalize extends FROM resolvable from NEITHER the
     * active-chain window, NOR the durable finalized-hash table, NOR the
     * best-header ancestry) set only the internal g_blocked_class counter — no
     * registry-visible blocker, so the stall-meta safety net could not see it.
     * note_tip_missing now raises a TRANSIENT "tip_finalize.current_tip_missing"
     * (height in reason), and the clear helper (called once old_tip resolves)
     * removes it. */
    {
        blocker_clear("tip_finalize.current_tip_missing");
        tip_finalize_observe_note_tip_missing(3162166);
        struct blocker_snapshot sn[32];
        int nn = blocker_snapshot_all(sn, 32);
        bool found = false;
        for (int k = 0; k < nn; k++) {
            if (strcmp(sn[k].id, "tip_finalize.current_tip_missing") == 0) {
                found = sn[k].class == BLOCKER_TRANSIENT &&
                        strstr(sn[k].reason, "height=3162166") != NULL;
                break;
            }
        }
        TF_CHECK("tip_missing: note raises typed TRANSIENT blocker with height",
                 found);
        tip_finalize_observe_clear_tip_missing();
        TF_CHECK("tip_missing: clear helper removes it on resolve",
                 !blocker_exists("tip_finalize.current_tip_missing"));
    }

    /* Differential property KAT: the incremental utxo_apply SUM cache must
     * equal the pure SUM(...) WHERE height<=? AND ok=1 at EVERY finalized
     * height, across a randomized log with ok=0 gaps (which force the
     * non-adjacent fallback) and a mid-stream reset (a shutdown/reinit). The
     * cache is the watermark discipline the whole task rests on: a running
     * total that is byte-identical to the full recompute. Deterministic
     * (fixed-seed LCG — no external RNG), so failures are reproducible. */
    {
        sqlite3 *sdb = NULL;
        bool open_ok = sqlite3_open(":memory:", &sdb) == SQLITE_OK;
        TF_CHECK("sum_cache_kat: open :memory:", open_ok);
        if (open_ok) {
            open_ok = exec_sql(sdb,
                "CREATE TABLE utxo_apply_log ("
                "  height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
                "  ok INTEGER NOT NULL, spent_count INTEGER NOT NULL,"
                "  added_count INTEGER NOT NULL)");
            TF_CHECK("sum_cache_kat: schema", open_ok);
        }
        enum { KAT_N = 4000 };
        static int kat_ok[KAT_N];
        static int64_t kat_spent[KAT_N], kat_added[KAT_N];
        uint64_t lcg = 0x9e3779b97f4a7c15ULL;  /* fixed seed */
        bool ins_ok = open_ok;
        sqlite3_stmt *ins = NULL;
        if (ins_ok)
            ins_ok = sqlite3_prepare_v2(sdb,
                "INSERT INTO utxo_apply_log"
                "(height,status,ok,spent_count,added_count) VALUES(?,?,?,?,?)",
                -1, &ins, NULL) == SQLITE_OK;
        for (int h = 0; h < KAT_N && ins_ok; h++) {
            lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
            int ok = ((lcg >> 33) % 7) != 0;  /* ~1 in 7 rows is ok=0 (a gap) */
            int64_t sp = (int64_t)((lcg >> 20) & 0x3f);
            int64_t ad = (int64_t)((lcg >> 40) & 0x3f);
            kat_ok[h] = ok; kat_spent[h] = sp; kat_added[h] = ad;
            sqlite3_reset(ins);
            sqlite3_bind_int(ins, 1, h);
            sqlite3_bind_text(ins, 2, ok ? "verified" : "value_overflow",
                              -1, SQLITE_STATIC);
            sqlite3_bind_int(ins, 3, ok);
            sqlite3_bind_int64(ins, 4, sp);
            sqlite3_bind_int64(ins, 5, ad);
            ins_ok = sqlite3_step(ins) == SQLITE_DONE;
        }
        if (ins) sqlite3_finalize(ins);
        TF_CHECK("sum_cache_kat: randomized log built", ins_ok);

        utxo_apply_sum_through_reset();
        int mismatches = 0;
        for (int h = 0; h < KAT_N && ins_ok; h++) {
            if (h == KAT_N / 2)
                utxo_apply_sum_through_reset();  /* mid-stream shutdown/reinit */
            if (!kat_ok[h])
                continue;  /* production calls the cache only on ok=1 finalizes */
            int64_t is = -1, ia = -1, fs = -1, fa = -1;
            bool a = utxo_apply_sum_through_incremental(sdb, h, kat_spent[h],
                                                        kat_added[h], &is, &ia);
            bool b = utxo_apply_sums_through(sdb, h, &fs, &fa);
            if (!a || !b || is != fs || ia != fa)
                mismatches++;
        }
        TF_CHECK("sum_cache_kat: incremental == full SUM at every ok=1 height",
                 ins_ok && mismatches == 0);
        utxo_apply_sum_through_reset();
        if (sdb) sqlite3_close(sdb);
    }

    printf("tip_finalize_stage tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
