/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for the cursor-bounded shielded-value backfill
 * (engine/services/src/utxo_recovery_backfill.c). Proves:
 *   (a) the shielded_backfill_height cursor persists across a simulated reboot
 *       (close + reopen node.db) and gates a re-run to a skip;
 *   (b) the suffix walk visits ONLY heights above the cursor — the finalized
 *       prefix is never re-scanned;
 *   (c) a stale cursor (done < tip) no longer forces a full O(chain) re-walk:
 *       a shielded block recorded below the cursor stays untouched and the
 *       cursor advances monotonically to tip.
 */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"

#include "services/utxo_recovery_service.h"
#include "models/database.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "storage/disk_block_io.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/amount.h"
#include "core/uint256.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SBF_CHECK(name, expr) do {                                     \
    if (expr) { printf("  shielded_backfill: %s... OK\n", (name)); }   \
    else { printf("  shielded_backfill: %s... FAIL\n", (name));        \
           failures++; }                                               \
} while (0)

/* Build the body for height h whose Sapling valueDelta is `sapling_value`
 * (zclassicd: valueDeltaZat = -sum(tx.valueBalance), so valueBalance is the
 * negation). Header fields make the hash unique per height. */
static void sbf_make_block(struct block *b, int h, int64_t sapling_value)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = 1700000000u + (uint32_t)h;
    b->header.nBits = 0x2000ffffu;
    b->header.nNonce.data[0] = (uint8_t)(h & 0xFF);
    b->header.nNonce.data[1] = (uint8_t)((h >> 8) & 0xFF);
    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    transaction_init(&b->vtx[0]);
    transaction_alloc(&b->vtx[0], 1, 1);
    b->vtx[0].vin[0].sequence = 0xffffffff;
    b->vtx[0].vout[0].value = COIN;
    b->vtx[0].overwintered = true;
    b->vtx[0].version = 4;
    b->vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
    b->vtx[0].value_balance = -sapling_value;
}

/* The block hash for height h (header-only; independent of the body value). */
static void sbf_hash_for(int h, struct uint256 *out)
{
    struct block b;
    sbf_make_block(&b, h, 0);
    block_get_hash(&b, out);
    block_free(&b);
}

/* Install a body-backed block_index at height h on the active chain whose BODY
 * on disk carries `sapling_value` (the truth). The cached nSaplingValue is
 * seeded with `cached` so tests can prove the cache never wins over the body.
 * Heights MUST be installed in ascending order. */
static struct block_index *sbf_install_cached(struct main_state *ms,
                                              const char *datadir, int h,
                                              int64_t sapling_value,
                                              int64_t cached)
{
    struct block b;
    sbf_make_block(&b, h, sapling_value);
    struct uint256 hh;
    block_get_hash(&b, &hh);
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    bool wrote = write_block_to_disk(&b, &pos, datadir, msg_start);
    block_free(&b);
    if (!wrote)
        return NULL;
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &hh);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nVersion = 4;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)h;
    bi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    bi->nFile = pos.nFile;
    bi->nDataPos = pos.nPos;
    bi->nTx = 1;
    bi->nSproutValue = 0;
    bi->nSaplingValue = cached;
    if (!active_chain_install_tip_slot(&ms->chain_active, bi))
        return NULL;
    return bi;
}

static const char *g_sbf_dir;
static struct block_index *sbf_install(struct main_state *ms, int h,
                                       int64_t sapling_value)
{
    return sbf_install_cached(ms, g_sbf_dir, h, sapling_value, sapling_value);
}

/* Count blocks rows carrying a nonzero shielded value within [lo,hi]. */
static int sbf_shielded_rows(struct node_db *ndb, int lo, int hi)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM blocks "
            "WHERE (sprout_value != 0 OR sapling_value != 0) "
            "AND height >= ? AND height <= ?",
            -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(s, 1, lo);
    sqlite3_bind_int(s, 2, hi);
    if (sqlite3_step(s) == SQLITE_ROW)
        n = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* Insert a fully-populated real blocks row (as normal sync would) with
 * sentinel solution/chain_work/sapling_root and zeroed shielded values, so a
 * later backfill pass can be checked for preserving the consensus columns. */
static bool sbf_insert_real_row(struct node_db *ndb, const struct uint256 *hash,
                                int height, const uint8_t *solution,
                                int solution_len, const uint8_t chain_work[32],
                                const uint8_t sapling_root[32])
{
    sqlite3_stmt *s = NULL;
    static const uint8_t z32[32] = {0};
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,"
            "time,bits,nonce,solution,chain_work,status,file_num,data_pos,"
            "undo_pos,num_tx,sapling_root,sprout_root,sapling_value,sprout_value)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,0,0)",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_bind_blob(s, 3, z32, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, 4);
    sqlite3_bind_blob(s, 5, z32, 32, SQLITE_STATIC);
    sqlite3_bind_int64(s, 6, 1700000000);
    sqlite3_bind_int(s, 7, 0x2000ffff);
    sqlite3_bind_blob(s, 8, z32, 32, SQLITE_STATIC);
    sqlite3_bind_blob(s, 9, solution, solution_len, SQLITE_STATIC);
    sqlite3_bind_blob(s, 10, chain_work, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 11, 4 /* BLOCK_VALID_TREE */);
    sqlite3_bind_int(s, 12, 1);
    sqlite3_bind_int(s, 13, 1000 + height);
    sqlite3_bind_int(s, 14, 42 /* undo_pos */);
    sqlite3_bind_int(s, 15, 1);
    sqlite3_bind_blob(s, 16, sapling_root, 32, SQLITE_STATIC);
    bool ok = (sqlite3_step(s) == SQLITE_DONE);
    sqlite3_finalize(s);
    return ok;
}

/* Read one blocks-row column blob for `height`; returns bytes copied (<=cap). */
static int sbf_read_col_blob(struct node_db *ndb, int height, const char *col,
                             uint8_t *out, int cap)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s FROM blocks WHERE height=?", col);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(s, 1, height);
    int n = -1;
    if (sqlite3_step(s) == SQLITE_ROW) {
        n = sqlite3_column_bytes(s, 0);
        const void *b = sqlite3_column_blob(s, 0);
        if (n > cap) n = cap;
        if (b && n > 0) memcpy(out, b, (size_t)n);
        else if (n < 0) n = 0;
    }
    sqlite3_finalize(s);
    return n;
}

static int64_t sbf_read_col_int(struct node_db *ndb, int height, const char *col)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s FROM blocks WHERE height=?", col);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(s, 1, height);
    int64_t v = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

/* Heights 1..8 with body + row (3..5 carry the WRONG sign, the pre-8d8346b743
 * writer's output); height 9 has a body but no blocks row. */
static bool sbf_build_verify_fixture(struct main_state *ms, struct node_db *ndb)
{
    uint8_t sol[8], cw[32], sr[32];
    memset(sol, 0x11, sizeof(sol));
    memset(cw, 0x22, sizeof(cw));
    memset(sr, 0x33, sizeof(sr));
    bool built = true;
    for (int h = 1; h <= 8; h++) {
        built &= (sbf_install(ms, h, 100 + h) != NULL);
        struct uint256 hh;
        sbf_hash_for(h, &hh);
        built &= sbf_insert_real_row(ndb, &hh, h, sol, (int)sizeof(sol), cw, sr);
        sqlite3_stmt *s = NULL;
        sqlite3_prepare_v2(ndb->db,
            "UPDATE blocks SET sapling_value=? WHERE height=?", -1, &s, NULL);
        sqlite3_bind_int64(s, 1, (h >= 3 && h <= 5) ? -(100 + h) : 100 + h);
        sqlite3_bind_int(s, 2, h);
        built &= (sqlite3_step(s) == SQLITE_DONE);
        sqlite3_finalize(s);
    }
    return built & (sbf_install(ms, 9, 109) != NULL);
}

/* self-verify: wrong-sign repair, no rewrite of correct rows, cursor resume */
static int sbf_test_verify_pass(void)
{
    int failures = 0;
    char vdir[256];
    {
        test_make_tmpdir(vdir, sizeof(vdir), "shielded_backfill", "verify");
        g_sbf_dir = vdir;
        char vpath[320];
        snprintf(vpath, sizeof(vpath), "%s/node.db", vdir);
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(f) node.db opens", node_db_open(&ndb, vpath));
        struct main_state ms;
        main_state_init(&ms);
        SBF_CHECK("(f) fixture built", sbf_build_verify_fixture(&ms, &ndb));
        uint8_t cw[32];
        memset(cw, 0x22, sizeof(cw));
        SBF_CHECK("(f) update-count trigger installs",
                  sqlite3_exec(ndb.db,
                      "CREATE TABLE upd_log(h INTEGER);"
                      "CREATE TRIGGER log_upd AFTER UPDATE OF sapling_value,"
                      "sprout_value ON blocks BEGIN "
                      "INSERT INTO upd_log VALUES(NEW.height); END",
                      NULL, NULL, NULL) == SQLITE_OK);

        struct shielded_value_verify_batch b1 = {0};
        struct zcl_result r = utxo_recovery_verify_shielded_values_batch(
            &ndb, NULL, &ms, vdir, 1, 9, 4, &b1);
        SBF_CHECK("(i) batch 1 ok", r.ok && b1.from == 1 && b1.through == 4 &&
                  !b1.at_tip);
        SBF_CHECK("(i) batch 1 repaired heights 3 and 4", b1.repaired == 2);
        int64_t cur = -1;
        node_db_state_get_int(&ndb, "shielded_value_verify_height", &cur);
        SBF_CHECK("(i) cursor persisted at 4", cur == 4);

        /* reboot: close + reopen; the next batch resumes above the cursor */
        node_db_close(&ndb);
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(i) node.db reopens", node_db_open(&ndb, vpath));
        struct shielded_value_verify_batch b2 = {0};
        r = utxo_recovery_verify_shielded_values_batch(&ndb, NULL, &ms, vdir,
                                                       1, 9, 4, &b2);
        SBF_CHECK("(i) batch 2 resumes at 5", r.ok && b2.from == 5 &&
                  b2.through == 8 && !b2.at_tip);
        SBF_CHECK("(i) batch 2 repaired height 5 only", b2.repaired == 1);
        struct shielded_value_verify_batch b3 = {0};
        r = utxo_recovery_verify_shielded_values_batch(&ndb, NULL, &ms, vdir,
                                                       1, 9, 4, &b3);
        SBF_CHECK("(i) batch 3 reaches tip", r.ok && b3.from == 9 &&
                  b3.at_tip && b3.repaired == 0);
        struct shielded_value_verify_batch b4 = {0};
        r = utxo_recovery_verify_shielded_values_batch(&ndb, NULL, &ms, vdir,
                                                       1, 9, 4, &b4);
        SBF_CHECK("(i) finished pass is a no-op", r.ok && b4.already_done &&
                  b4.scanned == 0);

        bool all_ok = true;
        for (int h = 1; h <= 8; h++)
            all_ok &= (sbf_read_col_int(&ndb, h, "sapling_value") == 100 + h);
        SBF_CHECK("(f) every wrong-sign row repaired to the derived value",
                  all_ok);
        sqlite3_stmt *s = NULL;
        int updates = -1;
        sqlite3_prepare_v2(ndb.db, "SELECT COUNT(*) FROM upd_log", -1, &s,
                           NULL);
        if (sqlite3_step(s) == SQLITE_ROW)
            updates = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        SBF_CHECK("(g) correct rows were not rewritten (3 updates total)",
                  updates == 3);
        SBF_CHECK("(f) no row invented for a height without one",
                  sbf_shielded_rows(&ndb, 9, 9) == 0);
        SBF_CHECK("(f) in-memory index refreshed to the derived value",
                  active_chain_at(&ms.chain_active, 4)->nSaplingValue == 104);
        uint8_t got[32];
        SBF_CHECK("(f) consensus columns untouched",
                  sbf_read_col_blob(&ndb, 4, "chain_work", got, 32) == 32 &&
                  memcmp(got, cw, 32) == 0);
        main_state_free(&ms);
        node_db_close(&ndb);
    }
    return failures;
}

/* a cached WRONG nSaplingValue must not win over the body */
static int sbf_test_cache_vs_body(void)
{
    int failures = 0;
    char vdir[256];
    {
        test_make_tmpdir(vdir, sizeof(vdir), "shielded_backfill", "cache");
        g_sbf_dir = vdir;
        char vpath[320];
        snprintf(vpath, sizeof(vpath), "%s/node.db", vdir);
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(h) node.db opens", node_db_open(&ndb, vpath));
        struct main_state ms;
        main_state_init(&ms);
        struct block_index *bi = sbf_install_cached(&ms, vdir, 1, 700, -700);
        SBF_CHECK("(h) block with wrong-sign cache installed", bi != NULL);
        int updated = -1;
        struct zcl_result r = utxo_recovery_backfill_shielded_range(
            &ndb, NULL, &ms, vdir, 1, 1, &updated);
        SBF_CHECK("(h) backfill ok", r.ok && updated == 1);
        SBF_CHECK("(h) row carries the body-derived value, not the cache",
                  sbf_read_col_int(&ndb, 1, "sapling_value") == 700);
        SBF_CHECK("(h) in-memory cache refreshed to the derived value",
                  bi && bi->nSaplingValue == 700);
        /* a second pass finds a correct row: nothing to count */
        updated = -1;
        r = utxo_recovery_backfill_shielded_range(&ndb, NULL, &ms, vdir, 1, 1,
                                                  &updated);
        SBF_CHECK("(h) re-run rewrites nothing", r.ok && updated == 0);
        main_state_free(&ms);
        node_db_close(&ndb);
    }
    return failures;
}

/* a missing body mid-range stops the batch: the cursor stays below it, no done
 * marker is set, and a later batch (body present) repairs it */
static int sbf_test_verify_missing_body(void)
{
    int failures = 0;
    char vdir[256], vpath[320];
    test_make_tmpdir(vdir, sizeof(vdir), "shielded_backfill", "missing_body");
    g_sbf_dir = vdir;
    snprintf(vpath, sizeof(vpath), "%s/node.db", vdir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    SBF_CHECK("(k) node.db opens", node_db_open(&ndb, vpath));
    struct main_state ms;
    main_state_init(&ms);
    SBF_CHECK("(k) fixture built", sbf_build_verify_fixture(&ms, &ndb));
    struct block_index *gap = active_chain_at(&ms.chain_active, 3);
    uint32_t status = gap ? gap->nStatus : 0;
    if (gap)
        gap->nStatus &= ~(uint32_t)BLOCK_HAVE_DATA;   /* body "missing" */

    struct shielded_value_verify_batch b1 = {0};
    struct zcl_result r = utxo_recovery_verify_shielded_values_batch(
        &ndb, NULL, &ms, vdir, 1, 9, 512, &b1);
    int64_t cur = -1, done = 0;
    node_db_state_get_int(&ndb, "shielded_value_verify_height", &cur);
    SBF_CHECK("(k) batch stops at the missing body", r.ok && b1.scanned == 2 &&
              b1.through == 2 && !b1.at_tip);
    SBF_CHECK("(k) cursor stays below the gap", cur == 2);
    SBF_CHECK("(k) no done marker while a height is unverified",
              !(node_db_state_get_int(&ndb, "shielded_value_verify_done",
                                      &done) && done));
    SBF_CHECK("(k) heights above the gap not touched yet",
              sbf_read_col_int(&ndb, 4, "sapling_value") == -104);

    if (gap)
        gap->nStatus = status;                       /* body now present */
    struct shielded_value_verify_batch b2 = {0};
    r = utxo_recovery_verify_shielded_values_batch(&ndb, NULL, &ms, vdir, 1, 9,
                                                   512, &b2);
    SBF_CHECK("(k) later batch resumes at the gap and finishes",
              r.ok && b2.from == 3 && b2.at_tip && b2.repaired == 3);
    SBF_CHECK("(k) gap row repaired",
              sbf_read_col_int(&ndb, 3, "sapling_value") == 103);
    main_state_free(&ms);
    node_db_close(&ndb);
    return failures;
}

/* the verify pass yields to sync */
static int sbf_test_verify_yield(void)
{
    int failures = 0;
    SBF_CHECK("(j) runs at the live edge",
              utxo_recovery_shielded_verify_may_run(1000, 1000, 1000) &&
              utxo_recovery_shielded_verify_may_run(1000, 999, 1001));
    SBF_CHECK("(j) yields while the projection lags",
              !utxo_recovery_shielded_verify_may_run(1000, 900, 1000));
    SBF_CHECK("(j) yields while headers are ahead of the chain",
              !utxo_recovery_shielded_verify_may_run(1000, 1000, 1500));
    SBF_CHECK("(j) yields with no chain or unknown tips",
              !utxo_recovery_shielded_verify_may_run(0, 0, 0) &&
              !utxo_recovery_shielded_verify_may_run(1000, -1, 1000));
    return failures;
}

int test_utxo_recovery_shielded_backfill(void);
int test_utxo_recovery_shielded_backfill(void)
{
    int failures = 0;
    printf("\n=== utxo_recovery shielded backfill (cursor-bounded) ===\n");

    /* ---- Pure planner ---- */
    {
        SBF_CHECK("plan: unset cursor covers only the tip (no whole-chain body read)",
                  utxo_recovery_shielded_backfill_start(-1, 5000) == 5000);
        SBF_CHECK("plan: cursor 4000 starts at 4001",
                  utxo_recovery_shielded_backfill_start(4000, 5000) == 4001);
        SBF_CHECK("plan: cursor == tip skips",
                  utxo_recovery_shielded_backfill_start(5000, 5000) == 0);
        SBF_CHECK("plan: cursor > tip skips",
                  utxo_recovery_shielded_backfill_start(6000, 5000) == 0);
        SBF_CHECK("plan: shallow tip skips",
                  utxo_recovery_shielded_backfill_start(-1, 900) == 0);
    }

    char dir[256];
    char ndb_path[320];
    disk_block_io_set_deferred_sync(true);

    /* ---- (b) suffix-only walk visits ONLY heights above the cursor ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "suffix");
        g_sbf_dir = dir;
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(b) node.db opens", node_db_open(&ndb, ndb_path));

        struct main_state ms;
        main_state_init(&ms);
        /* Tip 1100; EVERY height carries a nonzero shielded value so that, if
         * the walk mistakenly touched the prefix, prefix rows WOULD appear. */
        bool built = true;
        for (int h = 1; h <= 1100; h++)
            built &= (sbf_install(&ms, h, 1000 + h) != NULL);
        SBF_CHECK("(b) chain built", built);

        SBF_CHECK("(b) cursor seed 1050",
                  node_db_state_set_int(&ndb, "shielded_backfill_height", 1050));
        int updated = -1;
        struct zcl_result r = utxo_recovery_backfill_shielded_range(
            &ndb, NULL, &ms, dir, 1051, 1100, &updated);
        SBF_CHECK("(b) range walk ok", r.ok);
        SBF_CHECK("(b) wrote exactly the 50 suffix rows", updated == 50);
        SBF_CHECK("(b) suffix rows present (1051..1100)",
                  sbf_shielded_rows(&ndb, 1051, 1100) == 50);
        SBF_CHECK("(b) prefix rows NOT written (1..1050)",
                  sbf_shielded_rows(&ndb, 1, 1050) == 0);
        int64_t cur = -1;
        node_db_state_get_int(&ndb, "shielded_backfill_height", &cur);
        SBF_CHECK("(b) cursor advanced to tip", cur == 1100);

        main_state_free(&ms);
        node_db_close(&ndb);
    }

    /* ---- (a) cursor sticks across a simulated reboot ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "reboot");
        g_sbf_dir = dir;
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(a) node.db opens", node_db_open(&ndb, ndb_path));

        struct main_state ms;
        main_state_init(&ms);
        bool built = true;
        for (int h = 1; h <= 1100; h++)
            built &= (sbf_install(&ms, h, 2000 + h) != NULL);
        SBF_CHECK("(a) chain built", built);

        /* Unset cursor → the gated entry covers (0,1100]. */
        utxo_recovery_backfill_shielded_if_needed(&ndb, NULL, &ms, dir, 1100);
        int64_t cur = -1;
        node_db_state_get_int(&ndb, "shielded_backfill_height", &cur);
        SBF_CHECK("(a) first pass stamps cursor at tip", cur == 1100);
        SBF_CHECK("(a) absent-cursor boot read only the tip body",
                  sbf_shielded_rows(&ndb, 1, 1099) == 0 &&
                  sbf_shielded_rows(&ndb, 1100, 1100) == 1);

        /* Simulate a reboot: close + reopen the same node.db file. */
        node_db_close(&ndb);
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(a) node.db reopens", node_db_open(&ndb, ndb_path));
        int64_t cur2 = -1;
        SBF_CHECK("(a) cursor survives reboot",
                  node_db_state_get_int(&ndb, "shielded_backfill_height",
                                        &cur2) && cur2 == 1100);

        /* Re-run at the same tip must SKIP (plan: done >= tip). Prove the skip
         * by using an EMPTY chain: if it tried to walk it would find nothing
         * and could not have re-written; the row count staying at 1100 with no
         * work confirms the fast skip path. */
        struct main_state ms2;
        main_state_init(&ms2);
        utxo_recovery_backfill_shielded_if_needed(&ndb, NULL, &ms2, dir, 1100);
        int64_t cur3 = -1;
        node_db_state_get_int(&ndb, "shielded_backfill_height", &cur3);
        SBF_CHECK("(a) re-run keeps cursor (skip)", cur3 == 1100);
        SBF_CHECK("(a) re-run left rows intact",
                  sbf_shielded_rows(&ndb, 1, 1100) == 1);

        main_state_free(&ms);
        main_state_free(&ms2);
        node_db_close(&ndb);
    }

    /* ---- (c) stale cursor → suffix only; recorded prefix stays untouched ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "regression");
        g_sbf_dir = dir;
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(c) node.db opens", node_db_open(&ndb, ndb_path));

        struct main_state ms;
        main_state_init(&ms);
        /* A real shielded block sits at h=500 (BELOW the cursor). The old
         * full-map walk would rediscover and re-write it on every boot; the
         * cursor-bounded walk must skip it. Suffix 1051..1100 are shielded and
         * SHOULD be written. Install ascending so height publishes as 1100. */
        SBF_CHECK("(c) prefix shielded block installed",
                  sbf_install(&ms, 500, 777000) != NULL);
        bool built = true;
        for (int h = 1051; h <= 1100; h++)
            built &= (sbf_install(&ms, h, 3000 + h) != NULL);
        SBF_CHECK("(c) suffix chain built", built);

        SBF_CHECK("(c) valid cursor at 1050",
                  node_db_state_set_int(&ndb, "shielded_backfill_height", 1050));
        utxo_recovery_backfill_shielded_if_needed(&ndb, NULL, &ms, dir, 1100);

        SBF_CHECK("(c) suffix written (1051..1100)",
                  sbf_shielded_rows(&ndb, 1051, 1100) == 50);
        SBF_CHECK("(c) recorded prefix block h=500 NOT re-scanned/written",
                  sbf_shielded_rows(&ndb, 1, 1050) == 0);
        int64_t cur = -1;
        node_db_state_get_int(&ndb, "shielded_backfill_height", &cur);
        SBF_CHECK("(c) cursor advanced monotonically to tip", cur == 1100);

        main_state_free(&ms);
        node_db_close(&ndb);
    }

    /* ---- (d) a pre-populated REAL row keeps its consensus columns ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "preserve");
        g_sbf_dir = dir;
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(d) node.db opens", node_db_open(&ndb, ndb_path));

        struct main_state ms;
        main_state_init(&ms);
        bool built = true;
        for (int h = 1051; h <= 1100; h++)
            built &= (sbf_install(&ms, h, 4000 + h) != NULL);
        SBF_CHECK("(d) suffix chain built", built);

        /* Normal sync already wrote a real row at h=1075 with real
         * solution/chain_work/sapling_root and zeroed shielded values. */
        uint8_t real_sol[64], real_cw[32], real_sr[32];
        memset(real_sol, 0xAB, sizeof(real_sol));
        memset(real_cw, 0xCD, sizeof(real_cw));
        memset(real_sr, 0xEF, sizeof(real_sr));
        struct uint256 h1075;
        sbf_hash_for(1075, &h1075);
        SBF_CHECK("(d) real row pre-inserted",
                  sbf_insert_real_row(&ndb, &h1075, 1075, real_sol,
                                      (int)sizeof(real_sol), real_cw, real_sr));

        SBF_CHECK("(d) cursor seed 1050",
                  node_db_state_set_int(&ndb, "shielded_backfill_height", 1050));
        int updated = -1;
        struct zcl_result r = utxo_recovery_backfill_shielded_range(
            &ndb, NULL, &ms, dir, 1051, 1100, &updated);
        SBF_CHECK("(d) range walk ok", r.ok);
        SBF_CHECK("(d) all 50 suffix rows carried a value", updated == 50);

        /* The derived shielded value landed on the real row... */
        SBF_CHECK("(d) sapling_value SET on real row",
                  sbf_read_col_int(&ndb, 1075, "sapling_value") == (4000 + 1075));
        /* ...WITHOUT disturbing the consensus columns. */
        uint8_t got[64];
        int gn = sbf_read_col_blob(&ndb, 1075, "solution", got, sizeof(got));
        SBF_CHECK("(d) solution SURVIVED intact",
                  gn == (int)sizeof(real_sol) &&
                  memcmp(got, real_sol, sizeof(real_sol)) == 0);
        gn = sbf_read_col_blob(&ndb, 1075, "chain_work", got, sizeof(got));
        SBF_CHECK("(d) chain_work SURVIVED intact",
                  gn == 32 && memcmp(got, real_cw, 32) == 0);
        gn = sbf_read_col_blob(&ndb, 1075, "sapling_root", got, sizeof(got));
        SBF_CHECK("(d) sapling_root SURVIVED intact",
                  gn == 32 && memcmp(got, real_sr, 32) == 0);
        SBF_CHECK("(d) undo_pos SURVIVED intact",
                  sbf_read_col_int(&ndb, 1075, "undo_pos") == 42);

        main_state_free(&ms);
        node_db_close(&ndb);
    }

    /* ---- (e) a failed value write must not certify coverage in the cursor ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "write_fail");
        g_sbf_dir = dir;
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBF_CHECK("(e) node.db opens", node_db_open(&ndb, ndb_path));

        struct main_state ms;
        main_state_init(&ms);
        SBF_CHECK("(e) shielded block installed",
                  sbf_install(&ms, 1, 5001) != NULL);

        uint8_t real_sol[64], real_cw[32], real_sr[32];
        memset(real_sol, 0xAC, sizeof(real_sol));
        memset(real_cw, 0xCE, sizeof(real_cw));
        memset(real_sr, 0xF0, sizeof(real_sr));
        struct uint256 h1;
        sbf_hash_for(1, &h1);
        SBF_CHECK("(e) real row pre-inserted",
                  sbf_insert_real_row(&ndb, &h1, 1, real_sol,
                                      (int)sizeof(real_sol), real_cw, real_sr));
        SBF_CHECK("(e) write-failure trigger installs",
                  sqlite3_exec(ndb.db,
                      "CREATE TRIGGER fail_shielded_backfill_update "
                      "BEFORE UPDATE OF sapling_value,sprout_value ON blocks "
                      "WHEN NEW.height=1 BEGIN "
                      "SELECT RAISE(ABORT,'shielded value write refused'); END",
                      NULL, NULL, NULL) == SQLITE_OK);

        int updated = -1;
        struct zcl_result r = utxo_recovery_backfill_shielded_range(
            &ndb, NULL, &ms, dir, 1, 1, &updated);
        SBF_CHECK("(e) rejected value write fails the pass", !r.ok);
        SBF_CHECK("(e) failed pass leaves out_updated untouched", updated == -1);
        int64_t cur = -1;
        SBF_CHECK("(e) failed write leaves coverage cursor unset",
                  !node_db_state_get_int(&ndb, "shielded_backfill_height",
                                         &cur));
        SBF_CHECK("(e) failed write leaves value unchanged",
                  sbf_read_col_int(&ndb, 1, "sapling_value") == 0);

        main_state_free(&ms);
        node_db_close(&ndb);
    }

    failures += sbf_test_verify_pass();
    failures += sbf_test_cache_vs_body();
    failures += sbf_test_verify_missing_body();
    failures += sbf_test_verify_yield();
    disk_block_io_set_deferred_sync(false);

    printf("=== shielded backfill: %d failure(s) ===\n", failures);
    return failures;
}
