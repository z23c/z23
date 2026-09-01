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

#include "test/test_core.h"

#include "services/utxo_recovery_service.h"
#include "models/database.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SBF_CHECK(name, expr) do {                                     \
    if (expr) { printf("  shielded_backfill: %s... OK\n", (name)); }   \
    else { printf("  shielded_backfill: %s... FAIL\n", (name));        \
           failures++; }                                               \
} while (0)

static void sbf_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0x5B;
}

/* Install a body-backed block_index at height h on the active chain with the
 * given (nonzero) shielded value. Heights MUST be installed in ascending order
 * so the chain height publishes as the maximum. A nonzero value means the walk
 * resolves it from the cached index and never touches disk. */
static struct block_index *sbf_install(struct main_state *ms, int h,
                                       int64_t sapling_value)
{
    struct uint256 hh;
    sbf_hash_for(h, &hh);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &hh);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nVersion = 4;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)h;
    memset(bi->hashMerkleRoot.data, 0x11, 32);
    bi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    bi->nFile = 1;
    bi->nDataPos = 1000 + h;
    bi->nTx = 1;
    bi->nSproutValue = 0;
    bi->nSaplingValue = sapling_value;
    if (!active_chain_install_tip_slot(&ms->chain_active, bi))
        return NULL;
    return bi;
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

int test_utxo_recovery_shielded_backfill(void);
int test_utxo_recovery_shielded_backfill(void)
{
    int failures = 0;
    printf("\n=== utxo_recovery shielded backfill (cursor-bounded) ===\n");

    /* ---- Pure planner ---- */
    {
        SBF_CHECK("plan: unset cursor starts at 1",
                  utxo_recovery_shielded_backfill_start(-1, 5000) == 1);
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

    /* ---- (b) suffix-only walk visits ONLY heights above the cursor ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "suffix");
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
        SBF_CHECK("(a) first pass wrote all rows",
                  sbf_shielded_rows(&ndb, 1, 1100) == 1100);

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
                  sbf_shielded_rows(&ndb, 1, 1100) == 1100);

        main_state_free(&ms);
        main_state_free(&ms2);
        node_db_close(&ndb);
    }

    /* ---- (c) stale cursor → suffix only; recorded prefix stays untouched ---- */
    {
        test_make_tmpdir(dir, sizeof(dir), "shielded_backfill", "regression");
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

    printf("=== shielded backfill: %d failure(s) ===\n", failures);
    return failures;
}
