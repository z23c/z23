/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for chain_state_validator service — boot-time cross-check
 * between coins_best_block and active chain tip.
 */

#include "test/test_core.h"
#include "coins/coins_view.h"
#include "services/chain_state_validator.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "validation/chain_linkage_check.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "jobs/tip_finalize_stage.h"
#include "services/utxo_recovery_service.h"
#include "services/chain_state_service.h"
#include "services/chain_activation_service.h"
#include "models/database.h"
#include "chain/chainparams.h"
#include <sqlite3.h>

#define CSV_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a minimal chain of n blocks in main_state with matching
 * active_chain tip. */
static void csv_build_chain(struct main_state *ms, int n)
{
    struct uint256 hashes[256];
    int limit = n < 256 ? n : 256;

    for (int h = 0; h < limit; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[3] = 0xBB;

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));

        if (h > 0) {
            struct block_index *prev = block_map_find(
                &ms->map_block_index, &hashes[h - 1]);
            if (prev) pi->pprev = prev;
        }
    }
    /* Set active chain tip to last block */
    if (limit > 0) {
        struct block_index *tip = block_map_find(
            &ms->map_block_index, &hashes[limit - 1]);
        if (tip) active_chain_move_window_tip(&ms->chain_active, tip);
    }
}

/* After-execute observations for the derived-agree verdict. */
struct csv_exec_out {
    bool ran;
    bool exec_ok;
    bool best_is_tip;
    bool recovered;
};

/* Run the validator's verdict through the real recovery executor on this
 * fixture (CSR over the same maps and coins view) and report the end state.
 * EV_BOOT_VALIDATION_FAILED is not observable from here: the verdict path
 * to it (case_legacy_coins_empty) is bypassed by construction, which the
 * action value asserts. */
static void csv_execute_verdict(struct main_state *ms,
                                struct coins_view_cache *cache,
                                const char *pdir,
                                struct boot_validation_result *vr,
                                struct csv_exec_out *out)
{
    char db_path[320];
    snprintf(db_path, sizeof(db_path), "%s/csv_node.db", pdir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, db_path))
        return;
    chain_params_select(CHAIN_MAIN);
    struct chain_state_repository *csr = csr_instance();
    csr_init(csr, &ms->map_block_index, &ms->chain_active,
             &ms->pindex_best_header, cache, &ndb, NULL);
    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, ms, NULL, chain_params_get(), NULL);
    struct utxo_recovery_ctx uctx = {
        .state = ms, .coins_tip = cache, .ndb = &ndb,
        .datadir = "/nonexistent", .params = chain_params_get(),
        .activation_ctl = &ctl,
    };
    struct recovery_exec_result er = utxo_recovery_execute(&uctx, vr);
    struct uint256 best;
    memset(&best, 0, sizeof(best));
    coins_view_cache_get_best_block(cache, &best);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    out->ran = true;
    out->exec_ok = er.status.ok;
    out->recovered = er.recovered;
    out->best_is_tip = tip && tip->phashBlock &&
                       uint256_cmp(tip->phashBlock, &best) == 0;
    csr_free(csr);
    node_db_close(&ndb);
}

/* Null legacy coins best + a proven coins_kv whose DERIVED coins-best is
 * seeded (anchor row) at height `seed_h` with the hash of the block at
 * `seed_h` (hash_ok) or a hash absent from the index (!hash_ok). Chain tip
 * is h=49. Returns the validator verdict; *seeded reports fixture success. */
static enum boot_recovery_action csv_null_legacy_derived(int seed_h,
                                                         bool hash_ok,
                                                         bool *seeded,
                                                         struct csv_exec_out *out)
{
    char pdir[256];
    if (!test_mkdtemp(pdir, sizeof(pdir), "csv_der")) {
        *seeded = false;
        return BOOT_RECOVER_WIPE_WAIT;
    }
    char cmd[320];

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    block_map_init(&ms.map_block_index);
    active_chain_init(&ms.chain_active);
    csv_build_chain(&ms, 50);

    *seeded = false;
    if (progress_store_open(pdir)) {
        sqlite3 *db = progress_store_db();
        uint8_t txid[32], one = 1;
        uint8_t hash[32] = {0};
        hash[0] = (uint8_t)seed_h;
        hash[3] = hash_ok ? 0xBB : 0xEE;
        uint8_t applied[8] = {0};
        applied[0] = (uint8_t)(seed_h + 1);
        memset(txid, 0x77, sizeof(txid));
        *seeded = db && coins_kv_ensure_schema(db) &&
                  coins_kv_add(db, txid, 0, 1000LL, 1, false, NULL, 0) &&
                  progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                    &one, 1) &&
                  progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, applied,
                                    sizeof(applied)) &&
                  sqlite3_exec(db,
                      "CREATE TABLE IF NOT EXISTS validate_headers_log ("
                      " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
                      " ok INTEGER NOT NULL, fail_reason TEXT,"
                      " validated_at INTEGER);", NULL, NULL, NULL)
                      == SQLITE_OK &&
                  tip_finalize_stage_seed_anchor(seed_h, hash, false);
    }

    struct coins_view_cache cache;
    struct coins_view nv;
    memset(&nv, 0, sizeof(nv));
    coins_view_cache_init(&cache, &nv); /* legacy best stays null */
    struct boot_validation_result r =
        validate_coins_chain_agreement(&ms, &cache, "/nonexistent");
    if (out && *seeded && r.action == BOOT_OK_COMMIT_DERIVED_BEST)
        csv_execute_verdict(&ms, &cache, pdir, &r, out);

    coins_view_cache_free(&cache);
    block_map_free(&ms.map_block_index);
    progress_store_close();
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", pdir);
    TEST_DISCARD(system(cmd));
    return r.action;
}

/* 2b/2c: null legacy best with a derived coins-best. Returns failures. */
static int csv_derived_cases(void)
{
    int failures = 0;
    /* ── 2b. Null legacy best, but the DERIVED coins-best IS the chain tip
     *        → BOOT_OK (healthy warm boot, coins are not empty) ── */
    {
        struct csv_exec_out ex = {0};
        bool seeded = false;
        enum boot_recovery_action a =
            csv_null_legacy_derived(49, true, &seeded, &ex);
        CSV_CHECK("csv: null legacy + derived best == chain tip → commit-derived verdict",
                  seeded && a == BOOT_OK_COMMIT_DERIVED_BEST);
        CSV_CHECK("csv: executing it leaves the coins view best == active tip",
                  ex.ran && ex.exec_ok && ex.recovered && ex.best_is_tip);
    }

    /* ── 2c. Null legacy best, derived best present but NOT the tip →
     *        today's verdict (WIPE_WAIT; no chainstate dir) ── */
    {
        bool s1 = false, s2 = false;
        enum boot_recovery_action wrong_hash =
            csv_null_legacy_derived(49, false, &s1, NULL);
        enum boot_recovery_action lagging =
            csv_null_legacy_derived(48, true, &s2, NULL);
        CSV_CHECK("csv: null legacy + derived hash != tip → WIPE_WAIT",
                  s1 && wrong_hash == BOOT_RECOVER_WIPE_WAIT);
        CSV_CHECK("csv: null legacy + derived best below tip → WIPE_WAIT",
                  s2 && lagging == BOOT_RECOVER_WIPE_WAIT);
    }
    return failures;
}

int test_chain_state_validator(void)
{
    printf("\n=== chain state validator tests ===\n");
    int failures = 0;

    /* Test isolation: clear any chain-linkage HOLD left by a PRIOR group in
     * the shared-process monolith (test_zcl); the HOLD is process-global and
     * an inherited g_refuse_from makes csv_build_chain's advance refuse. */
    chain_linkage_reset_for_testing();

    /* Also disarm the active-chain authority
     * (active_chain_register_authority) and its block_map
     * (active_chain_register_block_map), which an earlier group leaves armed
     * with no unregister API; otherwise active_chain_tip() returns a dangling
     * block_index* from a freed block_map. Production never calls these with
     * a zeroed authority. */
    active_chain_register_authority(&(struct active_chain_authority){0});
    active_chain_register_block_map(NULL);

    /* ── 1. Coins and chain agree → BOOT_OK ──────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        csv_build_chain(&ms, 100);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        /* Set coins_best_block to chain tip hash */
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        coins_view_cache_set_best_block(&cache, tip->phashBlock);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: coins == chain tip → BOOT_OK",
                  r.action == BOOT_OK && r.coins_height == 99);

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    /* ── 2. Empty coins, chain with blocks → reimport/wipe ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        csv_build_chain(&ms, 50);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);
        /* coins_best_block is null (default) */

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/nonexistent");

        CSV_CHECK("csv: null coins + chain at h=49 → WIPE_WAIT",
                  r.action == BOOT_RECOVER_WIPE_WAIT);

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    failures += csv_derived_cases();

    /* ── 3. Chain at genesis, null coins → BOOT_OK ─────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        /* No chain built — tip is NULL */

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: genesis + null coins → BOOT_OK",
                  r.action == BOOT_OK);

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    /* ── 4. Chain at genesis, coins unknown → reset cursor via executor ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        csv_build_chain(&ms, 1);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        struct uint256 unknown;
        memset(&unknown, 0xAB, sizeof(unknown));
        coins_view_cache_set_best_block(&cache, &unknown);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        struct uint256 after;
        coins_view_cache_get_best_block(&cache, &after);

        CSV_CHECK("csv: genesis + unknown coins → RESET_COINS_TO_GENESIS",
                  r.action == BOOT_RECOVER_RESET_COINS_TO_GENESIS &&
                  uint256_eq(&after, &unknown));

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    /* ── 5. Coins behind chain → RESET_CHAIN ─────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        csv_build_chain(&ms, 100);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        /* Set coins_best_block to block at h=50 (behind tip at h=99) */
        struct uint256 h50;
        memset(&h50, 0, sizeof(h50));
        h50.data[0] = 50;
        h50.data[3] = 0xBB;
        coins_view_cache_set_best_block(&cache, &h50);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: coins at h=50, chain at h=99 → RESET_CHAIN",
                  r.action == BOOT_RECOVER_RESET_CHAIN &&
                  r.coins_height == 50);

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    /* ── 5b. Coins behind chain BUT the chain tip IS the durable
     *        reducer-finalized tip → BOOT_OK (reducer tip is the authority) ──
     * Same shape as test 5 with a durable tip_finalize tip seeded at the
     * chain tip: the stale coins.db best is benign lagging materialization,
     * so the validator must AGREE. Test 5 (no progress store) still asserts
     * RESET_CHAIN. */
    {
        char pdir[96];
        snprintf(pdir, sizeof(pdir), "/tmp/zcl_csv_fin_%d", (int)getpid());
        char rmcmd[160];
        snprintf(rmcmd, sizeof(rmcmd), "rm -rf '%s'", pdir);
         TEST_DISCARD(system(rmcmd));
        char mkcmd[160];
        snprintf(mkcmd, sizeof(mkcmd), "mkdir -p '%s'", pdir);
         TEST_DISCARD(system(mkcmd));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        csv_build_chain(&ms, 100);
        struct block_index *tip = active_chain_tip(&ms.chain_active);

        bool seeded = false;
        if (tip && tip->phashBlock && progress_store_open(pdir)) {
            /* Seed the durable finalized-tip log row WITHOUT initialising the
             * stage (tip_finalize_stage_init registers an irreversible global
             * active_chain authority); stamp the 'tip_finalize' cursor
             * directly. */
            bool row = tip_finalize_stage_seed_anchor(tip->nHeight,
                                                      tip->phashBlock->data,
                                                      false);
            char sql[160];
            snprintf(sql, sizeof(sql),
                     "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at)"
                     " VALUES('tip_finalize',%d,0)", tip->nHeight + 1);
            seeded = row &&
                     sqlite3_exec(progress_store_db(), sql, NULL, NULL, NULL)
                         == SQLITE_OK;
        }

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        struct uint256 h50;
        memset(&h50, 0, sizeof(h50));
        h50.data[0] = 50;
        h50.data[3] = 0xBB;
        coins_view_cache_set_best_block(&cache, &h50);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: coins behind + chain==reducer-finalized tip → BOOT_OK",
                  seeded && r.action == BOOT_OK && r.coins_height == 99);

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
        progress_store_close();
         TEST_DISCARD(system(rmcmd));
    }

    /* ── 6. Coins not in index, chain > 1000 → reset coins cursor ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        /* Build a chain longer than 1000 using a compact range */
        struct uint256 hashes[2];
        /* Genesis */
        memset(&hashes[0], 0, sizeof(hashes[0]));
        hashes[0].data[0] = 0xF0;
        hashes[0].data[3] = 0xCC;
        struct block_index *genesis = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hashes[0]);
        genesis->nHeight = 0;
        genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        genesis->nTx = 1;
        genesis->nChainTx = 1;
        arith_uint256_set_u64(&genesis->nChainWork, 1);

        /* Tip at h=2000 */
        memset(&hashes[1], 0, sizeof(hashes[1]));
        hashes[1].data[0] = 0xF1;
        hashes[1].data[3] = 0xCC;
        struct block_index *tip = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hashes[1]);
        tip->nHeight = 2000;
        /* pprev = NULL: a non-adjacent pprev is the splice shape the
         * linkage check refuses; this subtest only needs SOME tip at h=2000
         * with an unknown coins_best hash. */
        tip->pprev = NULL;
        tip->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        tip->nTx = 1;
        tip->nChainTx = 2001;
        arith_uint256_set_u64(&tip->nChainWork, 2001);
        active_chain_move_window_tip(&ms.chain_active, tip);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        /* Set coins_best_block to hash NOT in block_map */
        struct uint256 unknown;
        memset(&unknown, 0xDE, sizeof(unknown));
        coins_view_cache_set_best_block(&cache, &unknown);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        struct uint256 after;
        coins_view_cache_get_best_block(&cache, &after);

        CSV_CHECK("csv: coins hash not in index, chain > 1000 → reset cursor",
                  r.action == BOOT_RECOVER_RESET_COINS_TO_CHAIN_TIP &&
                  uint256_eq(&after, &unknown));

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    /* ── 7. Chain at genesis, coins set to known block → RESET ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        /* Insert a block at h=500 but don't set it as active tip */
        struct uint256 hash;
        memset(&hash, 0, sizeof(hash));
        hash.data[0] = 0x42;
        hash.data[3] = 0xDD;
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hash);
        bi->nHeight = 500;
        bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        bi->nTx = 1;

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);
        coins_view_cache_set_best_block(&cache, &hash);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: genesis tip + coins at known h=500 → RESET_CHAIN",
                  r.action == BOOT_RECOVER_RESET_CHAIN &&
                  r.coins_height == 500);

        coins_view_cache_free(&cache);
        block_map_free(&ms.map_block_index);
    }

    printf("=== chain state validator: %d failures ===\n", failures);
    return failures;
}
