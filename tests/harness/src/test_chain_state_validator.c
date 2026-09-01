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
#include "jobs/tip_finalize_stage.h"
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

int test_chain_state_validator(void)
{
    printf("\n=== chain state validator tests ===\n");
    int failures = 0;

    /* Test isolation: clear any chain-linkage HOLD left set by a PRIOR test
     * group in the shared-process monolith (test_zcl). The validator's HOLD is
     * process-global and persists until witnessed success; without this reset
     * an inherited g_refuse_from makes csv_build_chain's advance refuse
     * unexpectedly and the success-path assertions below deref a tip that was
     * never promoted -> SIGSEGV. The per-process parallel runner (test_parallel)
     * is unaffected (fresh globals per group) — this is a test_zcl-only leak
     * that kept `make ci` red, so the pre-push gate could never be armed. */
    chain_linkage_reset_for_testing();

    /* The HOLD reset alone is INSUFFICIENT in the monolith. active_chain_tip()
     * also consults a SECOND pair of process-global pointers — the active-chain
     * authority (active_chain_register_authority) and its block_map
     * (active_chain_register_block_map). An earlier group leaves these armed
     * with NO unregister API: tip_finalize_stage_init registers an authority
     * whose is_authoritative()==true permanently (see the comment in test 6
     * below), and test_process_headers_adversarial only restores them on its
     * success path. When armed, active_chain_tip() takes the authority branch,
     * looks the tip hash up in the LEAKED (now main_state_free'd) block_map, and
     * returns a dangling block_index* — so csv_build_chain's success-path
     * `tip->phashBlock` derefs freed memory -> SIGSEGV. Disarm both here (the
     * missing unregister) so this group's active_chain_tip() reads only its own
     * local window. Production never calls these with a zeroed authority. */
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
     * Identical shape to test 5 (coins at h=50, chain at h=99), but with a
     * durable tip_finalize tip seeded at the chain tip. The stale coins.db best
     * is benign lagging materialization (the projection authority is at the
     * finalized tip), so the validator must AGREE rather than reset the public
     * tip down and discard finalized progress. Test 5 (no progress store) still
     * asserts RESET_CHAIN — proving this branch never over-fires without a
     * finalized tip. */
    {
        char pdir[96];
        snprintf(pdir, sizeof(pdir), "/tmp/zcl_csv_fin_%d", (int)getpid());
        char rmcmd[160];
        snprintf(rmcmd, sizeof(rmcmd), "rm -rf '%s'", pdir);
        (void)system(rmcmd);
        char mkcmd[160];
        snprintf(mkcmd, sizeof(mkcmd), "mkdir -p '%s'", pdir);
        (void)system(mkcmd);

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        csv_build_chain(&ms, 100);
        struct block_index *tip = active_chain_tip(&ms.chain_active);

        bool seeded = false;
        if (tip && tip->phashBlock && progress_store_open(pdir)) {
            /* Seed the durable finalized-tip log row WITHOUT initialising the
             * stage: tip_finalize_stage_init would register an irreversible
             * global active_chain authority (is_authoritative()==true, no
             * unregister API) that leaks into later tests. seed_anchor writes
             * the tip_finalize_log anchor row but only stamps the cursor when
             * g_stage is wired, so we stamp the 'tip_finalize' cursor directly. */
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
        (void)system(rmcmd);
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
        /* pprev = NULL: a tip whose pprev label is non-adjacent (genesis
         * at h=0) is the splice shape the validation-pack linkage check
         * now (correctly) refuses; this subtest only needs SOME tip at
         * h=2000 with an unknown coins_best hash. */
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
