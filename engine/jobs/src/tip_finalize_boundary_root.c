/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Boundary coin-root recording for tip_finalize's post-finalize step.
 *
 * coins_kv_commitment folds the coins set as it stands NOW. The reducer lets
 * utxo_apply run ahead of tip_finalize, so at finalize time the set can
 * already include blocks above the boundary. The legacy per-height row
 * ("mmb_utxo_root:<h>", read by the MMB leaf builders) is therefore written
 * as before, but the bound record ("coin_root_v2:<h>", served by
 * /api/v1/coins/roots) is written only when the applied frontier equals h+1,
 * i.e. the set is exactly the state after block h. */

#include "tip_finalize_post_step.h"

#include "chain/chain.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

static void boundary_persist_legacy(sqlite3 *db, int height,
                                    const uint8_t root[32])
{
    /* Runs on the serial reducer drive under progress_store_tx_lock, so the
     * streak counter is race-free. Log the first failure of a streak only. */
    static int s_fail_streak = 0;
    if (!coins_kv_boundary_root_set_in_tx(db, height, root)) {
        if (s_fail_streak++ == 0)
            LOG_WARN("tip_finalize",
                     "boundary utxo_root persist failed h=%d "
                     "(leaf still carries the computed root; "
                     "suppressing repeats until it recovers)", height);
    } else if (s_fail_streak > 0) {
        LOG_INFO("tip_finalize",
                 "boundary utxo_root persist recovered h=%d "
                 "after %d suppressed failure(s)", height, s_fail_streak);
        s_fail_streak = 0;
    }
}

static void boundary_persist_bound(sqlite3 *db, const struct block_index *bi,
                                   const uint8_t root[32])
{
    /* With the in-RAM overlay active, tip_finalize runs outside the writer
     * bracket, so the fold reads only the durable table and misses unflushed
     * coins while the frontier already counts them. */
    if (coins_ram_active()) {
        LOG_INFO("tip_finalize",
                 "boundary coin root h=%d not bound: in-RAM overlay active",
                 bi->nHeight);
        return;
    }
    int32_t applied = -1;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found) || !found ||
        applied != bi->nHeight + 1) {
        LOG_INFO("tip_finalize",
                 "boundary coin root h=%d not bound: coins applied frontier "
                 "%s (need %d)", bi->nHeight,
                 found ? "ahead of or behind the boundary" : "unreadable",
                 bi->nHeight + 1);
        return;
    }
    if (!coins_kv_boundary_record_set_in_tx(db, bi->nHeight,
                                            bi->phashBlock->data, root))
        LOG_WARN("tip_finalize", "bound coin root persist failed h=%d",
                 bi->nHeight);
}

void tip_finalize_record_boundary_root(struct sqlite3 *db,
                                       const struct block_index *bi,
                                       uint8_t root_out[32])
{
    memset(root_out, 0, 32);
    if (!db || !bi || !bi->phashBlock || coins_kv_commitment(db, root_out) != 0) {
        memset(root_out, 0, 32);
        LOG_WARN("tip_finalize",
                 "coins_kv_commitment failed h=%d; leaf carries zero "
                 "utxo_root sentinel", bi ? bi->nHeight : -1);
        return;
    }
    boundary_persist_legacy(db, bi->nHeight, root_out);
    boundary_persist_bound(db, bi, root_out);
}
