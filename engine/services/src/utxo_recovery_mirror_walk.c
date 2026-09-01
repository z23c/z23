/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:legacy-mirror-walk-fallbacks
//
// Moved verbatim from utxo_recovery_restore.c: pure lookups whose
// not-found result (0 / NULL) is a normal answer for the restore
// arbitration, not a failure to explain. No fallible service surface.

/* UTXO Recovery - mirror-walk helpers (split from utxo_recovery_restore.c
 * for the E1 ceiling). Whole file is a wave-3 deletion unit: both walks
 * read the rebuildable utxos mirror / lean block rows and are only the
 * legacy fallback below the wave-2 derived coins-best.
 */

#include "services/utxo_recovery_service.h"
#include "services/chain_restore_repair.h"
#include "jobs/reducer_frontier.h"
#include "validation/main_state.h"
#include "models/database.h"
#include "models/block.h"
#include <string.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"

#include "utxo_recovery_internal.h"

int utxo_recovery_max_utxo_height(struct utxo_recovery_ctx *ctx)
{
    if (!ctx || !ctx->ndb || !ctx->ndb->open || !ctx->ndb->db)
        return 0;

    /* The DERIVED coins-best height (coins_applied_height - 1,
     * coins_kv's own co-committed state) outranks the mirror's MAX(height)
     * — interior holes / flush lag in the rebuildable projection must not
     * steer the restore. Legacy mirror read on !found (pre-seed datadirs:
     * coins_kv_seed_from_node_db has not run yet, key absent — the gating
     * is naturally correct). wave-3 delete: the mirror walk below. */
    {
        int32_t d_h = -1;
        if (reducer_frontier_derive_coins_best_now(&d_h, NULL, NULL))
            return d_h > 0 ? d_h : 0;
    }

    sqlite3_stmt *stmt = NULL;
    int max_h = 0;
    if (sqlite3_prepare_v2(ctx->ndb->db,
            "SELECT MAX(height) FROM utxos", -1, &stmt, NULL) == SQLITE_OK) {
        if (stmt && AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW)
            max_h = sqlite3_column_int(stmt, 0);
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return max_h;
}

struct block_index *utxo_recovery_find_disk_backed_utxo_tip(
    struct utxo_recovery_ctx *ctx,
    int max_height)
{
    if (!ctx || !ctx->ndb || !ctx->ndb->open || max_height <= 0)
        return NULL;

    const int floor = max_height > 10000 ? max_height - 10000 : 1;
    for (int h = max_height; h >= floor; h--) {
        struct db_block blk;
        if (!db_block_find_by_height(ctx->ndb, h, &blk))
            continue;
        struct uint256 hash;
        memcpy(hash.data, blk.hash, sizeof(hash.data));
        struct block_index *bi = block_map_find(&ctx->state->map_block_index,
                                                &hash);
        if (!bi)
            continue;
        if (chain_restore_block_is_consensus_backed_on_disk(bi,
                                                            ctx->datadir))
            return bi;
    }
    return NULL;
}
