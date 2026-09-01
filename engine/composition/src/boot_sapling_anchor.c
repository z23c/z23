/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Seed a verified Sapling frontier after snapshot/refold reset. */

#include "config/boot_internal.h"

#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Birth-defect fix for the empty Sapling anchor-frontier stall. A
 * nonzero-activation seed (-refold-from-anchor / -load-snapshot-at-own-height)
 * resets the sapling anchor table via anchor_kv_reset_mark_empty_below_in_tx
 * without an initial frontier row, so the first shielded-output block above the
 * seed fails closed.
 * The node already holds a header-verified Sapling frontier in RAM here.
 * anchor_kv_seed_frontier_row independently verifies its root against the
 * activation header and writes nothing on mismatch; an unaligned snapshot
 * therefore defers safely to sapling_anchor_frontier_unavailable at runtime. */
void boot_seed_sapling_anchor_frontier_after_reset(struct main_state *state)
{
    if (!state || !state->sapling_tree_loaded)
        return;
    sqlite3 *db = progress_store_db();
    if (!db)
        return;

    int64_t activation = 0;
    bool found = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &activation,
                                     &found) ||
        !found || activation <= 0)
        return;
    bool empty = false;
    if (!anchor_kv_table_is_empty(db, ANCHOR_POOL_SAPLING, &empty) || !empty)
        return;

    const struct block_index *bi =
        active_chain_at(&state->chain_active, (int)activation);
    static const uint8_t zeros32[32] = {0};
    if (!bi || memcmp(bi->hashFinalSaplingRoot.data, zeros32, 32) == 0)
        return;

    progress_store_tx_lock();
    bool ok = anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                          &state->sapling_tree, activation,
                                          &bi->hashFinalSaplingRoot);
    progress_store_tx_unlock();
    if (ok)
        printf("[boot] seeded verified Sapling anchor frontier at seed h=%lld "
               "— no anchor-frontier stall on the first shielded block\n",
               (long long)activation);
}
