/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: rewind the node.db projection cursor below a connected `blocks`
 * row that a reorg left off the active chain, so the catchup walk re-indexes
 * the winners.
 *
 * node_db_catchup_fork_rewind: the catchup cursor only ever advanced, so a
 * block indexed as tip and then reorged away kept its connected row while the
 * winner at that height never got one. Rewinding below the lowest such row
 * lets the ascending walk write the winners (db_block_save_canonical demotes
 * each same-height loser).
 */

// one-result-type-ok:cursor-rewind-predicates — every function here answers
// "was the cursor rewound" as a bool; each failure path logs its context, and
// the callers (catchup entry, backfill tick) only branch on the answer.

#include "node_db_catchup_internal.h"
#include "services/node_db_catchup_service.h"

#include "chain/chain.h"
#include "controllers/sync_controller.h" // shape-layer-ok:relocated-catchup-debt
#include "models/block.h"
#include "models/database.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"

#include <string.h>

/* Maximum heights below the cursor inspected for a reorged-away row; a reorg
 * deeper than this is outside the node's reorg limit. The scan also stops
 * after CATCHUP_FORK_SCAN_EMPTY consecutive heights without a row (lean or
 * sparse tip), so an unindexed region costs a handful of lookups. */
#define CATCHUP_FORK_SCAN_DEPTH 4096
#define CATCHUP_FORK_SCAN_EMPTY 32

/* Is the connected row at h a loser the walk can replace? Only a hash
 * mismatch against an EXISTING active entry that has body data counts: no
 * entry (cursor above the active tip) has nothing to compare, and an entry
 * without BLOCK_HAVE_DATA would be re-walked as a lean hole without ever
 * replacing the loser, rewinding on every tick. */
static bool fork_row_is_stale(const struct active_chain *chain, int h,
                              const struct db_block *row, bool *agrees)
{
    *agrees = false;
    const struct block_index *pindex = active_chain_at(chain, h);
    if (!pindex || !pindex->phashBlock ||
        !(pindex->nStatus & BLOCK_HAVE_DATA))
        return false;
    *agrees = memcmp(row->hash, pindex->phashBlock->data, 32) == 0;
    return !*agrees;
}

/* Lowest stale connected row at or below `cursor`, walking down until the
 * first agreeing row; -1 when none. */
static int fork_lowest_stale_row(struct node_db *ndb,
                                 const struct active_chain *chain, int cursor)
{
    int floor_h = cursor > CATCHUP_FORK_SCAN_DEPTH
                      ? cursor - CATCHUP_FORK_SCAN_DEPTH : 0;
    int lowest_stale = -1;
    int empty_run = 0;
    for (int h = cursor; h >= floor_h && empty_run < CATCHUP_FORK_SCAN_EMPTY;
         h--) {
        struct db_block row;
        if (!db_block_find_by_height(ndb, h, &row)) {
            empty_run++;
            continue;
        }
        empty_run = 0;
        bool agrees = false;
        if (fork_row_is_stale(chain, h, &row, &agrees))
            lowest_stale = h;
        else if (agrees)
            break;
    }
    return lowest_stale;
}

/* Rewind the cursor to the highest height below `stale_h` that has an
 * active-chain slot (a sparse chain may lack the slot right below); none ->
 * from genesis. *fork_out receives the height rewound to. */
static bool fork_rewind_below(struct node_db *ndb,
                              const struct active_chain *chain, int stale_h,
                              int *fork_out)
{
    int fork_h = stale_h - 1;
    const struct block_index *fork = NULL;
    while (fork_h >= 0 && !(fork = active_chain_at(chain, fork_h)))
        fork_h--;
    *fork_out = fork_h;
    if (fork_h < 0)
        return node_db_sync_reset_tip(ndb);
    return fork->phashBlock &&
           node_db_sync_set_tip(ndb, fork->phashBlock->data, fork_h);
}

bool node_db_catchup_fork_rewind_at(struct node_db *ndb,
                                  const struct active_chain *chain, int cursor)
{
    if (!ndb || !ndb->open || !chain || cursor < 0)
        return false;
    int stale_h = fork_lowest_stale_row(ndb, chain, cursor);
    if (stale_h < 0)
        return false;
    int fork_h = -1;
    bool ok = fork_rewind_below(ndb, chain, stale_h, &fork_h);
    LOG_WARN("catchup", "projection row at height %d is off the active "
             "chain (reorg); projection cursor %d -> %d %s", stale_h, cursor,
             fork_h, ok ? "rewound so the winner is re-indexed"
                        : "rewind FAILED");
    return ok;
}

bool node_db_catchup_service_rewind_stale_fork(struct node_db *ndb,
                                               const struct active_chain *chain)
{
    int cursor = -1;
    if (!ndb || !ndb->open || !chain ||
        !node_db_sync_get_tip_height_checked(ndb, &cursor))
        return false;
    return node_db_catchup_fork_rewind_at(ndb, chain, cursor);
}
