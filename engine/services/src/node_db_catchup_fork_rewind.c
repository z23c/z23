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
#include "services/explorer_unwind_service.h"
#include "models/explorer_index.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
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

/* What the unwind needs from the chain and the cursor it moves. The unwind
 * replays ZNAM / ZID / ZDIR operations from the common prefix, so it reads
 * blocks of the ACTIVE chain at or below the fork height; it prunes
 * `transactions` rows by comparing block hashes against the active chain
 * above it; and it moves the projection cursor to the fork before it lets
 * the catalog backfills run again. */
struct fork_block_source {
    struct node_db *ndb;
    const struct active_chain *chain;
    const char *datadir;
    const struct block_index *fork; /* NULL when the fork is genesis' parent */
    bool cursor_moved;
};

static bool fork_read_block(void *ctx, int height, struct block *out)
{
    const struct fork_block_source *r = ctx;
    const struct block_index *pindex = active_chain_at(r->chain, height);
    if (!pindex || !(pindex->nStatus & BLOCK_HAVE_DATA))
        return false;
    return read_block_from_disk_index(out, pindex, r->datadir);
}

static bool fork_active_hash(void *ctx, int height, uint8_t out[32])
{
    const struct fork_block_source *r = ctx;
    const struct block_index *pindex = active_chain_at(r->chain, height);
    if (!pindex || !pindex->phashBlock)
        return false;
    memcpy(out, pindex->phashBlock->data, 32);
    return true;
}

/* Rewind the projection cursor to the fork. Runs inside the unwind's fold
 * guard window (see explorer_unwind_chain.after_commit). */
static bool fork_move_cursor(void *ctx, int fork_h)
{
    struct fork_block_source *r = ctx;
    if (fork_h < 0)
        r->cursor_moved = node_db_sync_reset_tip(r->ndb);
    else
        r->cursor_moved = r->fork && r->fork->phashBlock &&
                          node_db_sync_set_tip(r->ndb, r->fork->phashBlock->data,
                                               fork_h);
    return r->cursor_moved;
}

/* The history window of the derived catalogs must cover every reorg this scan
 * can detect, or an exact rewind would be impossible for a depth the
 * projection itself rewinds. The scan finds a stale row as deep as
 * cursor - CATCHUP_FORK_SCAN_DEPTH and the fork is the height below it. */
static_assert(CATCHUP_FORK_SCAN_DEPTH + 1 <= CATALOG_HISTORY_DEPTH,
              "catalog digest history must cover the deepest fork the scan "
              "can rewind to");

/* Rewind the cursor to the highest height below `stale_h` that has an
 * active-chain slot (a sparse chain may lack the slot right below); none ->
 * from genesis. *fork_out receives the height rewound to.
 *
 * Before the cursor moves, everything the losing branch left in the
 * projection and the overlays is unwound to the fork (see
 * explorer_index_unwind_above_chain), and the cursor moves inside the same
 * fold-guard window. The unwind is one transaction. When it fails the cursor
 * is still rewound so the winner is indexed (the pre-fix behaviour) and the
 * failure is logged and raised as the named explorer.unwind_failed blocker.
 * When it cannot start because a catalog fold still holds its guard it
 * changed nothing: the cursor is NOT moved (a rewind without the unwind would
 * re-walk the winner over the loser's rows) and the next tick retries;
 * *deferred is set. */
static bool fork_rewind_below(struct node_db *ndb,
                              const struct active_chain *chain,
                              const char *datadir, int stale_h, int *fork_out,
                              bool *deferred)
{
    int fork_h = stale_h - 1;
    const struct block_index *fork = NULL;
    while (fork_h >= 0 && !(fork = active_chain_at(chain, fork_h)))
        fork_h--;
    *fork_out = fork_h;
    struct fork_block_source source = { ndb, chain, datadir,
                                        fork_h >= 0 ? fork : NULL, false };
    struct explorer_unwind_chain src = {
        .read = datadir ? fork_read_block : NULL,
        .active_hash = fork_active_hash,
        .after_commit = fork_move_cursor,
        .ctx = &source,
    };
    struct explorer_unwind_report report;
    struct zcl_result unwound =
        explorer_index_unwind_above_chain(ndb, fork_h, &src, &report);
    if (!unwound.ok && unwound.code == EXPLORER_UNWIND_ERR_BUSY) {
        *deferred = true;
        LOG_WARN("catchup", "reorg unwind to height %d deferred: %s", fork_h,
                 unwound.message);
        return false;
    }
    if (!unwound.ok)
        LOG_ERROR("catchup", "reorg unwind to height %d failed (%s): ZNAM/"
                  "ZID/ZDIR and token tables may still hold the losing "
                  "branch; run a reindex-explorer to rebuild them", fork_h,
                  unwound.message);
    if (!source.cursor_moved && unwound.code != EXPLORER_UNWIND_ERR_HOOK)
        (void)fork_move_cursor(&source, fork_h);
    return source.cursor_moved;
}

int node_db_catchup_fork_rewind_at(struct node_db *ndb,
                                   const struct active_chain *chain, int cursor,
                                   const char *datadir)
{
    if (!ndb || !ndb->open || !chain || cursor < 0)
        return 0;
    int stale_h = fork_lowest_stale_row(ndb, chain, cursor);
    if (stale_h < 0)
        return 0;
    int fork_h = -1;
    bool deferred = false;
    bool ok = fork_rewind_below(ndb, chain, datadir, stale_h, &fork_h,
                                &deferred);
    if (deferred)
        return -1;  // raw-return-ok:fork_rewind_below logged the deferral
    LOG_WARN("catchup", "projection row at height %d is off the active "
             "chain (reorg); projection cursor %d -> %d %s", stale_h, cursor,
             fork_h, ok ? "rewound so the winner is re-indexed"
                        : "rewind FAILED");
    return ok ? 1 : 0;
}

bool node_db_catchup_service_rewind_stale_fork(struct node_db *ndb,
                                               const struct active_chain *chain,
                                               const char *datadir)
{
    int cursor = -1;
    if (!ndb || !ndb->open || !chain ||
        !node_db_sync_get_tip_height_checked(ndb, &cursor))
        return false;
    return node_db_catchup_fork_rewind_at(ndb, chain, cursor, datadir) > 0;
}
