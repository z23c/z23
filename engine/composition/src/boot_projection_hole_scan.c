/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: keep full projection-hole audits off the shared SQLite hot path. */

#include "config/boot_projection_hole_scan.h"

#include "controllers/sync_controller.h"
#include "chain/chain.h"
#include "models/block.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

/* Interior projection holes are a recovery audit, not a five-second hot-path
 * predicate. Scan once after startup, then hourly while healthy; a newly
 * frozen behind-tip cursor forces one immediate scan. */
#define PROJECTION_HOLE_SCAN_INTERVAL_SEC 3600
#define PROJECTION_HOLE_SCAN_RETRY_SEC      30

bool boot_projection_sparse_prefix_is_expected(int projection_tip,
                                               int chain_tip)
{
    if (projection_tip <= 0 || chain_tip < 0 || projection_tip > chain_tip)
        return false;
    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return false;
    int32_t applied = -1;
    progress_store_tx_lock();
    bool ok = coins_kv_is_proven_authority(pdb, &applied);
    progress_store_tx_unlock();
    return ok && applied > projection_tip;
}

void boot_projection_hole_scan_init(struct boot_projection_hole_scan *state)
{
    if (!state)
        return;
    state->last_stall_scanned_cursor = INT_MIN;
    state->next_scan_unix = 0;
}

static bool scan_first_missing_connected(struct node_db *canonical,
                                         int max_height, int *height_out)
{
    if (height_out)
        *height_out = -1;
    if (!canonical || !canonical->open || !canonical->path[0] ||
        !height_out) {
        LOG_ERROR("projection_backfill",
                  "hole scan refused: canonical database unavailable");
        return false;
    }

    return db_block_first_missing_connected_height(canonical, max_height,
                                                    height_out);
}

bool boot_projection_hole_scan_if_due(
    struct boot_projection_hole_scan *state,
    struct node_db *canonical,
    int max_height,
    bool sparse_prefix,
    bool behind,
    bool cursor_frozen,
    int projection_cursor,
    int64_t now_unix,
    bool *ran_out,
    int *missing_height_out)
{
    if (ran_out)
        *ran_out = false;
    if (missing_height_out)
        *missing_height_out = -1;
    if (!state || !ran_out || !missing_height_out) {
        LOG_ERROR("projection_backfill", "hole scan scheduler invalid args");
        return false;
    }

    bool stalled_due = cursor_frozen &&
                       projection_cursor != state->last_stall_scanned_cursor;
    bool periodic_due = now_unix >= state->next_scan_unix;
    if (max_height < 0 || sparse_prefix || (!periodic_due && !stalled_due))
        return true;

    *ran_out = true;
    bool ok = scan_first_missing_connected(canonical, max_height,
                                           missing_height_out);
    if (behind)
        state->last_stall_scanned_cursor = projection_cursor;
    state->next_scan_unix = now_unix +
        (ok ? PROJECTION_HOLE_SCAN_INTERVAL_SEC
            : PROJECTION_HOLE_SCAN_RETRY_SEC);

    /* A real hole keeps the historical rapid repair/recheck loop; the hourly
     * cadence resumes only after a scan proves the repaired prefix contiguous. */
    if (ok && *missing_height_out >= 0)
        state->next_scan_unix = 0;
    return ok;
}

/* Highest height the projection cursor may claim at boot: the active tip,
 * lowered to the highest connected row (one indexed MAX, O(1) because this
 * runs synchronously in boot) when rows end below the tip, so catchup refills
 * a range node.db lost (restored backup, crash). Stays at the tip when there
 * are no connected rows (body-less snapshot / imported history is sparse by
 * design) and when the height right above the top row has no stored body:
 * catchup could only record a lean hole there, and rewinding would replay to
 * the tip on every boot. Interior holes stay the background scan's job. */
static int finalize_target_height(struct node_db *ndb,
                                  const struct active_chain *chain,
                                  int chain_tip)
{
    int top = db_block_max_height(ndb);
    if (top < 0 || top >= chain_tip)
        return chain_tip;
    const struct block_index *next = active_chain_at(chain, top + 1);
    if (!next || !(next->nStatus & BLOCK_HAVE_DATA))
        return chain_tip;
    const struct block_index *slot = active_chain_at(chain, top);
    return (slot && slot->phashBlock) ? top : chain_tip;
}

bool boot_projection_finalize_cursor(struct node_db *ndb,
                                     const struct active_chain *chain,
                                     int *cursor_out)
{
    if (cursor_out)
        *cursor_out = -1;
    if (!ndb || !ndb->open || !chain)
        return false;
    int chain_tip = active_chain_height(chain);
    if (chain_tip < 0)
        return false;
    int target = finalize_target_height(ndb, chain, chain_tip);
    const struct block_index *slot = active_chain_at(chain, target);
    if (!slot || !slot->phashBlock) {
        LOG_ERROR("projection_backfill",
                  "finalize cursor refused: no active slot at %d", target);
        return false;
    }
    int previous = node_db_sync_get_tip_height(ndb);
    if (previous > target)
        LOG_WARN("projection_backfill",
                 "cursor %d is above the highest projected row (chain tip "
                 "%d); rewinding to %d so catchup fills %d..%d",
                 previous, chain_tip, target, target + 1, chain_tip);
    if (!node_db_sync_set_tip(ndb, slot->phashBlock->data, target)) {
        LOG_ERROR("projection_backfill",
                  "finalize cursor: set_tip failed at %d", target);
        return false;
    }
    if (cursor_out)
        *cursor_out = target;
    return true;
}
