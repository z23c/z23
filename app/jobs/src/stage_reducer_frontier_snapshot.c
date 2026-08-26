/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Read the reducer-frontier snapshot. Observation only — every
 * function here reads the progress store and the block files and reports what
 * it saw into the caller's result struct. Nothing here mutates a cursor, a
 * row, a coin, or a block index entry; the repairs that act on this snapshot
 * live in stage_repair_reducer_frontier.c and its sibling TUs. */

#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "stage_repair_reducer_frontier_internal.h"

#include "jobs/reducer_frontier.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include <stdint.h>

bool stage_reducer_frontier_block_pos_readable_hash(
    const struct block_index *bi, const char *datadir)
{
    if (!bi || !bi->phashBlock || !datadir || bi->nFile < 0)
        return false;

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    pos.nFile = bi->nFile;
    pos.nPos = bi->nDataPos;

    struct block blk;
    block_init(&blk);
    bool ok = read_block_from_disk_pread(&blk, &pos, datadir);
    if (ok) {
        struct uint256 got;
        block_get_hash(&blk, &got);
        ok = uint256_cmp(&got, bi->phashBlock) == 0;
    }
    block_free(&blk);
    return ok;
}

bool stage_reducer_frontier_read_snapshot(
    sqlite3 *db, struct stage_reducer_frontier_reconcile_result *out)
{
    progress_store_tx_lock();

    int32_t hstar = 0;
    int32_t served_floor = 0;
    if (!reducer_frontier_compute_hstar(db, &hstar, &served_floor)) {
        progress_store_tx_unlock();
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier_compute_hstar failed");
        return false;
    }

    int32_t coins_applied = 0;
    bool coins_found = false;
    if (!coins_kv_get_applied_height(db, &coins_applied, &coins_found)) {
        progress_store_tx_unlock();
        LOG_WARN("stage_repair",
                 "[stage_repair] coins_applied_height read failed");
        return false;
    }

    /* utxo_apply's OWN contiguous applied frontier — the coin-tear test
     * compares coins_applied against THIS, never the tip_finalize-pinned global
     * MIN H*. coins_applied tracks the utxo_apply cursor by construction
     * (co-committed in one BEGIN IMMEDIATE), so a real tear is coins applied
     * above utxo_apply's own ok=1 prefix; coins legitimately leading the
     * slower-to-finalize H* is pipeline depth, not a tear. Read under the lock
     * already held; reducer_frontier_log_frontier re-takes the recursive lock
     * safely. */
    int32_t utxo_apply_contig = hstar;
    if (!reducer_frontier_log_frontier(db, "utxo_apply_log", "utxo_apply",
                                       &utxo_apply_contig)) {
        progress_store_tx_unlock();
        LOG_WARN("stage_repair",
                 "[stage_repair] utxo_apply frontier read failed");
        return false;
    }

    /* One read per stage cursor: the named indices below feed the result
     * fields, every cursor feeds sweep_top. */
    static const char *const stages[] = {
        "validate_headers", /* [0] */
        "body_fetch",       /* [1] */
        "body_persist",     /* [2] */
        "script_validate",
        "proof_validate",
        "utxo_apply",
        "tip_finalize",     /* [6] */
    };
    int cursors[sizeof(stages) / sizeof(stages[0])];
    int sweep_top = served_floor;
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        cursors[i] = -1;
        if (!stage_repair_cursor_at_unlocked(db, stages[i], &cursors[i])) {
            progress_store_tx_unlock();
            return false;
        }
        if (cursors[i] > 0 && cursors[i] - 1 > sweep_top)
            sweep_top = cursors[i] - 1;
    }

    progress_store_tx_unlock();

    out->hstar = hstar;
    out->served_floor = served_floor;
    out->validate_headers_cursor_before = cursors[0];
    out->validate_headers_cursor_after = cursors[0];
    out->body_fetch_cursor_before = cursors[1];
    out->body_fetch_cursor_after = cursors[1];
    out->body_persist_cursor_before = cursors[2];
    out->body_persist_cursor_after = cursors[2];
    out->tip_finalize_cursor_before = cursors[6];
    out->tip_finalize_cursor_after = cursors[6];
    out->sweep_top = sweep_top;
    out->lowest_have_data_cleared = -1;
    out->lowest_validate_headers_refill_hole = -1;
    out->lowest_validate_headers_hash_split = -1;
    out->lowest_body_fetch_refill_hole = -1;
    out->lowest_body_persist_refill_hole = -1;
    out->lowest_script_validate_refill_hole = -1;
    out->lowest_proof_validate_refill_hole = -1;
    out->script_validate_cursor_before = -1;
    out->script_validate_cursor_after = -1;
    out->proof_validate_cursor_before = -1;
    out->proof_validate_cursor_after = -1;
    out->tipfin_backfill_height = -1;
    out->coins_applied_found = coins_found;
    out->coins_applied_height = coins_found ? coins_applied : -1;
    if (!coins_found)
        out->refused_coin_unknown = true;
    else if (coins_applied > utxo_apply_contig + 1)
        out->refused_coin_tear = true;
    return true;
}
