/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Pure boot-heuristic predicate for the automatic zclassicd-LevelDB
 * header pull (engine/composition/src/boot.c app_init, the need_zcd decision). Split out
 * of boot.c to keep boot.c smaller — this file is the "seam" the E1
 * file-size policy (tools/file_size_policy.c) asks for. */

#include "config/boot.h"

#include "models/block.h"              /* db_block_max_height */
#include "services/block_index_loader.h" /* load_block_index_from_blocks_table */
#include "validation/main_state.h"     /* struct main_state, map_block_index */
#include "util/log_macros.h"

#include <stdint.h>

/* Decide whether boot should auto-pull zclassicd's LevelDB block index.
 * Two independent triggers, either fires it (both require a legacy source
 * to actually be present — callers stat() it and pass the result in):
 *   1. RATIO: local_index_size has fewer than 90% of the expected chain
 *      height's entries — e.g. after a UTXO-snapshot sync our own index
 *      has only a handful of entries with scrambled heights.
 *   2. EMPTY DATADIR: local_index_size == 0. On a genuinely fresh/empty
 *      datadir chain_h is ALSO 0 (nothing to estimate it from yet), so
 *      the ratio test degenerates to `0 < 0` — always false — and would
 *      never fire without this explicit case. Without it a fresh node
 *      silently falls back to a slow P2P header crawl instead of the
 *      ~60-second legacy import. Invariant: local==0 with a legacy
 *      source present must ALWAYS trigger the pull. */
bool boot_need_legacy_header_pull(int64_t local_index_size, int64_t chain_h,
                                  bool legacy_source_present)
{
    if (!legacy_source_present)
        return false;
    if (local_index_size <= 0)
        return true;
    return local_index_size < chain_h * 9 / 10;
}

/* Decide whether boot should bulk-hydrate the in-memory block index from
 * the node.db `blocks` table (the --importblockindex CLI's sink). Same
 * ratio+empty shape as boot_need_legacy_header_pull above, but keyed off
 * the blocks table's row count instead of a legacy-source stat(): a small
 * (possibly stale) map must never permanently block this rung just because
 * an earlier loader rung happened to report "loaded" — see the header
 * comment in config/boot.h for the exact defect this closes. */
bool boot_need_blocks_table_hydrate(int64_t map_size, int64_t blocks_table_rows)
{
    if (blocks_table_rows <= 0)
        return false;
    if (map_size <= 1)
        return true;
    return map_size < blocks_table_rows * 9 / 10;
}

/* Dispatch wrapper for the boot.c blocks-table-hydrate rung (kept out of
 * boot.c for the E1 file-size ceiling): evaluates
 * boot_need_blocks_table_hydrate against the LIVE node.db + in-memory map,
 * logs the row counts + chosen path at INFO — no silent path choice — and
 * runs the hydrate when
 * it fires. Returns true iff the hydrate ran AND succeeded, so the caller
 * can fold the result straight into its own `loaded` flag. no-ops (false)
 * on a closed/NULL db or NULL main_state. */
bool boot_dispatch_blocks_table_hydrate(struct node_db *ndb, struct main_state *ms)
{
    if (!ndb || !ndb->open || !ms)
        return false;

    int64_t blocks_rows = db_block_max_height(ndb);
    bool want = boot_need_blocks_table_hydrate(
        (int64_t)ms->map_block_index.size, blocks_rows);
    LOG_INFO("block_index",
             "blocks-table hydrate dispatch: map_size=%zu "
             "blocks_table_rows=%lld -> %s",
             ms->map_block_index.size, (long long)blocks_rows,
             want ? "bulk hydrate (deterministic)"
                  : "skip (map already covers blocks table)");
    if (!want)
        return false;
    return load_block_index_from_blocks_table(ndb, ms).ok;
}
