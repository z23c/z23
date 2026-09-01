/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Best-work chain-selection helpers for the reducer activation path. */

#include "platform/time_compat.h"
#include <stdio.h>

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "process_block_internal.h"
#include "util/log_macros.h"

/* add_to_block_index() lives in core/modules/validation/src/accept_block_header.c
 * with its sole caller so header admission owns the runtime in-memory
 * block_index producer. The declaration remains in
 * process_block_internal.h for validation-internal callers. */

struct block_index *find_most_work_chain(struct main_state *ms)
{
    if (!ms)
        return NULL;

    struct most_work_selection_stats stats;
    struct block_index *best = select_most_work_eligible(
            &ms->chain_active, &ms->map_block_index, &stats);

    if (stats.skipped_no_chaintx > 0 && !best) {
        LOG_WARN("chain_selection",
                 "find_most_work_chain: WARNING: %d blocks skipped "
                 "(no data, nChainTx==0)", stats.skipped_no_chaintx);
    }

    /* refuse to return a candidate BELOW the current tip.
     * The tip is canonical. A "fork tip" at a lower height with higher
     * nChainWork can appear from old import data with incorrect work
     * accounting, but reorging backwards 17 k blocks because of it is
     * never the right answer — the staged activation path would hit the
     * finality guard, log "below_finality_depth" every second, and the chain
     * would never advance. Treat below-tip best as "no work pending" and let
     * gap-fill close the headers-vs-bodies window. */
    if (stats.refused_below_tip) {
        static time_t g_last_stale_log = 0;
        time_t now_log = platform_time_wall_time_t();
        if (now_log - g_last_stale_log >= 60) {
            g_last_stale_log = now_log;
            LOG_INFO("chain_selection",
                     "find_most_work_chain: ignoring stale fork tip "
                     "h=%d (tip h=%d, depth=%d) -- returning tip",
                     stats.refused_below_tip_height,
                     stats.refused_below_tip_tip_height,
                     stats.refused_below_tip_tip_height -
                     stats.refused_below_tip_height);
        }
    }

    /* Diagnostic: when chain selection keeps the current tip as best, emit a
     * rate-limited log line naming the filter counters. This is how the
     * canary identifies which shortlisted cause is keeping production stuck
     * without another investigative round-trip.
     *
     * also kick the gap-fill service so it requests the
     * missing bodies for headers above the tip. Without this kick,
     * gap_fill only wakes every GAPFILL_TICK_SECS=5s and the headers
     * gap closes slowly; an explicit kick from chain selection
     * accelerates convergence whenever activation runs. */
    {
        struct block_index *tip = active_chain_tip(&ms->chain_active);
        if (tip && best == tip) {
            int header_h = ms->pindex_best_header
                         ? ms->pindex_best_header->nHeight : 0;
            if (header_h > tip->nHeight + 1) {
                process_block_kick_gap_fill();
            }
            if (header_h > tip->nHeight + 100) {
                static time_t g_last_stuck_log = 0;
                time_t now_log = platform_time_wall_time_t();
                if (now_log - g_last_stuck_log >= 60) {
                    g_last_stuck_log = now_log;
                    LOG_WARN("chain_selection",
                             "find_most_work_chain: STUCK at tip h=%d "
                             "(best_header h=%d, gap=%d) "
                             "skipped[failed=%d invalid=%d no_data=%d]",
                             tip->nHeight, header_h,
                             header_h - tip->nHeight,
                             stats.skipped_failed, stats.skipped_invalid,
                             stats.skipped_no_chaintx);
                }
            }
        }
    }

    return best;
}

/* Header acceptance moved to core/modules/validation/src/accept_block_header.c. The
 * reducer (reducer_ingest_block / reducer_kick, app/services + app/jobs) is
 * the sole block-connect engine; every ingest call site routes through it.
 * Selection helpers remain here. Active-tip child disk verification lives in
 * process_block_tip_child.c, tip publication lives in
 * process_block_tip_publish.c, contextual-header skip policy lives in
 * process_block_contextual_header.c, block-index hydration lives in
 * process_block_index.c, and failed-child propagation lives in
 * process_block_failed_child.c. */
