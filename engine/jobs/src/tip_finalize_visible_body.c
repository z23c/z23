/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Reconcile a body that arrives after its header advanced tip_finalize. */

#include "tip_finalize_visible_body.h"

#include "jobs/tip_finalize_stage.h"
#include "tip_finalize_batch_drain.h"
#include "tip_finalize_log_store.h"
#include "tip_finalize_post_step.h"
#include "tip_finalize_stage_observe.h"

#include "chain/chain.h"
#include "platform/time_compat.h"
#include "support/log_throttle.h"
#include "util/log_macros.h"
#include "util/stage.h"
#include "validation/main_state.h"

#include <limits.h>
#include <stdint.h>

static int32_t g_last_mempool_reconcile_height = -1;
static struct uint256 g_last_mempool_reconcile_hash;

const char *tip_finalize_precondition_block_reason(
    const struct block_index *bi)
{
    if (!bi) return "block_missing";
    if (block_has_any_failure(bi)) return "block_failed";
    if (!(bi->nStatus & BLOCK_HAVE_DATA)) return "have_data_missing";
    if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS)
        return "not_script_valid";
    if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_HEADER)
        return "not_header_valid";
    return NULL;
}

void tip_finalize_visible_body_reset(void)
{
    g_last_mempool_reconcile_height = -1;
    uint256_set_null(&g_last_mempool_reconcile_hash);
}

/* A header-only lookahead can advance the cursor before the successor body
 * arrives. Reconcile the newly visible body once per process identity. If
 * served-tip authority still trails it, finish publication; otherwise run
 * the idempotent wallet plus mempool/cache subsets through one body view.
 * Returns whether any reconciliation work ran so the caller can account its
 * cost outside stage_run_once(). */
bool tip_finalize_reconcile_visible_cursor_body(
    struct sqlite3 *db, struct stage *stage, struct main_state *ms)
{
    if (!db || !stage || !ms) return false;
    uint64_t cursor = stage_cursor(stage);
    if (cursor > INT32_MAX) return false;
    int32_t height = (int32_t)cursor;
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi && height > 0) {
        struct uint256 hash;
        if (tip_finalize_stage_block_hash_at(db, height - 1, hash.data))
            bi = block_map_find(&ms->map_block_index, &hash);
    }
    if (!bi || !bi->phashBlock || bi->nHeight != height ||
        tip_finalize_precondition_block_reason(bi) != NULL)
        return false;

    /* A header witness proves the parent, not this body's transition. */
    struct utxo_apply_row applied;
    if (utxo_apply_log_at(db, height, &applied) != 1 || applied.ok != 1)
        return false;
    if (g_last_mempool_reconcile_height == height &&
        uint256_eq(&g_last_mempool_reconcile_hash, bi->phashBlock))
        return false;

    /* Stamp before reading so a corrupt promised body warns once per boot. */
    g_last_mempool_reconcile_height = height;
    g_last_mempool_reconcile_hash = *bi->phashBlock;
    if (tip_finalize_observe_last_height() < height) {
        if (!tip_finalize_run_mempool_reconcile(bi)) return false;
        if (!tip_finalize_batch_window_move(ms, bi)) {
            /* A failed move is transient and remains eligible for retry. */
            tip_finalize_visible_body_reset();
            LOG_WARN("tip_finalize",
                     "[tip_finalize] visible-body window move failed h=%d",
                     height);
            return true;
        }
        tip_finalize_run_post_finalize(bi);
        tip_finalize_observe_update_last_advance(
            bi->nHeight, bi->phashBlock->data);
        LOG_INFO("tip_finalize",
                 "[tip_finalize] visible-body authority publish h=%d "
                 "cursor=%llu",
                 height, (unsigned long long)cursor);
        return true;
    }
    if (!tip_finalize_run_wallet_mempool_reconcile(bi)) {
        tip_finalize_visible_body_reset();
        return false;
    }
    /* This is normal for every body that arrives behind a header witness.
     * Logging each height turns a 3M-block sync into 3M formatted writes.
     * Preserve operator progress with a first/300 s keepalive and an exact
     * suppressed count. The reducer drive serializes this call; the shared
     * throttle is atomic regardless. */
    static struct log_throttle progress_log = LOG_THROTTLE_INIT;
    uint64_t repeated = 0;
    if (log_throttle_should_emit(&progress_log, 1,
                                 platform_time_wall_unix(), 300,
                                 &repeated))
        LOG_INFO("tip_finalize",
                 "[tip_finalize] visible-body wallet/mempool reconcile h=%d "
                 "cursor=%llu repeated=%llu",
                 height, (unsigned long long)cursor,
                 (unsigned long long)repeated);
    return true;
}
