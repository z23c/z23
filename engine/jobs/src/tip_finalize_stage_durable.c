/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_stage_durable — implementation. See
 * tip_finalize_stage_durable.h. */

#include "tip_finalize_stage_durable.h"

#include "jobs/tip_finalize_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_helpers.h"
#include "tip_finalize_log_store.h"
#include "tip_finalize_stage_observe.h"

#include "chain/chain.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "platform/time_compat.h"

#include <stdint.h>
#include <string.h>

#define STAGE_NAME "tip_finalize"

static bool publish_resolved_durable_tip(sqlite3 *db, const char *reason)
{
    int h = -1;
    uint8_t hash[32];
    if (!tip_finalize_stage_resolve_durable_tip(db, &h, hash))
        return false; // raw-return-ok:durable-tip-absent
    tip_finalize_observe_update_last_advance(h, hash);
    LOG_INFO("tip_finalize",
             "[tip_finalize] authority publish durable h=%d reason=%s",
             h, reason ? reason : "");
    return true;
}

static bool has_no_durable_tip_history(sqlite3 *db)
{
    uint64_t cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME, &cursor))
        LOG_FAIL("tip_finalize", "durable history cursor read failed");
    return cursor == 0 &&
           stage_log_row_count(db, STAGE_NAME, "tip_finalize_log") <= 0;
}

static bool fresh_tip_coin_frontier_allows(sqlite3 *db,
                                           const struct block_index *tip,
                                           const char *reason)
{
    if (!db || !tip || tip->nHeight < 0)
        return true;
    int32_t applied = -1;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] fresh authority coin-frontier read failed "
                 "h=%d reason=%s",
                 tip->nHeight, reason ? reason : "");
        return false;
    }
    if (!found)
        return true;  /* legacy/pre-coins-kv datadir: do not change behavior */
    if (applied > tip->nHeight)
        return true;
    LOG_WARN("tip_finalize",
             "[tip_finalize] fresh authority publish skipped h=%d "
             "coins_applied_height=%d reason=%s (finalized>coins)",
             tip->nHeight, applied, reason ? reason : "");
    return false;
}

bool tip_finalize_stage_hydrate_cursor_from_store(sqlite3 *db,
                                                  stage_t *stage,
                                                  const char *reason)
{
    if (!stage)
        return true;
    uint64_t cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME, &cursor))
        LOG_FAIL("tip_finalize", "cursor hydrate read failed");

    /* CROSS-TXN REORG-REWIND CRASH-WINDOW CLAMP (uv_cursor_gap cure).
     *
     * step_finalize enforces tip_finalize_cursor <= utxo_apply_cursor FORWARD
     * (tip_finalize_stage.c: `if (next_h > uv_cursor) note_cursor_gap; IDLE`)
     * but that invariant can be VIOLATED on disk across a crash: the reorg
     * unwind commits {utxo_apply cursor rewind + coins inverse-delta + log
     * deletes + frontier} in ONE txn (utxo_apply_delta_reorg.c ~:492-507),
     * while tip_finalize's OWN cursor is rewound in a SEPARATE, LATER txn at
     * the top of its next step (rewind_cursor_if_active_chain_reorged ->
     * stage_set_cursor in tip_finalize_stage.c). A kill-9 landing between those
     * two durable commits persists tip_finalize_cursor > utxo_apply_cursor —
     * the exact "durably-committed window where cursors disagree BY DESIGN"
     * documented in invariant_sentinel.c (~:434). The live sweep tolerates it
     * via two-sweep confirmation; a crash+respawn does NOT get a second live
     * sweep — it reboots straight into the persisted inversion and step_finalize
     * then wedges forever on the tip_finalize.uv_cursor_gap blocker ("its own
     * cursor is ahead of its upstream, which the pipeline order should make
     * unreachable").
     *
     * Restore the invariant on open by lowering ONLY the tip_finalize CURSOR to
     * the durable utxo_apply cursor. This is always safe (the invariant is
     * tip_finalize <= utxo_apply, so a legitimate state never satisfies the
     * clamp condition) and NEVER touches a tip_finalize_log row (served-floor
     * invariant): the surviving ok=1 rows re-finalize forward (log_insert is
     * INSERT OR REPLACE) as utxo_apply re-folds past them — slower, never
     * wrong. Read utxo_apply's DURABLE cursor (the same stage_cursor row the
     * gate reads); a decrease bypasses the LCC raise guard in stage_set_cursor. */
    uint64_t uv_cursor = 0;
    if (!stage_cursor_read_or_zero(db, "utxo_apply", STAGE_NAME, &uv_cursor))
        LOG_FAIL("tip_finalize", "cursor hydrate: utxo_apply read failed");
    if (cursor > uv_cursor) {
        static struct log_throttle clamp_throttle = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&clamp_throttle,
                (uint64_t)cursor ^ ((uint64_t)uv_cursor << 20),
                platform_time_wall_unix(), 60, &reps))
            LOG_WARN("tip_finalize",
                     "[tip_finalize] cursor clamp on open: durable "
                     "tip_finalize cursor=%llu exceeds upstream utxo_apply "
                     "cursor=%llu — clamping the tip_finalize CURSOR DOWN to the "
                     "upstream frontier (cross-txn reorg-rewind crash window; "
                     "tip_finalize_log rows preserved, re-finalize forward) "
                     "reason=%s repeated=%llu",
                     (unsigned long long)cursor, (unsigned long long)uv_cursor,
                     reason ? reason : "", (unsigned long long)reps);
        cursor = uv_cursor;
    }

    if (!stage_set_cursor(stage, db, cursor)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] cursor hydrate failed cursor=%llu reason=%s",
                 (unsigned long long)cursor, reason ? reason : "");
        return false;
    }
    return true;
}

static bool publish_resolved_or_fresh_tip(
    sqlite3 *db, const struct block_index *existing_tip, const char *reason)
{
    if (publish_resolved_durable_tip(db, reason))
        return true;
    if (existing_tip && existing_tip->phashBlock &&
        has_no_durable_tip_history(db) &&
        fresh_tip_coin_frontier_allows(db, existing_tip, reason)) {
        tip_finalize_observe_update_last_advance(
            existing_tip->nHeight, existing_tip->phashBlock->data);
        LOG_INFO("tip_finalize",
                 "[tip_finalize] authority publish fresh h=%d reason=%s",
                 existing_tip->nHeight, reason ? reason : "");
        return true;
    }
    return false;
}

void tip_finalize_stage_publish_resolved_or_fresh_tip(
    sqlite3 *db, const struct block_index *existing_tip, const char *reason)
{
    (void)publish_resolved_or_fresh_tip(db, existing_tip, reason);
}

void tip_finalize_stage_warm_authority_caches(
    sqlite3 *db, const struct block_index *existing_tip, const char *reason)
{
    /* A published provable tip means a live boot already warmed/advanced —
     * republishing the (possibly older) durable pair over the newer runtime
     * authority would be a regression, not a warm. The terminal verb this
     * exists for always calls pre-services with nothing published. Mirrors
     * tf_warm_provable_tip_once (static to the stage TU) over the same
     * public primitives. */
    if (!db || reducer_frontier_provable_tip_is_published())
        return;
    bool authority_published =
        publish_resolved_or_fresh_tip(db, existing_tip, reason);
    progress_store_tx_lock();
    if (!reducer_frontier_provable_tip_is_published()) {
        int32_t hs = 0, sf = 0;
        if (reducer_frontier_compute_hstar(db, &hs, &sf)) {
            reducer_frontier_provable_tip_set(hs);
            LOG_INFO("tip_finalize",
                     "[tip_finalize] provable-tip cache warmed h=%d reason=%s",
                     reducer_frontier_provable_tip_cached(),
                     reason ? reason : "");
        } else if (authority_published && existing_tip &&
                   existing_tip->nHeight == 0) {
            /* A fresh datadir reaches this boot-order seam before reducer stage
             * tables exist, so compute_hstar cannot derive a durable frontier.
             * The runtime authority pair above nevertheless owns the compiled
             * genesis block. Publish exactly H*=0 so the chain-binding service
             * can apply its already-fail-closed clean-genesis admission; never
             * synthesize a positive frontier here. */
            reducer_frontier_provable_tip_set(0);
            LOG_INFO("tip_finalize",
                     "[tip_finalize] provable-tip cache warmed from clean "
                     "genesis runtime authority h=0 reason=%s",
                     reason ? reason : "");
        } else {
            LOG_WARN("tip_finalize",
                     "[tip_finalize] verb warm: compute_hstar failed "
                     "(cache holds prior H*)");
        }
    }
    progress_store_tx_unlock();
}

bool tip_finalize_stage_finalized_tip_at(sqlite3 *db, int height,
                                         uint8_t out_hash[32])
{
    if (!db || !out_hash || height < 0)
        return false;
    progress_store_tx_lock();
    struct finalized_tip_row row;
    if (!finalized_tip_row_at(db, height, &row)) {
        progress_store_tx_unlock();
        return false;
    }
    if (!row.found || !row.ok || !row.has_tip_hash) {
        progress_store_tx_unlock();
        return false;
    }
    memcpy(out_hash, row.tip_hash.data, 32);
    progress_store_tx_unlock();
    return true;
}

bool tip_finalize_stage_block_hash_at(sqlite3 *db, int height,
                                      uint8_t out_hash[32])
{
    if (!db || !out_hash || height < 0)
        return false;
    progress_store_tx_lock();

    /* FINALIZED convention (step_finalize): the ok=1 row at height-1 binds
     * the LOOKAHEAD new_tip = active_chain_at(height), so its tip_hash IS
     * this height's own hash. An anchor row at height-1 carries hash(height-1)
     * (the seed's own hash) and must be skipped here — exactly the
     * finalized_row_active_match discrimination. */
    if (height > 0) {
        struct finalized_tip_row prev;
        if (finalized_tip_row_at(db, height - 1, &prev) &&
            prev.found && prev.ok && prev.has_tip_hash && !prev.is_anchor) {
            memcpy(out_hash, prev.tip_hash.data, 32);
            progress_store_tx_unlock();
            return true;
        }
    }

    /* ANCHOR convention (tip_finalize_stage_seed_anchor): a seed row at height
     * carries the block's OWN hash. A finalized row at height carries
     * hash(height+1) — the successor's hash — and must NOT be returned as this
     * height's hash (an inconsistent authority pair). */
    struct finalized_tip_row own;
    if (finalized_tip_row_at(db, height, &own) &&
        own.found && own.ok && own.has_tip_hash && own.is_anchor) {
        memcpy(out_hash, own.tip_hash.data, 32);
        progress_store_tx_unlock();
        return true;
    }

    progress_store_tx_unlock();
    return false;
}

bool tip_finalize_stage_resolve_durable_tip(sqlite3 *db, int *out_height,
                                            uint8_t out_hash[32])
{
    if (!db || !out_height || !out_hash)
        return false;
    uint64_t cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME, &cursor))
        LOG_FAIL("tip_finalize", "durable tip cursor read failed");
    if (cursor == 0)
        return false;
    /* Try cursor (anchor-at-cursor steady state), then cursor-1 (legacy +1
     * lattice / finalized-row convention). block_hash_at discriminates the row
     * types, so whichever height resolves owns the returned hash. */
    for (int back = 0; back <= 1; back++) {
        int h = (int)cursor - back;
        if (h < 0)
            break;
        if (tip_finalize_stage_block_hash_at(db, h, out_hash)) {
            *out_height = h;
            return true;
        }
    }
    return false;
}
