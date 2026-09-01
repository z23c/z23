/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_block_prefetch — the PRODUCTION wiring for the block-body read-ahead
 * worker (engine/modules/storage/block_prefetch.c). The worker itself is decoupled: it
 * takes two callbacks (the fold's leading height + a height->disk-position
 * resolver) so it never touches main_state directly and stays unit-testable.
 * This file supplies the two production adapters and the start/stop calls that
 * boot_services.c / boot_services_shutdown.c invoke — exactly the
 * single-registration-call split the other boot_*.c composition-root helpers
 * use (boot_canary_watch.c, boot_utxo_parity.c, ...).
 *
 * cursor adapter: the fold's leading body-read height is body_fetch_stage_cursor()
 *   — the height whose body body_fetch is about to pull from disk. Warming
 *   [cursor+lead, cursor+lead+window) overlaps the next window's cold reads with
 *   the current batch's fold.
 * pos adapter: active_chain_at(height) -> block_index -> block_index_disk_pos_snapshot,
 *   the SAME lock-free active-chain window read + have-data check bg_validation /
 *   pv_lookahead already run ALONGSIDE the reducer drive (no added locking).
 *
 * Default OFF: only started when -prefetch-blocks was passed. FAIL-SAFE: a
 * failed start is logged and ignored — the fold reads bodies cold exactly as
 * today. */

#include "config/boot_internal.h"

#include "storage/block_prefetch.h"
#include "jobs/body_fetch_stage.h"        /* body_fetch_stage_cursor */
#include "validation/main_state.h"
#include "validation/chainstate.h"        /* active_chain_at */
#include "chain/chain.h"                  /* block_index_disk_pos_snapshot */
#include "util/log_macros.h"

#include <stddef.h>
#include <stdint.h>

/* main_state for the pos resolver, captured at start. Read-only from the worker
 * thread; active_chain_at is a lock-free window read. */
static struct main_state *g_bp_ms = NULL;

/* Leading fold height = the height body_fetch is about to read from disk. */
static bool boot_bp_cursor(void *user, int32_t *out_height)
{
    (void)user;
    if (!out_height)
        return false;
    uint64_t c = body_fetch_stage_cursor();
    if (c > (uint64_t)INT32_MAX)
        return false;
    *out_height = (int32_t)c;
    return true;
}

/* Resolve a height's on-disk block position via the active-chain window. */
static bool boot_bp_pos(void *user, int32_t height, struct disk_block_pos *out)
{
    struct main_state *ms = (struct main_state *)user;
    if (!ms || !out || height < 0)
        return false;
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi)
        return false;
    return block_index_disk_pos_snapshot(bi, out, NULL);
}

void boot_block_prefetch_start(const struct app_context *ctx,
                               struct main_state *ms)
{
    if (!ctx || !ctx->prefetch_blocks)
        return; /* lever OFF (default) — no worker, cold reads as today */
    if (!ms) {
        LOG_WARN("block_prefetch",
                 "[block_prefetch] -prefetch-blocks set but no main_state; "
                 "skipping (fold reads cold)");
        return;
    }

    g_bp_ms = ms;
    struct block_prefetch_config cfg;
    block_prefetch_config_default(&cfg);
    cfg.enabled = true; /* the flag is the master switch here */

    if (!block_prefetch_start(ctx->datadir, &cfg,
                              boot_bp_cursor, NULL,
                              boot_bp_pos, ms)) {
        LOG_WARN("block_prefetch",
                 "[block_prefetch] start failed — fold reads cold (fail-safe)");
        g_bp_ms = NULL;
        return;
    }
    LOG_INFO("block_prefetch",
             "[block_prefetch] -prefetch-blocks: read-ahead worker started");
}

void boot_block_prefetch_stop(void)
{
    block_prefetch_stop(); /* idempotent + safe without a prior start */
    g_bp_ms = NULL;
}
