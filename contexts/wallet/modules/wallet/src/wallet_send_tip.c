/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The height a wallet send builds against: the chain tip, never a stale scan
 * cursor. The wallet module cannot read the reducer, so boot registers the
 * authoritative tip source (the same pattern as the coin reservation probe). */

#include "wallet/wallet.h"

#include <stdio.h>

static wallet_chain_tip_source g_tip_source;
static void *g_tip_ctx;

void wallet_set_chain_tip_source(wallet_chain_tip_source source, void *ctx)
{
    /* Startup composition only: installed before RPC worker threads build
     * sends and left in place for the process lifetime. */
    g_tip_source = source;
    g_tip_ctx = ctx;
}

bool wallet_send_build_height(struct wallet *w, int *height_out,
                              const char **error)
{
    static _Thread_local char refusal[128];
    if (!w || !height_out || !error)
        return false;
    int tip = g_tip_source ? g_tip_source(g_tip_ctx) : 0;
    zcl_mutex_lock(&w->cs);
    int best = w->best_block_height;
    zcl_mutex_unlock(&w->cs);
    if (tip <= 0) {
        /* No authoritative tip (hermetic fixture or unpublished cache):
         * nothing to compare against, keep the wallet cursor. */
        *height_out = best;
        return true;
    }
    /* The lag is the wallet's height cursor against the tip, not
     * wallet_scanned_through_height(): a pending scan-gap marker (restore,
     * birthday change, unread boot range) lowers that and may never clear
     * (a wallet without a Sapling key keeps counting shielded outputs as
     * unscanned), which would refuse every send forever with a message that
     * waiting cannot fix. A gap marker is reported by readiness and the
     * rescan commands, and sends kept working with it before this guard. */
    if (best < tip) {
        int behind = tip - best;
        snprintf(refusal, sizeof(refusal),
                 "wallet is %d block%s behind chain tip (scanned %d, tip %d)",
                 behind, behind == 1 ? "" : "s", best, tip);
        *error = refusal;
        return false;
    }
    /* best >= tip: the wallet cursor has reached the node's published tip.
     * Build for the block after the cursor (the mempool validates the next
     * block; a cursor ahead of the tip is the active chain, a transient
     * one-block lead of the active chain over the published tip). */
    *height_out = best;
    return true;
}
