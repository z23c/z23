/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Post-load block-index derivation: recompute every pointer-graph
 * field, then publish the header frontier. Shared by the flat loader, the
 * LevelDB loader, and the event-log projection rebuild (E1 file-size split
 * out of block_index_loader.c); both entry points are declared in
 * services/block_index_loader.h. */

#include "services/block_index_loader.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "util/log_macros.h"

#include <stddef.h>

/* Forward pass over a height-sorted block_index array: recompute nChainWork,
 * nChainTx, skip links, cached branch id, and failed-child propagation from
 * each entry's already-linked pprev. Shared by the legacy LevelDB loader and
 * the event-log projection rebuild so both compute pointer-graph-derived
 * fields through one helper. Declared in services/block_index_loader.h. */
void block_index_forward_pass(struct block_index **sorted,
                              size_t count)
{
    for (size_t i = 0; i < count; i++) {
        struct block_index *pindex = sorted[i];

        struct arith_uint256 proof = GetBlockProof(pindex);
        if (pindex->pprev)
            arith_uint256_add(&pindex->nChainWork,
                              &pindex->pprev->nChainWork, &proof);
        else
            pindex->nChainWork = proof;

        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx)
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                else
                    pindex->nChainTx = 0;
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }

        block_index_build_skip(pindex);

        if (pindex->pprev) {
            if (block_index_is_valid(pindex, BLOCK_VALID_CONSENSUS) &&
                !pindex->nCachedBranchId)
                pindex->nCachedBranchId = pindex->pprev->nCachedBranchId;
        }

        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev &&
            (pindex->pprev->nStatus & BLOCK_FAILED_MASK))
            pindex->nStatus |= BLOCK_FAILED_CHILD;
    }
}

/* After the map is loaded and the forward pass has recomputed nChainWork,
 * make the header frontier REAL: publish the max-chainwork header into
 * pindex_best_header and seat it in the active_chain[] window.
 *
 * THE LINCHPIN. On a full-index boot (`--importblockindex` then a normal
 * boot) load_block_index fills the header MAP but the empty-datadir fallback
 * is the ONLY path that ever set pindex_best_header or the active_chain
 * window. So active_chain_tip() stays NULL over a map of millions of headers,
 * push_getheaders falls to a genesis-only locator, and header sync pins near
 * genesis with nothing to escalate it. Promoting the best header here anchors
 * the getheaders locator at the true frontier so block bodies can be fetched
 * and folded forward.
 *
 * This changes ONLY which header the chain/locator anchors at — never
 * consensus validity, coins, or H*. active_chain_height()/tip() defer to the
 * reducer authority once tip_finalize registers it, and getblockcount/health
 * read H* (the committed reducer prefix), so a served tip seated above coins
 * is the designed recovered-datadir state (see tip_finalize_stage_init), not a
 * false "synced" claim. Idempotent (work-ranked promotion never downgrades)
 * and safe: a later coins-reconcile (bii_anchor) only restores the tip UP to
 * the coins height, never below this frontier. */
void promote_best_header_after_load(struct main_state *ms,
                                    struct block_index **sorted,
                                    size_t count)
{
    if (!ms || !sorted || count == 0)
        return;

    struct block_index *best = NULL;
    for (size_t i = 0; i < count; i++) {
        struct block_index *pi = sorted[i];
        if (!pi || !pi->phashBlock)
            continue;
        if (pi->nStatus & BLOCK_FAILED_MASK)
            continue;
        if (!best) {
            best = pi;
            continue;
        }
        bool have_work = !arith_uint256_is_zero(&pi->nChainWork) &&
                         !arith_uint256_is_zero(&best->nChainWork);
        bool better = have_work
            ? arith_uint256_compare(&pi->nChainWork, &best->nChainWork) > 0
            : pi->nHeight > best->nHeight;
        if (better)
            best = pi;
    }
    if (!best)
        return;

    /* (1) Publish the header frontier through the work-ranked CSR seam — the
     * same primitive header_admit_stage uses on the live path. Idempotent:
     * a strictly-better candidate wins, otherwise this is a no-op. */
    bool promoted = false;
    enum csr_result prc = csr_promote_header_tip(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header, best,
        "loader_best_header", &promoted);
    if (prc != CSR_OK) {
#ifdef ZCL_TESTING
        /* Isolated fixtures do not boot the process-wide CSR — mirror
         * header_admit_stage's test-only fallback so the frontier is still
         * published. */
        if (prc == CSR_REJECTED_NOT_INITIALIZED) {
            struct block_index *current = ms->pindex_best_header;
            bool advance = current == NULL;
            if (current && current != best) {
                bool have_work =
                    !arith_uint256_is_zero(&best->nChainWork) &&
                    !arith_uint256_is_zero(&current->nChainWork);
                advance = have_work
                    ? arith_uint256_compare(&best->nChainWork,
                                            &current->nChainWork) > 0
                    : best->nHeight > current->nHeight;
            }
            if (advance)
                ms->pindex_best_header = best;
        } else
#endif
        LOG_WARN("block_index",
                 "loader: best-header promotion rejected code=%s h=%d",
                 csr_result_name(prc), best->nHeight);
    }

    /* (2) Seat the frontier in the active_chain[] window so active_chain_tip()
     * is non-NULL over a non-empty map. Only advance — never downgrade a
     * higher window a prior step may have installed. chain_set_active_tip
     * publishes the served-tip authority + events; a NULL/OOM refusal is
     * non-fatal (pindex_best_header still carries the frontier and the
     * NULL-tip locator anchors there). */
    struct block_index *cur = active_chain_cached_tip(&ms->chain_active);
    if (!cur || best->nHeight > cur->nHeight) {
        struct zcl_result r = chain_set_active_tip(ms, best,
                                                   TIP_FROM_P2P_REPAIR,
                                                   "loader_best_header");
        if (!r.ok)
            LOG_WARN("block_index",
                     "loader: best-header window seat failed h=%d: %s",
                     best->nHeight, r.message);
    }
}
