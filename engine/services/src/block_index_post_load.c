/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Post-load block-index derivation: recompute every pointer-graph
 * field, then publish the header frontier. Shared by the flat loader, the
 * LevelDB loader, and the event-log projection rebuild (E1 file-size split
 * out of block_index_loader.c); both entry points are declared in
 * services/block_index_loader.h. */
// one-result-type-ok:sort-counting — pure ordering and predicate helpers, not a fallible service surface

#include "services/block_index_loader.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "services/island_anchor.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static bool block_index_counting_allowed(int32_t max, size_t n)
{
    return max >= 0 && max < INT32_MAX &&
           (uint64_t)max <= 4ull * n + 1024u && n <= UINT32_MAX;
}

#ifdef ZCL_TESTING
bool block_index_sort_counting_allowed_for_test(int32_t max_height, size_t count)
{
    return block_index_counting_allowed(max_height, count);
}
#endif

void block_index_sort_forward_pass_input(struct block_index **arr, size_t n)
{
    if (block_index_ptrs_height_sorted(arr, n))
        return;
    int32_t max = 0;
    bool dense = true;
    for (size_t i = 0; i < n; i++) {
        if (arr[i]->nHeight < 0) {
            dense = false;
            break;
        }
        if (arr[i]->nHeight > max)
            max = arr[i]->nHeight;
    }
    if (dense && block_index_counting_allowed(max, n)) {
        uint32_t *start = zcl_calloc((size_t)max + 2u, sizeof(*start),
                                     "flat save sort counts");
        struct block_index **out = zcl_malloc(n * sizeof(*out),
                                              "flat save sort");
        if (start && out) {
            for (size_t i = 0; i < n; i++) start[arr[i]->nHeight + 1]++;
            for (int32_t h = 0; h <= max; h++) start[h + 1] += start[h];
            for (size_t i = 0; i < n; i++) out[start[arr[i]->nHeight]++] = arr[i];
            memcpy(arr, out, n * sizeof(*out));
            free(start);
            free(out);
            return;
        }
        free(start);
        free(out);
    }
    qsort(arr, n, sizeof(*arr), block_index_ptr_cmp_height);
}

/* nChainWork from the parent's work plus this entry's proof; a parentless
 * entry gets its own proof, except the registered FlySync island root, which
 * keeps the work recorded in its durable fact (services/island_anchor.h).
 * Declared in services/block_index_loader.h. */
void block_index_set_chainwork(struct block_index *bi)
{
    struct arith_uint256 proof = GetBlockProof(bi);
    if (bi->pprev)
        arith_uint256_add(&bi->nChainWork, &bi->pprev->nChainWork, &proof);
    else if (!island_anchor_seed_root_work(bi))
        bi->nChainWork = proof;
}

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

        block_index_set_chainwork(pindex);

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

        /* An operator-invalidated root (kept by the loader) or a descendant
         * of one makes every derived CHILD mark below it operator-derived, so
         * the self-heal and repair paths leave the whole subtree alone. The
         * root's own persisted mark is the only authority; this is
         * re-derived on every load. */
        if (pindex->pprev && (pindex->pprev->nStatus & BLOCK_OPERATOR_INVALID) &&
            (pindex->nStatus & BLOCK_FAILED_MASK) == BLOCK_FAILED_CHILD)
            pindex->nStatus |= BLOCK_OPERATOR_INVALID;
    }
}

/* Work-then-height ranking used by every best-header choice below: compare
 * nChainWork when both entries carry chainwork, otherwise compare heights.
 * Pure comparison — no side effects, no logging. */
static bool header_ranks_above(struct block_index *cand,
                               struct block_index *ref)
{
    bool have_work = !arith_uint256_is_zero(&cand->nChainWork) &&
                     !arith_uint256_is_zero(&ref->nChainWork);
    return have_work
        ? arith_uint256_compare(&cand->nChainWork, &ref->nChainWork) > 0
        : cand->nHeight > ref->nHeight;
}

/* Scan a height-sorted block_index array for the strongest header eligible
 * to be published as the frontier: non-NULL with a block hash and not under
 * BLOCK_FAILED_MASK, ranked by header_ranks_above. Returns NULL when no
 * entry qualifies. */
static struct block_index *find_best_header_candidate(
    struct block_index **sorted, size_t count)
{
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
        if (header_ranks_above(pi, best))
            best = pi;
    }
    return best;
}

#ifdef ZCL_TESTING
/* Test-only CSR-less promotion mirroring header_admit_stage's fallback:
 * advance pindex_best_header to `best` only when no frontier is set yet or
 * `best` ranks above the current one. Never downgrades. */
static void promote_best_header_without_csr(struct main_state *ms,
                                            struct block_index *best)
{
    struct block_index *current = ms->pindex_best_header;
    bool advance = current == NULL;
    if (current && current != best)
        advance = header_ranks_above(best, current);
    if (advance)
        ms->pindex_best_header = best;
}
#endif

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

    struct block_index *best = find_best_header_candidate(sorted, count);
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
            promote_best_header_without_csr(ms, best);
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
