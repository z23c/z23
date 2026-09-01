/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * main_state_best_known_successor — "the next block to serve after
 * `parent`" for getheaders/getblocks serving and tip-successor probes.
 *
 * History: both core/modules/net/src/msg_headers.c and msg_blocks.c carried a
 * private copy of this as a FULL SCAN of map_block_index per call
 * (block_map_next takes the map rwlock once per visited bucket). At a
 * live tip the map holds ~3.1M entries and the serving loops call this
 * up to ~2x2000 times per getheaders message, so one hostile locator
 * pointed near genesis cost billions of lock-guarded bucket visits —
 * a remote CPU-burn that also contends the map lock against block
 * intake (an externally-induced tip stall). This shared version makes
 * the served paths cheap and leaves the scan only for genuinely
 * off-path branch points, which an attacker cannot reference without
 * first planting real PoW headers in our index.
 */

#include "validation/main_state.h"
#include "chain/chain.h"

static bool successor_same_block(const struct block_index *a,
                                 const struct block_index *b)
{
    return a && b && a->nHeight == b->nHeight && a->phashBlock &&
           b->phashBlock && uint256_eq(a->phashBlock, b->phashBlock);
}

static bool successor_failed_by_hash(struct main_state *ms,
                                     const struct block_index *bi)
{
    if (!ms || !bi || block_has_any_failure(bi))
        return true;
    struct block_index *owner = bi->phashBlock
        ? block_map_find(&ms->map_block_index, bi->phashBlock) : NULL;
    return owner && owner->nHeight == bi->nHeight &&
           block_has_any_failure(owner);
}

struct block_index *main_state_best_known_successor(struct main_state *ms,
                                                    struct block_index *parent)
{
    if (!ms || !parent || !parent->phashBlock)
        return NULL;

    /* O(1): parent sits on the active chain below the tip — the
     * successor is the next window slot. This is every hop of a normal
     * serve. (A connected active-chain child always has data, matching
     * the old scan's equal-work HAVE_DATA tiebreak.) */
    struct block_index *active_parent =
        active_chain_at(&ms->chain_active, parent->nHeight);
    if (successor_same_block(active_parent, parent)) {
        struct block_index *next =
            active_chain_at(&ms->chain_active, parent->nHeight + 1);
        if (next && !successor_failed_by_hash(ms, next))
            return next;
        /* parent is the active tip (or the slot is unusable): try the
         * header-only zone above the validated tip. */
    }

    /* O(log n): parent lies on the best-header path — serve along it.
     * Covers announcing/serving headers above the validated tip while
     * bodies are still downloading, without touching the map scan. */
    struct block_index *bh = ms->pindex_best_header;
    if (bh && bh->nHeight > parent->nHeight) {
        struct block_index *anc =
            block_index_get_ancestor(bh, parent->nHeight);
        if (successor_same_block(anc, parent)) {
            struct block_index *next =
                block_index_get_ancestor(bh, parent->nHeight + 1);
            if (next && !successor_failed_by_hash(ms, next))
                return next;
        }
    }

    /* Slow path: parent is a genuinely off-path branch point (stale
     * fork). Full map scan for its best non-failed child — acceptable
     * here because stale branches are short and planting one costs the
     * requester real proof-of-work. */
    struct block_index *best = NULL;
    size_t iter = 0;
    struct block_index *candidate = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &candidate)) {
        if (!candidate || !candidate->phashBlock || !candidate->pprev)
            continue;
        if (!successor_same_block(candidate->pprev, parent))
            continue;
        if (candidate->nHeight != parent->nHeight + 1)
            continue;
        if (successor_failed_by_hash(ms, candidate))
            continue;
        if (!best ||
            arith_uint256_compare(&candidate->nChainWork,
                                  &best->nChainWork) > 0 ||
            (arith_uint256_compare(&candidate->nChainWork,
                                   &best->nChainWork) == 0 &&
             (candidate->nStatus & BLOCK_HAVE_DATA) &&
             !(best->nStatus & BLOCK_HAVE_DATA))) {
            best = candidate;
        }
    }
    return best;
}
