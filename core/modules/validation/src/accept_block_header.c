/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * accept_block_header — header-only acceptance into the block index. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "validation/process_block.h"
#include "validation/main_logic.h"
#include "validation/check_block.h"
#include "validation/chainstate.h"
#include "validation/accept_block_header.h"
#include "chain/pow.h"
#include "domain/consensus/header_accept.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "process_block_internal.h"

/* ── Lib-side wrappers around the pure DOMAIN header checks ──────
 *
 * These translate a domain `zcl_result` into a `validation_state` populated
 * with the consensus reject code, reason, and DoS score expected by the P2P
 * reject path.
 *
 * Each domain function writes the reason and DoS score into its
 * out-params; the wrapper forwards them through
 * validation_state_dos / validation_state_invalid using the same
 * reject_code (REJECT_INVALID vs REJECT_OBSOLETE) the legacy macro
 * used. The high-level accept_block_header() entry point further
 * down this file still calls the older check_block_header /
 * contextual_check_block_header functions (its scope is unchanged);
 * these wrappers are the seam future callers reach for.
 */

bool accept_block_header_check_version_too_low(
        const struct block_header *header,
        int32_t min_version,
        struct validation_state *state)
{
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX] = {0};
    int  dos = 0;
    struct zcl_result r =
        domain_consensus_check_header_version_too_low(
            header, min_version, reason, sizeof(reason), &dos);
    if (r.ok) return true;
    /* Legacy REJECT_IF: dos=100, corruption=false, code=REJECT_INVALID.
     * The domain returns dos=100 in `dos` on this rejection. */
    return validation_state_dos(state, dos, false, REJECT_INVALID,
                                reason, false, NULL);
}

bool accept_block_header_check_version_obsolete(
        const struct block_header *header,
        int32_t obsolete_below,
        struct validation_state *state)
{
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX] = {0};
    int  dos = 0;
    struct zcl_result r =
        domain_consensus_check_header_version_obsolete(
            header, obsolete_below, reason, sizeof(reason), &dos);
    if (r.ok) return true;
    /* Legacy REJECT_OBSOLETE_IF: dos=0, corruption=false,
     * code=REJECT_OBSOLETE. */
    return validation_state_invalid(state, false, REJECT_OBSOLETE,
                                    reason, NULL);
}

bool accept_block_header_check_timestamp_too_new(
        const struct block_header *header,
        int64_t now_upper_bound,
        struct validation_state *state)
{
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX] = {0};
    int  dos = 0;
    struct zcl_result r =
        domain_consensus_check_header_timestamp_too_new(
            header, now_upper_bound, reason, sizeof(reason), &dos);
    if (r.ok) return true;
    /* Legacy REJECT_INVALID_IF: dos=0, corruption=false,
     * code=REJECT_INVALID. */
    return validation_state_invalid(state, false, REJECT_INVALID,
                                    reason, NULL);
}

bool accept_block_header_check_timestamp_too_old(
        const struct block_header *header,
        int64_t prev_mtp,
        struct validation_state *state)
{
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX] = {0};
    int  dos = 0;
    struct zcl_result r =
        domain_consensus_check_header_timestamp_too_old(
            header, prev_mtp, reason, sizeof(reason), &dos);
    if (r.ok) return true;
    /* Legacy REJECT_INVALID_IF: dos=0, corruption=false,
     * code=REJECT_INVALID. */
    return validation_state_invalid(state, false, REJECT_INVALID,
                                    reason, NULL);
}

bool accept_block_header_check_equihash_solution_size(
        const struct block_header *header,
        size_t expected_solution_size,
        struct validation_state *state)
{
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX] = {0};
    int  dos = 0;
    struct zcl_result r =
        domain_consensus_check_header_equihash_solution_size(
            header, expected_solution_size,
            reason, sizeof(reason), &dos);
    if (r.ok) return true;
    /* Legacy REJECT_IF: dos=100, corruption=false,
     * code=REJECT_INVALID. */
    return validation_state_dos(state, dos, false, REJECT_INVALID,
                                reason, false, NULL);
}

bool accept_block_header_check_bits_match(
        const struct block_header *header,
        uint32_t expected_bits,
        struct validation_state *state)
{
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX] = {0};
    int  dos = 0;
    struct zcl_result r =
        domain_consensus_check_header_bits_match(
            header, expected_bits, reason, sizeof(reason), &dos);
    if (r.ok) return true;
    /* Legacy REJECT_IF: dos=100, corruption=false,
     * code=REJECT_INVALID. */
    return validation_state_dos(state, dos, false, REJECT_INVALID,
                                reason, false, NULL);
}

/* The reducer still needs one runtime in-memory block_index producer:
 * header scalars, pprev, and nChainWork via block_map_insert. Its only caller
 * is accept_block_header() below. Declaration stays in
 * process_block_internal.h. */
struct block_index *add_to_block_index(struct main_state *ms,
                                       const struct block_header *header)
{
    struct uint256 hash;
    block_header_get_hash(header, &hash);

    struct block_index *pindex = zcl_calloc(1, sizeof(struct block_index), "process_block_index");
    if (!pindex)
        return NULL;
    block_index_init(pindex);

    pindex->nVersion = header->nVersion;
    pindex->hashMerkleRoot = header->hashMerkleRoot;
    pindex->hashFinalSaplingRoot = header->hashFinalSaplingRoot;
    pindex->nTime = header->nTime;
    pindex->nBits = header->nBits;
    pindex->nNonce = header->nNonce;
    if (header->nSolutionSize > 0) {
        pindex->nSolution = zcl_malloc(header->nSolutionSize, "block_solution");
        if (pindex->nSolution)
            memcpy(pindex->nSolution, header->nSolution, header->nSolutionSize);
        pindex->nSolutionSize = pindex->nSolution ? header->nSolutionSize : 0;
    } else {
        pindex->nSolution = NULL;
        pindex->nSolutionSize = 0;
    }

    /* Option A: stable per-node hash storage, written before publishing
     * pindex into the map so concurrent lock-free locator builds never
     * deref a freed bucket. */
    pindex->hashBlock = hash;
    pindex->phashBlock = &pindex->hashBlock;

    if (!block_map_insert(&ms->map_block_index, &hash, pindex)) {
        free(pindex->nSolution);
        free(pindex);
        return block_map_find(&ms->map_block_index, &hash);
    }

    /* Link to previous block */
    struct block_index *pprev = block_map_find(&ms->map_block_index,
                                                &header->hashPrevBlock);
    if (pprev) {
        pindex->pprev = pprev;
        pindex->nHeight = pprev->nHeight + 1;
        block_index_build_skip(pindex);

        /* Chain work = prev + work for this block */
        struct arith_uint256 block_proof = GetBlockProof(pindex);
        arith_uint256_add(&pindex->nChainWork, &pprev->nChainWork, &block_proof);
    } else {
        pindex->nHeight = 0;
        pindex->nChainWork = GetBlockProof(pindex);
    }

    return pindex;
}

bool accept_block_header(const struct block_header *header,
                         struct validation_state *state,
                         struct main_state *ms,
                         const struct chain_params *params,
                         struct block_index **ppindex)
{
    struct uint256 hash;
    block_header_get_hash(header, &hash);

    struct block_index *pindex = block_map_find(&ms->map_block_index, &hash);
    if (pindex) {
        if (ppindex)
            *ppindex = pindex;
        if (uint256_cmp(&hash, &params->consensus.hashGenesisBlock) != 0) {
            struct block_index *header_prev = block_map_find(
                &ms->map_block_index, &header->hashPrevBlock);
            if (!header_prev) {
                return validation_state_invalid(state, false, 0,
                                                "bad-prevblk", NULL);
            }
            /* Heights are DERIVED from the parent link, never installed from
             * the active-chain label. A label-trust path here
             * (expected_height = active_chain_height() when pindex ==
             * active_tip, plus a parent nHeight rewrite to active_h - 1) let
             * an internally inconsistent authority pair re-height the live
             * tip header and its parent one LOW when a peer re-delivered a
             * headers batch containing the current tip — cascading a -1
             * splice over every header above and unwinding the reducer onto
             * the wrong blocks. The hash-linked derive-walk below is the
             * only height repair. */
            int expected_height = header_prev->nHeight + 1;
            if (pindex->pprev != header_prev ||
                pindex->nHeight != expected_height) {
                if (pindex->nHeight != expected_height)
                    LOG_WARN("validation",
                             "accept_block_header: relink h=%d->%d "
                             "derive-from-parent",
                             pindex->nHeight, expected_height);
                pindex->pprev = header_prev;
                pindex->nHeight = expected_height;
                block_index_build_skip(pindex);
                struct arith_uint256 proof = GetBlockProof(pindex);
                arith_uint256_add(&pindex->nChainWork,
                                  &header_prev->nChainWork, &proof);
            }
        }
        /* Fix scrambled heights from LDB import.  After snapshot sync,
         * block_map entries above the coins tip may have nHeight=0 or
         * wrong values because the flat-file/LDB import didn't walk
         * pprev chains for blocks it couldn't fully validate.  Walk UP
         * the pprev chain to find the first correct ancestor, then
         * propagate heights DOWN — same algorithm as boot_index.c.
         * Without this, the getheaders loop stalls forever because
         * pindex_best_header never advances past the wrong height. */
        if (pindex->pprev &&
            pindex->nHeight != pindex->pprev->nHeight + 1) {
            /* Walk up to find first correct ancestor */
            struct block_index *stack[2048];
            int depth = 0;
            struct block_index *cur = pindex;
            /* monotonicity guard. A corrupt pprev cycle
             * would otherwise hold this thread until depth==2048, but
             * also poison every block we push on the stack. Bail clean. */
            while (cur->pprev &&
                   cur->pprev->nHeight < cur->nHeight &&
                   cur->nHeight != cur->pprev->nHeight + 1 &&
                   depth < 2048) {
                stack[depth++] = cur;
                cur = cur->pprev;
            }
            /* Fix cur if needed */
            if (cur->pprev && cur->nHeight != cur->pprev->nHeight + 1) {
                cur->nHeight = cur->pprev->nHeight + 1;
                struct arith_uint256 proof = GetBlockProof(cur);
                arith_uint256_add(&cur->nChainWork,
                                  &cur->pprev->nChainWork, &proof);
            }
            /* Propagate down the stack */
            for (int i = depth - 1; i >= 0; i--) {
                struct block_index *fix = stack[i];
                if (fix->pprev) {
                    fix->nHeight = fix->pprev->nHeight + 1;
                    struct arith_uint256 proof = GetBlockProof(fix);
                    arith_uint256_add(&fix->nChainWork,
                                      &fix->pprev->nChainWork, &proof);
                }
            }
        }
        if ((pindex->nStatus & BLOCK_FAILED_MASK) == BLOCK_FAILED_CHILD)
            pindex->nStatus &= ~BLOCK_FAILED_CHILD;
        /* Re-arriving headers must promote nStatus from
         * BLOCK_VALID_HEADER to BLOCK_VALID_TREE. Without this, blocks
         * stored to block_map by body-pull / direct-import (which
         * leave status at BLOCK_VALID_HEADER + BLOCK_HAVE_DATA) stay
         * invisible to find_most_work_chain forever — that filter
         * requires VALID_TREE. The new-pindex path below does this
         * promotion correctly; the existing-pindex path was silently
         * skipping it, leaving the node wedged with on-disk bodies the
         * chain refuses to connect. pprev_valid here means we've
         * already gone through the "Fix scrambled heights" pass above,
         * so ancestry is linked. */
        if ((pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE &&
            !(pindex->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) |
                              BLOCK_VALID_TREE;
        }
        return true;
    }

    /* Get prev block index */
    struct block_index *pindex_prev = NULL;
    if (uint256_cmp(&hash, &params->consensus.hashGenesisBlock) != 0) {
        pindex_prev = block_map_find(&ms->map_block_index,
                                      &header->hashPrevBlock);
        if (!pindex_prev) {
            /* Parent not in our block index — this is an orphan block.
             * Normal during sync (blocks arrive before headers).
             * DoS=0: don't penalize the peer for out-of-order delivery. */
            return validation_state_invalid(state, false, 0,
                                            "bad-prevblk", NULL);
        }
        if (pindex_prev->nStatus & BLOCK_FAILED_MASK) {
            /* Don't ban peer — parent may have been marked failed by a
             * prior validation bug (e.g. turnstile false positive).
             * The block is invalid from our perspective, but the peer
             * isn't misbehaving. DoS=0 rejects without penalty. */
            return validation_state_invalid(state, false, REJECT_INVALID,
                                            "bad-prevblk", NULL);
        }
    }

    if (!check_block_header(header, state, params, true)) {
        LOG_FAIL("validation", "check_block_header failed for accepted header");
    }

    /* Fix pindex_prev height if scrambled (same logic as the already-known
     * path above).  After snapshot sync + LDB import, block_map entries
     * may have nHeight=0 or wrong values because pprev chains weren't
     * fully resolved.  Without this fix, contextual_check_block_header
     * applies rules for the WRONG height (e.g. pre-Sapling equihash size
     * check at computed height 2 for a block really at height 2M+). */
    if (pindex_prev && pindex_prev->pprev &&
        pindex_prev->nHeight != pindex_prev->pprev->nHeight + 1) {
        struct block_index *stack[2048];
        int depth = 0;
        struct block_index *cur = pindex_prev;
        /* monotonicity guard (see same site at L1575). */
        while (cur->pprev &&
               cur->pprev->nHeight < cur->nHeight &&
               cur->nHeight != cur->pprev->nHeight + 1 &&
               depth < 2048) {
            stack[depth++] = cur;
            cur = cur->pprev;
        }
        if (cur->pprev && cur->nHeight != cur->pprev->nHeight + 1) {
            cur->nHeight = cur->pprev->nHeight + 1;
            struct arith_uint256 proof = GetBlockProof(cur);
            arith_uint256_add(&cur->nChainWork,
                              &cur->pprev->nChainWork, &proof);
        }
        for (int i = depth - 1; i >= 0; i--) {
            struct block_index *fix = stack[i];
            if (fix->pprev) {
                fix->nHeight = fix->pprev->nHeight + 1;
                struct arith_uint256 proof = GetBlockProof(fix);
                arith_uint256_add(&fix->nChainWork,
                                  &fix->pprev->nChainWork, &proof);
            }
        }
    }

    /* Skip contextual header check during IBD when the block index has
     * scrambled heights from snapshot/LDB import, OR when the post-
     * FlyClient-snapshot tail leaves the PoW averaging window unable to
     * walk back contiguously. In either case, the contextual
     * check would spuriously fail; full validation happens later in
     * connect_block(). This mirrors Bitcoin Core's header-first sync
     * model, where header structure is checked before block connection. */
    if (pindex_prev &&
        !process_block_should_skip_contextual_header(ms, pindex_prev,
                                                     &params->consensus) &&
        !contextual_check_block_header(header, state, params, pindex_prev,
                                        ms->fCheckpointsEnabled))
        LOG_FAIL("validation", "contextual_check_block_header failed for header at height %d",
                 pindex_prev->nHeight + 1);

    pindex = add_to_block_index(ms, header);
    if (!pindex)
        return validation_state_error(state, "add-to-block-index-failed");

    if ((pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
        pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) |
                           BLOCK_VALID_TREE;

    if (ppindex)
        *ppindex = pindex;

    return true;
}
