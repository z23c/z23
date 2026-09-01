/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: apply one block file's parsed header metadata to the in-memory
 * block index — create missing entries, repair zeroed headers, link pprev,
 * accumulate chain work, and mark BLOCK_HAVE_DATA.
 *
 * The APPLY half of the boot block-file scan cluster, split out of
 * engine/composition/src/boot_block_file_scan.c when that file passed the 800-line
 * shape ceiling. It reads no file and opens no descriptor: it consumes the
 * boot_scan_file_result arrays the parse half already produced, so this TU
 * is the whole of "what the scan does to the block index". The blk*.dat
 * parse, its worker pool, and the scan driver stay in
 * boot_block_file_scan.c; the shared structs and this file's one exported
 * entry point are in boot_block_file_scan_internal.h.
 *
 * Consensus-adjacent: touches the block-index load surface. Moved
 * byte-identically from boot_block_file_scan.c — no logic change.
 */

#include "boot_block_file_scan_internal.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "primitives/block.h"
#include "util/safe_alloc.h"

#include <stdlib.h>

/* Create a block_index entry directly from a parsed header.
 * Skips PoW/equihash validation here; local disk blocks are checked
 * later against the SHA3 UTXO checkpoint. This is 1000x faster than
 * accept_block_header (no equihash solve check). On a map-insert
 * collision the fresh node is freed and the existing map entry is
 * returned, so the caller must not assume it owns the result. */
static struct block_index *create_block_index_fast(
    struct main_state *ms, const struct boot_scan_block_meta *meta)
{
    struct block_index *pindex = zcl_calloc(1, sizeof(struct block_index), "boot.index.block_index");
    if (!pindex) return NULL;
    block_index_init(pindex);

    pindex->nVersion = meta->nVersion;
    pindex->hashMerkleRoot = meta->hashMerkleRoot;
    pindex->hashFinalSaplingRoot = meta->hashFinalSaplingRoot;
    pindex->nTime = meta->nTime;
    pindex->nBits = meta->nBits;
    pindex->nNonce = meta->nNonce;
    /* Don't store solution in block_index — saves 1.3KB per entry
     * (4GB total for 3M entries). Read from disk when needed. */
    pindex->nSolution = NULL;
    pindex->nSolutionSize = 0;

    /* Option A: stable per-node hash storage (never freed by bucket
     * realloc), seeded before publishing pindex into the map. */
    pindex->hashBlock = meta->hash;
    pindex->phashBlock = &pindex->hashBlock;

    if (!block_map_insert(&ms->map_block_index, &meta->hash, pindex)) {
        free(pindex);
        return block_map_find(&ms->map_block_index, &meta->hash);
    }

    /* Link to previous block */
    struct block_index *pprev = block_map_find(
        &ms->map_block_index, &meta->hashPrevBlock);
    if (pprev) {
        pindex->pprev = pprev;
        pindex->nHeight = pprev->nHeight + 1;
        block_index_build_skip(pindex);
        struct arith_uint256 proof = GetBlockProof(pindex);
        arith_uint256_add(&pindex->nChainWork,
                          &pprev->nChainWork, &proof);
    } else {
        /* Genesis or orphan — height determined on retry pass */
        pindex->nHeight = 0;
        pindex->nChainWork = GetBlockProof(pindex);
    }

    pindex->nStatus = BLOCK_VALID_TREE;
    return pindex;
}

struct boot_scan_apply_counts scan_apply_one_file(
    struct main_state *ms,
    const struct boot_scan_file_result *r,
    const struct chain_params *params)
{
    struct boot_scan_apply_counts counts = {0};
    for (size_t i = 0; i < r->count; i++) {
        const struct boot_scan_block_meta *meta = &r->blocks[i];
        struct block_index *bi = block_map_find(&ms->map_block_index,
                                                &meta->hash);

        if (!bi && params) {
            bi = create_block_index_fast(ms, meta);
            if (bi)
                counts.created++;
        }

        if (!bi)
            continue;

        if (bi->nVersion == 0 || bi->nTime == 0 || bi->nBits == 0) {
            bi->nVersion = meta->nVersion;
            bi->hashMerkleRoot = meta->hashMerkleRoot;
            bi->hashFinalSaplingRoot = meta->hashFinalSaplingRoot;
            bi->nTime = meta->nTime;
            bi->nBits = meta->nBits;
            bi->nNonce = meta->nNonce;
            counts.header_fixed++;
        }

        if (!bi->pprev && bi->nHeight == 0 && params) {
            struct block_index *pprev = block_map_find(
                &ms->map_block_index, &meta->hashPrevBlock);
            if (pprev) {
                bi->pprev = pprev;
                bi->nHeight = pprev->nHeight + 1;
                block_index_build_skip(bi);
                struct arith_uint256 proof = GetBlockProof(bi);
                arith_uint256_add(&bi->nChainWork,
                                  &pprev->nChainWork, &proof);
            }
        }

        if (!(bi->nStatus & BLOCK_HAVE_DATA)) {
            bi->nStatus |= BLOCK_HAVE_DATA;
            bi->nStatus = (bi->nStatus & ~(unsigned)BLOCK_VALID_MASK) |
                           BLOCK_VALID_TRANSACTIONS;
            bi->nFile = r->file_idx;
            bi->nDataPos = meta->nDataPos;
            if (bi->nTx == 0)
                bi->nTx = meta->nTx;
            counts.marked++;
        } else {
            /* Duplicate record: keep the EARLIEST copy. Append/rewrite
             * frontiers advance upward through a blk file (a foreign writer
             * on a hardlinked file — e.g. a live zclassicd sharing the inode
             * — or our own appends), so the lowest-offset copy is the most
             * durable; last-copy-wins picked exactly the copy most likely to
             * be overwritten later (2026-08 producer-fold wedge: 314 stale
             * tail positions). A torn entry (nFile < 0) always takes the
             * fresh record. */
            if (bi->nFile != r->file_idx ||
                bi->nDataPos != meta->nDataPos) {
                if (bi->nFile < 0 || r->file_idx < bi->nFile ||
                    (r->file_idx == bi->nFile &&
                     meta->nDataPos < bi->nDataPos)) {
                    bi->nFile = r->file_idx;
                    bi->nDataPos = meta->nDataPos;
                }
            }
            if (bi->nTx == 0)
                bi->nTx = meta->nTx;
        }
    }
    return counts;
}
