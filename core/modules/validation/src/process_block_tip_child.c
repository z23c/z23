/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Active-tip child discovery and disk verification helpers for process_block.
 *
 * Chain selection can decide that the active tip has a direct child only
 * after the indexed disk bytes prove both the candidate hash and prev-hash
 * edge. Keep that repair and verification logic separate from the broader
 * best-work scan in process_block_core.c. */

#include <stdio.h>

#include "chain/chain.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "validation/main_state.h"

#include "process_block_internal.h"

bool process_block_verify_active_tip_child_on_disk(
    const struct block_index *candidate,
    const struct block_index *tip,
    const char *datadir)
{
    if (!candidate || !tip || !tip->phashBlock || !candidate->phashBlock ||
        !datadir || !datadir[0])
        return false;
    if (!(candidate->nStatus & BLOCK_HAVE_DATA) ||
        candidate->nFile < 0 || candidate->nDataPos == 0)
        return false;

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_index(&blk, candidate, datadir)) {
        block_free(&blk);
        return false;
    }

    struct uint256 disk_hash;
    block_header_get_hash(&blk.header, &disk_hash);
    bool ok = uint256_eq(&disk_hash, candidate->phashBlock) &&
              uint256_eq(&blk.header.hashPrevBlock, tip->phashBlock);
    block_free(&blk);
    return ok;
}

/* True when BLOCK_HAVE_DATA is set, nFile is non-negative, and nDataPos
 * is non-zero. */
static bool active_tip_child_bytes_indexed(const struct block_index *candidate)
{
    if (!(candidate->nStatus & BLOCK_HAVE_DATA))
        return false;
    if (candidate->nFile < 0 || candidate->nDataPos == 0)
        return false;
    return true;
}

/* Rebuilds skip and stores tip chain work plus this block's proof. */
static void refresh_active_tip_child_skip_and_work(struct block_index *candidate,
                                                   const struct block_index *tip)
{
    block_index_build_skip(candidate);
    struct arith_uint256 proof = GetBlockProof(candidate);
    arith_uint256_add(&candidate->nChainWork,
                      &tip->nChainWork, &proof);
}

/* Index screen for a direct child of tip before disk verification. */
static bool active_tip_direct_child_indexed(const struct block_index *candidate,
                                            const struct block_index *tip)
{
    bool prev_matches;
    bool tree_valid;

    if (!candidate || candidate == tip)
        return false;
    if (!candidate->pprev || !candidate->pprev->phashBlock)
        return false;
    prev_matches = uint256_eq(candidate->pprev->phashBlock, tip->phashBlock);
    if (!prev_matches)
        return false;
    if (block_has_any_failure(candidate))
        return false;
    tree_valid = block_index_is_valid(candidate, BLOCK_VALID_TREE);
    if (!tree_valid)
        return false;
    return active_tip_child_bytes_indexed(candidate);
}

/* Sets height to one above tip, then refreshes skip and chain work, when
 * the height differs. */
static void repair_active_tip_child_height(struct block_index *candidate,
                                           const struct block_index *tip)
{
    if (candidate->nHeight == tip->nHeight + 1)
        return;
    candidate->nHeight = tip->nHeight + 1;
    refresh_active_tip_child_skip_and_work(candidate, tip);
}

/* True when child is a different next-height block with indexed block data. */
static bool active_tip_next_height_child_has_data(const struct block_index *child,
                                                  const struct block_index *candidate)
{
    if (!child || child == candidate)
        return false;
    if (child->nHeight != candidate->nHeight + 1)
        return false;
    return active_tip_child_bytes_indexed(child);
}

static bool active_tip_child_has_disk_continuation(struct main_state *ms,
                                                   const struct block_index *candidate,
                                                   const char *datadir)
{
    size_t ci = 0;
    struct block_index *child;
    bool has_continuation = false;

    /* Continuation scoring is a small-index tie breaker. On imported
     * mainnet indexes it is O(candidates * block_map_size) before RPC
     * starts, so keep large boots bounded and let the verified unlinked
     * fallback repair any stale pprev edge after direct-child selection. */
    if (!datadir || !datadir[0] || !candidate->phashBlock ||
        ms->map_block_index.size >= 500000)
        return false;

    while (block_map_next(&ms->map_block_index, &ci, NULL, &child)) {
        struct disk_block_pos pos;
        struct block blk;
        bool read_ok;

        if (!active_tip_next_height_child_has_data(child, candidate))
            continue;

        disk_block_pos_init(&pos);
        pos.nFile = child->nFile;
        pos.nPos = child->nDataPos;

        block_init(&blk);
        read_ok = read_block_from_disk_pread(&blk, &pos, datadir);
        if (!read_ok) {
            block_free(&blk);
            continue;
        }
        has_continuation =
            uint256_eq(&blk.header.hashPrevBlock,
                       candidate->phashBlock);
        block_free(&blk);
        if (has_continuation)
            break;
    }
    return has_continuation;
}

/* True when best is unset, candidate has a continuation best lacks, or
 * both match on continuation and candidate has more chain work. */
static bool active_tip_child_outranks(const struct block_index *candidate,
                                      bool has_continuation,
                                      const struct block_index *best,
                                      bool best_has_continuation)
{
    if (!best)
        return true;
    if (has_continuation && !best_has_continuation)
        return true;
    return has_continuation == best_has_continuation &&
           arith_uint256_compare(&candidate->nChainWork,
                                 &best->nChainWork) > 0;
}

struct block_index *find_best_active_tip_child(struct main_state *ms,
                                               struct block_index *tip,
                                               const char *datadir)
{
    struct block_index *best = NULL;
    bool best_has_continuation = false;
    size_t iter = 0;
    struct block_index *candidate;

    if (!ms || !tip || !tip->phashBlock)
        return NULL;

    while (block_map_next(&ms->map_block_index, &iter, NULL, &candidate)) {
        bool has_continuation;

        if (!active_tip_direct_child_indexed(candidate, tip))
            continue;
        if (!process_block_verify_active_tip_child_on_disk(
                candidate, tip, datadir)) {
            fprintf(stderr, // obs-ok:pre-existing-diagnostic
                    "process_block_tip_child: skipping stale active-tip child "
                    "h=%d file=%d pos=%u; local block bytes do not verify "
                    "against index hash and current tip\n",
                    candidate->nHeight, candidate->nFile,
                    candidate->nDataPos);
            candidate->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
            candidate->nFile = -1;
            candidate->nDataPos = 0;
            continue;
        }

        repair_active_tip_child_height(candidate, tip);
        has_continuation = active_tip_child_has_disk_continuation(
            ms, candidate, datadir);
        if (active_tip_child_outranks(candidate, has_continuation,
                                      best, best_has_continuation)) {
            best = candidate;
            best_has_continuation = has_continuation;
        }
    }

    return best;
}

/* Index screen before the unlinked child's disk header is read. */
static bool unlinked_active_tip_child_indexed(const struct block_index *candidate,
                                              const struct block_index *tip)
{
    if (!candidate || candidate == tip)
        return false;
    if (!candidate->phashBlock)
        return false;
    if (candidate->pprev == tip)
        return false;
    if (candidate->nHeight != tip->nHeight + 1)
        return false;
    if (block_has_any_failure(candidate))
        return false;
    return active_tip_child_bytes_indexed(candidate);
}

/* Returns whether the on-disk header matches the index hash and names tip
 * as its parent. */
static bool unlinked_child_disk_extends_tip(const struct block_index *candidate,
                                            const struct block_index *tip,
                                            const char *datadir)
{
    struct block blk;
    struct uint256 disk_hash;
    bool read_ok;
    bool matches_index;
    bool extends_tip;

    block_init(&blk);
    read_ok = read_block_from_disk_index(&blk, candidate, datadir);
    if (!read_ok) {
        block_free(&blk);
        return false;
    }

    block_header_get_hash(&blk.header, &disk_hash);
    matches_index = uint256_eq(&disk_hash, candidate->phashBlock);
    extends_tip = uint256_eq(&blk.header.hashPrevBlock, tip->phashBlock);
    block_free(&blk);
    if (!matches_index || !extends_tip)
        return false;
    return true;
}

/* Sets pprev to tip, refreshes skip and chain work, and fills nChainTx
 * when nChainTx is zero and nTx is positive. */
static void link_verified_unlinked_active_tip_child(struct block_index *candidate,
                                                   struct block_index *tip)
{
    candidate->pprev = tip;
    refresh_active_tip_child_skip_and_work(candidate, tip);
    if (candidate->nChainTx == 0 && candidate->nTx > 0)
        candidate->nChainTx = tip->nChainTx + candidate->nTx;
}

struct block_index *find_verified_unlinked_active_tip_child(
    struct main_state *ms,
    struct block_index *tip,
    const char *datadir)
{
    struct block_index *best = NULL;
    size_t iter = 0;
    struct block_index *candidate;

    if (!ms || !tip || !tip->phashBlock || !datadir)
        return NULL;

    while (block_map_next(&ms->map_block_index, &iter, NULL, &candidate)) {
        if (!unlinked_active_tip_child_indexed(candidate, tip))
            continue;
        if (!unlinked_child_disk_extends_tip(candidate, tip, datadir))
            continue;
        link_verified_unlinked_active_tip_child(candidate, tip);
        if (!best ||
            arith_uint256_compare(&candidate->nChainWork,
                                  &best->nChainWork) > 0)
            best = candidate;
    }

    if (best) {
        fprintf(stderr, // obs-ok:pre-existing-diagnostic
            "process_block_tip_child: repaired unlinked active-tip child "
            "h=%d from disk-verified prev hash\n",
            best->nHeight);
    }
    return best;
}
