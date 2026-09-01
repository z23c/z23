/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain-restore consensus-backed predicates and nearest-backed ancestor walks.
 * The repair/finalize unit decides when to use these checks; this file owns
 * only the block-index/on-disk evidence predicates.
 */
// one-result-type-ok:predicate-only

#include "services/chain_restore_repair.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "util/util.h"

bool chain_restore_block_is_consensus_backed(
    const struct block_index *tip)
{
    if (!tip || !tip->phashBlock)
        return false;
    if (tip->nStatus & BLOCK_FAILED_MASK)
        return false;
    if (!block_index_is_valid(tip, BLOCK_VALID_TREE))
        return false;  // raw-return-ok:predicate-negative
    if (!(tip->nStatus & BLOCK_HAVE_DATA))
        return false;
    if (tip->nHeight > 0 && (!tip->pprev || tip->nBits == 0))
        return false;
    if (tip->nHeight > 0 && (tip->nFile < 0 || tip->nDataPos == 0))
        return false;
    if (tip->nTx == 0 || tip->nChainTx == 0)
        return false;
    if (uint256_is_null(&tip->hashMerkleRoot))
        return false;
    return true;
}

/* True only for the exact cold-import seed anchor named by the caller. A
 * torn/orphan root whose hash or height differs keeps facing the full
 * pprev/prev-hash gates. */
static bool chain_restore_is_seed_anchor(
    const struct block_index *tip,
    const struct uint256 *seed_anchor_hash,
    int seed_anchor_height)
{
    if (!seed_anchor_hash || seed_anchor_height < 0)
        return false;
    if (!tip || !tip->phashBlock)
        return false;
    if (tip->nHeight != seed_anchor_height)
        return false;
    return uint256_cmp(tip->phashBlock, seed_anchor_hash) == 0;
}

bool chain_restore_block_is_consensus_backed_on_disk_seeded(
    const struct block_index *tip,
    const char *datadir,
    const struct uint256 *seed_anchor_hash,
    int seed_anchor_height)
{
    if (!tip || !tip->phashBlock)
        return false;

    const bool is_seed = chain_restore_is_seed_anchor(tip, seed_anchor_hash,
                                                      seed_anchor_height);

    if (tip->nStatus & BLOCK_FAILED_MASK)
        return false;
    if (!(tip->nStatus & BLOCK_HAVE_DATA))
        return false;
    /* The cold-import seed anchor legitimately has a null pprev. Skip the
     * pprev-presence gate only for the provenance-matched anchor. */
    if (!is_seed &&
        tip->nHeight > 0 && (!tip->pprev || !tip->pprev->phashBlock))
        return false;
    if (tip->nHeight > 0 && (tip->nFile < 0 || tip->nDataPos == 0))
        return false;
    if (!datadir || !datadir[0])
        return false;

    struct block blk;
    if (!read_block_from_disk_index_pread(&blk, tip, datadir)) {
        /* blk-file writers and stage readers resolve under GetDataDir(true)
         * — the NET-SPECIFIC datadir (<base>/regtest on regtest/testnet,
         * ==base on mainnet; see reducer_ingest_service.c body persist).
         * Boot-recovery callers pass the BASE datadir, so on a subdir net
         * the first read misses every persisted body and the tip restore
         * refuses ("not disk-backed") on a fully-persisted chain. Retry
         * under the canonical net dir; on mainnet it equals datadir and
         * the retry is a cheap no-op. */
        char net_dir[2048];
        GetDataDir(true, net_dir, sizeof(net_dir));
        if (!net_dir[0] || strcmp(net_dir, datadir) == 0 ||
            !read_block_from_disk_index_pread(&blk, tip, net_dir))
            return false;  // raw-return-ok:predicate-negative
    }

    bool ok = true;
    struct uint256 disk_hash;
    block_get_hash(&blk, &disk_hash);

    if (!tip->phashBlock || uint256_cmp(&disk_hash, tip->phashBlock) != 0) {
        char got[65] = {0};
        char want[65] = {0};
        uint256_get_hex(&disk_hash, got);
        if (tip->phashBlock)
            uint256_get_hex(tip->phashBlock, want);
        LOG_WARN("chain",
                 "[chain-restore] disk hash mismatch at h=%d got=%s want=%s",
                 tip->nHeight, got, want[0] ? want : "<null>");
        ok = false;
    }

    /* The seed anchor's on-disk prev-hash points at a block we do not hold, so
     * skip the disk prev-hash comparison for the provenance-matched anchor
     * only. The self-hash, merkle, and nBits gates still run. */
    if (ok && !is_seed && tip->nHeight > 0) {
        if (!tip->pprev || !tip->pprev->phashBlock ||
            uint256_cmp(&blk.header.hashPrevBlock,
                        tip->pprev->phashBlock) != 0) {
            char got[65] = {0};
            char want[65] = {0};
            uint256_get_hex(&blk.header.hashPrevBlock, got);
            if (tip->pprev && tip->pprev->phashBlock)
                uint256_get_hex(tip->pprev->phashBlock, want);
            LOG_WARN("chain",
                     "[chain-restore] disk prev-hash mismatch at h=%d "
                     "got=%s want=%s",
                     tip->nHeight, got, want[0] ? want : "<null>");
            ok = false;
        }
    }

    if (ok && !uint256_is_null(&tip->hashMerkleRoot) &&
        uint256_cmp(&blk.header.hashMerkleRoot, &tip->hashMerkleRoot) != 0) {
        char got[65] = {0};
        char want[65] = {0};
        uint256_get_hex(&blk.header.hashMerkleRoot, got);
        uint256_get_hex(&tip->hashMerkleRoot, want);
        LOG_WARN("chain",
                 "[chain-restore] disk merkle mismatch at h=%d got=%s want=%s",
                 tip->nHeight, got, want);
        ok = false;
    }

    if (ok && tip->nBits != 0 && blk.header.nBits != tip->nBits) {
        LOG_WARN("chain",
                 "[chain-restore] disk nBits mismatch at h=%d got=%u want=%u",
                 tip->nHeight, blk.header.nBits, tip->nBits);
        ok = false;
    }

    block_free(&blk);
    return ok;
}

bool chain_restore_block_is_consensus_backed_on_disk(
    const struct block_index *tip,
    const char *datadir)
{
    return chain_restore_block_is_consensus_backed_on_disk_seeded(
        tip, datadir, NULL, -1);
}

struct block_index *chain_restore_nearest_consensus_backed_ancestor(
    struct block_index *tip)
{
    for (struct block_index *walk = tip; walk; walk = walk->pprev) {
        if (chain_restore_block_is_consensus_backed(walk))
            return walk;
    }
    return NULL;
}

struct block_index *chain_restore_nearest_consensus_backed_ancestor_on_disk_seeded(
    struct block_index *tip,
    const char *datadir,
    const struct uint256 *seed_anchor_hash,
    int seed_anchor_height)
{
    int checked = 0;
    for (struct block_index *walk = tip; walk; walk = walk->pprev) {
        if (chain_restore_block_is_consensus_backed_on_disk_seeded(
                walk, datadir, seed_anchor_hash, seed_anchor_height))
            return walk;
        checked++;
        if (checked >= 4096) {
            LOG_INFO("chain",
                     "[chain-restore] no disk-backed ancestor found within "
                     "%d blocks below h=%d",
                     checked, tip ? tip->nHeight : -1);
            return NULL;
        }
    }
    return NULL;
}

struct block_index *chain_restore_nearest_consensus_backed_ancestor_on_disk(
    struct block_index *tip,
    const char *datadir)
{
    return chain_restore_nearest_consensus_backed_ancestor_on_disk_seeded(
        tip, datadir, NULL, -1);
}
