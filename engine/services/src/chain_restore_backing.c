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
    if (block_index_merkle_is_null(tip))
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

/* Index-entry gates run before the disk read: failure status, data presence,
 * pprev presence (seed anchor excepted), and file location. */
static bool chain_restore_backing_index_gate(
    const struct block_index *tip,
    bool is_seed)
{
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
    return true;
}

/* Require a usable datadir, then read the tip's block body from it, retrying
 * once under the canonical net-specific data dir when the first read misses. */
static bool chain_restore_read_block_with_net_retry(
    struct block *blk,
    const struct block_index *tip,
    const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;
    if (read_block_from_disk_index_pread(blk, tip, datadir))
        return true;
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
    const bool same_dir = strcmp(net_dir, datadir) == 0;
    if (!net_dir[0] || same_dir)
        return false;  // raw-return-ok:predicate-negative
    return read_block_from_disk_index_pread(blk, tip, net_dir);
}

/* True when the index entry's own hash is missing or differs from the
 * block's on-disk hash. */
static bool chain_restore_disk_hash_mismatches(
    struct uint256 *disk_hash,
    const struct block_index *tip)
{
    if (!tip->phashBlock)
        return true;
    return uint256_cmp(disk_hash, tip->phashBlock) != 0;
}

/* True when the prev-hash comparison applies (earlier gates passed, not the
 * seed anchor, height > 0) and the parent entry or its hash is missing or
 * the on-disk prev-hash differs from the parent entry's hash. */
static bool chain_restore_disk_prev_hash_mismatches(
    struct block *blk,
    const struct block_index *tip,
    bool is_seed,
    bool ok)
{
    if (!ok || is_seed || tip->nHeight <= 0)
        return false;
    if (!tip->pprev || !tip->pprev->phashBlock)
        return true;
    return uint256_cmp(&blk->header.hashPrevBlock,
                       tip->pprev->phashBlock) != 0;
}

/* True when earlier gates passed, the index merkle root is meaningful, and
 * it differs from the block's on-disk merkle root. */
static bool chain_restore_disk_merkle_mismatches(
    struct block *blk,
    const struct block_index *tip,
    const struct uint256 *tip_merkle,
    bool ok)
{
    if (!ok || block_index_merkle_is_null(tip))
        return false;
    return uint256_cmp(&blk->header.hashMerkleRoot, tip_merkle) != 0;
}

/* True when earlier gates passed, the index records an nBits target, and the
 * block's on-disk nBits differs from it. */
static bool chain_restore_disk_nbits_mismatches(
    struct block *blk,
    const struct block_index *tip,
    bool ok)
{
    if (!ok || tip->nBits == 0)
        return false;
    return blk->header.nBits != tip->nBits;
}

/* Write the index entry's own hash as hex into out when present; out is left
 * untouched otherwise. */
static void chain_restore_index_hash_hex_if_present(
    const struct block_index *tip,
    char *out)
{
    if (tip->phashBlock)
        uint256_get_hex(tip->phashBlock, out);
}

/* Write the parent entry's hash as hex into out when the parent and its hash
 * are present; out is left untouched otherwise. */
static void chain_restore_prev_hash_hex_if_present(
    const struct block_index *tip,
    char *out)
{
    if (tip->pprev && tip->pprev->phashBlock)
        uint256_get_hex(tip->pprev->phashBlock, out);
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

    const bool index_ok = chain_restore_backing_index_gate(tip, is_seed);
    if (!index_ok)
        return false;

    struct block blk;
    const bool loaded =
        chain_restore_read_block_with_net_retry(&blk, tip, datadir);
    if (!loaded)
        return false;

    bool ok = true;
    struct uint256 disk_hash;
    block_get_hash(&blk, &disk_hash);

    if (chain_restore_disk_hash_mismatches(&disk_hash, tip)) {
        char got[65] = {0};
        char want[65] = {0};
        uint256_get_hex(&disk_hash, got);
        chain_restore_index_hash_hex_if_present(tip, want);
        LOG_WARN("chain",
                 "[chain-restore] disk hash mismatch at h=%d got=%s want=%s",
                 tip->nHeight, got, want[0] ? want : "<null>");
        ok = false;
    }

    /* The seed anchor's on-disk prev-hash points at a block we do not hold, so
     * skip the disk prev-hash comparison for the provenance-matched anchor
     * only. The self-hash, merkle, and nBits gates still run. */
    if (chain_restore_disk_prev_hash_mismatches(&blk, tip, is_seed, ok)) {
        char got[65] = {0};
        char want[65] = {0};
        uint256_get_hex(&blk.header.hashPrevBlock, got);
        chain_restore_prev_hash_hex_if_present(tip, want);
        LOG_WARN("chain",
                 "[chain-restore] disk prev-hash mismatch at h=%d "
                 "got=%s want=%s",
                 tip->nHeight, got, want[0] ? want : "<null>");
        ok = false;
    }

    const struct uint256 tip_merkle = block_index_merkle_root(tip);
    if (chain_restore_disk_merkle_mismatches(&blk, tip, &tip_merkle, ok)) {
        char got[65] = {0};
        char want[65] = {0};
        uint256_get_hex(&blk.header.hashMerkleRoot, got);
        uint256_get_hex(&tip_merkle, want);
        LOG_WARN("chain",
                 "[chain-restore] disk merkle mismatch at h=%d got=%s want=%s",
                 tip->nHeight, got, want);
        ok = false;
    }

    if (chain_restore_disk_nbits_mismatches(&blk, tip, ok)) {
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
