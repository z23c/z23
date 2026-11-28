/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Persist and verify the selected network's genesis body before advertising its data. */
#include "services/block_index_loader.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "core/serialize.h"
#include "domain/consensus/check_block.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include <string.h>

uint32_t block_index_genesis_bits(const struct chain_params *cp)
{
    struct arith_uint256 limit;
    uint256_to_arith(&limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&limit, false);
}

static bool genesis_identity(const struct block_index *genesis, const struct chain_params *params)
{
    return genesis && params && genesis->phashBlock && !genesis->nHeight && !genesis->pprev &&
           uint256_eq(genesis->phashBlock, &params->consensus.hashGenesisBlock);
}

static bool genesis_uninitialized(const struct block_index *genesis)
{
    return !genesis->nStatus && !genesis->nTx && !genesis->nChainTx && !genesis->nBits &&
           arith_uint256_is_zero(&genesis->nChainWork);
}

static bool genesis_block_valid(const struct block *block, const struct chain_params *params)
{
    struct uint256 hash;
    block_get_hash(block, &hash);
    return uint256_eq(&hash, &params->consensus.hashGenesisBlock) &&
           uint256_is_null(&block->header.hashPrevBlock) && block->num_vtx == 1 &&
           block->header.nBits == block_index_genesis_bits(params) &&
           domain_consensus_check_block_merkle_root(block, NULL, 0, NULL).ok;
}

static bool genesis_wire_matches(const struct block *block, const uint8_t *wire, size_t len)
{
    struct byte_stream out;
    stream_init(&out, len);
    bool same = block_serialize(block, &out) && out.size == len && !memcmp(out.data, wire, len);
    stream_free(&out);
    return same;
}

static void genesis_clear(struct block_index *genesis)
{
    block_index_hdrext_free(genesis);
    genesis->nVersion = 0;
    genesis->nTime = 0;
    genesis->nBits = 0;
    genesis->nTx = 0;
    genesis->nChainTx = 0;
    genesis->nStatus = 0;
    arith_uint256_set_zero(&genesis->nChainWork);
    uint256_set_null(&genesis->hashFinalSaplingRoot);
}

static bool genesis_set_header(struct block_index *genesis, const struct block_header *header)
{
    if (!block_index_set_merkle_nonce(genesis, &header->hashMerkleRoot, &header->nNonce) ||
        !block_index_set_solution(genesis, header->nSolution, header->nSolutionSize))
        return false;
    genesis->nVersion = header->nVersion;
    genesis->nTime = header->nTime;
    genesis->nBits = header->nBits;
    genesis->hashFinalSaplingRoot = header->hashFinalSaplingRoot;
    genesis->nTx = 1;
    genesis->nChainTx = 1;
    genesis->nChainWork = GetBlockProof(genesis);
    genesis->nStatus = (genesis->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_SCRIPTS;
    return true;
}

static bool genesis_check_disk(const struct disk_block_pos *pos, const char *datadir,
                               const uint8_t *wire, size_t len)
{
    struct block block;
    block_init(&block);
    bool ok = read_block_from_disk(&block, pos, datadir) && genesis_wire_matches(&block, wire, len);
    block_free(&block);
    return ok;
}

struct zcl_result block_index_store_genesis_body(struct block_index *genesis, const struct chain_params *params,
                                   const uint8_t *wire, size_t len, const char *datadir)
{
    if (!genesis_identity(genesis, params) || !genesis_uninitialized(genesis) ||
        !wire || !len || !datadir) return ZCL_ERR(-1, "genesis store: invalid identity or input");
    struct byte_stream stream;
    stream_init_from_data(&stream, wire, len);
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    struct block block;
    block_init(&block);
    bool ok = block_deserialize(&block, &stream) && !stream_remaining(&stream) &&
              genesis_block_valid(&block, params) &&
              write_block_to_disk(&block, &pos, datadir, params->pchMessageStart) &&
              genesis_check_disk(&pos, datadir, wire, len) &&
              genesis_set_header(genesis, &block.header) &&
              block_index_set_have_data_verified(genesis, &pos, datadir);
    if (!ok) genesis_clear(genesis);
    block_free(&block);
    return ok ? ZCL_OK : ZCL_ERR(-1, "genesis store: verification or persistence failed");
}

enum genesis_restore { GENESIS_REBUILD, GENESIS_VERIFIED, GENESIS_CONFLICT };

static enum genesis_restore genesis_restore_position(struct block_index *genesis,
    const struct chain_params *params, const uint8_t *wire, size_t len, const char *datadir)
{
    if (genesis->nFile < 0 || genesis->nDataPos < 8) return GENESIS_REBUILD;
    struct disk_block_pos pos = { .nFile = genesis->nFile, .nPos = genesis->nDataPos };
    struct block block;
    block_init(&block);
    if (!read_block_from_disk(&block, &pos, datadir)) {
        block_free(&block);
        return GENESIS_REBUILD;
    }
    /* Flat research rows clear HAVE_DATA before reaching here, so a stale
     * body is rebuilt. Other callers retaining HAVE_DATA refuse a conflict. */
    bool had_data = (block_index_status_load(genesis) & BLOCK_HAVE_DATA) != 0;
    bool same = genesis_wire_matches(&block, wire, len) && genesis_block_valid(&block, params) &&
                genesis_set_header(genesis, &block.header) &&
                (had_data || block_index_set_have_data_verified(genesis, &pos, datadir));
    block_free(&block);
    if (same) return GENESIS_VERIFIED;
    block_index_status_clear_bits(genesis, BLOCK_HAVE_DATA);
    return had_data ? GENESIS_CONFLICT : GENESIS_REBUILD;
}

struct zcl_result block_index_ensure_genesis_body(struct block_index *genesis, const struct chain_params *params,
                                    const uint8_t *wire, size_t len, const char *datadir)
{
    if (!genesis_identity(genesis, params) || !wire || !len || !datadir ||
        (block_index_status_load(genesis) & BLOCK_FAILED_ANY_MASK))
        return ZCL_ERR(-1, "genesis restore: invalid identity or input");
    enum genesis_restore restored = genesis_restore_position(genesis, params, wire, len, datadir);
    if (restored == GENESIS_VERIFIED) return ZCL_OK;
    if (restored == GENESIS_CONFLICT) return ZCL_ERR(-1, "genesis restore: conflicting body");
    genesis_clear(genesis);
    return block_index_store_genesis_body(genesis, params, wire, len, datadir);
}
