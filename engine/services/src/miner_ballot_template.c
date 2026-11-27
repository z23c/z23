/* purpose: Add a ballot to a bounded temporary mining template. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_ballot_template.h"
#include "services/miner_signal_round.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"
#include "validation/main_constants.h"
#include <stdlib.h>
#include <string.h>

static struct zcl_result ballot_append(struct transaction *cb,
                                        const uint8_t catalog[32],
                                        const uint8_t bitmap[32])
{
    if (!cb->vin || !transaction_is_coinbase(cb) || !cb->vout || !cb->num_vout ||
        cb->num_vout >= MAX_TX_OUTPUTS || cb->vin[0].script_sig.size > 100)
        return ZCL_ERR(-1, "Invalid coinbase output or script size");
    size_t n = cb->num_vout;
    struct tx_out *outputs = tx_out_array_alloc(n + 1, "miner ballot outputs");
    if (!outputs) return ZCL_ERR(-2, "Cannot allocate ballot outputs");
    memcpy(outputs, cb->vout, n * sizeof(*outputs));
    tx_out_set_null(&outputs[n]);
    outputs[n].value = 0;
    outputs[n].script_pub_key.size = MINER_SIGNAL_SCRIPT_BYTES;
    miner_signal_ballot_script(catalog, bitmap, outputs[n].script_pub_key.data);
    free(cb->vout);
    cb->vout = outputs;
    cb->num_vout = n + 1;
    return ZCL_OK;
}

static struct zcl_result ballot_check_size(struct block *block, size_t solution_size,
                                            size_t limit, size_t *out)
{
    uint8_t *buf = zcl_malloc(limit, "miner ballot serialization bound");
    if (!buf) return ZCL_ERR(-3, "Cannot allocate bounded block serialization");
    struct byte_stream s = { .data = buf, .capacity = limit, .owns_data = false };
    struct script *script = &block->vtx[0].vin[0].script_sig;
    size_t old_len = script->size;
    memset(script->data + old_len, 0, 100 - old_len);
    script->size = 100;
    /* Input header is unsolved; bytes beyond its zero length have no wire value. */
    memset(block->header.nSolution, 0, solution_size);
    block->header.nSolutionSize = solution_size;
    bool ok = block_serialize(block, &s) && !s.error;
    size_t size = s.size;
    block->header.nSolutionSize = 0;
    script->size = (uint16_t)old_len;
    free(buf);
    if (!ok) return ZCL_ERR(-4, "Reserved block serialization exceeds mining limit or failed");
    *out = size;
    return ZCL_OK;
}

static struct zcl_result ballot_update_merkle(struct block *block)
{
    struct uint256 *txids = zcl_malloc(block->num_vtx * sizeof(*txids), "miner ballot merkle");
    if (!txids) return ZCL_ERR(-5, "Cannot allocate merkle leaves");
    for (size_t i = 0; i < block->num_vtx; i++) {
        if (!transaction_hash_serialized(&block->vtx[i], &txids[i])) {
            free(txids);
            return ZCL_ERR(-6, "Cannot serialize a template transaction for hashing");
        }
    }
    block->vtx[0].hash = txids[0];
    bool mutated = false;
    struct uint256 root = merkle_root_mutated_in_place(txids, block->num_vtx, &mutated);
    free(txids);
    if (mutated) return ZCL_ERR(-7, "Mutated Merkle tree in mining template");
    block->header.hashMerkleRoot = root;
    return ZCL_OK;
}

struct zcl_result miner_ballot_template_apply(struct block *block,
    const uint8_t catalog[32], const uint8_t bitmap[32],
    const struct chain_params *params, int height, size_t mining_limit,
    size_t *reserved_size_out)
{
    if (!block || !catalog || !bitmap || !params || !reserved_size_out || height < 0 ||
        !mining_limit || mining_limit > DEFAULT_BLOCK_MAX_SIZE ||
        !block->vtx || !block->num_vtx || block->num_vtx > MAX_BLOCK_TRANSACTIONS ||
        block->header.nSolutionSize != 0)
        return ZCL_ERR(-8, "Invalid unsolved mining template or policy limit");
    unsigned n = chain_params_equihash_n(params, height);
    unsigned k = chain_params_equihash_k(params, height);
    if (!equihash_params_supported(n, k)) return ZCL_ERR(-9, "Unsupported Equihash parameters");
    struct equihash_params ep;
    equihash_params_init(&ep, n, k);
    if (!ep.solution_width || ep.solution_width > MAX_SOLUTION_SIZE)
        return ZCL_ERR(-10, "Equihash solution width exceeds header capacity");
    struct zcl_result r = ballot_append(&block->vtx[0], catalog, bitmap);
    if (!r.ok) return r;
    size_t reserved = 0;
    r = ballot_check_size(block, ep.solution_width, mining_limit, &reserved);
    if (!r.ok) return r;
    r = ballot_update_merkle(block);
    if (!r.ok) return r;
    *reserved_size_out = reserved;
    return ZCL_OK;
}
