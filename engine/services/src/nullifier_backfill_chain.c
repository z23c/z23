/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * nullifier_backfill_chain — bind an owner-gated historical nullifier fold
 * to one immutable selected-chain prefix and authenticate each disk body.
 * node.db height rows are body locations only; active-chain ancestry is the
 * selection authority and the block header's Merkle root binds transactions. */
// repair-rung-ok:test_nullifier_backfill_service
// one-result-type-ok:private-wire-codec

#include "nullifier_backfill_chain.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "primitives/block.h"
#include "services/nullifier_backfill_service.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define NBF_CHAIN_SUBSYS "nullifier_backfill"
#define NBF_CHAIN_BINDING_VERSION 1u
#define NBF_CHAIN_BINDING_WIRE_SIZE 76u

static void nbf_put_u32le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static uint32_t nbf_get_u32le(const uint8_t in[4])
{
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static void nbf_binding_encode(const struct nbf_chain_binding *binding,
                               uint8_t out[NBF_CHAIN_BINDING_WIRE_SIZE])
{
    memset(out, 0, NBF_CHAIN_BINDING_WIRE_SIZE);
    out[0] = NBF_CHAIN_BINDING_VERSION;
    nbf_put_u32le(out + 4, (uint32_t)binding->target_height);
    memcpy(out + 8, binding->target_hash.data, 32);
    nbf_put_u32le(out + 40, (uint32_t)binding->tip_height);
    memcpy(out + 44, binding->tip_hash.data, 32);
}

bool nbf_chain_binding_equal(const struct nbf_chain_binding *a,
                             const struct nbf_chain_binding *b)
{
    return a && b &&
           a->target_height == b->target_height &&
           a->tip_height == b->tip_height &&
           uint256_eq(&a->target_hash, &b->target_hash) &&
           uint256_eq(&a->tip_hash, &b->tip_hash);
}

struct zcl_result nbf_chain_binding_read(
    sqlite3 *db,
    struct nbf_chain_binding *out,
    bool *found_out,
    bool *valid_out)
{
    uint8_t wire[NBF_CHAIN_BINDING_WIRE_SIZE];
    size_t len = 0;
    bool found = false;

    if (found_out)
        *found_out = false;
    if (valid_out)
        *valid_out = false;
    if (out)
        memset(out, 0, sizeof(*out));
    if (!db || !out || !found_out || !valid_out) {
        LOG_WARN(NBF_CHAIN_SUBSYS, "read_chain_binding: invalid args");
        return ZCL_ERR(-4, "read_chain_binding invalid args");
    }

    progress_store_tx_lock();
    bool got = progress_meta_get(db, NULLIFIER_BACKFILL_CHAIN_KEY,
                                 wire, sizeof(wire), &len, &found);
    progress_store_tx_unlock();
    if (!got) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "read_chain_binding: progress_meta_get failed");
        return ZCL_ERR(-5, "failed to read nullifier chain binding");
    }
    *found_out = found;
    if (!found)
        return ZCL_OK;
    if (len != sizeof(wire) || wire[0] != NBF_CHAIN_BINDING_VERSION ||
        wire[1] != 0 || wire[2] != 0 || wire[3] != 0) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "read_chain_binding: malformed version/length len=%zu",
                 len);
        return ZCL_OK;
    }
    uint32_t target_height = nbf_get_u32le(wire + 4);
    uint32_t tip_height = nbf_get_u32le(wire + 40);
    if (target_height > INT_MAX || tip_height > INT_MAX ||
        tip_height < target_height) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "read_chain_binding: invalid heights target=%u tip=%u",
                 target_height, tip_height);
        return ZCL_OK;
    }
    out->target_height = (int)target_height;
    memcpy(out->target_hash.data, wire + 8, 32);
    out->tip_height = (int)tip_height;
    memcpy(out->tip_hash.data, wire + 44, 32);
    *valid_out = true;
    return ZCL_OK;
}

struct zcl_result nbf_chain_binding_capture(
    const struct nullifier_backfill_config *cfg,
    int64_t activation,
    struct nbf_chain_binding *out)
{
    struct active_chain_window_snapshot snapshot;
    int target_height;

    if (!cfg || !cfg->main || !out || activation <= 0 ||
        activation > INT_MAX) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "capture_chain_binding: invalid args main=%p activation=%lld",
                 cfg ? (void *)cfg->main : NULL, (long long)activation);
        return ZCL_ERR(-6, "selected-chain authority unavailable");
    }
    target_height = (int)activation - 1;
    memset(&snapshot, 0, sizeof(snapshot));
    if (!active_chain_capture_window(&cfg->main->chain_active,
                                     target_height, &snapshot) ||
        !snapshot.tip || !snapshot.requested ||
        snapshot.height < target_height ||
        snapshot.tip->nHeight != snapshot.height ||
        snapshot.requested->nHeight != target_height ||
        !snapshot.tip->phashBlock || !snapshot.requested->phashBlock ||
        block_has_any_failure(snapshot.tip) ||
        block_has_any_failure(snapshot.requested) ||
        !block_index_is_valid(snapshot.tip, BLOCK_VALID_TREE) ||
        !block_index_is_valid(snapshot.requested, BLOCK_VALID_TREE)) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "capture_chain_binding: selected prefix unavailable "
                 "target=%d window=%d tip=%p requested=%p",
                 target_height, snapshot.height, (void *)snapshot.tip,
                 (void *)snapshot.requested);
        return ZCL_ERR(-7, "selected chain does not prove target height %d",
                       target_height);
    }
    memset(out, 0, sizeof(*out));
    out->target_height = target_height;
    out->target_hash = *snapshot.requested->phashBlock;
    out->tip_height = snapshot.height;
    out->tip_hash = *snapshot.tip->phashBlock;
    out->target = snapshot.requested;
    out->tip = snapshot.tip;
    return ZCL_OK;
}

bool nbf_chain_binding_store_in_tx(
    sqlite3 *db,
    const struct nbf_chain_binding *binding)
{
    uint8_t wire[NBF_CHAIN_BINDING_WIRE_SIZE];

    if (!db || !binding)
        LOG_FAIL(NBF_CHAIN_SUBSYS, "store_chain_binding: invalid args");
    nbf_binding_encode(binding, wire);
    if (!progress_meta_set_in_tx(db, NULLIFIER_BACKFILL_CHAIN_KEY,
                                 wire, sizeof(wire)))
        LOG_FAIL(NBF_CHAIN_SUBSYS, "store_chain_binding: meta write failed");
    return true;
}

struct zcl_result nbf_chain_body_verify(
    const struct nbf_chain_binding *binding,
    const struct block *blk,
    int64_t height)
{
    struct block_index *expected;
    struct uint256 block_hash;
    struct uint256 merkle_root;
    struct uint256 *txids;

    if (!binding || !binding->target || !blk || height < 0 ||
        height > binding->target_height) {
        LOG_WARN(NBF_CHAIN_SUBSYS, "verify_selected_body: invalid h=%lld",
                 (long long)height);
        return ZCL_ERR(-17, "invalid selected body height %lld",
                       (long long)height);
    }
    expected = block_index_get_ancestor(binding->target, (int)height);
    if (!expected || expected->nHeight != height || !expected->phashBlock ||
        block_has_any_failure(expected) ||
        !block_index_is_valid(expected, BLOCK_VALID_TREE)) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "verify_selected_body: selected ancestry unavailable h=%lld",
                 (long long)height);
        return ZCL_ERR(-18, "selected ancestry unavailable at height %lld",
                       (long long)height);
    }
    block_get_hash(blk, &block_hash);
    if (!uint256_eq(&block_hash, expected->phashBlock) ||
        !uint256_eq(&blk->header.hashMerkleRoot,
                    &expected->hashMerkleRoot)) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "verify_selected_body: header/hash mismatch h=%lld",
                 (long long)height);
        return ZCL_ERR(-19, "block body is not selected-chain height %lld",
                       (long long)height);
    }
    if (blk->num_vtx == 0 || blk->num_vtx > MAX_BLOCK_TRANSACTIONS ||
        blk->num_vtx > SIZE_MAX / sizeof(*txids)) {
        LOG_WARN(NBF_CHAIN_SUBSYS,
                 "verify_selected_body: invalid tx count h=%lld count=%zu",
                 (long long)height, blk->num_vtx);
        return ZCL_ERR(-26, "invalid selected body tx count at height %lld",
                       (long long)height);
    }
    txids = zcl_malloc(blk->num_vtx * sizeof(*txids),
                       "nullifier_backfill_txids");
    if (!txids)
        return ZCL_ERR(-27, "txid allocation failed at height %lld",
                       (long long)height);
    for (size_t i = 0; i < blk->num_vtx; i++)
        txids[i] = blk->vtx[i].hash;
    merkle_root = compute_merkle_root(txids, blk->num_vtx);
    free(txids);
    if (!uint256_eq(&merkle_root, &blk->header.hashMerkleRoot)) {
        LOG_WARN(NBF_CHAIN_SUBSYS, "verify_selected_body: merkle mismatch h=%lld",
                 (long long)height);
        return ZCL_ERR(-28, "body merkle mismatch at height %lld",
                       (long long)height);
    }
    return ZCL_OK;
}
