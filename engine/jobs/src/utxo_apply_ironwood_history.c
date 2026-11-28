/* purpose: Reconstruct Ironwood anchors from the accepted private ancestry. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood_history.h"
#include "jobs/stage_helpers.h"
#include "chain/chainparams.h"
#include "domain/consensus/check_block.h"
#include "primitives/transaction_v6_digest.h"
#include "services/ironwood_resident_params.h"
#include <string.h>

static const struct chain_research_descriptor *history_profile(void)
{
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    return d && chain_research_profile_current() == d && chain_params_get() == d->chain &&
           d->genesis_wire && d->genesis_wire_len ? d : NULL;
}

struct zcl_result utxo_ironwood_history_begin(const struct block_index *parent,
    const struct block_index **slots, size_t slot_count, struct ironwood_history_cursor *out)
{
    if (!history_profile() || !parent || !parent->phashBlock || parent->nHeight < 0 ||
        !slots || !out || (size_t)parent->nHeight >= slot_count)
        return ZCL_ERR(-1, "Invalid Ironwood history parent or workspace");
    struct ironwood_history_cursor next = {0};
    next.parent = parent;
    next.scan = parent;
    next.slots = slots;
    next.slot_count = slot_count;
    next.scan_height = next.parent_height = parent->nHeight;
    next.scanning = true;
    next.parent_hash = *parent->phashBlock;
    size_t size = 0;
    const uint8_t *params = ironwood_resident_merkle_parameters(&size);
    struct zcl_result r = ironwood_note_frontier_extend(&next.frontier, NULL, 0,
                                                        params, size, next.root);
    if (!r.ok) return ZCL_ERR(-1, "%s", r.message);
    *out = next;
    return ZCL_OK;
}

static bool history_txid(const struct transaction *tx, struct uint256 *out,
                         struct v6_wire_view *view, bool *is_v6)
{
    bool wire = tx->v6_wire.data || tx->v6_wire.size;
    *is_v6 = wire || (tx->overwintered && tx->version == IRONWOOD_TX_VERSION);
    if (!*is_v6) return transaction_hash_serialized(tx, out);
    if (!wire || !tx->overwintered || tx->version != IRONWOOD_TX_VERSION ||
        tx->version_group_id != IRONWOOD_VERSION_GROUP_ID ||
        v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, view) != V6_WIRE_OK)
        return false;
    struct v6_digests digests;
    if (!v6_wire_digests(view, &digests)) return false;
    memcpy(out->data, digests.txid, sizeof out->data);
    return true;
}

static struct zcl_result history_fold(struct ironwood_history_cursor *next,
                                      const struct block *block)
{
    if (!block->num_vtx || block->num_vtx > MAX_BLOCK_TRANSACTIONS ||
        !block->vtx || block->header.nSolutionSize > MAX_SOLUTION_SIZE)
        return ZCL_ERR(-1, "Invalid Ironwood history block");
    size_t size = 0;
    const uint8_t *params = ironwood_resident_merkle_parameters(&size);
    uint64_t count = next->frontier.count;
    for (size_t i = 0; i < block->num_vtx; ++i) {
        const struct transaction *tx = &block->vtx[i];
        struct v6_wire_view view;
        struct uint256 hash;
        bool is_v6;
        if (!history_txid(tx, &hash, &view, &is_v6) || !uint256_eq(&hash, &tx->hash))
            return ZCL_ERR(-1, "Ironwood history transaction identity mismatch");
        if (is_v6) {
            struct zcl_result r = ironwood_frontier_append_v6(&next->frontier,
                tx->v6_wire.data, tx->v6_wire.size, params, size);
            if (!r.ok) return ZCL_ERR(-1, "%s", r.message);
        }
    }
    if (!domain_consensus_check_block_merkle_root(block, NULL, 0, NULL).ok)
        return ZCL_ERR(-1, "Ironwood history Merkle root mismatch");
    if (next->frontier.count != count) {
        struct zcl_result r = ironwood_note_frontier_extend(&next->frontier, NULL, 0, params, size, next->root);
        if (!r.ok) return ZCL_ERR(-1, "%s", r.message);
    }
    return ZCL_OK;
}

static struct zcl_result history_scan(const struct ironwood_history_cursor *in,
                                      struct ironwood_history_cursor *next)
{
    const struct block_index *bi = in->scan;
    const struct chain_research_descriptor *d = history_profile();
    if (!d || !bi || !bi->phashBlock || bi->nHeight != in->scan_height ||
        (size_t)in->scan_height >= in->slot_count)
        return ZCL_ERR(-1, "Ironwood history ancestry unavailable");
    if (!in->scan_height) {
        if (bi->pprev || !uint256_eq(bi->phashBlock, &d->chain->consensus.hashGenesisBlock))
            return ZCL_ERR(-1, "Ironwood history genesis mismatch");
        next->scanning = false;
    } else {
        if (!bi->pprev || !bi->pprev->phashBlock || bi->pprev->nHeight != in->scan_height - 1)
            return ZCL_ERR(-1, "Ironwood history ancestry discontinuity");
        next->scan = bi->pprev;
        --next->scan_height;
    }
    in->slots[in->scan_height] = bi;
    return ZCL_OK;
}

static struct zcl_result history_body(const struct ironwood_history_cursor *in,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct ironwood_history_cursor *next, struct ironwood_history_event *event)
{
    const struct block_index *bi = in->slots[in->replay_height];
    if (!bi || !bi->phashBlock || bi->nHeight != in->replay_height ||
        (in->replay_height && bi->pprev != in->slots[in->replay_height - 1]))
        return ZCL_ERR(-1, "Ironwood history indexed ancestry changed");
    struct block block;
    block_init(&block);
    if (!(reader ? reader(&block, bi, datadir, user) :
                   stage_default_block_reader(&block, bi, datadir, user))) {
        block_free(&block);
        return ZCL_ERR(UTXO_IRONWOOD_HISTORY_BODY_MISSING, "Ironwood history block body unavailable");
    }
    if (block.header.nSolutionSize > MAX_SOLUTION_SIZE) {
        block_free(&block);
        return ZCL_ERR(-1, "Ironwood history block solution too large");
    }
    struct uint256 hash;
    block_get_hash(&block, &hash);
    struct zcl_result r = ZCL_OK;
    if (!uint256_eq(&hash, bi->phashBlock) ||
        !uint256_eq(&block.header.hashPrevBlock, &in->previous_hash))
        r = ZCL_ERR(-1, "Ironwood history block header mismatch");
    else r = history_fold(next, &block);
    block_free(&block);
    if (!r.ok) return ZCL_ERR(-1, "%s", r.message);
    event->available = true;
    event->height = in->replay_height;
    event->block_hash = hash;
    event->count = next->frontier.count;
    memcpy(event->root, next->root, sizeof event->root);
    next->previous_hash = hash;
    if (in->replay_height == in->parent_height) next->complete = true;
    else ++next->replay_height;
    return ZCL_OK;
}

struct zcl_result utxo_ironwood_history_step(const struct ironwood_history_cursor *in,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct ironwood_history_cursor *out, struct ironwood_history_event *event)
{
    if (!in || !out || !event || !history_profile() || !in->parent ||
        !in->parent->phashBlock || in->parent->nHeight != in->parent_height ||
        !uint256_eq(in->parent->phashBlock, &in->parent_hash) || in->complete ||
        !in->slots || in->parent_height < 0 ||
        (size_t)in->parent_height >= in->slot_count || in->scan_height < 0 ||
        in->replay_height < 0 || in->replay_height > in->parent_height)
        return ZCL_ERR(-1, "Invalid or changed Ironwood history cursor");
    struct ironwood_history_cursor next = *in;
    struct ironwood_history_event result = {0};
    struct zcl_result r = in->scanning ? history_scan(in, &next) :
        history_body(in, reader, datadir, user, &next, &result);
    if (!r.ok) return r;
    *out = next;
    *event = result;
    return ZCL_OK;
}
