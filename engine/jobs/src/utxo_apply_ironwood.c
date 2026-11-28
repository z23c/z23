/* purpose: Stage branch-bound Ironwood anchors and frontier updates. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood.h"
#include "chain/chain.h"
#include "base/serialize_le.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_wire.h"
#include "services/ironwood_note_frontier.h"
#include <string.h>

static enum utxo_ironwood_result storage_result(enum ironwood_checkpoint_result r)
{
    switch (r) {
    case IRONWOOD_CHECKPOINT_FOUND: return UTXO_IRONWOOD_OK;
    case IRONWOOD_CHECKPOINT_MISSING: return UTXO_IRONWOOD_ANCHOR_MISSING;
    case IRONWOOD_CHECKPOINT_INCOMPLETE: return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    default: return UTXO_IRONWOOD_LOCAL_ERROR;
    }
}

static bool candidate_matches(const struct block_index *bi, const struct block *block)
{
    if (!bi || !block || !bi->phashBlock || !bi->pprev || !bi->pprev->phashBlock ||
        bi->nHeight <= 0 || bi->pprev->nHeight != bi->nHeight - 1 ||
        (!block->num_vtx || !block->vtx) || block->num_vtx > MAX_BLOCK_TRANSACTIONS ||
        block->header.nSolutionSize > MAX_SOLUTION_SIZE) return false;
    struct uint256 hash;
    block_header_get_hash(&block->header, &hash);
    return !memcmp(hash.data, bi->phashBlock->data, 32) &&
        !memcmp(block->header.hashPrevBlock.data, bi->pprev->phashBlock->data, 32);
}

static enum utxo_ironwood_result check_anchor(struct ironwood_checkpoint_session *session,
    const struct block_index *bi, const struct v6_wire_view *view)
{
    if (!view->ironwood.count) return UTXO_IRONWOOD_OK;
    if (view->ironwood.anchor.size != 32) return UTXO_IRONWOOD_MALFORMED;
    struct ironwood_checkpoint hit;
    enum utxo_ironwood_result r = storage_result(ironwood_checkpoint_find_root(
        session, bi->nHeight, view->ironwood.anchor.data, &hit));
    if (r != UTXO_IRONWOOD_OK) return r;
    if (hit.height < 0 || hit.height >= bi->nHeight) return UTXO_IRONWOOD_LOCAL_ERROR;
    struct block_index *ancestor = block_index_get_ancestor(bi->pprev, (int)hit.height);
    if (!ancestor || !ancestor->phashBlock || memcmp(hit.block_hash, ancestor->phashBlock->data, 32))
        return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    return UTXO_IRONWOOD_OK;
}

static enum utxo_ironwood_result parse_transaction(const struct transaction *tx,
    struct v6_wire_view *view, bool *v6)
{
    *v6 = tx->version == IRONWOOD_TX_VERSION;
    if (!*v6) return tx->v6_wire.size || tx->v6_wire.data ? UTXO_IRONWOOD_MALFORMED : UTXO_IRONWOOD_OK;
    if (!tx->overwintered || tx->version_group_id != IRONWOOD_VERSION_GROUP_ID ||
        !tx->v6_wire.data || !tx->v6_wire.size ||
        v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, view) != V6_WIRE_OK)
        return UTXO_IRONWOOD_MALFORMED;
    if (tx->lock_time != zcl_read_u32_le(view->header.data + 12) ||
        tx->expiry_height != zcl_read_u32_le(view->header.data + 16) ||
        tx->num_vin != view->inputs || tx->num_vout != view->outputs ||
        tx->num_shielded_spend != view->sapling_spends.count ||
        tx->num_shielded_output != view->sapling_outputs.count) return UTXO_IRONWOOD_MALFORMED;
    return UTXO_IRONWOOD_OK;
}

static enum utxo_ironwood_result check_all_anchors(struct ironwood_checkpoint_session *session,
    const struct block_index *bi, const struct block *block, bool *has_actions)
{
    *has_actions = false;
    for (size_t i = 0; i < block->num_vtx; ++i) {
        struct v6_wire_view view;
        bool v6;
        enum utxo_ironwood_result r = parse_transaction(&block->vtx[i], &view, &v6);
        if (r != UTXO_IRONWOOD_OK) return r;
        if (v6 && view.ironwood.count) *has_actions = true;
        if (v6 && (r = check_anchor(session, bi, &view)) != UTXO_IRONWOOD_OK) return r;
    }
    return UTXO_IRONWOOD_OK;
}

static enum utxo_ironwood_result load_parent(struct ironwood_checkpoint_session *session,
    const struct block_index *bi, const struct utxo_ironwood_parent *expected,
    struct ironwood_checkpoint *row)
{
    enum utxo_ironwood_result r = storage_result(ironwood_checkpoint_latest_before(session, bi->nHeight, row));
    if (r != UTXO_IRONWOOD_OK) return r == UTXO_IRONWOOD_ANCHOR_MISSING ? UTXO_IRONWOOD_HISTORY_INCOMPLETE : r;
    if (row->height != bi->nHeight - 1 || memcmp(row->block_hash, bi->pprev->phashBlock->data, 32) ||
        row->count != expected->count || memcmp(row->root, expected->root, 32)) return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    return UTXO_IRONWOOD_OK;
}

static enum utxo_ironwood_result fold_block(const struct block *block,
    const uint8_t *params, size_t size, struct ironwood_note_frontier *tree)
{
    for (size_t i = 0; i < block->num_vtx; ++i) {
        const struct transaction *tx = &block->vtx[i];
        if (tx->version == IRONWOOD_TX_VERSION && !ironwood_frontier_append_v6(tree,
                tx->v6_wire.data, tx->v6_wire.size, params, size).ok) return UTXO_IRONWOOD_LOCAL_ERROR;
    }
    return UTXO_IRONWOOD_OK;
}

enum utxo_ironwood_result utxo_apply_ironwood_prepare(
    struct ironwood_checkpoint_session *session, const struct block_index *bi,
    const struct block *block, const struct utxo_ironwood_parent *parent,
    const uint8_t *params, size_t size, struct utxo_ironwood_pending *out)
{
    if (!session || !parent || !params || !out) return UTXO_IRONWOOD_LOCAL_ERROR;
    if (!candidate_matches(bi, block)) return UTXO_IRONWOOD_MALFORMED;
    bool has_actions;
    enum utxo_ironwood_result r = check_all_anchors(session, bi, block, &has_actions);
    if (r != UTXO_IRONWOOD_OK) return r;
    struct ironwood_checkpoint row;
    r = load_parent(session, bi, parent, &row);
    if (r != UTXO_IRONWOOD_OK) return r;
    struct ironwood_note_frontier tree = {0};
    if (has_actions) {
        if (!ironwood_frontier_restore(row.payload, row.payload_size, parent->count,
                parent->root, params, size, &tree).ok) return UTXO_IRONWOOD_LOCAL_ERROR;
        r = fold_block(block, params, size, &tree);
        if (r != UTXO_IRONWOOD_OK) return r;
    }
    struct utxo_ironwood_pending pending = {0};
    pending.checkpoint.height = bi->nHeight;
    pending.checkpoint.count = has_actions ? tree.count : parent->count;
    memcpy(pending.checkpoint.block_hash, bi->phashBlock->data, 32);
    memcpy(pending.parent_hash, bi->pprev->phashBlock->data, 32);
    pending.changed = has_actions;
    if (pending.changed) {
        if (!ironwood_note_frontier_extend(&tree, NULL, 0, params, size, pending.checkpoint.root).ok)
            return UTXO_IRONWOOD_LOCAL_ERROR;
    } else {
        memcpy(pending.checkpoint.root, parent->root, 32);
    }
    if (pending.changed && !ironwood_frontier_encode(&tree, pending.checkpoint.payload,
            sizeof pending.checkpoint.payload, &pending.checkpoint.payload_size).ok)
        return UTXO_IRONWOOD_LOCAL_ERROR;
    *out = pending;
    return UTXO_IRONWOOD_OK;
}
