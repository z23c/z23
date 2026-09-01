/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Active-chain projection repair helpers for post-restore boot. */
// one-result-type-ok:internal-counting-repair-helper
// repair-rung-ok:test_rebuild_active_chain_relinks_wrong_active_parent

#include "chain_restore_repair_internal.h"

#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "util/log_macros.h"

static void chain_restore_active_repair_store_slot(struct active_chain *c,
                                                   int h,
                                                   struct block_index *bi)
{
    zcl_mutex_lock(&c->write_lock);
    c->chain[h] = bi;
    zcl_mutex_unlock(&c->write_lock);
}

static void chain_restore_recompute_active_suffix(struct active_chain *c,
                                                  int first_h,
                                                  int tip_h)
{
    if (!c || first_h < 0 || tip_h < first_h)
        return;

    for (int h = first_h; h <= tip_h; h++) {
        struct block_index *cur = active_chain_at(c, h);
        if (!cur || cur->nHeight != h)
            continue;
        if (h > 0 && cur->pprev != active_chain_at(c, h - 1))
            continue;

        struct arith_uint256 proof = GetBlockProof(cur);
        if (cur->pprev)
            arith_uint256_add(&cur->nChainWork,
                              &cur->pprev->nChainWork, &proof);
        else
            cur->nChainWork = proof;

        if (cur->nTx > 0) {
            if (cur->pprev) {
                cur->nChainTx = cur->pprev->nChainTx
                    ? cur->pprev->nChainTx + cur->nTx
                    : 0;
            } else {
                cur->nChainTx = cur->nTx;
            }
        }
        block_index_build_skip(cur);
    }
}

static int chain_restore_relabel_wrong_height_parents(
    struct active_chain *c,
    int tip_h)
{
    if (!c || tip_h <= 0)
        return 0;

    int relabeled = 0;
    int slotted = 0;
    int old_slots_cleared = 0;
    int first_changed = tip_h + 1;

    for (int h = tip_h; h > 0; h--) {
        struct block_index *child = active_chain_at(c, h);
        if (!child || child->nHeight != h)
            continue;

        struct block_index *parent = child->pprev;
        if (!parent || parent == child || !parent->phashBlock)
            continue;
        if (parent->nStatus & BLOCK_FAILED_MASK)
            continue;

        struct block_index *prev_slot = active_chain_at(c, h - 1);
        if (prev_slot && prev_slot != parent)
            continue;
        if (prev_slot == parent && parent->nHeight == h - 1)
            continue;

        int old_h = parent->nHeight;
        if (old_h >= 0 && old_h <= tip_h && old_h != h - 1 &&
            active_chain_at(c, old_h) == parent) {
            chain_restore_active_repair_store_slot(c, old_h, NULL);
            old_slots_cleared++;
        }

        if (parent->nHeight != h - 1) {
            parent->nHeight = h - 1;
            relabeled++;
        }
        if (prev_slot != parent) {
            chain_restore_active_repair_store_slot(c, h - 1, parent);
            slotted++;
        }
        if (h - 1 < first_changed)
            first_changed = h - 1;
    }

    if (first_changed <= tip_h)
        chain_restore_recompute_active_suffix(c, first_changed, tip_h);

    if (relabeled > 0 || slotted > 0 || old_slots_cleared > 0) {
        LOG_WARN("chain_restore",
                 "rebuild_active_chain: repaired wrong-height parent links "
                 "relabeled=%d slotted=%d old_slots_cleared=%d first_h=%d",
                 relabeled, slotted, old_slots_cleared,
                 first_changed <= tip_h ? first_changed : -1);
    }

    return relabeled + slotted + old_slots_cleared;
}

static int chain_restore_relink_active_slot_parents(
    struct active_chain *c,
    int tip_h)
{
    if (!c || tip_h <= 0)
        return 0;

    int relinked = 0;
    int first_changed = tip_h + 1;

    for (int h = 1; h <= tip_h; h++) {
        struct block_index *child = active_chain_at(c, h);
        struct block_index *parent = active_chain_at(c, h - 1);
        if (!child || !parent)
            continue;
        if (child == parent)
            continue;
        if (child->nHeight != h || parent->nHeight != h - 1)
            continue;
        if (child->nStatus & BLOCK_FAILED_MASK)
            continue;
        if (parent->nStatus & BLOCK_FAILED_MASK)
            continue;
        if (child->pprev == parent)
            continue;

        /* Same-height disagreements need disk prev-hash evidence. This
         * projection fallback repairs only detached stale links. */
        if (child->pprev && child->pprev->nHeight == h - 1)
            continue;

        child->pprev = parent;
        child->pskip = NULL;
        relinked++;
        if (h < first_changed)
            first_changed = h;
    }

    if (first_changed <= tip_h)
        chain_restore_recompute_active_suffix(c, first_changed, tip_h);

    if (relinked > 0) {
        LOG_WARN("chain_restore",
                 "rebuild_active_chain: relinked active slot parents "
                 "relinked=%d first_h=%d",
                 relinked, first_changed <= tip_h ? first_changed : -1);
    }

    return relinked;
}

int chain_restore_repair_active_projection(struct active_chain *c, int tip_h)
{
    return chain_restore_relabel_wrong_height_parents(c, tip_h)
         + chain_restore_relink_active_slot_parents(c, tip_h);
}
