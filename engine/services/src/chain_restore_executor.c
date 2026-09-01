// one-result-type-ok:pure-predicate — chain_restore_index_verified_consistent is a total, side-effect-free boolean question (index clean over a non-trivial size) with no failure path; the fallible service surfaces in this file already return struct zcl_result.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain restore executor - applies verified restore plans to mutable chain
 * state through the chain-state repository. */

#include "services/chain_restore_executor.h"
#include "services/chain_restore_planner.h"
#include "services/chain_restore_repair.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "net/snapshot_sync_contract.h"
#include "models/db_txn.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct zcl_result chain_restore_commit_tip_via_csr(struct main_state *ms,
                                                   struct block_index *target,
                                                   bool update_header_tip,
                                                   const char *reason)
{
    if (!ms || !target || !target->phashBlock)
        return ZCL_ERR(-1, "chain_restore: null arg (ms=%p target=%p phash=%p)",
                       (void *)ms, (void *)target,
                       target ? (void *)target->phashBlock : NULL);

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_RESTORE,
        .decision = POLICY_ALLOW,
        .from_height = active_chain_height(&ms->chain_active),
        .to_height = target->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "restore_plan_verified",
        .reason = reason ? reason : "chain_restore",
    };
    struct chain_state_commit commit = {
        .new_tip             = target,
        .new_coins_best      = *target->phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip   = update_header_tip,
        .rollback_auth       = &rollback_auth,
        .wallet_scan_height  = -1,
        .reason              = reason ? reason : "chain_restore",
    };

    struct chain_state_repository *csr = csr_instance();
    enum csr_result rc = csr_commit_tip(csr, &commit);
    if (rc == CSR_OK)
        return ZCL_OK;

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED) {
        (void)chain_set_active_tip(ms, target, TIP_FROM_RESTORE,
                             reason ? reason : "csr_uninit_fallback");
        if (update_header_tip)
            ms->pindex_best_header = target;
        return ZCL_OK;
    }
#endif

    LOG_WARN("chain_restore", "chain_restore: csr rejected tip commit (%s) reason=%s h=%d", csr_result_name(rc), reason ? reason : "", target->nHeight);
    return ZCL_ERR((int)rc,
                   "csr rejected tip commit (%s) reason=%s h=%d",
                   csr_result_name(rc), reason ? reason : "",
                   target->nHeight);
}

struct zcl_result chain_restore_commit_header_via_csr(struct main_state *ms,
                                                      struct block_index *target,
                                                      const char *reason)
{
    if (!ms || !target || !target->phashBlock)
        return ZCL_ERR(-1, "chain_restore: null arg (ms=%p target=%p phash=%p)",
                       (void *)ms, (void *)target,
                       target ? (void *)target->phashBlock : NULL);

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_RESTORE,
        .decision = POLICY_ALLOW,
        .from_height = ms->pindex_best_header
            ? ms->pindex_best_header->nHeight : -1,
        .to_height = target->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "restore_header_verified",
        .reason = reason ? reason : "chain_restore.header",
    };
    struct chain_state_header_commit commit = {
        .new_header_tip = target,
        .rollback_auth = &rollback_auth,
        .reason = reason ? reason : "chain_restore.header",
    };

    enum csr_result rc = csr_commit_header_tip(csr_instance(), &commit);
    if (rc == CSR_OK)
        return ZCL_OK;

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED) {
        ms->pindex_best_header = target;
        return ZCL_OK;
    }
#endif

    LOG_WARN("chain_restore", "chain_restore: csr rejected header commit (%s) reason=%s h=%d", csr_result_name(rc), reason ? reason : "", target->nHeight);
    return ZCL_ERR((int)rc,
                   "csr rejected header commit (%s) reason=%s h=%d",
                   csr_result_name(rc), reason ? reason : "",
                   target->nHeight);
}

struct block_index *chain_restore_create_anchor(
    struct main_state *ms,
    const struct uint256 *hash,
    int height)
{
    if (!ms || !hash || height <= 0)
        LOG_NULL("chain_restore", "create_anchor called with null ms/hash or height=%d", height);

    struct block_index *anchor = zcl_calloc(1, sizeof(struct block_index), "chain_restore anchor");
    if (!anchor)
        LOG_NULL("chain_restore", "calloc failed for anchor block_index at h=%d", height);

    block_index_init(anchor);
    anchor->nHeight = height;
    anchor->nStatus = BLOCK_VALID_UNKNOWN;
    anchor->nChainTx = 0;
    anchor->nTx = 0;
    arith_uint256_set_zero(&anchor->nChainWork);

    /* Option A: anchor owns its hash in per-node storage (anchor is a
     * heap block_index, so &anchor->hashBlock is stable for its lifetime).
     * Seed before publishing into the map. */
    anchor->hashBlock = *hash;
    anchor->phashBlock = &anchor->hashBlock;

    if (!block_map_insert(&ms->map_block_index, hash, anchor)) {
        free(anchor);
        return NULL;
    }

    return anchor;
}

struct block_index *chain_restore_execute(
    const struct chain_restore_plan *plan,
    struct main_state *ms)
{
    if (!plan || !ms)
        LOG_NULL("chain_restore", "execute called with null plan or main_state");

    if (plan->next_state == CHAIN_RESTORE_FAILED)
        return NULL;

    struct block_index *target = NULL;

    if (plan->should_create_anchor) {
        target = chain_restore_create_anchor(
            ms, &plan->anchor_hash, plan->anchor_height);
        if (!target)
            LOG_NULL("chain_restore", "anchor creation failed at h=%d",
                     plan->anchor_height);
        printf("Chain restore: anchor at h=%d\n", plan->anchor_height);
    } else if (plan->next_state == CHAIN_RESTORE_FOUND_IN_INDEX) {
        target = block_map_find(&ms->map_block_index, &plan->anchor_hash);
        if (!target)
            LOG_NULL("chain_restore", "hash in plan but not in block_map");
    }

    if (!target)
        return NULL;

    /* Route the tip/header mutations through the chain_state_repository
     * so block_map, active_chain, coins_tip and pindex_best_header
     * move through the single concrete-state boundary. */
    if (plan->should_set_chain_tip && target->phashBlock) {
        struct chain_state_repository *csr = csr_instance();
        struct node_db *cr_ndb = (csr && csr->initialized) ? csr->ndb : NULL;

        if (cr_ndb && cr_ndb->open) {
            DB_TXN_SCOPE(txn, cr_ndb, "chain_restore.execute");
            if (!txn) {
                fprintf(stderr,
                    "chain_restore: failed to open db_txn scope\n");
                return NULL;
            }
            struct zcl_result r = chain_restore_commit_tip_via_csr(
                    ms, target, plan->should_set_best_header,
                    "chain_restore.execute");
            if (!r.ok) {
                /* Scope auto-rollback fires on return. */
                return NULL;
            }
            if (!db_txn_commit(txn))
                return NULL;
        } else {
            struct zcl_result r = chain_restore_commit_tip_via_csr(
                       ms, target, plan->should_set_best_header,
                       "chain_restore.execute");
            if (!r.ok)
                return NULL;
        }
    } else if (plan->should_set_best_header) {
        /* Extremely rare: plan asked for header-only update with no
         * chain tip change. Preserve legacy behaviour. */
        struct zcl_result r = chain_restore_commit_header_via_csr(
                ms, target, "chain_restore.header_only");
        if (!r.ok) {
            return NULL;
        }
    }

    if (plan->should_set_snapshot_anchor)
        snapsync_set_anchor(target);

    /* Post-restore finalize — rebuild active_chain from pprev + block_map
     * and surface the integrity result. Unit tests pass
     * datadir implicitly via the NULL path (skips disk-backfill); real
     * boot paths call chain_restore_finalize directly with a datadir. */
    /* discard result — boot finalize at top level handles propagation */
    (void)chain_restore_finalize(ms, NULL);

    return target;
}

bool chain_restore_index_verified_consistent(int index_repaired,
                                             size_t index_size)
{
    return index_repaired == 0 && index_size > 1000;
}

struct zcl_result chain_restore_finalize_verified(struct main_state *ms,
                                                  const char *datadir,
                                                  int index_repaired,
                                                  size_t index_size)
{
    /* Boot fast path: when the block-index repair passes just proved the
     * in-memory index fully consistent (index_repaired == 0 over a
     * non-trivial index) and the SHA3 sidecar has verified it, the disk-backed
     * active_chain rebuild inside chain_restore_finalize is pure waste. That
     * rebuild re-reads every block header from disk (3M+ reads) and, on any
     * single stale read, falls all the way back to a full multi-GB block-file
     * rescan — measured at ~74s of pre-RPC-bind wall time on a fresh 2-step
     * datadir, over half the whole boot — only to re-confirm a chain the
     * in-memory pprev walk can slot in O(tip). Enable the trust fastpath for
     * THIS finalize call so it takes the pprev walk; the post-restore
     * integrity check inside finalize stays the fail-safe. The flag is scoped
     * to this call and cleared immediately, so the chain_integrity_failed
     * remedy keeps its authoritative disk rebuild, and we never disturb a
     * fast-restart binding that already set the flag. */
    bool trust = (chain_restore_index_verified_consistent(index_repaired,
                                                          index_size) &&
                  !chain_restore_trust_index_fastpath());
    if (trust) {
        printf("[chain-restore] index verified consistent (0 repairs, %zu "
               "entries) — finalize trusting in-memory pprev walk, skipping "
               "disk header re-read + block-file rescan\n", index_size);
        fflush(stdout);
        chain_restore_set_trust_index_fastpath(true);
    }
    struct zcl_result r = chain_restore_finalize(ms, datadir);
    if (trust)
        chain_restore_set_trust_index_fastpath(false);
    return r;
}
