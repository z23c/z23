/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only projections split from chain_state_service.c so mutation policy
 * stays small and diagnostics reuse one repository-owned capture boundary. */

#include "services/chain_state_service.h"
#include "chain_state_internal.h"

#include "coins/coins_view.h"
#include "models/database.h"
#include <string.h>

struct zcl_result csr_commit_tip_result(
    struct chain_state_repository *csr,
    const struct chain_state_commit *commit)
{
    enum csr_result rc = csr_commit_tip(csr, commit);
    if (rc == CSR_OK)
        return ZCL_OK;
    return ZCL_ERR(-(1000 + (int)rc), "csr_commit_tip: %s reason=%s",
                   csr_result_name(rc),
                   commit && commit->reason ? commit->reason : "");
}

void csr_snapshot(struct chain_state_repository *csr,
                  struct chain_state_view *out)
{
    struct node_db *ndb = NULL;

    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->tip_height = -1;
    out->header_height = -1;
    out->utxo_count = -1;
    out->sql_max_height = -1;
    if (!csr || !csr->initialized)
        return;

    /* LOCK-ORDER LAW: reducer stages hold progress_store_tx_lock before they
     * publish through the CSR.  Copy only repository-owned memory while this
     * mutex is held.  The external progress.kv/node.db observations below run
     * after unlock, otherwise health/agent snapshotting creates the inverse
     * csr->progress edge and deadlocks the reducer. */
    pthread_mutex_lock(&csr->lock);
    if (csr->chain_active) {
        out->tip_height = active_chain_height(csr->chain_active);
        struct block_index *tip = active_chain_cached_tip(csr->chain_active);
        if (tip && tip->phashBlock)
            out->tip_hash = *tip->phashBlock;
    }
    if (csr->pindex_best_hdr && *csr->pindex_best_hdr)
        out->header_height = (*csr->pindex_best_hdr)->nHeight;
    if (csr->coins_tip)
        coins_view_cache_get_best_block(csr->coins_tip,
                                        &out->coins_best_block);
    out->consistent = memcmp(out->tip_hash.data,
                             out->coins_best_block.data, 32) == 0;
    out->commits_ok = csr->commits_ok;
    for (int i = 0; i < CSR_NUM_RESULTS; i++)
        out->commits_rejected_total += csr->commits_rejected[i];
    ndb = csr->ndb;
    pthread_mutex_unlock(&csr->lock);

    /* These projection counts are independent point-in-time observations;
     * they are intentionally not atomic with the in-memory frontier copy. */
    /* Introspection must not compete for progress_store_tx_lock with a reducer
     * batch. The canonical coins_kv count is used by commit validation, while
     * this field's public contract is the rebuildable node.db projection. */
    out->utxo_count = ndb ? node_db_utxo_count(ndb) : -1;
    out->sql_max_height = csr_internal_sqlite_max_block_height(ndb);
}

int64_t csr_header_height(struct chain_state_repository *csr)
{
    int64_t height = -1;
    if (!csr || !csr->initialized)
        return -1; /* raw-return-ok:sentinel */
    pthread_mutex_lock(&csr->lock);
    if (csr->pindex_best_hdr && *csr->pindex_best_hdr)
        height = (*csr->pindex_best_hdr)->nHeight;
    pthread_mutex_unlock(&csr->lock);
    return height;
}

struct block_index *csr_header_tip_snapshot(struct chain_state_repository *csr)
{
    struct block_index *tip = NULL;
    if (!csr || !csr->initialized)
        return NULL;
    pthread_mutex_lock(&csr->lock);
    if (csr->pindex_best_hdr)
        tip = *csr->pindex_best_hdr;
    pthread_mutex_unlock(&csr->lock);
    return tip;
}

uint64_t csr_header_generation(const struct chain_state_repository *csr)
{
    return csr ? atomic_load(&csr->header_generation) : 0;
}

struct zcl_result csr_capture_frontiers(
    struct chain_state_repository *csr,
    struct active_chain *expected_chain,
    struct block_index **expected_header_slot,
    int requested_height,
    struct chain_state_frontier_view *out)
{
    if (!out)
        return ZCL_ERR(-1, "capture_frontiers: null out requested_height=%d",
                       requested_height);
    memset(out, 0, sizeof(*out));
    out->window.height = -1;
    out->window.requested_height = requested_height;
    if (!csr)
        return ZCL_ERR(-2, "capture_frontiers: null csr requested_height=%d",
                       requested_height);

    pthread_mutex_lock(&csr->lock);
    out->initialized = csr->initialized;
    out->bound_to_expected_state = csr->initialized &&
        csr->chain_active == expected_chain &&
        csr->pindex_best_hdr == expected_header_slot;
    bool captured = false;
    if (out->bound_to_expected_state) {
        captured = active_chain_capture_window(
            csr->chain_active, requested_height, &out->window);
        if (csr->pindex_best_hdr)
            out->header_tip = *csr->pindex_best_hdr;
    }
    pthread_mutex_unlock(&csr->lock);
    if (!captured)
        return ZCL_ERR(-3,
                       "capture_frontiers: not captured requested_height=%d "
                       "initialized=%d bound_to_expected_state=%d",
                       requested_height, out->initialized,
                       out->bound_to_expected_state);
    return ZCL_OK;
}
