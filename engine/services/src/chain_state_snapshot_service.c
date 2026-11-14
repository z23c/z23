/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only projections split from chain_state_service.c so mutation policy
 * stays small and diagnostics reuse one repository-owned capture boundary. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* pthread_timedjoin_np via platform/thread_compat.h */
#endif

#include "services/chain_state_service.h"
#include "chain_state_internal.h"

#include "coins/coins_view.h"
#include "models/database.h"
#include "platform/thread_compat.h"
#include "storage/progress_store.h"

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <time.h>

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

/* Bounded csr->lock acquisition for the non-blocking observer: a holder that
 * waits on progress_store_tx_lock (csr_commit_tip / csr_clear_active_tip take
 * CSR, then PS) can itself be parked behind an ingest, so waiting on CSR can
 * be a transitive wait on the ingest.  Wait at most this long. */
#define CSR_SNAPSHOT_BOUNDED_WAIT_NS 50000000L

static bool csr_lock_bounded(struct chain_state_repository *csr)
{
    return platform_mutex_lock_bounded_ns(&csr->lock, CSR_SNAPSHOT_BOUNDED_WAIT_NS);
}

/* Try-enter the node.db connection mutex (serialized build: the shared
 * connection's mutex is recursive and an ingest statement can hold it for a
 * long time).  While held, every sqlite call the observer makes on this
 * connection re-enters it without waiting.  A busy mutex answers EBUSY.  A
 * missing/closed db needs no mutex: *token stays NULL and the answer is ok. */
struct zcl_result csr_ndb_try_enter(struct node_db *ndb, void **token)
{
    *token = NULL;
    if (!ndb || !ndb->open || !ndb->db)
        return ZCL_OK;
    sqlite3_mutex *mu = sqlite3_db_mutex(ndb->db);
    if (!mu)
        return ZCL_OK;
    if (sqlite3_mutex_try(mu) != SQLITE_OK)
        return ZCL_ERR(EBUSY, "node.db connection mutex busy (an ingest "
                              "statement owns it)");
    *token = mu;
    return ZCL_OK;
}

void csr_ndb_leave(void *token)
{
    if (token)
        sqlite3_mutex_leave((sqlite3_mutex *)token);
}

/* Copy repository-owned memory under csr->lock (caller holds it). */
static struct node_db *csr_snapshot_copy_locked(
    struct chain_state_repository *csr, struct chain_state_view *out,
    struct active_chain **chain)
{
    *chain = csr->chain_active;
    if (csr->pindex_best_hdr && *csr->pindex_best_hdr)
        out->header_height = (*csr->pindex_best_hdr)->nHeight;
    if (csr->coins_tip)
        coins_view_cache_get_best_block(csr->coins_tip,
                                        &out->coins_best_block);
    out->commits_ok = csr->commits_ok;
    for (int i = 0; i < CSR_NUM_RESULTS; i++)
        out->commits_rejected_total += csr->commits_rejected[i];
    return csr->ndb;
}

static void csr_snapshot_tip(struct active_chain *chain, struct chain_state_view *out)
{
    if (!chain) return;
    int height = active_chain_height(chain);
    struct block_index *tip = active_chain_at(chain, height);
    if (!tip || !tip->phashBlock || tip->nHeight != height) return;
    out->tip_height = height;
    out->tip_hash = *tip->phashBlock;
    out->consistent = memcmp(out->tip_hash.data, out->coins_best_block.data, 32) == 0;
}

static void csr_snapshot_view_reset(struct chain_state_view *out)
{
    memset(out, 0, sizeof(*out));
    out->tip_height = -1;
    out->header_height = -1;
    out->utxo_count = -1;
    out->sql_max_height = -1;
}

void csr_snapshot(struct chain_state_repository *csr,
                  struct chain_state_view *out)
{
    struct node_db *ndb = NULL;
    struct active_chain *chain = NULL;

    if (!out)
        return;
    csr_snapshot_view_reset(out);
    if (!csr || !csr->initialized)
        return;

    /* LOCK-ORDER LAW: reducer stages hold progress_store_tx_lock before they
     * publish through the CSR.  Copy only repository-owned memory while this
     * mutex is held.  The external progress.kv/node.db observations below run
     * after unlock, otherwise health/agent snapshotting creates the inverse
     * csr->progress edge and deadlocks the reducer. active_chain_height is
     * one of those observations: it reads tip_finalize_log under
     * progress_store_tx_lock. */
    pthread_mutex_lock(&csr->lock);
    ndb = csr_snapshot_copy_locked(csr, out, &chain);
    pthread_mutex_unlock(&csr->lock);

    /* These projection counts are independent point-in-time observations;
     * they are intentionally not atomic with the in-memory frontier copy.
     * The active chain object has process lifetime. */
    csr_snapshot_tip(chain, out);
    /* Introspection must not compete for progress_store_tx_lock with a reducer
     * batch. The canonical coins_kv count is used by commit validation, while
     * this field's public contract is the rebuildable node.db projection. */
    out->utxo_count = ndb ? node_db_utxo_count(ndb) : -1;
    out->sql_max_height = csr_internal_sqlite_max_block_height(ndb);
}

struct zcl_result csr_snapshot_bounded(struct chain_state_repository *csr,
                                       struct chain_state_view *out)
{
    struct node_db *ndb = NULL;
    struct active_chain *chain = NULL;

    if (!out)
        return ZCL_ERR(EINVAL, "csr_snapshot_bounded: no view to fill");
    csr_snapshot_view_reset(out);
    if (!csr || !csr->initialized)
        return ZCL_OK;

    /* csr->lock is taken with a deadline and released BEFORE the progress
     * store is touched: never PS while holding CSR, never CSR while holding
     * PS (csr_commit_tip / csr_clear_active_tip take CSR then PS). */
    if (!csr_lock_bounded(csr))
        return ZCL_ERR(EBUSY, "chain state lock busy past its bound");
    ndb = csr_snapshot_copy_locked(csr, out, &chain);
    pthread_mutex_unlock(&csr->lock);

    /* active_chain_height reads tip_finalize_log under the (blocking,
     * recursive) progress-store lock.  Take that lock with a try and HOLD it
     * for just that call: while held, the callee's own acquisition is a
     * recursive no-wait, and no CSR/other lock is taken inside, so an ingest
     * cannot slip in between the check and the use.  Busy means an ingest
     * owns it: answer busy, never queue. */
    if (chain) {
        if (!progress_store_tx_trylock())
            return ZCL_ERR(EBUSY, "progress store busy (an ingest owns it)");
        csr_snapshot_tip(chain, out);
        progress_store_tx_unlock();
    }
    /* utxo_count is not part of any bounded observation: its COUNT(*) scan
     * is skipped (left at -1) instead of racing the ingest's writes.  The
     * sql_max read goes through the shared node.db connection, whose mutex an
     * ingest statement can hold for long: try-enter it, busy answers EBUSY. */
    void *ndb_token = NULL;
    struct zcl_result entered = csr_ndb_try_enter(ndb, &ndb_token);
    if (!entered.ok)
        return entered;
    out->sql_max_height = csr_internal_sqlite_max_block_height(ndb);
    csr_ndb_leave(ndb_token);
    return ZCL_OK;
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
