/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Bulk node database catch-up coordinates block indexing, wallet scanning,
 * witness advancement, transaction commits and turbo-mode teardown.
 * Decryption and lock-contention recovery live in their dedicated services. */

// one-result-type-ok:recovery-primitive-int — the catchup job consumes the
// indexed block count or -1 on setup failure; failures are logged before return.

#include "platform/time_compat.h"
#include "controllers/sync_controller.h"
#include "services/node_db_catchup_service.h"
#include "services/node_db_catchup_lock_guard.h"
#include "config/db_service.h"
#include "services/db_maintenance.h"
#include "node_db_catchup_internal.h"
#include "util/boot_progress.h"
#include "models/db_txn.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/explorer_index.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "chain/chain.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "keys/key.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "core/utiltime.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "storage/dbwrapper.h"
#include "storage/coins_db.h"
#include "coins/undo.h"
#include "validation/chainstate.h"
#include "validation/connect_block.h"
#include "validation/txmempool.h"
#include "validation/process_block.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "support/cleanse.h"
#include "event/event.h"
#include "config/runtime.h"
#include "jobs/refold_progress.h"
#include "services/invariant_sentinel.h"
#include "storage/progress_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include <signal.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include <errno.h>

extern volatile sig_atomic_t g_shutdown_requested;

#define SYNC_PROJECTION_TIP_HASH_KEY   "sync_projection_tip_hash"
#define SYNC_PROJECTION_TIP_HEIGHT_KEY "sync_projection_tip_height"

/* ── Sync-controller helpers reached by forward declaration ──
 * These are defined in the sync_controller_*.c siblings and declared in
 * the controller-private sync_controller_internal.h (which is not on the
 * services include path). The catchup body calls them but does not own
 * them; their declarations are mirrored here verbatim so the contract is
 * a single source of truth. */
struct sync_db_turbo_scope {
    struct node_db *ndb;
    bool entered;
};

bool sync_db_turbo_scope_begin(struct sync_db_turbo_scope *scope,
                               struct node_db *ndb,
                               bool enabled);
bool sync_db_turbo_scope_end(struct sync_db_turbo_scope *scope);

void sync_job_catchup_begin(int start_height, int target_height);
void sync_job_catchup_progress(int height);
void sync_job_catchup_finish(void);

bool node_db_sync_wallet_tx_checked(struct node_db *ndb,
                                    const struct transaction *tx,
                                    const struct wallet *w,
                                    int block_height,
                                    bool *is_ours_out,
                                    bool *success_out);

bool advance_wallet_witnesses(struct node_db *ndb,
                              const struct block *blk,
                              struct incremental_merkle_tree *tree,
                              int height, struct wallet *wallet);

/* ── "A catchup walk is running" ──────────────────────────────────────
 *
 * db_maintenance asks this before taking the node.db write lock for its
 * periodic wal/analyze/vacuum op, because that op is what pushes this
 * walk's post-commit BEGIN IMMEDIATE past its 10 s busy timeout. A depth
 * counter rather than a flag so the bounded whole-walk restart (which
 * re-enters node_db_catchup_service_run) nests cleanly. Incremented and
 * decremented in lockstep with the sync-controller's own catchup job
 * status, through the two wrappers below — every begin has exactly one
 * finish on every return path. */
static _Atomic int g_catchup_active_depth = 0;

bool node_db_catchup_service_active(void)
{
    return atomic_load(&g_catchup_active_depth) > 0;
}

static void catchup_active_begin(int start_height, int target_height)
{
    atomic_fetch_add(&g_catchup_active_depth, 1);
    sync_job_catchup_begin(start_height, target_height);
}

static void catchup_active_finish(void)
{
    atomic_fetch_sub(&g_catchup_active_depth, 1);
    sync_job_catchup_finish();
}

/* The serialized writer whose worker thread runs this walk, or NULL when the
 * walk runs on a plain thread. */
static struct db_service *catchup_db_service(const struct node_db *ndb)
{
    struct db_service *svc = app_runtime_db_service();
    return svc && db_service_is_started(svc) &&
           db_service_node_db(svc) == ndb ? svc : NULL;
}

#ifdef ZCL_TESTING
/* Reopen-retry fixtures — see node_db_catchup_service.h. */
static _Atomic int  g_test_reopen_busy_armed = 0;
static _Atomic int  g_test_reopen_attempts = 0;
static _Atomic bool g_test_reopen_no_backoff = false;

void node_db_catchup_test_force_reopen_busy(int n)
{
    atomic_store(&g_test_reopen_busy_armed, n > 0 ? n : 0);
    atomic_store(&g_test_reopen_no_backoff, n > 0);
}

int node_db_catchup_test_reopen_attempts(void)
{
    return atomic_load(&g_test_reopen_attempts);
}

void node_db_catchup_test_set_active(bool active)
{
    atomic_store(&g_catchup_active_depth, active ? 1 : 0);
}

int node_db_catchup_test_active_depth(void)
{
    return atomic_load(&g_catchup_active_depth);
}

/* Runs once, right after a pass enters turbo mode and before its first
 * BEGIN IMMEDIATE: the window in which another writer can open a transaction
 * on the shared connection. */
static void (*g_test_after_turbo_hook)(struct node_db *ndb);

void node_db_catchup_test_set_after_turbo_hook(void (*hook)(struct node_db *))
{
    g_test_after_turbo_hook = hook;
}

static void catchup_test_after_turbo(struct node_db *ndb)
{
    void (*hook)(struct node_db *) = g_test_after_turbo_hook;
    g_test_after_turbo_hook = NULL;
    if (hook)
        hook(ndb);
}

void node_db_catchup_test_reset_reopen(void)
{
    atomic_store(&g_test_reopen_busy_armed, 0);
    atomic_store(&g_test_reopen_attempts, 0);
    atomic_store(&g_test_reopen_no_backoff, false);
    atomic_store(&g_catchup_active_depth, 0);
}
#endif

/* One BEGIN IMMEDIATE attempt on the post-commit reopen path. Under
 * ZCL_TESTING an armed injection fails the attempt exactly as a plain
 * SQLITE_BUSY would, without touching the handle — so the retry plumbing
 * runs for real against a database that is not actually locked. */
static bool catchup_reopen_attempt(struct node_db *ndb)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_reopen_attempts, 1);
    int armed = atomic_load(&g_test_reopen_busy_armed);
    while (armed > 0) {
        if (atomic_compare_exchange_weak(&g_test_reopen_busy_armed,
                                         &armed, armed - 1))
            return false;
    }
#endif
    return node_db_begin_immediate(ndb);
}

/* Backoff before retry number `attempt` (1-based): BASE doubled per prior
 * retry, capped at MAX. */
static int catchup_reopen_backoff_ms(int attempt)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_test_reopen_no_backoff))
        return 0;
#endif
    int ms = NODE_DB_CATCHUP_REOPEN_BACKOFF_BASE_MS;
    for (int i = 1; i < attempt && ms < NODE_DB_CATCHUP_REOPEN_BACKOFF_MAX_MS;
         i++)
        ms *= 2;
    return ms > NODE_DB_CATCHUP_REOPEN_BACKOFF_MAX_MS
        ? NODE_DB_CATCHUP_REOPEN_BACKOFF_MAX_MS : ms;
}

/* Reopen the batch transaction after a clean COMMIT, surviving a transient
 * SQLITE_BUSY (see the policy comment in node_db_catchup_service.h).
 * Returns true with a write transaction open. On false the caller keeps
 * the unchanged fail-closed abort; *busy_snapshot_out is set when the
 * failure carried the one class no wait can cure, so the whole-walk
 * restart guard answers it instead of this loop. */
static bool catchup_reopen_batch_txn(struct node_db *ndb, int h,
                                     bool *busy_snapshot_out)
{
    for (int attempt = 1; attempt <= NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS;
         attempt++) {
        if (catchup_reopen_attempt(ndb))
            return true;
        if (node_db_catchup_lock_guard_busy_snapshot(ndb)) {
            *busy_snapshot_out = true;
            return false;
        }
        if (attempt > NODE_DB_CATCHUP_REOPEN_MAX_RETRIES)
            break;
        LOG_WARN("catchup",
                 "catchup: reopen busy, retry %d/%d (height %d)",
                 attempt, NODE_DB_CATCHUP_REOPEN_MAX_RETRIES, h);
        platform_sleep_ms(catchup_reopen_backoff_ms(attempt));
    }
    return false;
}

/* Lean index: block header + txid index + the full explorer projections.
 *
 * Per-block write order: stamp the txid index rows (transactions table),
 * run the single per-block explorer hook (explorer_index_block, which
 * writes tx_outputs/inputs/op_returns/sapling/joinsplits/sprout_nullifiers
 * + the chained view_integrity receipt), compute the per-block shielded
 * values using the consensus helper, THEN db_block_save_canonical.
 * prev_receipt carries the previous height's receipt
 * forward across the ascending catchup walk (NULL/zeros at genesis);
 * out_receipt receives this height's receipt for the next iteration.
 *
 * The explorer hook never gates this path: it touches node.db only and a
 * projection save failure is a degraded explorer row, logged and skipped,
 * never an abort. */
static bool sync_block_lean(struct node_db *ndb,
                            const struct block *blk,
                            const struct block_index *pindex,
                            const uint8_t prev_receipt[32],
                            uint8_t out_receipt[32])
{
    if (!ndb || !ndb->open || !blk || !pindex || !pindex->phashBlock)
        LOG_FAIL("sync", "sync_block_lean: invalid args (ndb=%p, blk=%p, pindex=%p, hash=%p)",
                 (void *)ndb, (void *)blk, (void *)pindex,
                 (const void *)(pindex ? pindex->phashBlock : NULL));

    struct db_block db_blk;
    memset(&db_blk, 0, sizeof(db_blk));
    memcpy(db_blk.hash, pindex->phashBlock->data, 32);
    db_blk.height = pindex->nHeight;
    /* Get prev_hash from block header (always available) rather than
     * pprev pointer (may be NULL if block_index has gaps) */
    memcpy(db_blk.prev_hash, blk->header.hashPrevBlock.data, 32);
    db_blk.version = blk->header.nVersion;
    memcpy(db_blk.merkle_root,
           blk->header.hashMerkleRoot.data, 32);
    db_blk.time = blk->header.nTime;
    db_blk.bits = blk->header.nBits;
    memcpy(db_blk.nonce, blk->header.nNonce.data, 32);
    db_blk.solution = (uint8_t *)blk->header.nSolution;
    db_blk.solution_len = blk->header.nSolutionSize;
    memcpy(db_blk.chain_work, pindex->nChainWork.pn, 32);
    db_blk.status = pindex->nStatus;
    if ((db_blk.status & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS)
        db_blk.status = (db_blk.status & ~BLOCK_VALID_MASK) |
                        BLOCK_VALID_TRANSACTIONS;
    db_blk.status |= BLOCK_HAVE_DATA;
    db_blk.file_num = pindex->nFile;
    db_blk.data_pos = (int)pindex->nDataPos;
    db_blk.num_tx = (int)blk->num_vtx;

    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];

        struct db_tx_index db_tx;
        memset(&db_tx, 0, sizeof(db_tx));
        memcpy(db_tx.txid, tx->hash.data, 32);
        memcpy(db_tx.block_hash, pindex->phashBlock->data, 32);
        db_tx.block_height = pindex->nHeight;
        db_tx.tx_index = (int)i;
        db_tx.file_num = pindex->nFile;
        db_tx.file_pos = (int)pindex->nDataPos;
        db_tx.is_coinbase = (i == 0);
        if (!db_tx_save(ndb, &db_tx))
            LOG_FAIL("sync", "sync_block_lean: db_tx_save failed at height %d tx %zu",
                     pindex->nHeight, i);
    }

    /* Explorer receipt values retain their existing sign convention. */
    if (!explorer_index_block(ndb, blk, pindex, prev_receipt, out_receipt,
                              NULL, NULL))
        LOG_WARN("catchup", "sync_block_lean: explorer projections failed at "
                 "height %d (continuing — degraded explorer row, not fatal)",
                 pindex->nHeight);
    connect_block_shielded_values(blk, &db_blk.sprout_value,
                                  &db_blk.sapling_value);

    if (!db_block_save_canonical(ndb, &db_blk))
        LOG_FAIL("sync", "sync_block_lean: db_block_save_canonical failed at height %d",
                 pindex->nHeight);

    return true;
}

static bool catchup_set_sparse_projection_tip(struct node_db *ndb,
                                              const uint8_t hash[32],
                                              int height)
{
    if (!ndb || !ndb->open || !hash)
        LOG_FAIL("catchup",
                 "sparse projection tip: invalid args (ndb=%p, hash=%p)",
                 (void *)ndb, (const void *)hash);
    if (!invariant_sentinel_check_pair(ndb, hash, height,
                                       "sparse_projection_tip"))
        return false;
    return node_db_state_set(ndb, SYNC_PROJECTION_TIP_HASH_KEY, hash, 32) &&
           node_db_state_set_int(ndb, SYNC_PROJECTION_TIP_HEIGHT_KEY,
                                 (int64_t)height);
}

/* Try-decrypt Sapling outputs into SQLite moved to
 * node_db_catchup_decrypt.c (E1 file-size ratchet); the walk calls
 * node_db_catchup_try_sapling_decrypt via node_db_catchup_internal.h. */

/* Lean-hole bookkeeping for one walk. The counters are only advanced by the
 * catchup_hole_* helpers; the walk keeps every log call itself. */
struct catchup_holes {
    int lean;
    int first_h;
    int missing_index;
    int first_missing_index_h;
    int missing_data;
    int missing_file;
    int first_missing_file_h;
    int first_missing_file_num;
    int suspicious;
    int skip_file;
};

static void catchup_hole_note(struct catchup_holes *hl, int h)
{
    if (++hl->lean == 1)
        hl->first_h = h;
}

/* Returns true while the caller should still log this hole class. */
static bool catchup_hole_missing_index(struct catchup_holes *hl, int h)
{
    catchup_hole_note(hl, h);
    hl->missing_index++;
    if (hl->first_missing_index_h < 0)
        hl->first_missing_index_h = h;
    return hl->missing_index <= 3;
}

static bool catchup_hole_missing_data(struct catchup_holes *hl, int h)
{
    catchup_hole_note(hl, h);
    hl->missing_data++;
    return hl->missing_data <= 3;
}

static bool catchup_hole_suspicious(struct catchup_holes *hl, int h)
{
    catchup_hole_note(hl, h);
    hl->suspicious++;
    return hl->lean <= 3;
}

/* Returns true when the caller should log the mapping failure. */
static bool catchup_hole_map_failed(struct catchup_holes *hl, int h,
                                    int nfile, int code)
{
    bool warn = false;
    hl->missing_file++;
    if (hl->first_missing_file_h < 0) {
        hl->first_missing_file_h = h;
        hl->first_missing_file_num = nfile;
    }
    if (code != ENOENT && code != ENOTDIR) {
        hl->suspicious++;
        warn = hl->suspicious <= 3;
    }
    hl->skip_file = nfile;
    catchup_hole_note(hl, h);
    return warn;
}

/* Swap the read-only mapping cache to `nfile`. */
static struct zcl_result catchup_map_file(
    struct node_db_catchup_block_mapping *cache, int *cached_file,
    const char *datadir, int nfile)
{
    node_db_catchup_block_mapping_close(cache);
    struct zcl_result mapped =
        node_db_catchup_block_mapping_open_quiet(cache, datadir, nfile);
    *cached_file = mapped.ok ? nfile : -1;
    return mapped;
}

enum catchup_frame_check {
    CATCHUP_FRAME_BOUND,
    CATCHUP_FRAME_HASH_MISMATCH,
    CATCHUP_FRAME_NO_INDEX_HASH,
};

static enum catchup_frame_check catchup_frame_check(
    const struct block *blk, const struct block_index *pindex)
{
    if (!pindex->phashBlock)
        return CATCHUP_FRAME_NO_INDEX_HASH;
    struct uint256 got;
    block_get_hash(blk, &got);
    return uint256_eq(&got, pindex->phashBlock)
        ? CATCHUP_FRAME_BOUND : CATCHUP_FRAME_HASH_MISMATCH;
}

enum catchup_wallet_scan {
    CATCHUP_WALLET_OK,
    CATCHUP_WALLET_TX_FAILED,
    CATCHUP_WALLET_DECRYPT_FAILED,
    CATCHUP_WALLET_SPEND_FAILED,
};

/* Wallet scan of one block. On a failure *tx_i / *spend_i name the
 * offending transaction / spend for the caller's log line. */
static enum catchup_wallet_scan catchup_scan_wallet_block(
    struct node_db *ndb, struct block *blk, struct wallet *w, int h,
    int *wallet_hits, size_t *tx_i, size_t *spend_i)
{
    if (!w)
        return CATCHUP_WALLET_OK;
    for (size_t i = 0; i < blk->num_vtx; i++) {
        *tx_i = i;
        bool tx_is_ours = false;
        bool tx_ok = false;
        if (!node_db_sync_wallet_tx_checked(ndb, &blk->vtx[i], w, h,
                                           &tx_is_ours, &tx_ok) || !tx_ok)
            return CATCHUP_WALLET_TX_FAILED;
        if (tx_is_ours)
            (*wallet_hits)++;
        bool decrypt_ok = true;
        node_db_catchup_try_sapling_decrypt(ndb, &blk->vtx[i], w, h,
                                            &decrypt_ok);
        if (!decrypt_ok)
            return CATCHUP_WALLET_DECRYPT_FAILED;
        for (size_t si = 0; si < blk->vtx[i].num_shielded_spend; si++) {
            struct transaction *mtx = (struct transaction *)&blk->vtx[i];
            transaction_compute_hash(mtx);
            /* Only ERROR is fatal; NOT_FOUND (not our note) is benign. */
            if (node_db_sync_sapling_spend(ndb,
                    blk->vtx[i].v_shielded_spend[si].nullifier.data,
                    mtx->hash.data) == DB_MARK_SPENT_ERROR) {
                *spend_i = si;
                return CATCHUP_WALLET_SPEND_FAILED;
            }
        }
    }
    return CATCHUP_WALLET_OK;
}

static int catchup_count_wallet_keys(const struct wallet *w)
{
    int wallet_keys = 0;
    if (w) {
        for (size_t i = 0; i < w->keystore.num_keys; i++)
            if (w->keystore.keys[i].used) wallet_keys++;
    }
    return wallet_keys;
}

/* Append block h to the persisted tree only when the tree covers h-1; an
 * already-covered or non-adjacent height is left to whoever owns the tree. */
static bool catchup_tree_step(struct node_db *ndb, const struct active_chain *chain,
                              const struct block *blk,
                              struct catchup_sapling_tree *ct, int h,
                              struct wallet *w)
{
    bool may = catchup_sapling_tree_prepare(ct, chain, h);
    catchup_sapling_tree_persist_dirty(ndb, ct);
    if (!may) {
        catchup_sapling_tree_note_skipped(ct, h);
        return true;
    }
    if (!advance_wallet_witnesses(ndb, blk, &ct->tree, h, w))
        return false; // raw-return-ok:caller logs the failed height
    catchup_sapling_tree_note_advanced(ct, h);
    return true;
}

/* Force the completion checkpoint when the tree covers the committed cursor. */
static void catchup_final_checkpoint(const struct catchup_sapling_tree *ct,
                                     const struct block_index *tip, int h)
{
    if (tip && tip->phashBlock && ct->height == h)
        sapling_tree_flat_checkpoint_note(&ct->tree, h,
                                          tip->phashBlock->data, true);
}

static void catchup_note_busy_snapshot(struct node_db *ndb, bool *busy_snapshot)
{
    if (node_db_catchup_lock_guard_busy_snapshot(ndb))
        *busy_snapshot = true;
}

/* Record the batch's last indexed block as the projection cursor. */
static bool catchup_set_batch_tip(struct node_db *ndb,
                                  const struct block_index *pindex, int h,
                                  bool *busy_snapshot)
{
    if (!pindex->phashBlock) {
        LOG_WARN("catchup", "catchup: missing hash at batch commit %d", h);
        return false;
    }
    if (node_db_sync_set_tip(ndb, pindex->phashBlock->data, h))
        return true;
    LOG_WARN("catchup", "catchup: failed to set tip at batch commit %d", h);
    catchup_note_busy_snapshot(ndb, busy_snapshot);
    return false;
}

/* The open batch plus the cursor facts needed to close it between heights. */
struct catchup_batch {
    int64_t t_start;
    int indexed_at_start;
    int last_committed_height;
    bool tx_open;
    bool busy_snapshot;
    bool bulk_mode;
};

/* Close the open batch once it has been held for the time cap, on any height:
 * BEGIN IMMEDIATE holds the write lock even with nothing written, and a
 * stretch of holes (absent or unreadable bodies) loops without reaching the
 * post-index commit check, so without this the lock would be held across the
 * whole stretch. A batch that holds rows first records the last indexed block
 * as the cursor (every height up to it is processed; holes are recorded, not
 * skipped silently); an empty batch just cycles. Then commit, yield, reopen.
 * The cap is also reached early, after NODE_DB_CATCHUP_WAITER_MIN_HOLD_MS,
 * while a detached writer is waiting (node_db_catchup_lock_guard_batch_due).
 * Returns false when the walk must abort; tx_open then says whether the
 * caller still owns an open transaction to roll back. */
static bool catchup_cycle_batch(struct node_db *ndb, int h, int indexed,
                                const struct block_index *tip, int tip_h,
                                struct catchup_batch *b)
{
    int64_t now = node_db_catchup_lock_guard_now_ms();
    if (!node_db_catchup_lock_guard_batch_due(now - b->t_start))
        return true;
    bool rows = indexed != b->indexed_at_start;
    if (rows && !catchup_set_batch_tip(ndb, tip, tip_h, &b->busy_snapshot))
        return false;
    if (!node_db_commit(ndb)) {
        LOG_WARN("catchup", "catchup: timed batch COMMIT failed at height %d", h);
        catchup_note_busy_snapshot(ndb, &b->busy_snapshot);
        node_db_rollback(ndb);
        b->tx_open = false;
        return false;
    }
    node_db_catchup_lock_guard_note_batch_commit();
    node_db_catchup_lock_guard_note_timed_commit(rows);
#ifdef ZCL_TESTING
    node_db_catchup_lock_guard_test_note_cycle(now);
#endif
    b->tx_open = false;
    b->indexed_at_start = indexed;
    if (rows)
        b->last_committed_height = tip_h;
    node_db_catchup_lock_guard_yield_to_writers(catchup_db_service(ndb),
                                                !b->bulk_mode);
    if (!catchup_reopen_batch_txn(ndb, h, &b->busy_snapshot)) {
        LOG_WARN("catchup", "catchup: failed to reopen transaction after timed batch");
        return false;
    }
    b->t_start = node_db_catchup_lock_guard_now_ms();
#ifdef ZCL_TESTING
    node_db_catchup_lock_guard_test_note_reopen(
        node_db_catchup_lock_guard_now_ms());
#endif
    b->tx_open = true;
    return true;
}

/* Failure tail shared by the three pre-walk transaction aborts. */

static void catchup_abort_pass(bool *restore_ok)
{
    *restore_ok = false;
    node_db_catchup_lock_guard_note_outcome(true);
    catchup_active_finish();
}

/* Post-commit work of one batch: bounded WAL checkpoint, flat-file Sapling
 * checkpoint, progress line. */
static void catchup_batch_committed(struct node_db *ndb, bool bulk_mode,
                                    const struct catchup_sapling_tree *ct,
                                    const struct block_index *pindex, int h,
                                    int indexed, int total, int wallet_hits,
                                    int64_t t_start)
{
    /* Turbo WAL bound: the bulk wal_autocheckpoint folds frames
     * rarely and the bulk journal_size_limit only caps the file
     * after a checkpoint — neither truncates a runaway WAL
     * mid-run, which is how single runs reached tens of GB.
     * The transaction just committed, so no write transaction
     * is open and the size-triggered checkpoint below can
     * actually move frames. Best-effort: a false return never
     * aborts the catchup. */
    if (bulk_mode)
        node_db_turbo_maybe_checkpoint(
            ndb, DB_MAINT_DEFAULT_WAL_MAX_BYTES);
    /* Persist the Sapling note-commitment frontier to the flat-file
     * checkpoint (rate-limited to every
     * SAPLING_CHECKPOINT_BLOCK_INTERVAL blocks). {h, block hash,
     * root} are self-consistent here: the tree was just advanced to
     * h by appending this block's outputs. A clean restart resumes
     * replay from this height instead of re-folding from Sapling
     * activation. */
    if (pindex->phashBlock && ct->height == h)
        sapling_tree_flat_checkpoint_note(&ct->tree, h,
                                          pindex->phashBlock->data,
                                          false);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    int rate = elapsed > 0 ? indexed / (int)elapsed : 0;
    printf("SQLite: %d/%d blocks (height %d, %d blk/s, %d wallet txs)\n",
           indexed, total, h, rate, wallet_hits);
    fflush(stdout);
}

/* Final-commit fallback for a walk that indexed nothing: advance the
 * projection cursor over a proven sparse prefix. Returns the new cursor
 * height, or -1 when no tip could be set. */
static int catchup_advance_sparse_tip(
    struct node_db *ndb, const struct active_chain *chain,
    const struct catchup_holes *hl, int indexed, int total, int start,
    int chain_tip, bool proven_authority, int32_t proven_applied)
{
    int sparse_target = node_db_catchup_sparse_prefix_target(
        indexed, total, hl->lean, hl->first_h, start, chain_tip,
        hl->suspicious, hl->missing_index,
        hl->first_missing_index_h, proven_authority, proven_applied);
    const struct block_index *sparse_tip = sparse_target >= start
        ? active_chain_at(chain, sparse_target) : NULL;
    if (sparse_tip && sparse_tip->phashBlock &&
        catchup_set_sparse_projection_tip(ndb,
                                          sparse_tip->phashBlock->data,
                                          sparse_target))
        return sparse_target;
    return -1; // raw-return-ok:caller logs "final commit missing tip hash" and fails the walk
}

static bool catchup_args_invalid(const struct node_db *ndb,
                                 const struct active_chain *chain)
{
    return !ndb || !ndb->open || !chain;
}

static bool catchup_pass_suppressed(void)
{
    /* Abort-streak park (node_db_catchup_lock_guard.c): after 8 consecutive
     * failed passes the worker parks behind the named blocker
     * "node_db_catchup.abort_storm" and every pass is a no-op until an
     * operator clears it — a pass that always fails must not be re-run
     * forever (each pass burns the 10 s busy timeout). Single chokepoint: both
     * call sites funnel through here. */
    if (node_db_catchup_lock_guard_parked())
        return true;

    /* Skip the node.db catchup while a from-genesis refold runs.
     * The refold re-walks the frozen prefix and indexes ZERO readable blocks
     * during the window, so every ~5 s re-trigger (boot_background_workers.c)
     * would take the node.db writer lock, find no tip hash, log
     * "catchup: final commit missing tip hash", and roll back — pure log spam +
     * lock contention against the fold. Returning 0 ("no work this pass") here
     * short-circuits before turbo-mode setup / node_db_begin, the single
     * chokepoint both call sites (boot loop + sync_controller) funnel through.
     * Mirrors the proven utxo_mirror_sync_run_once guard. The first post-refold
     * pass resumes catchup normally once refold_in_progress() clears. */
    return refold_in_progress();
}

static int catchup_start_height(int db_tip)
{
    int start = db_tip + 1;
    if (start < 0) start = 0;
    return start;
}

static bool catchup_read_proven(int32_t *proven_applied)
{
    sqlite3 *progress_db = progress_store_db();
    if (!progress_db)
        return false;
    return node_db_catchup_read_proven_authority(progress_db, proven_applied);
}

static void catchup_seed_receipt(struct node_db *ndb, int start,
                                 uint8_t prev_receipt[32])
{
    if (start > 0)
        (void)db_view_integrity_get(ndb, start - 1, prev_receipt);
}

static void catchup_pump_watchdog(int h)
{
    /* Pump systemd watchdog liveness during long node_db sync-catchup
     * loops (block indexing replay). */
    if ((h % 100) == 0)
        boot_progress_tick("node_db_sync_catchup");
}

static struct zcl_result catchup_map_if_needed(
    struct node_db_catchup_block_mapping *cache, int *cached_file,
    const char *datadir, int nfile)
{
    if (nfile != *cached_file)
        return catchup_map_file(cache, cached_file, datadir, nfile);
    return ZCL_OK;
}

static bool catchup_batch_due(int indexed, int batch_size,
                              const struct catchup_batch *cb)
{
    int64_t t_now = node_db_catchup_lock_guard_now_ms();
    return indexed % batch_size == 0 ||
           node_db_catchup_lock_guard_batch_due(t_now - cb->t_start);
}

static void catchup_capture_busy_snapshot(struct node_db *ndb, bool failed,
                                          struct catchup_batch *cb)
{
    /* Capture the snapshot class of the first write failure BEFORE any
     * rollback (a successful ROLLBACK would clobber the handle errcode).
     * No DB op runs between a failing write and this point on the break
     * paths above. */
    if (failed && !cb->busy_snapshot &&
        node_db_catchup_lock_guard_busy_snapshot(ndb))
        cb->busy_snapshot = true;
}

static bool catchup_tip_hashed(const struct block_index *tip)
{
    return tip && tip->phashBlock;
}

static void catchup_final_commit_done(struct catchup_batch *cb,
                                      int last_indexed_height,
                                      const struct block_index *last_indexed_tip,
                                      const struct catchup_sapling_tree *ct)
{
    cb->tx_open = false;
    cb->last_committed_height = last_indexed_height;
    /* Force a fresh flat-file checkpoint at catchup completion (including on
     * reaching tip), so the next boot has a checkpoint at the newest applied
     * height. */
    catchup_final_checkpoint(ct, last_indexed_tip, cb->last_committed_height);
}

static void catchup_print_summary(bool interrupted, int indexed,
                                  int64_t elapsed, int tip)
{
    printf("SQLite catchup %s: %d blocks in %llds (%d blk/s, tip=%d)\n",
           interrupted ? "stopped" : "complete",
           indexed, (long long)elapsed,
           elapsed > 0 ? indexed / (int)elapsed : indexed,
           tip);
    fflush(stdout);
}

/* True when the wallet holds keys and may own notes at or below the seed, so
 * the walk must not skip that range: its scan is what records them. A wallet
 * without a known birthday floor (0) is treated as older than the seed. */
static bool catchup_wallet_needs_prefix(const struct wallet *w)
{
    int keys = catchup_count_wallet_keys(w);
    if (w)
        keys += (int)w->sapling_keys.num_keys;
    int floor = 0;
    if (w) {
        zcl_mutex_lock(&((struct wallet *)w)->cs);
        floor = w->initial_scan_floor;
        if (w->scan_retry.pending && w->scan_retry.from < floor)
            floor = w->scan_retry.from;
        zcl_mutex_unlock(&((struct wallet *)w)->cs);
    }
    return node_db_catchup_prefix_needed(node_db_catchup_seed_height(), keys, floor);
}

/* First height a pass walks: the cursor next height, or with
 * -catchup-from-seed the first height above the shielded seed. */
static int catchup_first_height(int db_tip, const struct wallet *w)
{
    return node_db_catchup_start_height(catchup_start_height(db_tip),
                                        catchup_wallet_needs_prefix(w));
}

/* The first height to walk, or -1 when the seed is at or above the tip and
 * there is nothing to walk. */
static int catchup_walk_start(int db_tip, int chain_tip,
                              const struct wallet *w)
{
    int start = catchup_first_height(db_tip, w);
    if (start > chain_tip) {
        LOG_INFO("catchup", "catchup: seed height %d is at or above the tip %d "
                 "— nothing to walk", start - 1, chain_tip);
        return -1; // raw-return-ok:logged above; there is nothing to walk
    }
    if (node_db_catchup_from_seed() && start == catchup_start_height(db_tip) &&
        catchup_wallet_needs_prefix(w))
        LOG_INFO("catchup", "catchup: -catchup-from-seed ignored: the wallet "
                 "may hold notes at or below the shielded seed; walking from "
                 "%d", start);
    if (start > catchup_start_height(db_tip))
        LOG_INFO("catchup", "catchup: -catchup-from-seed starts at %d, above "
                 "the shielded seed; heights %d..%d are not walked",
                 start, catchup_start_height(db_tip), start - 1);
    return start;
}

/* The LOG_*_IN calls below name node_db_catchup_service_run so a line moved
 * into a helper prints the same "fn():" text it printed in the run body. */

/* Every local of one catchup pass, so the phase helpers below can share it. */
struct catchup_pass {
    struct node_db *ndb;
    const struct active_chain *chain;
    struct wallet *w;
    const char *datadir;
    bool interrupted;
    struct catchup_batch cb;
    bool failed;
    int last_indexed_height;
    const struct block_index *last_indexed_tip;
    struct sync_db_turbo_scope turbo_mode;
    bool restore_ok;
    int start;
    int chain_tip;
    int total;
    int32_t proven_applied;
    bool proven_authority;
    int indexed;
    int wallet_hits;
    int batch_size;
    int64_t t_start;
    int cached_file;
    struct node_db_catchup_block_mapping cached_mapping;
    struct catchup_sapling_tree sapling_tree;
    struct catchup_holes holes;
    uint8_t prev_receipt[32];
};

static void catchup_pass_init(struct catchup_pass *ps, struct node_db *ndb,
                              const struct active_chain *chain,
                              struct wallet *w, const char *datadir,
                              int db_tip, int chain_tip)
{
    ps->ndb = ndb;
    ps->chain = chain;
    ps->w = w;
    ps->datadir = datadir;
    /* Keep pre-existing fast path behavior when there is no catchup work. */
    ps->last_indexed_height = db_tip;
    ps->cb.last_committed_height = db_tip;

    ps->start = catchup_first_height(db_tip, w);
    ps->chain_tip = chain_tip;
    ps->total = chain_tip - ps->start + 1;
    catchup_active_begin(ps->start, chain_tip);

    ps->proven_applied = -1;
    ps->proven_authority = catchup_read_proven(&ps->proven_applied);

    int wallet_keys = catchup_count_wallet_keys(w);
    printf("SQLite catchup: %d blocks (%d..%d), lean index + wallet scan"
           " (%d keys)\n", ps->total, ps->start, chain_tip, wallet_keys);
    fflush(stdout);

    /* Turbo mode (no fsync, indexes dropped, larger cache) is for IBD only. */
    ps->cb.bulk_mode = node_db_catchup_lock_guard_bulk_pass(ps->total);
}

/* Leave turbo mode and close the pass after a failed transaction open. */
static void catchup_unwind_open(struct catchup_pass *ps, const char *restore_msg)
{
    if (!sync_db_turbo_scope_end(&ps->turbo_mode))
        fprintf(stderr, "%s\n", restore_msg);
    catchup_abort_pass(&ps->restore_ok);
}

enum catchup_open { CATCHUP_OPEN_READY, CATCHUP_OPEN_YIELD, CATCHUP_OPEN_FAILED };

/* A turbo scope whose restore was owed when a pass yielded. The restore
 * (synchronous, cache, index rebuild) cannot run inside the other writer's
 * transaction: PRAGMA synchronous is refused there, so synchronous would stay
 * OFF, and the CREATE INDEX statements would join that transaction. It runs
 * from catchup_restore_owed once the connection is idle. Catchup passes are
 * serialized by the catchup trigger, and shutdown runs after they stop. */
static struct sync_db_turbo_scope g_owed_scope;

/* Restore a scope a yielded pass left owed. False: still owed (the
 * connection is inside a transaction, or the restore failed and is retried). */
bool node_db_catchup_service_restore_owed(struct node_db *ndb)
{
    if (!g_owed_scope.entered)
        return true;
    if (node_db_catchup_lock_guard_foreign_txn(ndb))
        return false;
    if (!sync_db_turbo_scope_end(&g_owed_scope)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                    "catchup: owed restore of normal mode failed; retrying next pass");
        return false;
    }
    return true;
}

/* Another thread's transaction is open on the shared connection: leave the
 * walk to the next trigger. A turbo scope this pass entered is not restored
 * here (that would run inside the foreign transaction); it is owed. */
static enum catchup_open catchup_yield_open(struct catchup_pass *ps)
{
    if (ps->turbo_mode.entered) {
        if (g_owed_scope.entered)
            LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                        "catchup: a second turbo scope is owed a restore; "
                        "the earlier one is superseded");
        g_owed_scope = ps->turbo_mode;
        ps->turbo_mode.entered = false;
        ps->turbo_mode.ndb = NULL;
    }
    node_db_catchup_lock_guard_note_open_yield(ps->start);
    catchup_active_finish();
    return CATCHUP_OPEN_YIELD;
}

static enum catchup_open catchup_open_pass(struct catchup_pass *ps)
{
    if (node_db_catchup_lock_guard_foreign_txn(ps->ndb))
        return catchup_yield_open(ps);
    if (!sync_db_turbo_scope_begin(&ps->turbo_mode, ps->ndb, ps->cb.bulk_mode)) {
        fprintf(stderr, "catchup: failed to enter turbo mode\n");
        node_db_catchup_lock_guard_note_outcome(true);
        catchup_active_finish();
        return CATCHUP_OPEN_FAILED;
    }
#ifdef ZCL_TESTING
    catchup_test_after_turbo(ps->ndb);
#endif

    /* Verify connection works before starting. BEGIN IMMEDIATE (all three
     * transaction opens in this run): the writer reservation is taken at
     * BEGIN, where the 10 s busy handler CAN wait out a contender — a
     * deferred BEGIN would only discover the contention at the first
     * write, as SQLITE_BUSY_SNAPSHOT, which no busy-handler wait can cure. */
    if (!node_db_begin_immediate(ps->ndb)) {
        if (node_db_catchup_lock_guard_foreign_txn(ps->ndb))
            return catchup_yield_open(ps);
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: BEGIN failed — aborting");
        catchup_unwind_open(ps, "catchup: failed to restore normal mode after BEGIN failure");
        return CATCHUP_OPEN_FAILED;
    }
    node_db_catchup_lock_guard_note_opened();
    ps->cb.tx_open = true;
    if (!node_db_commit(ps->ndb)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: initial COMMIT failed — aborting");
        node_db_rollback(ps->ndb);
        catchup_unwind_open(ps, "catchup: failed to restore normal mode after initial COMMIT failure");
        return CATCHUP_OPEN_FAILED;
    }
    ps->cb.tx_open = false;

    /* Commit-cadence cap (node_db_catchup_lock_guard.c): the old
     * 100000-block batch held the single WAL write lock across mmap disk
     * reads for minutes — past every other writer's budget (wallet ~80 s,
     * coins 30 s, this handle's own 10 s busy timeout) — producing
     * "database is locked" bursts. Commit every batch_size blocks (2000)
     * OR every NODE_DB_CATCHUP_COMMIT_BATCH_MAX_SECS, whichever first.
     * Catchup is an idempotent projection re-run, so finer granularity
     * changes only lock-hold time, never the final state. */
    ps->batch_size = node_db_catchup_lock_guard_batch_size();
    ps->cb.t_start = node_db_catchup_lock_guard_now_ms();
    ps->t_start = (int64_t)platform_time_wall_time_t();

    /* Read-only mapping cache.  The cache owns the source descriptor for the
     * complete mapping lifetime, as required on Windows and POSIX. */
    node_db_catchup_block_mapping_init(&ps->cached_mapping);

    /* Initialize Sapling commitment tree for catchup */
    catchup_sapling_tree_load(ps->ndb, ps->chain, &ps->sapling_tree);

    if (!node_db_begin_immediate(ps->ndb)) {
        if (node_db_catchup_lock_guard_foreign_txn(ps->ndb))
            return catchup_yield_open(ps);
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: failed to open main transaction");
        catchup_unwind_open(ps, "catchup: failed to restore normal mode after tx open failure");
        return CATCHUP_OPEN_FAILED;
    }
    ps->cb.tx_open = true;
    catchup_sapling_tree_persist_dirty(ps->ndb, &ps->sapling_tree);

    /* Integrity-receipt chain carry. Seed from the receipt at start-1
     * (zeros at a genesis start). Updated after each indexed block and
     * threaded into sync_block_lean so the per-height SHA3 receipt chains
     * across the whole ascending walk without a per-block SELECT. */
    catchup_seed_receipt(ps->ndb, ps->start, ps->prev_receipt);
    return CATCHUP_OPEN_READY;
}

/* How one height of the walk ended. NEXT and GO carry on; a hole is NEXT. */
enum catchup_step {
    CATCHUP_STEP_NEXT,
    CATCHUP_STEP_GO,
    CATCHUP_STEP_STOP,
    CATCHUP_STEP_FAIL,
};

/* Shutdown check, batch cycling, then locate and map the block's file. */
static enum catchup_step catchup_walk_locate(struct catchup_pass *ps, int h,
                                             const struct block_index **out)
{
    if (g_shutdown_requested)
        return CATCHUP_STEP_STOP;
#ifdef ZCL_TESTING
    node_db_catchup_lock_guard_test_height_delay();
#endif
    if (!catchup_cycle_batch(ps->ndb, h, ps->indexed, ps->last_indexed_tip,
                             ps->last_indexed_height, &ps->cb))
        return CATCHUP_STEP_FAIL;
    catchup_pump_watchdog(h);
    const struct block_index *pindex = active_chain_at(ps->chain, h);
    if (!pindex) {
        if (catchup_hole_missing_index(&ps->holes, h))
            LOG_INFO_IN("node_db_catchup_service_run", "catchup", "catchup: missing active-chain index at "
                        "height %d — recording lean hole", h);
        return CATCHUP_STEP_NEXT;
    }
    if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
        if (catchup_hole_missing_data(&ps->holes, h))
            LOG_INFO_IN("node_db_catchup_service_run", "catchup", "catchup: block data missing at height "
                        "%d — recording lean hole", h);
        return CATCHUP_STEP_NEXT;
    }
    if (pindex->nFile == ps->holes.skip_file) {
        catchup_hole_note(&ps->holes, h);
        return CATCHUP_STEP_NEXT;
    }

    /* Map a new file if needed. */
    struct zcl_result mapped = catchup_map_if_needed(
        &ps->cached_mapping, &ps->cached_file, ps->datadir, pindex->nFile);
    if (!mapped.ok) {
        if (catchup_hole_map_failed(&ps->holes, h, pindex->nFile,
                                    mapped.code))
            LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                        "catchup: mapping failed for blk%05d.dat "
                        "(errno=%d) — skipping its blocks",
                        pindex->nFile, mapped.code);
        return CATCHUP_STEP_NEXT;
    }

    if ((uint64_t)pindex->nDataPos >= ps->cached_mapping.mapping.size) {
        if (catchup_hole_suspicious(&ps->holes, h))
            LOG_INFO_IN("node_db_catchup_service_run", "catchup", "catchup: malformed block data offset at "
                        "height %d — recording lean hole", h);
        return CATCHUP_STEP_NEXT;
    }
    *out = pindex;
    return CATCHUP_STEP_GO;
}

/* Decode and hash-bind the frame, then lean index, wallet scan and tree step. */
static enum catchup_step catchup_walk_block(struct catchup_pass *ps,
                                            const struct block_index *pindex,
                                            int h)
{
    struct node_db *ndb = ps->ndb;
    struct block blk;
    block_init(&blk);

    size_t remaining = ps->cached_mapping.mapping.size -
                       (size_t)pindex->nDataPos;
    struct byte_stream s;
    stream_init_from_data(&s, ps->cached_mapping.mapping.data +
                              (size_t)pindex->nDataPos,
                          remaining);
    if (!block_deserialize(&blk, &s)) {
        block_free(&blk);
        if (catchup_hole_suspicious(&ps->holes, h))
            LOG_INFO_IN("node_db_catchup_service_run", "catchup", "catchup: undecodable block frame at "
                        "height %d — recording lean hole", h);
        return CATCHUP_STEP_NEXT;
    }

    /* Garbage at a wrong offset can still PARSE as a block; the lean
     * index must never hold a row whose hash disagrees with the
     * block index (the live h=6131 frame parsed, then poisoned
     * db_block_save with nonsense). Hash-bind every frame to its
     * index entry; a mismatch is a lean hole like any other
     * unreadable frame. */
    enum catchup_frame_check frame = catchup_frame_check(&blk, pindex);
    if (frame == CATCHUP_FRAME_HASH_MISMATCH) {
        block_free(&blk);
        if (catchup_hole_suspicious(&ps->holes, h))
            LOG_INFO_IN("node_db_catchup_service_run", "catchup", "catchup: frame hash mismatch at "
                        "height %d — recording lean hole", h);
        return CATCHUP_STEP_NEXT;
    }
    if (frame == CATCHUP_FRAME_NO_INDEX_HASH) {
        /* A torn index (e.g. cp -a of a running node) can carry an
         * active-chain slot with BLOCK_HAVE_DATA yet no phashBlock. Its
         * frame cannot be hash-bound to an identity and every downstream
         * write keys off pindex->phashBlock->data; record it as a
         * suspicious lean hole (never advanced over quietly) instead of
         * dereferencing NULL in sync_block_lean. */
        block_free(&blk);
        if (catchup_hole_suspicious(&ps->holes, h))
            LOG_INFO_IN("node_db_catchup_service_run", "catchup", "catchup: block index missing its hash "
                        "at height %d — recording lean hole", h);
        return CATCHUP_STEP_NEXT;
    }

    /* Lean index: block header + txid index + explorer projections */
    uint8_t this_receipt[32];
    if (!sync_block_lean(ps->ndb, &blk, pindex, ps->prev_receipt, this_receipt)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: lean index failed at height %d (sqlite=%s)", h, sqlite3_errmsg(ndb->db));
        block_free(&blk);
        return CATCHUP_STEP_FAIL;
    }
    memcpy(ps->prev_receipt, this_receipt, 32);

    /* Wallet scan */
    size_t i = 0;
    size_t si = 0;
    enum catchup_wallet_scan scan = catchup_scan_wallet_block(
        ps->ndb, &blk, ps->w, h, &ps->wallet_hits, &i, &si);
    if (scan == CATCHUP_WALLET_TX_FAILED)
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: wallet tx sync failed at height %d " "(tx=%d)", h, (int)i);
    if (scan == CATCHUP_WALLET_DECRYPT_FAILED)
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: sapling decrypt failed at height %d " "(tx=%d)", h, (int)i);
    if (scan == CATCHUP_WALLET_SPEND_FAILED)
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: sapling spend update failed at height %d " "(tx=%d, spend=%zu)", h, (int)i, si);
    if (scan != CATCHUP_WALLET_OK) {
        block_free(&blk);
        return CATCHUP_STEP_FAIL;
    }

    /* Advance Sapling tree + wallet witnesses */
    if (!catchup_tree_step(ps->ndb, ps->chain, &blk, &ps->sapling_tree, h, ps->w)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: witness/tree advance failed at height %d", h);
        block_free(&blk);
        return CATCHUP_STEP_FAIL;
    }

    block_free(&blk);
    ps->indexed++;
    ps->last_indexed_height = h;
    ps->last_indexed_tip = pindex;
    sync_job_catchup_progress(h);
    return CATCHUP_STEP_GO;
}

/* After an indexed block: test injection, then commit the batch if due. */
static enum catchup_step catchup_walk_post(struct catchup_pass *ps,
                                           const struct block_index *pindex,
                                           int h)
{
#ifdef ZCL_TESTING
    /* Armed by node_db_catchup_lock_guard_test_force_snapshot_failures:
     * fail this block exactly as a SQLITE_BUSY_SNAPSHOT write failure
     * would, so the rollback + bounded whole-walk restart plumbing is
     * exercised deterministically. */
    if (node_db_catchup_lock_guard_test_consume_snapshot_failure()) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                    "catchup: TEST-INJECTED SQLITE_BUSY_SNAPSHOT write "
                    "failure at height %d", h);
        ps->cb.busy_snapshot = true;
        return CATCHUP_STEP_FAIL;
    }
#endif

    if (!catchup_batch_due(ps->indexed, ps->batch_size, &ps->cb))
        return CATCHUP_STEP_NEXT;
    if (!catchup_set_batch_tip(ps->ndb, pindex, h, &ps->cb.busy_snapshot))
        return CATCHUP_STEP_FAIL;
    if (!node_db_commit(ps->ndb)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: batch COMMIT failed at height %d", h);
        catchup_note_busy_snapshot(ps->ndb, &ps->cb.busy_snapshot);
        node_db_rollback(ps->ndb);
        ps->cb.tx_open = false;
        return CATCHUP_STEP_FAIL;
    }
    node_db_catchup_lock_guard_note_batch_commit();
    ps->cb.tx_open = false;
    ps->cb.last_committed_height = h;
    catchup_batch_committed(ps->ndb, ps->cb.bulk_mode, &ps->sapling_tree,
                            pindex, h, ps->indexed, ps->total,
                            ps->wallet_hits, ps->t_start);
    ps->cb.indexed_at_start = ps->indexed;
    node_db_catchup_lock_guard_yield_to_writers(catchup_db_service(ps->ndb),
                                                !ps->cb.bulk_mode);
    /* The batch just committed is durable no matter what happens
     * next, so a busy reopen is worth waiting out rather than
     * aborting the pass (which stops catchup, withholds the boot
     * watchdog ping, and gets the node killed). */
    if (!catchup_reopen_batch_txn(ps->ndb, h, &ps->cb.busy_snapshot)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: failed to reopen transaction after batch commit");
        return CATCHUP_STEP_FAIL;
    }
    ps->cb.t_start = node_db_catchup_lock_guard_now_ms();
    ps->cb.tx_open = true;
    return CATCHUP_STEP_NEXT;
}

/* After the walk: unmap, snapshot the busy state, roll back a failure. */
static void catchup_close_abort(struct catchup_pass *ps)
{
    node_db_catchup_block_mapping_close(&ps->cached_mapping);

    catchup_capture_busy_snapshot(ps->ndb, ps->failed, &ps->cb);

    if (ps->failed) {
        if (ps->cb.tx_open && !node_db_rollback(ps->ndb))
            LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: rollback failed after failure");
        ps->cb.tx_open = false;
    }
}

/* Final commit, part one: the tip row (or the sparse proven-prefix cursor). */
static void catchup_final_tip(struct catchup_pass *ps)
{
    /* Final commit */
    if (!ps->cb.tx_open || ps->failed)
        return;
    if (catchup_tip_hashed(ps->last_indexed_tip)) {
        if (!node_db_sync_set_tip(ps->ndb,
                                  ps->last_indexed_tip->phashBlock->data,
                                  ps->last_indexed_height)) {
            LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: failed to set tip before final commit");
            ps->failed = true;
        }
        return;
    }
    int start = ps->start;
    int chain_tip = ps->chain_tip;
    int first_missing_index_h = ps->holes.first_missing_index_h;
    int sparse_target = catchup_advance_sparse_tip(
        ps->ndb, ps->chain, &ps->holes, ps->indexed, ps->total, ps->start,
        ps->chain_tip, ps->proven_authority, ps->proven_applied);
    if (sparse_target < 0) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: final commit missing tip hash");
        ps->failed = true;
        return;
    }
    ps->last_indexed_height = sparse_target;
    ps->cb.last_committed_height = sparse_target;
    LOG_INFO_IN("node_db_catchup_service_run", "catchup",
                "catchup: sparse proven prefix %d..%d has no block "
                "bodies; advanced SQLite projection cursor to h=%d "
                "without writing block rows (first missing active "
                "slot=%d)",
                start, chain_tip, sparse_target,
                first_missing_index_h);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=sparse_projection_tip_advance "
                "start=%d height=%d holes=%d first_missing_index=%d",
                ps->start, sparse_target, ps->holes.lean,
                first_missing_index_h);
}

/* Final commit, part two: the COMMIT itself and its failure handling. */
static void catchup_final_commit(struct catchup_pass *ps)
{
    if (!ps->cb.tx_open || ps->failed)
        return;
    if (node_db_commit(ps->ndb)) {
        catchup_final_commit_done(&ps->cb, ps->last_indexed_height,
                                  ps->last_indexed_tip, &ps->sapling_tree);
        return;
    }
    LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: final COMMIT failed");
    catchup_note_busy_snapshot(ps->ndb, &ps->cb.busy_snapshot);
    if (!node_db_rollback(ps->ndb))
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: final ROLLBACK failed");
    ps->cb.tx_open = false;
    ps->failed = true;
    ps->last_indexed_height = ps->cb.last_committed_height;
}

/* Roll back what a failure left open, then restore pragmas and indexes. */
static void catchup_close_restore(struct catchup_pass *ps)
{
    if (ps->failed) {
        if (ps->cb.tx_open && !node_db_rollback(ps->ndb))
            LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: final rollback path failed");
        ps->interrupted = false;
    }

    /* Restore safe pragmas and rebuild indexes */
    if (!sync_db_turbo_scope_end(&ps->turbo_mode)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup", "catchup: failed to restore normal mode");
        ps->restore_ok = false;
    }
}

static void catchup_log_holes(const struct catchup_holes *hl)
{
    if (hl->lean <= 0)
        return;
    int lean_holes = hl->lean;
    int first_hole_h = hl->first_h;
    int missing_file_holes = hl->missing_file;
    int first_missing_file_h = hl->first_missing_file_h;
    int first_missing_file_num = hl->first_missing_file_num;
    int suspicious_lean_holes = hl->suspicious;
    if (hl->suspicious > 0) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                    "catchup: %d lean-index hole(s) recorded (first h=%d, "
                    "missing_file_holes=%d first_file=blk%05d.dat@h=%d, "
                    "suspicious=%d) — unreadable/garbage frames skipped, "
                    "not aborted; those heights stay unindexed until their "
                    "bodies are refetched",
                    lean_holes, first_hole_h, missing_file_holes,
                    first_missing_file_num, first_missing_file_h,
                    suspicious_lean_holes);
    } else {
        LOG_INFO_IN("node_db_catchup_service_run", "catchup",
                    "catchup: %d lean-index hole(s) recorded (first h=%d, "
                    "missing_file_holes=%d first_file=blk%05d.dat@h=%d) — "
                    "expected sparse/snapshot block bodies skipped",
                    lean_holes, first_hole_h, missing_file_holes,
                    first_missing_file_num, first_missing_file_h);
    }
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=lean_catchup_holes count=%d first_h=%d",
                lean_holes, first_hole_h);
}

static void catchup_report_summary(const struct catchup_pass *ps)
{
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - ps->t_start;
    catchup_print_summary(ps->interrupted, ps->indexed, elapsed,
                          ps->cb.last_committed_height);
}

/* Returns 1 when the pass is not suppressed and the db tip is behind the
 * chain tip. Both tip outputs are written on every path. */
static int catchup_tips_need_work(struct node_db *ndb,
                                  const struct active_chain *chain,
                                  const struct wallet *w,
                                  int *db_tip, int *chain_tip)
{
    *db_tip = 0;
    *chain_tip = 0;
    if (catchup_pass_suppressed())
        return 0;
    /* An unreadable tip is not an absent one: read as -1 it would walk the
     * whole chain from genesis in bulk mode, which drops every secondary
     * index. The reader has logged it; this pass does nothing and the
     * background trigger retries. */
    if (!node_db_sync_get_tip_height_checked(ndb, db_tip))
        return 0;  // raw-return-ok:logged by the checked tip reader
    /* A reorg replaces blocks the projection already indexed; heal the cursor
     * before the "caught up" early-out below can hide the stale rows. */
    if (node_db_catchup_fork_rewind_at(ndb, chain, *db_tip) &&
        !node_db_sync_get_tip_height_checked(ndb, db_tip))
        return 0;  // raw-return-ok:logged by the checked tip reader
    *chain_tip = active_chain_height(chain);
    if (*db_tip >= *chain_tip)
        return 0;
    return catchup_walk_start(*db_tip, *chain_tip, w) >= 0;
}

/* Walk the pass from its start height through its chain tip, and end the
 * walk on a stop or fail step. */
static void catchup_walk_heights(struct catchup_pass *ps)
{
    for (int h = ps->start; h <= ps->chain_tip; h++) {
        const struct block_index *pindex = NULL;
        enum catchup_step st = catchup_walk_locate(ps, h, &pindex);
        if (st == CATCHUP_STEP_GO)
            st = catchup_walk_block(ps, pindex, h);
        if (st == CATCHUP_STEP_GO)
            st = catchup_walk_post(ps, pindex, h);
        if (st >= CATCHUP_STEP_STOP) {
            ps->interrupted = st == CATCHUP_STEP_STOP;
            ps->failed = st == CATCHUP_STEP_FAIL;
            break;
        }
    }
}

int node_db_catchup_service_run(struct node_db *ndb,
                                const struct active_chain *chain,
                                struct wallet *w,
                                const char *datadir)
{
    /* Unreadable blocks are LOUD HOLES, not abort triggers: on a
     * cold-import datadir the imported index carries the source node's
     * nFile/nDataPos layout, so low-height entries can claim
     * BLOCK_HAVE_DATA yet deserialize as garbage from OUR files. The old
     * abort-on-first-bad-frame turned one such frame into an infinite
     * restart loop that never reached the readable rows the tip needs
     * (garbage reads at low height, catchup aborting forever, tip pinned).
     * Consumers already handle missing lean rows (height_not_found). */
    struct catchup_pass ps = {
        .cb = {.last_committed_height = -1},
        .restore_ok = true,
        .cached_file = -1,
        .holes = {
            .first_h = -1,
            .first_missing_index_h = -1,
            .first_missing_file_h = -1,
            .first_missing_file_num = -1,
            .skip_file = -1,
        },
    };

    if (catchup_args_invalid(ndb, chain))
        LOG_ERR("sync", "catchup: invalid args (ndb=%p, chain=%p)", (void *)ndb, (void *)chain);
    (void)node_db_catchup_service_restore_owed(ndb);

    int db_tip = 0;
    int chain_tip = 0;
    if (!catchup_tips_need_work(ndb, chain, w, &db_tip, &chain_tip))
        return 0;
    if (!datadir)
        LOG_ERR("sync", "catchup: datadir is NULL (db_tip=%d, chain_tip=%d)",
                db_tip, chain_tip);

    catchup_pass_init(&ps, ndb, chain, w, datadir, db_tip, chain_tip);
    enum catchup_open opened = catchup_open_pass(&ps);
    if (opened == CATCHUP_OPEN_YIELD)
        return 0;
    if (opened == CATCHUP_OPEN_FAILED)
        return -1; // raw-return-ok:logged-above

    catchup_walk_heights(&ps);

    catchup_close_abort(&ps);
    catchup_final_tip(&ps);
    catchup_final_commit(&ps);
    catchup_close_restore(&ps);

    /* BUSY_SNAPSHOT restart seatbelt (node_db_catchup_lock_guard.c): the
     * rollback above unwound the poisoned transaction; the only cure for
     * SQLITE_BUSY_SNAPSHOT is a fresh transaction, and the only safe
     * granularity is the WHOLE walk — the in-memory Sapling tree/witness
     * state is ahead of the rolled-back rows. Catchup is an idempotent
     * projection re-run (tip/receipt/tree all re-derive from persisted
     * state), so a bounded recursion is exact. With BEGIN IMMEDIATE this
     * pass's own writes can no longer produce the class; this covers any
     * residual/regressed deferred writer. */
    if (node_db_catchup_lock_guard_restart_needed(ps.failed, ps.cb.busy_snapshot)) {
        catchup_active_finish();
        int r = node_db_catchup_service_run(ndb, chain, w, datadir);
        node_db_catchup_lock_guard_restart_done();
        return r;
    }

    bool failed = ps.failed;
    bool restore_ok = ps.restore_ok;
    int indexed = ps.indexed;

    /* One logical pass = one outcome (the restart path above returns
     * before this, so a restarted attempt never double-counts). Account
     * before LOG_ERR returns from a failed pass. */
    node_db_catchup_lock_guard_note_outcome(failed || !restore_ok);

    /* LOG_ERR (base/log_macros.h) logs AND `return -1;`s — this branch
     * never falls through to the unconditional catchup_active_finish()
     * at the bottom of this function, so the finish just above already
     * pairs the one begin from the top of this pass exactly once. A
     * plain read of this block (mistaking LOG_ERR for a non-returning
     * log call, like its LOG_WARN/LOG_ERROR neighbors) makes the pairing
     * look broken; it is not. Do not add a second finish on this path,
     * and do not remove this one — either change puts
     * g_catchup_active_depth off by one on every failed-closed pass. */
    if (failed || !restore_ok) {
        catchup_active_finish();
        LOG_ERR("sync", "catchup: aborting (failed=%d, restore_ok=%d, indexed=%d)",
                failed, restore_ok, indexed);
    }

    catchup_report_summary(&ps);
    catchup_log_holes(&ps.holes);

    /* Checkpoint WAL after bulk catchup to reclaim disk space */
    if (indexed > 10000)
        node_db_wal_checkpoint(ndb);

    catchup_active_finish();
    return indexed;
}

#ifdef ZCL_TESTING
bool node_db_catchup_test_sync_block_lean(struct node_db *ndb,
                                          const struct block *blk,
                                          const struct block_index *pindex)
{
    uint8_t prev[32] = {0};
    uint8_t out[32] = {0};
    return sync_block_lean(ndb, blk, pindex, prev, out);
}
#endif
