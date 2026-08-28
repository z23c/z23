/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_catchup_service: the bulk node_db sync-catchup orchestration.
 *
 * node_db_catchup_service_run is the core catchup algorithm lifted
 * verbatim out of sync_controller_catchup.c (node_db_sync_catchup). It
 * drives the turbo-mode scope, the DB connection verify, Sapling-tree
 * init, the main transaction/commit block-index loop (lean index +
 * wallet scan + witness advance), and turbo-mode teardown.
 *
 * The block-level helper it owns (sync_block_lean) is a single-use
 * orchestration detail of catchup and lives here as a static; the
 * Sapling try-decrypt helper moved to node_db_catchup_decrypt.c (E1
 * file-size ratchet) and the lock-contention seatbelts (commit cadence,
 * BUSY_SNAPSHOT restart, abort-streak park) live in
 * node_db_catchup_lock_guard.c. The shared sync-controller helpers
 * it calls (turbo scope, job-status setters, wallet-tx checked write,
 * witness advance, block-file mmap) are defined in the sync controller
 * siblings and reached here by forward declaration — their definitions
 * are not duplicated. */

// one-result-type-ok:recovery-primitive-int — E2 (one way out):
// node_db_catchup_service_run keeps the LOCKED plain-int contract (blocks
// indexed, or -1 on setup failure). Its single caller is the catchup job
// thread, which stores the int into job->result; the recovery-primitive
// int is consumed across the coins-wedge recovery surface. A zcl_result
// here buys nothing and forces a job-struct rewrite. Every failure path
// is logged via LOG_*/fprintf before the return, so the reason still
// travels with the failure.

#include "platform/time_compat.h"
#include "controllers/sync_controller.h"
#include "services/node_db_catchup_service.h"
#include "services/node_db_catchup_lock_guard.h"
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
#include "util/ar_step_readonly.h"
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

/* Lean index: block header + txid index + the full explorer projections.
 *
 * Per-block write order: stamp the txid index rows (transactions table),
 * run the single per-block explorer hook (explorer_index_block, which
 * writes tx_outputs/inputs/op_returns/sapling/joinsplits/sprout_nullifiers
 * + the chained view_integrity receipt and returns the shielded value
 * accumulators), backfill blk.sprout_value/sapling_value from those
 * accumulators, THEN db_block_save — so the blocks row and the integrity
 * receipt agree. prev_receipt carries the previous height's receipt
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

    /* Full per-block explorer projections + chained integrity receipt.
     * Read-derived, node.db-only; returns the shielded value accumulators
     * so the blocks row agrees with the receipt it just wrote. */
    int64_t sprout_val = 0, sapling_val = 0;
    if (!explorer_index_block(ndb, blk, pindex, prev_receipt, out_receipt,
                              &sprout_val, &sapling_val))
        LOG_WARN("catchup", "sync_block_lean: explorer projections failed at "
                 "height %d (continuing — degraded explorer row, not fatal)",
                 pindex->nHeight);
    db_blk.sprout_value = sprout_val;
    db_blk.sapling_value = sapling_val;

    if (!db_block_save(ndb, &db_blk))
        LOG_FAIL("sync", "sync_block_lean: db_block_save failed at height %d",
                 pindex->nHeight);

    return true;
}

/* Seed the integrity-receipt chain: read the sha3_hash receipt recorded
 * for height h (the block just below the catchup start). Fills `out` with
 * the 32-byte receipt and returns true, or leaves `out` untouched and
 * returns false when no row exists (genesis start → caller uses zeros). */
static bool catchup_read_prev_receipt(struct node_db *ndb, int h,
                                      uint8_t out[32])
{
    if (!ndb || !ndb->open || h < 0)
        return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT sha3_hash FROM view_integrity WHERE height=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_int64(s, 1, h);
    bool found = false;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(s, 0);
        if (blob && sqlite3_column_bytes(s, 0) >= 32) {
            memcpy(out, blob, 32);
            found = true;
        }
    }
    sqlite3_finalize(s);
    return found;
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

int node_db_catchup_service_run(struct node_db *ndb,
                                const struct active_chain *chain,
                                struct wallet *w,
                                const char *datadir)
{
    bool interrupted = false;
    bool tx_open = false;
    bool failed = false;
    int last_indexed_height = 0;
    int last_committed_height = -1;
    const struct block_index *last_indexed_tip = NULL;
    struct sync_db_turbo_scope turbo_mode = {0};
    bool restore_ok = true;

    if (!ndb || !ndb->open || !chain)
        LOG_ERR("sync", "catchup: invalid args (ndb=%p, chain=%p)", (void *)ndb, (void *)chain);

    /* Abort-streak park (node_db_catchup_lock_guard.c): after 8 consecutive
     * failed passes the worker parks behind the named blocker
     * "node_db_catchup.abort_storm" and every pass is a no-op until an
     * operator clears it — a pass that always fails must not be re-run
     * forever (the 2026-07-27 incident re-ran one 13k+ times, each pass
     * burning the 10 s busy timeout). Single chokepoint placement: both
     * call sites funnel through here. */
    if (node_db_catchup_lock_guard_parked())
        return 0;

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
    if (refold_in_progress())
        return 0;

    int db_tip = node_db_sync_get_tip_height(ndb);
    int chain_tip = active_chain_height(chain);
    if (db_tip >= chain_tip) return 0;
    if (!datadir)
        LOG_ERR("sync", "catchup: datadir is NULL (db_tip=%d, chain_tip=%d)",
                db_tip, chain_tip);

    /* Keep pre-existing fast path behavior when there is no catchup work. */
    last_indexed_height = db_tip;
    last_committed_height = db_tip;

    int start = db_tip + 1;
    if (start < 0) start = 0;
    int total = chain_tip - start + 1;
    sync_job_catchup_begin(start, chain_tip);

    bool proven_authority = false;
    int32_t proven_applied = -1;
    sqlite3 *progress_db = progress_store_db();
    if (progress_db)
        proven_authority =
            node_db_catchup_read_proven_authority(progress_db, &proven_applied);

    int wallet_keys = 0;
    if (w) {
        for (size_t i = 0; i < w->keystore.num_keys; i++)
            if (w->keystore.keys[i].used) wallet_keys++;
    }
    printf("SQLite catchup: %d blocks (%d..%d), lean index + wallet scan"
           " (%d keys)\n", total, start, chain_tip, wallet_keys);
    fflush(stdout);

    /* Turbo mode: disable fsync, drop indexes, enlarge cache. */
    bool bulk_mode = (total > 50000);
    if (!sync_db_turbo_scope_begin(&turbo_mode, ndb, bulk_mode)) {
        fprintf(stderr, "catchup: failed to enter turbo mode\n");
        node_db_catchup_lock_guard_note_outcome(true);
        sync_job_catchup_finish();
        return -1; // raw-return-ok:logged-above
    }

    /* Verify connection works before starting. BEGIN IMMEDIATE (all three
     * transaction opens in this run): the writer reservation is taken at
     * BEGIN, where the 10 s busy handler CAN wait out a contender — a
     * deferred BEGIN would only discover the contention at the first
     * write, as SQLITE_BUSY_SNAPSHOT, which no busy-handler wait can cure
     * (the 2026-07-27 catchup-poison drumbeat). */
    if (!node_db_begin_immediate(ndb)) {
        LOG_WARN("catchup", "catchup: BEGIN failed — aborting");
        if (!sync_db_turbo_scope_end(&turbo_mode))
            fprintf(stderr, "catchup: failed to restore normal mode after BEGIN failure\n");
        restore_ok = false;
        node_db_catchup_lock_guard_note_outcome(true);
        sync_job_catchup_finish();
        return -1; // raw-return-ok:logged-above
    }
    tx_open = true;
    if (!node_db_commit(ndb)) {
        LOG_WARN("catchup", "catchup: initial COMMIT failed — aborting");
        node_db_rollback(ndb);
        if (!sync_db_turbo_scope_end(&turbo_mode))
            fprintf(stderr, "catchup: failed to restore normal mode after initial COMMIT failure\n");
        restore_ok = false;
        node_db_catchup_lock_guard_note_outcome(true);
        sync_job_catchup_finish();
        return -1; // raw-return-ok:logged-above
    }
    tx_open = false;

    int indexed = 0;
    int wallet_hits = 0;
    /* Commit-cadence cap (node_db_catchup_lock_guard.c): the old
     * 100000-block batch held the single WAL write lock across mmap disk
     * reads for minutes — past every other writer's budget (wallet ~80 s,
     * coins 30 s, this handle's own 10 s busy timeout) — producing
     * "database is locked" bursts. Commit every batch_size blocks (2000)
     * OR every NODE_DB_CATCHUP_COMMIT_BATCH_MAX_SECS, whichever first.
     * Catchup is an idempotent projection re-run, so finer granularity
     * changes only lock-hold time, never the final state. */
    int batch_size = node_db_catchup_lock_guard_batch_size();
    int64_t t_batch_start = (int64_t)platform_time_wall_time_t();
    /* Set when the first failure of this pass carries the extended
     * SQLITE_BUSY_SNAPSHOT code — see the restart seatbelt at the tail. */
    bool busy_snapshot = false;
    int64_t t_start = (int64_t)platform_time_wall_time_t();

    /* Read-only mapping cache.  The cache owns the source descriptor for the
     * complete mapping lifetime, as required on Windows and POSIX. */
    int cached_file = -1;
    struct node_db_catchup_block_mapping cached_mapping;
    node_db_catchup_block_mapping_init(&cached_mapping);

    /* Initialize Sapling commitment tree for catchup */
    struct incremental_merkle_tree sapling_tree;
    sapling_tree_init(&sapling_tree);
    {
        uint8_t tree_buf[8192];
        size_t tree_len = 0;
        if (node_db_state_get(ndb, "sapling_tree", tree_buf, sizeof(tree_buf), &tree_len)
            && tree_len > 0) {
            struct byte_stream ts;
            stream_init_from_data(&ts, tree_buf, tree_len);
            sapling_tree_init(&sapling_tree);
            incremental_tree_deserialize(&sapling_tree, &ts);
        }
    }

    if (!node_db_begin_immediate(ndb)) {
        LOG_WARN("catchup", "catchup: failed to open main transaction");
        if (!sync_db_turbo_scope_end(&turbo_mode))
            fprintf(stderr, "catchup: failed to restore normal mode after tx open failure\n");
        restore_ok = false;
        node_db_catchup_lock_guard_note_outcome(true);
        sync_job_catchup_finish();
        return -1; // raw-return-ok:logged-above
    }
    tx_open = true;

    /* Unreadable blocks are LOUD HOLES, not abort triggers: on a
     * cold-import datadir the imported index carries the source node's
     * nFile/nDataPos layout, so low-height entries can claim
     * BLOCK_HAVE_DATA yet deserialize as garbage from OUR files. The old
     * abort-on-first-bad-frame turned one such frame into an infinite
     * restart loop that never reached the readable rows the tip needs
     * (garbage reads at low height, catchup aborting forever, tip pinned).
     * Consumers already handle missing lean rows (height_not_found). */
    int lean_holes = 0;
    int first_hole_h = -1;
    int missing_index_holes = 0;
    int first_missing_index_h = -1;
    int missing_data_holes = 0;
    int missing_file_holes = 0;
    int first_missing_file_h = -1;
    int first_missing_file_num = -1;
    int suspicious_lean_holes = 0;
    int skip_file = -1;

    /* Integrity-receipt chain carry. Seed from the receipt at start-1
     * (zeros at a genesis start). Updated after each indexed block and
     * threaded into sync_block_lean so the per-height SHA3 receipt chains
     * across the whole ascending walk without a per-block SELECT. */
    uint8_t prev_receipt[32] = {0};
    if (start > 0)
        catchup_read_prev_receipt(ndb, start - 1, prev_receipt);

    for (int h = start; h <= chain_tip; h++) {
        if (g_shutdown_requested) {
            interrupted = true;
            break;
        }
        /* Pump systemd watchdog liveness during long node_db sync-catchup
         * loops (block indexing replay). */
        if ((h % 100) == 0)
            boot_progress_tick("node_db_sync_catchup");
        const struct block_index *pindex = active_chain_at(chain, h);
        if (!pindex) {
            if (++lean_holes == 1) first_hole_h = h;
            missing_index_holes++;
            if (first_missing_index_h < 0)
                first_missing_index_h = h;
            if (missing_index_holes <= 3)
                LOG_INFO("catchup", "catchup: missing active-chain index at "
                         "height %d — recording lean hole", h);
            continue;
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
            if (++lean_holes == 1) first_hole_h = h;
            missing_data_holes++;
            if (missing_data_holes <= 3)
                LOG_INFO("catchup", "catchup: block data missing at height "
                         "%d — recording lean hole", h);
            continue;
        }
        if (pindex->nFile == skip_file) {
            if (++lean_holes == 1) first_hole_h = h;
            continue;
        }

        /* Map a new file if needed. */
        if (pindex->nFile != cached_file) {
            node_db_catchup_block_mapping_close(&cached_mapping);
            struct zcl_result mapped =
                node_db_catchup_block_mapping_open_quiet(
                    &cached_mapping, datadir, pindex->nFile);
            cached_file = mapped.ok ? pindex->nFile : -1;
            if (!mapped.ok) {
                missing_file_holes++;
                if (first_missing_file_h < 0) {
                    first_missing_file_h = h;
                    first_missing_file_num = pindex->nFile;
                }
                if (mapped.code != ENOENT && mapped.code != ENOTDIR) {
                    suspicious_lean_holes++;
                    if (suspicious_lean_holes <= 3)
                        LOG_WARN("catchup",
                                 "catchup: mapping failed for blk%05d.dat "
                                 "(errno=%d) — skipping its blocks",
                                 pindex->nFile, mapped.code);
                }
                skip_file = pindex->nFile;
                if (++lean_holes == 1) first_hole_h = h;
                continue;
            }
        }

        if ((uint64_t)pindex->nDataPos >= cached_mapping.mapping.size) {
            if (++lean_holes == 1) first_hole_h = h;
            suspicious_lean_holes++;
            if (lean_holes <= 3)
                LOG_INFO("catchup", "catchup: malformed block data offset at "
                         "height %d — recording lean hole", h);
            continue;
        }

        struct block blk;
        block_init(&blk);

        size_t remaining = cached_mapping.mapping.size -
                           (size_t)pindex->nDataPos;
        struct byte_stream s;
        stream_init_from_data(&s, cached_mapping.mapping.data +
                                  (size_t)pindex->nDataPos,
                              remaining);
        if (!block_deserialize(&blk, &s)) {
            block_free(&blk);
            if (++lean_holes == 1) first_hole_h = h;
            suspicious_lean_holes++;
            if (lean_holes <= 3)
                LOG_INFO("catchup", "catchup: undecodable block frame at "
                         "height %d — recording lean hole", h);
            continue;
        }

        /* Garbage at a wrong offset can still PARSE as a block; the lean
         * index must never hold a row whose hash disagrees with the
         * block index (the live h=6131 frame parsed, then poisoned
         * db_block_save with nonsense). Hash-bind every frame to its
         * index entry; a mismatch is a lean hole like any other
         * unreadable frame. */
        if (pindex->phashBlock) {
            struct uint256 got;
            block_get_hash(&blk, &got);
            if (!uint256_eq(&got, pindex->phashBlock)) {
                block_free(&blk);
                if (++lean_holes == 1) first_hole_h = h;
                suspicious_lean_holes++;
                if (lean_holes <= 3)
                    LOG_INFO("catchup", "catchup: frame hash mismatch at "
                             "height %d — recording lean hole", h);
                continue;
            }
        } else {
            /* A torn index (e.g. cp -a of a running node) can carry an
             * active-chain slot with BLOCK_HAVE_DATA yet no phashBlock. Its
             * frame cannot be hash-bound to an identity and every downstream
             * write keys off pindex->phashBlock->data; record it as a
             * suspicious lean hole (never advanced over quietly) instead of
             * dereferencing NULL in sync_block_lean. */
            block_free(&blk);
            if (++lean_holes == 1) first_hole_h = h;
            suspicious_lean_holes++;
            if (lean_holes <= 3)
                LOG_INFO("catchup", "catchup: block index missing its hash "
                         "at height %d — recording lean hole", h);
            continue;
        }

        /* Lean index: block header + txid index + explorer projections */
        uint8_t this_receipt[32];
        if (!sync_block_lean(ndb, &blk, pindex, prev_receipt, this_receipt)) {
            LOG_WARN("catchup", "catchup: lean index failed at height %d (sqlite=%s)", h, sqlite3_errmsg(ndb->db));
            block_free(&blk);
            failed = true;
            break;
        }
        memcpy(prev_receipt, this_receipt, 32);

        /* Wallet scan */
        if (w) {
            for (size_t i = 0; i < blk.num_vtx; i++) {
                bool tx_is_ours = false;
                bool tx_ok = false;
                if (!node_db_sync_wallet_tx_checked(ndb, &blk.vtx[i], w, h,
                                                   &tx_is_ours, &tx_ok) || !tx_ok) {
                    LOG_WARN("catchup", "catchup: wallet tx sync failed at height %d " "(tx=%d)", h, (int)i);
                    block_free(&blk);
                    failed = true;
                    break;
                }
                if (tx_is_ours)
                    wallet_hits++;
                bool decrypt_ok = true;
                node_db_catchup_try_sapling_decrypt(ndb, &blk.vtx[i], w, h,
                                                    &decrypt_ok);
                if (!decrypt_ok) {
                    LOG_WARN("catchup", "catchup: sapling decrypt failed at height %d " "(tx=%d)", h, (int)i);
                    block_free(&blk);
                    failed = true;
                    break;
                }
                for (size_t si = 0; si < blk.vtx[i].num_shielded_spend; si++) {
                    struct transaction *mtx = (struct transaction *)&blk.vtx[i];
                    transaction_compute_hash(mtx);
                    /* Only ERROR is fatal; NOT_FOUND (not our note) is benign. */
                    if (node_db_sync_sapling_spend(ndb,
                            blk.vtx[i].v_shielded_spend[si].nullifier.data,
                            mtx->hash.data) == DB_MARK_SPENT_ERROR) {
                        LOG_WARN("catchup", "catchup: sapling spend update failed at height %d " "(tx=%d, spend=%zu)", h, (int)i, si);
                        block_free(&blk);
                        failed = true;
                        break;
                    }
                }
                if (failed) break;
            }
        }
        if (failed) break;

        /* Advance Sapling tree + wallet witnesses */
        if (!advance_wallet_witnesses(ndb, &blk, &sapling_tree, h, w)) {
            LOG_WARN("catchup", "catchup: witness/tree advance failed at height %d", h);
            block_free(&blk);
            failed = true;
            break;
        }

        block_free(&blk);
        indexed++;
        last_indexed_height = h;
        last_indexed_tip = pindex;
        sync_job_catchup_progress(h);

#ifdef ZCL_TESTING
        /* Armed by node_db_catchup_lock_guard_test_force_snapshot_failures:
         * fail this block exactly as a SQLITE_BUSY_SNAPSHOT write failure
         * would, so the rollback + bounded whole-walk restart plumbing is
         * exercised deterministically. */
        if (node_db_catchup_lock_guard_test_consume_snapshot_failure()) {
            LOG_WARN("catchup",
                     "catchup: TEST-INJECTED SQLITE_BUSY_SNAPSHOT write "
                     "failure at height %d", h);
            failed = true;
            busy_snapshot = true;
            break;
        }
#endif

        int64_t t_now = (int64_t)platform_time_wall_time_t();
        if (indexed % batch_size == 0 ||
            t_now - t_batch_start >= NODE_DB_CATCHUP_COMMIT_BATCH_MAX_SECS) {
            if (pindex->phashBlock) {
                if (!node_db_sync_set_tip(ndb, pindex->phashBlock->data, h)) {
                    LOG_WARN("catchup", "catchup: failed to set tip at batch commit %d", h);
                    if (node_db_catchup_lock_guard_busy_snapshot(ndb))
                        busy_snapshot = true;
                    failed = true;
                    break;
                }
            } else {
                LOG_WARN("catchup", "catchup: missing hash at batch commit %d", h);
                failed = true;
                break;
            }
            if (!node_db_commit(ndb)) {
                LOG_WARN("catchup", "catchup: batch COMMIT failed at height %d", h);
                if (node_db_catchup_lock_guard_busy_snapshot(ndb))
                    busy_snapshot = true;
                node_db_rollback(ndb);
                tx_open = false;
                failed = true;
                break;
            }
            node_db_catchup_lock_guard_note_batch_commit();
            tx_open = false;
            t_batch_start = t_now;
            last_committed_height = h;
            /* Persist the Sapling note-commitment frontier to the flat-file
             * checkpoint (rate-limited to every
             * SAPLING_CHECKPOINT_BLOCK_INTERVAL blocks). {h, block hash,
             * root} are self-consistent here: the tree was just advanced to
             * h by appending this block's outputs. A clean restart resumes
             * replay from this height instead of re-folding from Sapling
             * activation. */
            if (pindex->phashBlock)
                sapling_tree_flat_checkpoint_note(&sapling_tree, h,
                                                  pindex->phashBlock->data,
                                                  false);
            int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
            int rate = elapsed > 0 ? indexed / (int)elapsed : 0;
            printf("SQLite: %d/%d blocks (height %d, %d blk/s, %d wallet txs)\n",
                   indexed, total, h, rate, wallet_hits);
            fflush(stdout);
            if (!node_db_begin_immediate(ndb)) {
                LOG_WARN("catchup", "catchup: failed to reopen transaction after batch commit");
                failed = true;
                break;
            }
            tx_open = true;
        }
    }

    node_db_catchup_block_mapping_close(&cached_mapping);

    /* Capture the snapshot class of the first write failure BEFORE any
     * rollback (a successful ROLLBACK would clobber the handle errcode).
     * No DB op runs between a failing write and this point on the break
     * paths above. */
    if (failed && !busy_snapshot &&
        node_db_catchup_lock_guard_busy_snapshot(ndb))
        busy_snapshot = true;

    if (failed) {
        if (tx_open && !node_db_rollback(ndb))
            LOG_WARN("catchup", "catchup: rollback failed after failure");
        tx_open = false;
    }

    /* Final commit */
    if (tx_open && !failed) {
        if (last_indexed_tip && last_indexed_tip->phashBlock) {
            if (!node_db_sync_set_tip(ndb,
                                      last_indexed_tip->phashBlock->data,
                                      last_indexed_height)) {
                LOG_WARN("catchup", "catchup: failed to set tip before final commit");
                failed = true;
            }
        } else {
            int sparse_target = node_db_catchup_sparse_prefix_target(
                indexed, total, lean_holes, first_hole_h, start, chain_tip,
                suspicious_lean_holes, missing_index_holes,
                first_missing_index_h, proven_authority, proven_applied);
            const struct block_index *sparse_tip = sparse_target >= start
                ? active_chain_at(chain, sparse_target) : NULL;
            if (sparse_tip && sparse_tip->phashBlock &&
                catchup_set_sparse_projection_tip(ndb,
                                                  sparse_tip->phashBlock->data,
                                                  sparse_target)) {
                last_indexed_height = sparse_target;
                last_committed_height = sparse_target;
                LOG_INFO("catchup",
                         "catchup: sparse proven prefix %d..%d has no block "
                         "bodies; advanced SQLite projection cursor to h=%d "
                         "without writing block rows (first missing active "
                         "slot=%d)",
                         start, chain_tip, sparse_target,
                         first_missing_index_h);
                event_emitf(EV_RECOVERY_ACTION, 0,
                            "action=sparse_projection_tip_advance "
                            "start=%d height=%d holes=%d first_missing_index=%d",
                            start, sparse_target, lean_holes,
                            first_missing_index_h);
            } else {
                LOG_WARN("catchup", "catchup: final commit missing tip hash");
                failed = true;
            }
        }
        if (!failed) {
            if (!node_db_commit(ndb)) {
                LOG_WARN("catchup", "catchup: final COMMIT failed");
                if (node_db_catchup_lock_guard_busy_snapshot(ndb))
                    busy_snapshot = true;
                if (!node_db_rollback(ndb))
                    LOG_WARN("catchup", "catchup: final ROLLBACK failed");
                tx_open = false;
                failed = true;
                last_indexed_height = last_committed_height;
            } else {
                tx_open = false;
                last_committed_height = last_indexed_height;
                /* Force a fresh flat-file checkpoint at catchup completion
                 * (including on reaching tip), so the next boot has a
                 * checkpoint at the newest applied height. Guarded on a
                 * resolvable tip block hash for the {height, hash, root} key. */
                if (last_indexed_tip && last_indexed_tip->phashBlock)
                    sapling_tree_flat_checkpoint_note(
                        &sapling_tree, last_committed_height,
                        last_indexed_tip->phashBlock->data, true);
            }
        }
    }

    if (failed) {
        if (tx_open && !node_db_rollback(ndb))
            LOG_WARN("catchup", "catchup: final rollback path failed");
        interrupted = false;
    }

    /* Restore safe pragmas and rebuild indexes */
    if (!sync_db_turbo_scope_end(&turbo_mode)) {
        LOG_WARN("catchup", "catchup: failed to restore normal mode");
        restore_ok = false;
    }

    /* BUSY_SNAPSHOT restart seatbelt (node_db_catchup_lock_guard.c): the
     * rollback above unwound the poisoned transaction; the only cure for
     * SQLITE_BUSY_SNAPSHOT is a fresh transaction, and the only safe
     * granularity is the WHOLE walk — the in-memory Sapling tree/witness
     * state is ahead of the rolled-back rows. Catchup is an idempotent
     * projection re-run (tip/receipt/tree all re-derive from persisted
     * state), so a bounded recursion is exact. With BEGIN IMMEDIATE this
     * pass's own writes can no longer produce the class; this covers any
     * residual/regressed deferred writer. */
    if (node_db_catchup_lock_guard_restart_needed(failed, busy_snapshot)) {
        sync_job_catchup_finish();
        int r = node_db_catchup_service_run(ndb, chain, w, datadir);
        node_db_catchup_lock_guard_restart_done();
        return r;
    }

    if (failed || !restore_ok) {
        sync_job_catchup_finish();
        LOG_ERR("sync", "catchup: aborting (failed=%d, restore_ok=%d, indexed=%d)",
                failed, restore_ok, indexed);
    }

    /* One logical pass = one outcome (the restart path above returns
     * before this, so a restarted attempt never double-counts). */
    node_db_catchup_lock_guard_note_outcome(failed || !restore_ok);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    printf("SQLite catchup %s: %d blocks in %llds (%d blk/s, tip=%d)\n",
           interrupted ? "stopped" : "complete",
           indexed, (long long)elapsed,
           elapsed > 0 ? indexed / (int)elapsed : indexed,
           last_committed_height);
    fflush(stdout);
    if (lean_holes > 0) {
        if (suspicious_lean_holes > 0) {
            LOG_WARN("catchup",
                     "catchup: %d lean-index hole(s) recorded (first h=%d, "
                     "missing_file_holes=%d first_file=blk%05d.dat@h=%d, "
                     "suspicious=%d) — unreadable/garbage frames skipped, "
                     "not aborted; those heights stay unindexed until their "
                     "bodies are refetched",
                     lean_holes, first_hole_h, missing_file_holes,
                     first_missing_file_num, first_missing_file_h,
                     suspicious_lean_holes);
        } else {
            LOG_INFO("catchup",
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

    /* Checkpoint WAL after bulk catchup to reclaim disk space */
    if (indexed > 10000)
        node_db_wal_checkpoint(ndb);

    sync_job_catchup_finish();
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
