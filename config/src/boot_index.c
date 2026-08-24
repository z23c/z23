/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Block index management: the chainstate rebuild/reindex core.
 *
 * Part of the boot composition root (config/src/). Owns the consensus
 * UTXO-replay surface — fast_rebuild_chainstate (a precheck), the full
 * reindex_chainstate replay plus its private DB-mode / coins-flush
 * helpers, boot_index_clear_coins_state, and the nChainTx/nChainWork
 * propagation pass (propagate_nchaintx).
 *
 * The background explorer address backfill lives in
 * config/src/boot_address_backfill.c; the on-disk block-file scan lives
 * in config/src/boot_block_file_scan.c. Block index flat-file save/load
 * and SQLite cache functions live in app/services/src/block_index_loader.c. */

#include "platform/time_compat.h"
#include "config/boot_internal.h"
#include "config/boot_memory_guard.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/process_block.h"
#include "validation/connect_block.h"
#include "storage/block_index_db.h"
#include "storage/disk_block_io.h"
#include "coins/coins_view.h"
#include "storage/coins_view_sqlite.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "controllers/sync_controller.h"
#include "net/snapshot_sync_contract.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "jobs/utxo_apply_delta.h"
#include "services/reindex_epilogue.h"
#include "services/utxo_recovery_service.h"
#include "validation/main_state.h"
#include "event/event.h"
#include "primitives/block.h"
#include "storage/boot_auto_reindex.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/boot_status.h"
#include "util/ar_step_readonly.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <malloc.h>
#include <sqlite3.h>
static bool boot_index_shielded_tx(sqlite3 *db, const struct block *blk,
                                   int height, int target_height, bool reset)
{
    if (!db || target_height < 0 || (reset == (blk != NULL)) ||
        (!reset && (height < 0 || height > target_height)))
        LOG_FAIL("reindex-chainstate",
                 "shielded tx invalid args reset=%d blk=%p h=%d target=%d",
                 reset ? 1 : 0, (const void *)blk, height, target_height);

    if (reset) return shielded_history_begin_full_replay(db, target_height);
    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("reindex-chainstate", "anchor BEGIN failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    bool ok = true;
    struct delta_summary summary;
    memset(&summary, 0, sizeof(summary));
    summary.ok = true;
    summary.status = "ok";
    ok = utxo_apply_check_and_insert_anchors_full_replay(
        db, blk, height, &summary);
    if (ok && summary.ok)
        ok = utxo_apply_check_and_insert_nullifiers(db, blk, height,
                                                    &summary);
    if (ok && summary.ok)
        ok = shielded_history_full_replay_advance_in_tx(
            db, height, target_height);
    if (ok && !summary.ok) {
        LOG_WARN("reindex-chainstate",
                 "shielded derivation refused h=%d status=%s kind=%s",
                 height, summary.status ? summary.status : "unknown",
                 summary.failure_kind ? summary.failure_kind : "unknown");
        ok = false;
    }
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("reindex-chainstate", "shielded %s failed: %s", finish,
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        ok = false;
    } else if (err) {
        sqlite3_free(err);
    }
    progress_store_tx_unlock();
    return ok;
}
static struct db_service *boot_index_db_service_for(struct node_db *ndb)
{
    struct db_service *dbsvc = app_runtime_db_service();

    if (!ndb || !dbsvc)
        return NULL;
    return db_service_node_db(dbsvc) == ndb ? dbsvc : NULL;
}

static bool boot_index_enter_turbo_mode(struct node_db *ndb)
{
    struct db_service *dbsvc = boot_index_db_service_for(ndb);

    if (dbsvc)
        return db_service_ibd_turbo_mode(dbsvc);
    return node_db_ibd_turbo_mode(ndb);
}

static bool boot_index_restore_normal_mode(struct node_db *ndb)
{
    struct db_service *dbsvc = boot_index_db_service_for(ndb);

    if (dbsvc)
        return db_service_normal_mode(dbsvc);
    return node_db_normal_mode(ndb);
}

static bool boot_index_set_sync_batch_size(struct node_db *ndb, int batch_size)
{
    struct db_service *dbsvc = boot_index_db_service_for(ndb);

    if (dbsvc)
        return db_service_set_sync_batch_size(dbsvc, batch_size);
    node_db_set_sync_batch_size(ndb, batch_size);
    return true;
}

static bool boot_index_flush_write(struct node_db *ndb)
{
    struct db_service *dbsvc = boot_index_db_service_for(ndb);

    if (dbsvc)
        return db_service_flush_write(dbsvc);
    return node_db_sync_flush(ndb);
}

/* Block index flat file save/load, SQLite cache, and LevelDB loading
 * have been extracted to app/services/src/block_index_loader.c.
 * See services/block_index_loader.h for the public API. */


/* ── Fast chainstate rebuild from SQLite UTXOs ─────────────── */

bool fast_rebuild_chainstate(struct coins_view_sqlite *cvs,
                              struct coins_view_cache *cvtip,
                              const char *datadir)
{
    (void)cvtip;
    (void)datadir;
    /* NULL cvs is a legitimate caller shape (the scan_fallback restore path
     * can run before coins_view_sqlite is wired) — "rebuild unavailable",
     * not a crash. */
    if (!cvs || !cvs->db) return false;

    sqlite3_stmt *cnt = NULL;
    if (sqlite3_prepare_v2(cvs->db, "SELECT count(*) FROM utxos",
                           -1, &cnt, NULL) != SQLITE_OK || !cnt) {
        fprintf(stderr, "fast_rebuild_chainstate: count prepare failed: %s\n",
                sqlite3_errmsg(cvs->db));
        return false;
    }
    int64_t total = 0;
    if (AR_STEP_ROW_READONLY(cnt) == SQLITE_ROW)
        total = sqlite3_column_int64(cnt, 0);
    sqlite3_finalize(cnt);

    if (total == 0) return false;

    printf("SQLite UTXO set: %lld UTXOs (canonical)\n", (long long)total);

    /* The derived coins-best (coins_kv authority) outranks the
     * node_state cache key — a missing/stale cache must not refuse the
     * rebuild on a canonical datadir. Legacy fallback: the cache key. */
    {
        int32_t d_h = -1;
        if (reducer_frontier_derive_coins_best_now(&d_h, NULL, NULL)) {
            printf("fast_rebuild_chainstate: derived coins-best h=%d "
                   "(coins_kv authority)\n", d_h);
            return true;
        }
    }

    struct uint256 best;
    if (!coins_view_sqlite_get_best_block(cvs, &best) ||
        uint256_is_null(&best)) {
        fprintf(stderr,
                "fast_rebuild_chainstate: coins_best_block missing; "
                "refusing legacy tip_hash fallback\n");
        return false;
    }

    return true;
}

/* ── Full chainstate reindex: replay all blocks ────────────── */

static bool boot_index_flush_reindex_coins(struct coins_view_sqlite *cvs,
                                           struct coins_view_cache *cvtip)
{
    if (!cvs || !cvtip)
        LOG_FAIL("boot_index",
                 "reindex coins flush: NULL arg cvs=%p cvtip=%p",
                 (void *)cvs, (void *)cvtip);

    bool ok = coins_view_sqlite_batch_write( // one-write-path-ok:boot-reindex-single-writer
        cvs, &cvtip->cache_coins, &cvtip->hash_block, &cvtip->commitment);
    if (!ok) {
        fprintf(stderr, // obs-ok:helper-context-logged
                "reindex-chainstate: coins flush failed; retaining %zu "
                "dirty entries\n",
                cvtip->cache_coins.size);
        return false;
    }

    coins_map_free(&cvtip->cache_coins);
    coins_map_init(&cvtip->cache_coins);
    cvtip->cached_coins_usage = 0;
    utxo_commitment_init(&cvtip->commitment);
    return true;
}

bool boot_index_reindex_replay_executable(struct main_state *ms,
                                          struct block_tree_db *btdb,
                                          bool btdb_open,
                                          const char *datadir)
{
    if (!datadir)
        return false;

    /* Preferred source: the loaded active chain (the late block-index gate and
     * the post-restore integrity path). Probe h=0/1 exactly like
     * reindex_chainstate's inline verb check. */
    if (ms && active_chain_tip(&ms->chain_active)) {
        int tip = active_chain_height(&ms->chain_active);
        for (int h = 0; h <= (tip < 1 ? tip : 1); h++) {
            struct block_index *pi = active_chain_at(&ms->chain_active, h);
            struct block pblk;
            if (!pi || !read_block_from_disk_index(&pblk, pi, datadir))
                return false;
            block_free(&pblk);
        }
        return true;
    }

    /* The early coins-view / progress.kv gates run BEFORE the in-memory index
     * is loaded, so resolve genesis from the durable block tree DB and attempt
     * the real body read — a cold-import (bodyless) datadir persists
     * BLOCK_HAVE_DATA with no genesis-side body, so the flag alone is not proof;
     * the READ is. Cannot prove genesis readable ⇒ refuse (never wipe state we
     * cannot rebuild from local inputs). */
    if (!btdb || !btdb_open)
        return false;
    const struct chain_params *cp = chain_params_get();
    if (!cp)
        return false;
    struct disk_block_index dbi;
    disk_block_index_init(&dbi);
    if (!block_tree_db_read_block_index(btdb, &cp->consensus.hashGenesisBlock,
                                        &dbi))
        return false;
    struct block_index probe;
    memset(&probe, 0, sizeof(probe));
    probe.phashBlock = &cp->consensus.hashGenesisBlock;
    probe.nHeight = 0;
    probe.nStatus = dbi.nStatus;
    probe.nFile = dbi.nFile;
    probe.nDataPos = dbi.nDataPos;
    struct block gblk;
    if (!read_block_from_disk_index(&gblk, &probe, datadir))
        return false;
    block_free(&gblk);
    return true;
}

/* Clear the persisted coins state (UTXO set + anchor + commitments) so the set
 * can be rebuilt from block data. Shared by reindex_chainstate and the
 * pre-integrity-gate path in app_init: a torn coins anchor would otherwise
 * FATAL the boot integrity gate before the operator's -reindex-chainstate
 * rebuild can run. Idempotent; node_db_exec logs each failing statement. */
bool boot_index_clear_coins_state(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return false;
    /* Wiping a CACHE is always legal (the keys below are projections of
     * coins_kv). Known gap: the reindex epilogue deletes-not-recomputes
     * these — tenacity-roadmap item 3 (F3), out of scope for wave 2. */
    bool ok = node_db_exec(ndb, "DELETE FROM utxos");
    /* coins_best_block (the anchor the gate checks), utxo_commitment (the XOR
     * checkpoint) and utxo_sha3 (the self-heal commitment) are ALL stale once
     * the set is rebuilt — clear them together so nothing stale survives to
     * mis-seed the rebuild or the boot self-heal. */
    if (!node_db_exec(ndb,
            "DELETE FROM node_state WHERE key IN "
            "('coins_best_block','utxo_commitment','utxo_sha3')"))
        ok = false;
    return ok;
}

bool boot_reindex_explorer(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("boot", "reindex_explorer: ndb invalid (ndb=%p)",
                 (void *)ndb);
    printf("Reindex explorer: truncating projection + ZNAM tables, "
           "rewinding catchup tip to genesis\n");
    bool ok = true;
    if (!db_explorer_index_truncate(ndb)) {
        LOG_WARN("boot", "reindex_explorer: projection truncate had errors "
                 "(continuing)");
        ok = false;
    }
    if (!node_db_sync_reset_tip(ndb)) {
        LOG_WARN("boot", "reindex_explorer: failed to rewind catchup tip "
                 "(reindex may not re-walk)");
        ok = false;
    }
    return ok;
}

bool boot_backfill_zslp(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("boot", "backfill_zslp: ndb invalid (ndb=%p)", (void *)ndb);
    printf("Backfill ZSLP: re-deriving tokens+transfers from op_returns "
           "(is_slp=1) — no full reindex...\n");
    int64_t n = db_zslp_backfill(ndb);
    if (n < 0) {
        LOG_WARN("boot", "backfill_zslp: backfill failed");
        return false;
    }
    return true;
}

bool reindex_chainstate(struct main_state *ms,
                          struct coins_view_sqlite *cvs,
                          struct coins_view_cache *cvtip,
                          struct node_db *ndb,
                          const char *datadir)
{
    int tip_height = active_chain_height(&ms->chain_active);
    if (tip_height < 0) {
        fprintf(stderr, "reindex-chainstate: no active chain\n");
        return false;
    }

    printf("reindex-chainstate: rebuilding UTXO set (%d blocks)...\n",
           tip_height + 1);
    event_emitf(EV_SYNC_STATE_CHANGE, 0, "reindex start blocks=%d",
                tip_height + 1);

    mallopt(M_MMAP_THRESHOLD, 32768);

    /* The replay reads every block from h=0 and cannot skip. Verify the
     * verb is executable BEFORE wiping the derived set: a cold-import
     * datadir has no block data below its import window, so a
     * wipe-then-discover order destroys a healthy mirror for nothing
     * (the wipe succeeds, then the very first genesis-side read fails). */
    for (int h = 0; h <= (tip_height < 1 ? tip_height : 1); h++) {
        struct block_index *probe = active_chain_at(&ms->chain_active, h);
        struct block pblk;
        if (!probe || !read_block_from_disk_index(&pblk, probe, datadir)) {
            fprintf(stderr,
                    "reindex-chainstate: block at height %d is unreadable — "
                    "replay-from-blocks/ is not executable on this datadir "
                    "(cold-import window has no genesis-side block data); "
                    "REFUSING before wiping the UTXO set. The right verb "
                    "here is a cold-import re-seed.\n", h);
            event_emitf(EV_BOOT_ACTIVATE, 0,
                        "reindex_refused_unexecutable probe_h=%d tip=%d",
                        h, tip_height);
            /* The verb can NEVER execute on this datadir — a pending
             * auto-reindex sentinel would replay this consume→refuse
             * cycle on every boot (task #29 follow-up). Clear it. */
            boot_auto_reindex_clear(datadir);
            return false;
        }
        block_free(&pblk);
    }

    if (!boot_index_flush_reindex_coins(cvs, cvtip))
        return false;
    coins_view_cache_free(cvtip);

    if (ndb->open) {
        if (boot_index_clear_coins_state(ndb))
            printf("reindex-chainstate: wiped SQLite UTXO set\n");
    }

    coins_view_cache_init(cvtip, &cvs->view);

    /* Reindex is the authoritative from-genesis shielded backfill. Reset roots
     * and nullifiers with a positive marker, derive each block in order, and
     * publish marker zero only in the successful epilogue. */
    sqlite3 *shielded_db = progress_store_db();
    if (!shielded_db ||
        !boot_index_shielded_tx(
            shielded_db, NULL, -1, tip_height, true)) {
        LOG_WARN("reindex-chainstate",
                 "cannot reset durable shielded history");
        return false;
    }

    set_flush_policy(3600, 1000000, 500);
    if (ndb->open) {
        if (!boot_index_enter_turbo_mode(ndb))
            fprintf(stderr, "reindex-chainstate: failed to enter turbo mode\n");
        if (!boot_index_set_sync_batch_size(ndb, 1000))
            fprintf(stderr, "reindex-chainstate: failed to set sync batch size\n");
    }

    extern _Atomic bool g_utxo_commitment_skip;
    atomic_store(&g_utxo_commitment_skip, true);

    if (ndb->open) {
        node_db_state_set(ndb, "sapling_tree", NULL, 0);
        node_db_state_set(ndb, "sapling_tree_rescan_height", NULL, 0);
    }

    const struct chain_params *cparams = chain_params_get();
    int64_t t_start = (int64_t)platform_time_wall_time_t();
    int errors = 0;
    boot_status_set_progress("reindex_chainstate", 0, tip_height);

    for (int h = 0; h <= tip_height; h++) {
        struct block_index *pindex = active_chain_at(
            &ms->chain_active, h);
        if (!pindex) {
            printf("reindex-chainstate: missing block_index at height %d\n", h);
            errors++;
            break;
        }

        struct block blk;
        if (!read_block_from_disk_index(&blk, pindex, datadir)) {
            fprintf(stderr, "reindex-chainstate: failed to read block at "
                    "height %d — stopping to prevent UTXO corruption\n", h);
            errors++;
            break; /* Can't skip blocks during UTXO replay */
        }

        struct validation_state state;
        validation_state_init(&state);
        if (!connect_block(&blk, &state, pindex, cvtip, cparams, false)) {
            fprintf(stderr, "reindex-chainstate: connect_block FATAL at "
                    "height %d: %s — stopping to prevent UTXO corruption\n",
                    h, state.reject_reason);
            block_free(&blk);
            errors++;
            break; /* MUST stop — continuing would skip this block's UTXOs */
        }

        if (!boot_index_shielded_tx(
                shielded_db, &blk, h, tip_height, false)) {
            fprintf(stderr,
                    "reindex-chainstate: shielded history derivation FATAL at "
                    "height %d — stopping to prevent opposite-verdict state\n",
                    h);
            block_free(&blk);
            errors++;
            break;
        }

        block_free(&blk);

        size_t cache_bytes = coins_view_cache_memory_usage(cvtip);
        bool need_flush = boot_reindex_cache_should_flush(h,
            cvtip->cache_coins.size, cache_bytes);
        if (need_flush) {
            if (!boot_index_flush_reindex_coins(cvs, cvtip)) {
                errors++;
                break;
            }
            malloc_trim(0);
            if (h % 1000 == 0 || h == tip_height)
                boot_status_set_progress("reindex_chainstate", h, tip_height);
        }
    }
    if (!boot_index_flush_reindex_coins(cvs, cvtip))
        errors++;

    atomic_store(&g_utxo_commitment_skip, false);
    /* Restore normal mode — flush every 500 blocks */
    set_flush_policy(3600, 500000, 500);
    if (ndb->open) {
        if (!boot_index_flush_write(ndb))
            fprintf(stderr, "reindex-chainstate: flush failed\n");
        if (!boot_index_restore_normal_mode(ndb))
            fprintf(stderr, "reindex-chainstate: failed to restore normal mode\n");
        if (!boot_index_set_sync_batch_size(ndb, 1))
            fprintf(stderr, "reindex-chainstate: failed to reset sync batch size\n");
    }

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    printf("reindex-chainstate: complete in %lldm%llds (%d errors)\n",
           (long long)(elapsed / 60), (long long)(elapsed % 60), errors);
    event_emitf(EV_SYNC_STATE_CHANGE, 0, "reindex complete %dm%ds errors=%d",
                (int)(elapsed / 60), (int)(elapsed % 60), errors);

    /* Derive ALL durable post-reindex state from the just-replayed set in one
     * ordered commit (tenacity-roadmap item 3): reseed coins_kv, recompute the
     * SHA3 commitment that boot_index_clear_coins_state deleted, and clamp the
     * reducer cursors + coins_applied_height + tip_finalize anchor to the
     * replayed tip. Without this the recovery path itself manufactures the
     * coins_applied > hstar coin-tear wedge; with the never-give-up unit that
     * degrades into an infinite reindex loop. Runs only after a clean replay
     * (errors==0); g_utxo_commitment_skip is already CLEARED above so the
     * commitment recompute runs with tracking ON. On failure it PAGES
     * (EV_OPERATOR_NEEDED, inside the epilogue) and returns false so the
     * reindex sentinel stays pending and the next boot retries — never
     * serving torn, never FATAL. Retries via the still-pending sentinel do
     * NOT advance the attempt budget (the count moves only when post-restore
     * integrity re-requests the rebuild), so the per-failure page is the
     * backstop for a persistently failing epilogue. */
    if (errors == 0) {
        if (!reindex_epilogue_derive(ms, ndb, datadir)) {
            fprintf(stderr, // obs-ok:paired-with-return-false-below
                    "reindex-chainstate: epilogue derivation FAILED — durable "
                    "state not clamped to replayed tip; sentinel left pending "
                    "for next-boot retry\n");
            boot_status_set_progress(NULL, -1, -1);
            return false;   /* leave the sentinel for retry; never serve torn */
        }
    }
    boot_status_set_progress(NULL, -1, -1);
    return errors == 0;
}

/* Address backfill (backfill_addresses_thread) moved to
 * config/src/boot_address_backfill.c. */

/* Block-file scan (scan_block_files_mark_data + helpers) moved to
 * config/src/boot_block_file_scan.c. */

/* ── Reusable nChainTx + nChainWork propagation ────────────────
 * Called after scan_block_files_mark_data or any operation that
 * sets BLOCK_HAVE_DATA on blocks. Propagates nChainTx (cumulative
 * tx count) and nChainWork so find_most_work_chain can consider
 * these blocks as chain tip candidates.
 * Returns the number of blocks whose nChainTx was updated. */
int propagate_nchaintx(struct main_state *ms)
{
    if (!ms) return 0;

    size_t total = ms->map_block_index.size;
    struct block_index **sorted = zcl_malloc(total * sizeof(struct block_index *), "boot.index.propagate_sorted");
    if (!sorted) return 0;

    size_t n = 0;
    size_t iter = 0;
    struct block_index *bi;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
        if (bi && (bi->pprev || (bi->nStatus & BLOCK_HAVE_DATA)))
            sorted[n++] = bi;
    }

    qsort(sorted, n, sizeof(struct block_index *), block_index_cmp_height);

    int total_propagated = 0;
    for (int pass = 0; pass < 50; pass++) {
        int propagated = 0;
        for (size_t i = 0; i < n; i++) {
            struct block_index *b = sorted[i];
            if (b->nHeight == 0) {
                if (b->nChainTx == 0) {
                    b->nChainTx = b->nTx > 0 ? b->nTx : 1;
                    propagated++;
                }
                if (arith_uint256_is_zero(&b->nChainWork)) {
                    b->nChainWork = GetBlockProof(b);
                    propagated++;
                }
            } else if (b->pprev && b->pprev->nChainTx > 0) {
                unsigned int ntx = b->nTx > 0 ? b->nTx : 1;
                unsigned int expected = b->pprev->nChainTx + ntx;
                if (b->nChainTx != expected) {
                    b->nChainTx = expected;
                    propagated++;
                }
            } else if (b->pprev && b->pprev->nChainTx == 0) {
                unsigned int ntx = b->pprev->nTx > 0 ? b->pprev->nTx : 1;
                b->pprev->nChainTx = b->pprev->nHeight > 0 ?
                    (unsigned)(b->pprev->nHeight) : ntx;
                unsigned int btx = b->nTx > 0 ? b->nTx : 1;
                b->nChainTx = b->pprev->nChainTx + btx;
                if (arith_uint256_is_zero(&b->pprev->nChainWork)) {
                    b->pprev->nChainWork = GetBlockProof(b->pprev);
                    if (b->pprev->pprev &&
                        !arith_uint256_is_zero(&b->pprev->pprev->nChainWork))
                        arith_uint256_add(&b->pprev->nChainWork,
                            &b->pprev->pprev->nChainWork,
                            &b->pprev->nChainWork);
                }
                propagated += 2;
            }
            /* Propagate nChainWork alongside nChainTx */
            if (b->pprev && !arith_uint256_is_zero(&b->pprev->nChainWork) &&
                arith_uint256_is_zero(&b->nChainWork)) {
                struct arith_uint256 proof = GetBlockProof(b);
                arith_uint256_add(&b->nChainWork,
                                  &b->pprev->nChainWork, &proof);
                propagated++;
            }
        }
        total_propagated += propagated;
        if (propagated == 0) break;
    }

    free(sorted);
    return total_propagated;
}

/* ── Coins/tip consistency safety check ────────────────────────────────
 *
 * After LDB import, the UTXO set can sit far above the chain tip (or the
 * coins_best hash can be missing from the index entirely). Promote the
 * durable UTXO anchor / reconcile coins_best vs the active tip.
 *
 * INVARIANT A (index half) on every real-block promotion: the coins
 * cursor PROPOSES a tip, it does not get to INSTALL one. A coins-best
 * block on a detached index island must not become the live tip — an
 * ungated promotion to an island root leaves tip-window holes and forces
 * a crash-only reindex. Refuse loudly and let header/body refill
 * re-derive. */
void boot_index_verify_coins_tip_consistency(struct main_state *ms,
                                             struct coins_view_sqlite *cvs,
                                             struct node_db *ndb)
{
    if (!ms)
        return;

    struct uint256 coins_hash;
    uint256_set_null(&coins_hash);
    int utxo_max_h = 0;
    bool derived = false;

    /* DERIVED inputs first. The stale-label promotion below guesses from
     * the mirror's MAX(height) + the node_state anchor cache, which can
     * over-promote to a detached island. On canonical datadirs both inputs
     * are substituted from coins_kv's own co-committed state: coins_hash =
     * the derived hash (when the durable logs resolve one), utxo_max_h =
     * the derived height. The promotion heuristic then cannot fire above
     * the derivation. Legacy datadirs keep the cache reads unchanged. */
    {
        int32_t d_h = -1;
        uint8_t d_hash[32];
        bool d_hf = false;
        if (reducer_frontier_derive_coins_best_now(&d_h, d_hash, &d_hf)) {
            derived = true;
            utxo_max_h = d_h > 0 ? d_h : 0;
            if (d_hf)
                memcpy(coins_hash.data, d_hash, 32);
        }
    }

    if (!derived) {
        /* Legacy LDB-import safety check: needs the coins.db best-block, not
         * the projection (no best-block). Read from the coins sqlite view
         * directly while that legacy recovery fallback remains. */
        if (cvs && cvs->db)
            coins_view_sqlite_get_best_block(cvs, &coins_hash);
        if (ndb && ndb->open) {
            sqlite3_stmt *hst = NULL;
            if (sqlite3_prepare_v2(ndb->db,
                    "SELECT MAX(height) FROM utxos", -1,
                    &hst, NULL) == SQLITE_OK && hst) {
                if (AR_STEP_ROW_READONLY(hst) == SQLITE_ROW)  // obs-ok:boot-utxo-max-scan
                    utxo_max_h = sqlite3_column_int(hst, 0);
                sqlite3_finalize(hst);
            }
        }
    }

    int chain_h = active_chain_height(&ms->chain_active);
    struct block_index *coins_bi = NULL;

    if (!uint256_is_null(&coins_hash))
        coins_bi = block_map_find(&ms->map_block_index, &coins_hash);

    if (coins_bi && utxo_max_h > 100000 &&
        utxo_max_h > coins_bi->nHeight + 100) {
        /* The block index can carry stale height labels after recovery
         * from flat-index damage.  When coins_best_block resolves to a
         * hash and the durable UTXO table proves a much higher snapshot
         * height, preserve that immutable high-water state.  The stale
         * label can also be too high after a legacy import from a running
         * node whose chainstate is behind its block tip; in both cases
         * replay must start from the durable UTXO anchor height. */
        struct block_index *best_anchor = NULL;
        struct block_index *best_have = NULL;
        size_t iter = 0;
        struct block_index *bi;
        while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
            if (!bi) continue;
            if (bi->nHeight > utxo_max_h) continue;
            if (!best_anchor || bi->nHeight > best_anchor->nHeight)
                best_anchor = bi;
            if (!(bi->nStatus & BLOCK_HAVE_DATA)) continue;
            if (!best_have || bi->nHeight > best_have->nHeight)
                best_have = bi;
        }
        struct block_index *promote_bi = best_anchor ? best_anchor : best_have;
        if (promote_bi && promote_bi->phashBlock) {
            printf("[boot] stale coins_best_block h=%d but UTXOs reach "
                   "h=%d — promoting anchor to h=%d%s\n",
                   coins_bi->nHeight, utxo_max_h, promote_bi->nHeight,
                   (promote_bi->nStatus & BLOCK_HAVE_DATA) ? " HAVE_DATA" : "");
            /* Invariant A — the same hash-linked-to-a-trust-root guard the
             * two sibling tip-promotion paths below enforce (the coins_bi
             * path and the best_have_data path). Without it, a header-only
             * or detached-island block resolved as the highest anchor would
             * be installed as the live tip: coins_best stamps onto a block
             * with no real pprev chain, the active_chain is left with
             * thousands of holes, and Part L's post-restore integrity gate
             * fail-fasts the boot. Refusing here falls through to the
             * HAVE_DATA search below, which re-derives forward via gap-fill. */
            if (!utxo_recovery_block_trust_rooted(promote_bi)) {
                fprintf(stderr,
                        "[boot] UTXO/chain mismatch: highest anchor h=%d "
                        "is NOT hash-linked to a trust root (detached "
                        "island); refusing tip promotion, keeping tip at "
                        "h=%d\n", promote_bi->nHeight, chain_h);
                event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=restore_tip_refused candidate=%d "
                    "via=unrooted reason=utxo_height_anchor",
                    promote_bi->nHeight);
            } else if (boot_promote_tip_via_csr(
                    promote_bi, "promote_utxo_height_anchor", true)) {
                snapsync_set_anchor(promote_bi);
                chain_h = promote_bi->nHeight;
                coins_bi = promote_bi;
            }
        }
    }

    /* Only promote coins_bi to tip if it's a real block (has data on
     * disk). A metadata-anchor placeholder (BLOCK_VALID_UNKNOWN, no
     * BLOCK_HAVE_DATA) has no real pprev chain — making it the tip
     * leaves the active_chain with 10k+ holes and trips Part L's
     * post-restore integrity gate (which then fail-fasts the boot).
     * If coins_bi is a placeholder, fall through to the HAVE_DATA
     * search below — that's the highest hash we can actually walk
     * back from. The chain will re-derive forward via gap-fill. */
    bool coins_bi_real = coins_bi &&
                         (coins_bi->nStatus & BLOCK_HAVE_DATA);
    if (coins_bi_real && coins_bi->nHeight > chain_h) {
        if (!utxo_recovery_block_trust_rooted(coins_bi)) {
            fprintf(stderr,
                "[boot] UTXO/chain mismatch: coins at h=%d, chain tip "
                "at h=%d — but the coins-best block is NOT hash-linked "
                "to a trust root (detached island); refusing tip "
                "promotion, keeping tip at h=%d\n",
                coins_bi->nHeight, chain_h, chain_h);
            event_emitf(EV_RECOVERY_ACTION, 0,
                "action=restore_tip_refused candidate=%d "
                "via=unrooted reason=utxo_chain_mismatch",
                coins_bi->nHeight);
        } else {
            printf("[boot] UTXO/chain mismatch: coins at h=%d, "
                   "chain tip at h=%d — correcting\n",
                   coins_bi->nHeight, chain_h);
            if (boot_promote_tip_preserving_header_via_csr(
                    coins_bi, "utxo_chain_mismatch", false)) {
                printf("[boot] Chain tip corrected to h=%d\n",
                       coins_bi->nHeight);
            }
        }
    } else if ((!coins_bi || !coins_bi_real) && !uint256_is_null(&coins_hash)) {
        /* coins_best_block hash not in block index. Find the highest
         * block with BLOCK_HAVE_DATA as our best anchor point. The
         * UTXO set should be valid somewhere near that height. */
        struct block_index *best_have_data = NULL;
        size_t iter = 0;
        struct block_index *bi;
        while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
            if (!bi) continue;
            if (!(bi->nStatus & BLOCK_HAVE_DATA)) continue;
            if (!best_have_data ||
                bi->nHeight > best_have_data->nHeight)
                best_have_data = bi;
        }
        if (best_have_data &&
            !utxo_recovery_block_trust_rooted(best_have_data)) {
            /* Same Invariant A refusal as above: the highest
             * HAVE_DATA block can sit on a detached island. */
            fprintf(stderr,
                "[boot] coins_best_block not in index and the highest "
                "HAVE_DATA block h=%d is NOT hash-linked to a trust "
                "root; refusing tip promotion\n",
                best_have_data->nHeight);
            event_emitf(EV_RECOVERY_ACTION, 0,
                "action=restore_tip_refused candidate=%d "
                "via=unrooted reason=best_have_data",
                best_have_data->nHeight);
        } else if (best_have_data &&
                   best_have_data->nHeight > chain_h + 100) {
            printf("[boot] coins_best_block not in index — "
                   "using highest HAVE_DATA block at h=%d\n",
                   best_have_data->nHeight);
            /* Resync coins view + UTXO state to the new tip:
             *   1. coins_best_block must match the tip hash, or
             *      connect_block will FATAL on the next block
             *      with "view/prevblock mismatch".
             *   2. UTXO rows above the new tip height belong to
             *      the fork we're abandoning. Delete them so
             *      future blocks see a coherent set. */
            if (boot_promote_tip_via_csr(
                    best_have_data, "best_have_data", true)) {
                /* Chose best_have_data over the orphan-coins
                 * anchor, so clear the anchor too — otherwise
                 * activation stays in ANCHOR_ACTIVE waiting for
                 * tip to climb above the anchor height, but we
                 * intentionally chose a LOWER tip and want
                 * gap-fill to drive us forward. */
                snapsync_set_anchor(NULL);
                if (ndb && ndb->open) {
                    int pruned = coins_rewind_above_tip(
                        ndb->db, best_have_data->nHeight, -1);
                    if (pruned < 0)
                        fprintf(stderr,
                            "[boot] WARN: failed to prune fork-side "
                            "utxos above h=%d (continuing)\n",
                            best_have_data->nHeight);
                    else
                        printf("[boot] pruned fork-side utxos above "
                               "h=%d (rows=%d)\n",
                               best_have_data->nHeight, pruned);
                }
                printf("[boot] cleared orphan-coins restore anchor — "
                       "gap-fill will resync above h=%d\n",
                       best_have_data->nHeight);
            }
        }
    }
}
