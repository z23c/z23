/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Snapshot controller — parallel LevelDB → SQLite import.
 *
 * Imports a snapshot into SQLite in parallel:
 *
 *   T1: block index LevelDB → blocks table (~30s for 3M blocks)
 *   T2: chainstate LevelDB  → utxos table  (~50s for 5M outputs)
 *   T3: wallet scan          → wallet_* tables (~10s)
 *
 * After import, copies block files + LevelDB to the C23 data dir for
 * ongoing consensus operation. See snapshot_controller.c for snapshot
 * creation and the shared SQLite transaction helpers used here. */

#pragma GCC diagnostic ignored "-Wformat-truncation"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "controllers/snapshot_controller.h"
#include "snapshot_controller_internal.h"
#include "config/file_ops.h"
#include "controllers/legacy_import.h"
#include "controllers/sync_controller.h"
#include "snapshot_import_chain_select.h"
#include "snapshot_import_row_verify.h"
#include "storage/dbwrapper.h"
#include "storage/block_index_db.h"
#include "storage/coins_db.h"
#include "chain/chain.h"   /* BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO */
#include "chain/chainparams.h"
#include "chain/checkpoints.h"  /* get_rom_state_checkpoint (re-derive floor) */
#include "chain/equihash.h"
#include "chain/pow.h"
#include "models/block.h"
#include "models/database.h"   /* node_db_state_set_int (fast-boot cursors) */
#include "models/utxo.h"
#include "wallet/wallet.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/thread_registry.h"

/* ---- Thread 1: Block index LevelDB → SQLite blocks table ---- */

struct block_index_import_args {
    const char *snapshot_dir;
    const char *db_path;
    bool header_only;   /* strip HAVE_DATA + file positions (lazy bodies) */
    int result;
    int count;
    int quarantined;    /* rows skipped this run — see import_row_verify() */
};

/* Process-lifetime count of rows quarantined by import_row_verify() across
 * every --importblockindex / snapshot-bundle call in this process. Exposed
 * for tests/diagnostics; never resets mid-process (a fresh CLI process
 * starts it at 0). */
static _Atomic(uint64_t) g_import_row_quarantine_total = 0;

uint64_t snapshot_import_block_index_quarantine_total(void)
{
    return atomic_load_explicit(&g_import_row_quarantine_total,
                                memory_order_relaxed);
}

static struct log_throttle g_import_row_verify_warn_throttle = LOG_THROTTLE_INIT;

/* Quarantine bookkeeping: bump the process counter, refresh the (rate-
 * limited) typed blocker, and log — never a silent skip. `reason` is a
 * short machine token from import_row_verify(); `block_hash` is the
 * LevelDB key's claimed hash (the same bytes the caller already has, valid
 * regardless of whether hash-bind itself is what failed). */
static void import_row_quarantine(int height, const uint8_t block_hash[32],
                                  const char *reason)
{
    atomic_fetch_add_explicit(&g_import_row_quarantine_total, 1,
                              memory_order_relaxed);

    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i * 2, 3, "%02x", block_hash[31 - i]);

    struct blocker_record r;
    char reason_buf[BLOCKER_REASON_MAX];
    snprintf(reason_buf, sizeof(reason_buf),
             "importblockindex: row quarantined height=%d hash=%s reason=%s "
             "(row skipped, bulk import continues)",
             height, hash_hex, reason);
    if (blocker_init(&r, "importblockindex_row_quarantine", "importblockindex",
                     BLOCKER_TRANSIENT, reason_buf))
        (void)blocker_set(&r);

    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_import_row_verify_warn_throttle,
                                 (uint64_t)height, platform_time_wall_unix(),
                                 30, &reps))
        LOG_WARN("importblockindex",
                 "row quarantined height=%d hash=%s reason=%s "
                 "(suppressed_since_last=%llu)",
                 height, hash_hex, reason, (unsigned long long)reps);
}

static bool import_block_index_reset(struct node_db *ndb)
{
    static const uint8_t zero_hash[32] = {0};
    if (!snapshot_tx_begin_checked(ndb, "T1 begin projection reset"))
        return false; // raw-return-ok:callee-logged
    if (!node_db_state_delete(ndb, "pprev_repaired_height") ||
        !node_db_state_delete(ndb, "shielded_backfill_height") ||
        !snapshot_sql_exec_checked(ndb, "DELETE FROM blocks",
                                   "T1 clear blocks") ||
        !node_db_sync_set_tip(ndb, zero_hash, -1)) {
        snapshot_tx_rollback_best_effort(ndb, "T1 rollback projection reset");
        LOG_FAIL("snapshot", "T1 atomic projection reset failed");
    }
    return snapshot_tx_commit_checked(ndb, "T1 commit projection reset");
}

static bool import_block_index_stamp_cursors(struct node_db *ndb,
                                             int max_height)
{
    if (!snapshot_tx_begin_checked(ndb, "T1 begin cursor stamp"))
        return false; // raw-return-ok:callee-logged
    if (!node_db_state_set_int(ndb, "pprev_repaired_height", max_height) ||
        !node_db_state_set_int(ndb, "shielded_backfill_height", max_height)) {
        snapshot_tx_rollback_best_effort(ndb, "T1 rollback cursor stamp");
        LOG_FAIL("snapshot", "T1 atomic fast-boot cursor stamp failed");
    }
    return snapshot_tx_commit_checked(ndb, "T1 commit cursor stamp");
}

/* Populate one blocks-table row from the deserialized source index record.
 * Per-block Sprout/Sapling value deltas travel in the source
 * CDiskBlockIndex, so populate the projection columns here instead of
 * forcing the boot-time backfill to re-read every block body from disk.
 * These are display/projection values (not consensus); the boot backfill
 * computes the identical per-block delta (sapling = Σ value_balance, sprout
 * = Σ vpub_old − vpub_new). hashFinalSaplingRoot is a CONSENSUS field
 * committed in every block HEADER; the source CDiskBlockIndex carries it,
 * so a header-only import already has the chain-committed tip Sapling root
 * without any block body. Persist it into the projection column now —
 * otherwise blocks.sapling_root stays all-zero until full block connection,
 * and the complete shielded-history import (-import-complete-shielded)
 * cannot bind its tip frontier against a zero column (it refuses,
 * all-or-nothing). Full connection later writes the IDENTICAL value (the
 * header field), so this is a pure projection fill, never a consensus
 * decision. header_only strips the body-location metadata so the node
 * fetches bodies lazily via P2P instead of trying to read files it does not
 * have; the zeroed positions are never read because HAVE_DATA/HAVE_UNDO are
 * cleared — the node gates all block-file reads on those status bits. Also
 * folds the row into *max_height (seeds the fast-boot cursors). */
static void import_block_index_fill_row(struct db_block *db_blk,
                                        struct disk_block_index *dbi,
                                        const uint8_t *block_hash,
                                        bool header_only,
                                        int *max_height)
{
    memset(db_blk, 0, sizeof(*db_blk));
    memcpy(db_blk->hash, block_hash, 32);
    db_blk->height = dbi->nHeight;
    memcpy(db_blk->prev_hash, dbi->hashPrev.data, 32);
    db_blk->version = dbi->nVersion;
    memcpy(db_blk->merkle_root, dbi->hashMerkleRoot.data, 32);
    db_blk->time = dbi->nTime;
    db_blk->bits = dbi->nBits;
    memcpy(db_blk->nonce, dbi->nNonce.data, 32);
    db_blk->solution = dbi->nSolution;
    db_blk->solution_len = dbi->nSolutionSize;
    db_blk->num_tx = (int)dbi->nTx;
    db_blk->sapling_value = dbi->nSaplingValue;
    db_blk->sprout_value = dbi->has_sprout_value ? dbi->nSproutValue : 0;
    memcpy(db_blk->sapling_root, dbi->hashFinalSaplingRoot.data, 32);
    if (dbi->nHeight > *max_height)
        *max_height = dbi->nHeight;
    if (header_only) {
        db_blk->status = (int)dbi->nStatus & ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        db_blk->file_num = 0;
        db_blk->data_pos = 0;
        db_blk->undo_pos = 0;
    } else {
        db_blk->status = (int)dbi->nStatus;
        db_blk->file_num = dbi->nFile;
        db_blk->data_pos = (int)dbi->nDataPos;
        db_blk->undo_pos = (int)dbi->nUndoPos;
    }
}

/* Re-derive the ROM state checkpoint height used as the verification
 * floor for imported rows (-1 when no ROM checkpoint is present). */
static int64_t import_block_index_rom_checkpoint_height(void)
{
    const struct rom_state_checkpoint *rom_cp = get_rom_state_checkpoint();
    return rom_cp ? (int64_t)rom_cp->height : -1;
}

/* Close the three sources the T1 import opened: the block index LevelDB
 * wrapper, the selected-chain record, and this thread's SQLite handle. */
static void import_block_index_close_sources(struct db_wrapper *dbw,
                                             struct snapshot_selected_chain *chain,
                                             struct node_db *ndb)
{
    db_wrapper_close(dbw);
    snapshot_selected_chain_free(chain);
    node_db_close(ndb);
}

/* Prepare the SQLite side for the bulk walk and position the iterator:
 * turbo pragmas, busy timeout, drop the block indexes, reset the blocks
 * projection, then seek to the first 'b' key and open the bulk load
 * transaction. On any failure everything opened so far is closed and
 * false is returned — the caller only returns NULL. */
static bool import_block_index_begin_bulk_scan(struct node_db *ndb,
                                               struct db_wrapper *dbw,
                                               struct snapshot_selected_chain *chain,
                                               struct db_iterator *it)
{
    /* Turbo mode */
    bool ok = snapshot_sql_exec_checked(ndb, "PRAGMA synchronous=OFF",
                                        "T1 set synchronous=OFF") &&
              snapshot_sql_exec_checked(ndb, "PRAGMA cache_size=-524288",
                                        "T1 set cache_size") &&
              snapshot_sql_exec_checked(ndb, "PRAGMA wal_autocheckpoint=0",
                                        "T1 disable wal_autocheckpoint");
    if (ok) {
        sqlite3_busy_timeout(ndb->db, 30000);

        /* Drop block indexes for bulk load */
        ok = snapshot_sql_exec_checked(ndb,
                "DROP INDEX IF EXISTS idx_blocks_prev",
                "T1 drop idx_blocks_prev") &&
             snapshot_sql_exec_checked(ndb,
                "DROP INDEX IF EXISTS idx_blocks_height",
                "T1 drop idx_blocks_height") &&
             snapshot_sql_exec_checked(ndb,
                "DROP INDEX IF EXISTS idx_blocks_chainwork",
                "T1 drop idx_blocks_chainwork");
    }
    if (ok)
        ok = import_block_index_reset(ndb);
    if (!ok) {
        import_block_index_close_sources(dbw, chain, ndb);
        return ok;
    }

    /* Iterate all 'b'-prefixed entries */
    db_iter_init(it, dbw);

    char seek_key[33];
    seek_key[0] = 'b';
    memset(seek_key + 1, 0, 32);
    db_iter_seek(it, seek_key, 33);

    bool begun = snapshot_tx_begin_checked(ndb,
                                           "T1 begin bulk load transaction");
    if (!begun) {
        db_iter_free(it);
        import_block_index_close_sources(dbw, chain, ndb);
    }
    return begun;
}

/* Outcome of import_block_index_next_row() for one source LevelDB row. */
enum snapshot_import_row_status {
    SNAPSHOT_IMPORT_ROW_END,      /* non-'b' key: the 'b' walk is over */
    SNAPSHOT_IMPORT_ROW_SKIPPED,  /* row not imported; iterator advanced */
    SNAPSHOT_IMPORT_ROW_READY     /* row verified and filled into *db_blk */
};

/* Fetch, deserialize, and harden-verify the row under *it. Rows that are
 * skipped (short key, failed deserialize, off the selected chain, or
 * quarantined by verification) advance the iterator and return
 * ..._SKIPPED; the first non-'b' key returns ..._END without advancing;
 * a row that passes every check is filled into *db_blk (whose solution
 * points into the caller-owned *dbi, which must outlive the save) and
 * returned as
 * ..._READY — the caller saves it and advances the iterator itself. */
static enum snapshot_import_row_status
import_block_index_next_row(struct db_iterator *it,
                            struct snapshot_selected_chain *selected_chain,
                            const struct chain_params *cp,
                            int64_t rom_checkpoint_height,
                            struct block_index_import_args *a,
                            int *max_height,
                            struct disk_block_index *dbi,
                            struct db_block *db_blk)
{
    size_t key_len;
    const char *key_data = db_iter_key(it, &key_len);

    if (key_len < 1 || key_data[0] != 'b')
        return SNAPSHOT_IMPORT_ROW_END;
    if (key_len < 33) {
        db_iter_next(it);
        return SNAPSHOT_IMPORT_ROW_SKIPPED;
    }

    /* Hash is in key bytes 1..32 */
    uint8_t block_hash[32];
    memcpy(block_hash, key_data + 1, 32);

    /* Deserialize disk_block_index from value */
    size_t val_len;
    const char *val_data = db_iter_value(it, &val_len);

    disk_block_index_init(dbi);
    struct byte_stream s;
    stream_init_from_data(&s, (unsigned char *)val_data, val_len);

    if (!disk_block_index_deserialize(dbi, &s)) {
        stream_free(&s);
        db_iter_next(it);
        return SNAPSHOT_IMPORT_ROW_SKIPPED;
    }
    stream_free(&s);

    if (!snapshot_selected_chain_contains(selected_chain, dbi->nHeight,
                                          block_hash)) {
        db_iter_next(it);
        return SNAPSHOT_IMPORT_ROW_SKIPPED;
    }

    /* Trust hardening: hash-bind this row to the LevelDB key
     * that named it, and check its PoW target — see import_row_verify()
     * doc comment above. A row failing either is quarantined (skipped,
     * counted, typed blocker) — the bulk import CONTINUES rather than
     * aborting on one bad legacy row. */
    char reason[64];
    if (!snapshot_import_row_verify(dbi, block_hash, cp,
                                    rom_checkpoint_height,
                                    reason, sizeof(reason))) {
        import_row_quarantine(dbi->nHeight, block_hash, reason);
        a->quarantined++;
        db_iter_next(it);
        return SNAPSHOT_IMPORT_ROW_SKIPPED;
    }

    import_block_index_fill_row(db_blk, dbi, block_hash,
                                a->header_only, max_height);
    return SNAPSHOT_IMPORT_ROW_READY;
}

/* Every 100000 imported rows: commit the in-flight bulk transaction,
 * report progress, and reopen a fresh one. Updates *tx_open to the live
 * transaction state and returns false when the batch commit or reopen
 * failed — the caller aborts the walk. */
static bool import_block_index_batch_rollover(struct node_db *ndb, int count,
                                              int64_t t_start, bool *tx_open)
{
    if (count % 100000 != 0)
        return true;
    bool committed = snapshot_tx_commit_checked(ndb, "T1 batch commit");
    if (!committed) {
        *tx_open = false;
        return committed;
    }
    *tx_open = false;
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    int rate = elapsed > 0 ? count / (int)elapsed : count;
    printf("T1: %d blocks (%d/s)\n", count, rate);
    fflush(stdout);
    bool reopened = snapshot_tx_begin_checked(ndb, "T1 batch reopen");
    *tx_open = reopened;
    return reopened;
}

/* Rebuild the block indexes dropped for the bulk load and restore the
 * turbo-mode pragmas. Returns the combined result of the checked
 * statements. */
static bool import_block_index_rebuild_block_indexes(struct node_db *ndb)
{
    /* Rebuild indexes */
    printf("T1: rebuilding block indexes...\n");
    fflush(stdout);
    return snapshot_sql_exec_checked(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_height"
            " ON blocks(height) WHERE status >= 3",
            "T1 rebuild idx_blocks_height") &&
           snapshot_sql_exec_checked(ndb,
            "CREATE INDEX IF NOT EXISTS idx_blocks_prev ON blocks(prev_hash)",
            "T1 rebuild idx_blocks_prev") &&
           snapshot_sql_exec_checked(ndb,
            "CREATE INDEX IF NOT EXISTS idx_blocks_chainwork"
            " ON blocks(chain_work DESC)",
            "T1 rebuild idx_blocks_chainwork") &&
           snapshot_sql_exec_checked(ndb, "PRAGMA synchronous=NORMAL",
            "T1 restore synchronous=NORMAL") &&
           snapshot_sql_exec_checked(ndb, "PRAGMA wal_autocheckpoint=1000",
            "T1 restore wal_autocheckpoint");
}

/* Wind the import down after the bulk walk. ok=false rolls the open bulk
 * transaction back (if any) and stops; otherwise the tail transaction is
 * committed, the block indexes rebuilt, the fast-boot cursors stamped,
 * the sources closed and, on full success, the completion line printed
 * and a->result set to 0. Every failure path closes the sources and
 * leaves a->result at -1. */
static void import_block_index_finalize(struct node_db *ndb,
                                        struct db_wrapper *dbw,
                                        struct snapshot_selected_chain *chain,
                                        bool ok, bool tx_open, int max_height,
                                        int64_t t_start,
                                        struct block_index_import_args *a)
{
    if (!ok) {
        if (tx_open)
            snapshot_tx_rollback_best_effort(ndb, "T1 rollback after failure");
        import_block_index_close_sources(dbw, chain, ndb);
        return;
    }

    bool committed = !tx_open ||
                     snapshot_tx_commit_checked(ndb, "T1 final commit");
    if (!committed) {
        import_block_index_close_sources(dbw, chain, ndb);
        return;
    }

    bool done = import_block_index_rebuild_block_indexes(ndb);
    if (!done) {
        import_block_index_close_sources(dbw, chain, ndb);
        return;
    }

    /* Fast-boot cursors: the imported index carries authoritative prev_hash
     * and per-block shielded deltas, so the normal boot's pprev-repair disk
     * walk and shielded backfill are redundant on this datadir. Stamp both
     * "done-through" cursors to the imported tip so boot skips those O(chain)
     * passes and RPC binds in seconds. A datadir NOT produced by this path
     * leaves the cursors absent (-1) and does the full work once. */
    if (max_height >= 0) {
        done = import_block_index_stamp_cursors(ndb, max_height);
        if (done) {
            printf("T1: fast-boot cursors set (pprev_repaired_height=%d, "
                   "shielded_backfill_height=%d)\n", max_height, max_height);
            fflush(stdout);
        }
    }
    if (!done) {
        import_block_index_close_sources(dbw, chain, ndb);
        return;
    }

    import_block_index_close_sources(dbw, chain, ndb);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    printf("T1: block index import complete: %d blocks in %llds"
           " (%d quarantined)\n",
           a->count, (long long)elapsed, a->quarantined);
    fflush(stdout);

    a->result = 0;
}

static void *import_block_index_thread(void *arg)
{
    struct block_index_import_args *a = arg;
    a->result = -1;
    a->count = 0;
    a->quarantined = 0;

    const struct chain_params *cp = chain_params_get();
    int64_t rom_checkpoint_height = import_block_index_rom_checkpoint_height();

    /* Open our own SQLite connection */
    struct node_db ndb;
    if (!node_db_open(&ndb, a->db_path)) {
        LOG_NULL("snapshot", "T1: failed to open SQLite");
    }

    /* Open block index LevelDB from snapshot */
    char idx_path[1024];
    snprintf(idx_path, sizeof(idx_path), "%s/blocks/index", a->snapshot_dir);

    struct snapshot_selected_chain selected_chain;
    snapshot_selected_chain_load(idx_path, &selected_chain);

    struct db_wrapper dbw;
    if (!db_wrapper_open(&dbw, idx_path, 256 << 20, false, false)) {
        LOG_WARN("snapshot", "T1: failed to open block index at %s", idx_path);
        snapshot_selected_chain_free(&selected_chain);
        node_db_close(&ndb);
        return NULL;
    }

    printf("T1: importing block index...\n");
    fflush(stdout);
    int64_t t_start = (int64_t)platform_time_wall_time_t();
    bool tx_open = false;
    bool ok = true;
    int max_height = -1;  /* highest imported height — seeds fast-boot cursors */

    struct db_iterator it;
    if (!import_block_index_begin_bulk_scan(&ndb, &dbw, &selected_chain,
                                            &it)) {
        return NULL;
    }
    tx_open = true;

    /* Shutdown poll: the bulk walk below iterates every 'b' row of the
     * source LevelDB (millions on a full zclassicd index, minutes on a slow
     * disk) with no other stop check, so a SIGTERM mid-import held the
     * zcl_snap_idx thread past the shutdown join. Poll the registry flag
     * every 4096 iterated rows (and on the very first row): on abort, log,
     * break to the shared !ok path — the open bulk transaction is rolled
     * back, nothing half-written, and a->result stays -1. A stop abort is
     * not an import failure; the import simply re-runs on the next boot. */
    int rows_seen = 0;
    while (db_iter_valid(&it)) {
        if ((rows_seen++ & 4095) == 0 && thread_registry_shutdown_requested()) {
            LOG_INFO("snapshot",
                     "T1: block index import aborted: shutdown requested "
                     "(%d rows imported)", a->count);
            ok = false;
            break;
        }

        struct disk_block_index dbi;
        struct db_block db_blk;
        enum snapshot_import_row_status row = import_block_index_next_row(
            &it, &selected_chain, cp, rom_checkpoint_height, a,
            &max_height, &dbi, &db_blk);
        if (row == SNAPSHOT_IMPORT_ROW_END)
            break;
        if (row == SNAPSHOT_IMPORT_ROW_SKIPPED)
            continue;

        /* Insert into SQLite blocks table */
        if (!db_block_save(&ndb, &db_blk)) {
            LOG_WARN("snapshot", "T1: block save failed at height %d", db_blk.height);
            ok = false;
            break;
        }
        a->count++;

        if (!import_block_index_batch_rollover(&ndb, a->count, t_start,
                                               &tx_open)) {
            ok = false;
            break;
        }

        db_iter_next(&it);
    }

    db_iter_free(&it);

    import_block_index_finalize(&ndb, &dbw, &selected_chain, ok, tx_open,
                                max_height, t_start, a);
    return NULL;
}

/* Synchronous block-index import — runs the same code path as the snapshot
 * import thread (above), reused for the standalone --importblockindex CLI.
 * snapshot_dir is the PARENT of blocks/index (e.g. ~/.zclassic for a running
 * zclassicd). header_only=true seeds the header chain only (lazy bodies).
 * Returns true on success; *out_count gets the number of headers imported. */
bool snapshot_import_block_index(const char *snapshot_dir, const char *db_path,
                                 bool header_only, int *out_count)
{
    struct block_index_import_args a = {
        .snapshot_dir = snapshot_dir,
        .db_path = db_path,
        .header_only = header_only,
        .result = -1,
        .count = 0,
    };
    import_block_index_thread(&a);
    if (out_count)
        *out_count = a.count;
    return a.result == 0;
}

/* ---- Thread 2: Chainstate LevelDB → SQLite utxos table ---- */

struct utxo_import_args {
    const char *snapshot_dir;
    const char *db_path;
    int result;
    int count;
};

static void *import_utxos_thread(void *arg)
{
    struct utxo_import_args *a = arg;
    struct node_db_sync_import_job job;
    a->result = -1;
    a->count = 0;

    struct node_db ndb;
    if (!node_db_open(&ndb, a->db_path)) {
        LOG_NULL("snapshot", "T2: failed to open SQLite");
    }

    char cs_path[1024];
    snprintf(cs_path, sizeof(cs_path), "%s/chainstate", a->snapshot_dir);

    struct coins_view_db cvdb;
    if (!coins_view_db_open(&cvdb, cs_path, 256 << 20, false, false)) {
        LOG_WARN("snapshot", "T2: failed to open chainstate at %s", cs_path);
        node_db_close(&ndb);
        return NULL;
    }

    printf("T2: importing UTXO set...\n");
    fflush(stdout);

    node_db_sync_import_job_init(&job);
    if (!node_db_sync_import_job_start(&job, &ndb, &cvdb)) {
        LOG_WARN("snapshot", "T2: failed to start UTXO import job");
        coins_view_db_close(&cvdb);
        node_db_close(&ndb);
        return NULL;
    }
    node_db_sync_import_job_join(&job, &a->count);

    coins_view_db_close(&cvdb);
    node_db_close(&ndb);

    printf("T2: UTXO import complete: %d outputs\n", a->count);
    fflush(stdout);

    a->result = 0;
    return NULL;
}

/* ---- Thread 3: Wallet scan of block files ---- */

struct wallet_import_args {
    const char *snapshot_dir;
    const char *db_path;
    struct wallet *wallet;
    int result;
    int count;
};

static void *import_wallet_thread(void *arg);

struct snapshot_import_job {
    pthread_t block_index_thread;
    bool block_index_started;
    pthread_t utxo_thread;
    bool utxo_started;
    pthread_t wallet_thread;
    bool wallet_started;
    struct block_index_import_args block_index_args;
    struct utxo_import_args utxo_args;
    struct wallet_import_args wallet_args;
};

static void snapshot_import_job_init(struct snapshot_import_job *job,
                                     const char *snapshot_dir,
                                     const char *db_path,
                                     struct wallet *wallet)
{
    if (!job)
        return;

    memset(job, 0, sizeof(*job));
    job->block_index_args.snapshot_dir = snapshot_dir;
    job->block_index_args.db_path = db_path;
    job->utxo_args.snapshot_dir = snapshot_dir;
    job->utxo_args.db_path = db_path;
    job->wallet_args.snapshot_dir = snapshot_dir;
    job->wallet_args.db_path = db_path;
    job->wallet_args.wallet = wallet;
}

static void snapshot_import_job_join(struct snapshot_import_job *job)
{
    if (!job)
        return;
    if (job->block_index_started) {
        pthread_join(job->block_index_thread, NULL);
        job->block_index_started = false;
    }
    if (job->utxo_started) {
        pthread_join(job->utxo_thread, NULL);
        job->utxo_started = false;
    }
    if (job->wallet_started) {
        pthread_join(job->wallet_thread, NULL);
        job->wallet_started = false;
    }
}

static bool snapshot_import_job_succeeded(const struct snapshot_import_job *job)
{
    if (!job)
        return false;
    return job->block_index_args.result == 0 &&
           job->utxo_args.result == 0 &&
           job->wallet_args.result == 0;
}

static bool snapshot_import_job_start(struct snapshot_import_job *job)
{
    if (!job)
        return false;

    if (thread_registry_spawn("zcl_snap_idx",
                                  import_block_index_thread,
                                  &job->block_index_args,
                                  &job->block_index_thread) != 0) {
        LOG_FAIL("snapshot", "snapshot_import: failed to start block-index import thread");
    }
    job->block_index_started = true;

    if (thread_registry_spawn("zcl_snap_utxo",
                                  import_utxos_thread,
                                  &job->utxo_args,
                                  &job->utxo_thread) != 0) {
        LOG_WARN("snapshot", "snapshot_import: failed to start UTXO import thread");
        snapshot_import_job_join(job);
        return false;
    }
    job->utxo_started = true;

    if (thread_registry_spawn("zcl_snap_wallet",
                                  import_wallet_thread,
                                  &job->wallet_args,
                                  &job->wallet_thread) != 0) {
        LOG_WARN("snapshot", "snapshot_import: failed to start wallet import thread");
        snapshot_import_job_join(job);
        return false;
    }
    job->wallet_started = true;

    return true;
}

static void *import_wallet_thread(void *arg)
{
    struct wallet_import_args *a = arg;
    a->result = -1;
    a->count = 0;

    struct node_db ndb;
    if (!node_db_open(&ndb, a->db_path)) {
        LOG_NULL("snapshot", "T3: failed to open SQLite");
    }

    int wallet_keys = 0;
    for (size_t i = 0; i < a->wallet->keystore.num_keys; i++)
        if (a->wallet->keystore.keys[i].used) wallet_keys++;

    if (wallet_keys == 0 && a->wallet->sapling_keys.num_keys == 0) {
        printf("T3: no wallet keys, skipping scan\n");
        fflush(stdout);
        node_db_close(&ndb);
        a->result = 0;
        return NULL;
    }

    printf("T3: wallet scan (%d t-keys, %zu z-keys)...\n",
           wallet_keys, a->wallet->sapling_keys.num_keys);
    fflush(stdout);

    a->count = legacy_import(a->snapshot_dir, &ndb, a->wallet,
                             a->wallet->sapling_keys.num_keys > 0);

    node_db_close(&ndb);

    printf("T3: wallet scan complete: %d transactions\n", a->count);
    fflush(stdout);

    a->result = 0;
    return NULL;
}

/* ---- Main import orchestrator ---- */

int snapshot_import(const char *snapshot_dir,
                    const char *c23_datadir,
                    struct node_db *ndb,
                    struct wallet *w)
{
    (void)ndb; /* Each thread opens its own SQLite connection */
    struct timespec t0;
    struct snapshot_import_job job;
    platform_time_monotonic_timespec(&t0);

    /* SQLite database path */
    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", c23_datadir);

    printf("snapshot_import: parallel import from %s\n", snapshot_dir);
    printf("  T1: block index LevelDB → SQLite blocks\n");
    printf("  T2: chainstate LevelDB  → SQLite utxos\n");
    printf("  T3: wallet scan         → SQLite wallet_*\n");
    fflush(stdout);

    snapshot_import_job_init(&job, snapshot_dir, db_path, w);
    if (!snapshot_import_job_start(&job))
        LOG_ERR("snapshot", "failed to start parallel import from %s", snapshot_dir);
    snapshot_import_job_join(&job);

    struct timespec t1_end;
    platform_time_monotonic_timespec(&t1_end);
    double import_time = (double)(t1_end.tv_sec - t0.tv_sec) +
                         (double)(t1_end.tv_nsec - t0.tv_nsec) / 1e9;

    printf("snapshot_import: parallel import complete in %.1fs\n",
           import_time);
    printf("  blocks: %d, utxos: %d, wallet txs: %d\n",
           job.block_index_args.count, job.utxo_args.count,
           job.wallet_args.count);
    fflush(stdout);

    if (!snapshot_import_job_succeeded(&job)) {
        LOG_WARN("snapshot_import", "snapshot_import: import workers failed " "(blocks=%d utxos=%d wallet=%d); refusing to sync files", job.block_index_args.result, job.utxo_args.result, job.wallet_args.result);
        return -1; // raw-return-ok:logged-above
    }

    /* Copy block files + LevelDB to C23 data dir for consensus engine */
    printf("snapshot_import: syncing files to %s...\n", c23_datadir);
    fflush(stdout);

    char src[2048], dst[2048];

    /* Block files: remove stale then byte-copy through checked helper. */
    snprintf(dst, sizeof(dst), "%s/blocks", c23_datadir);
    if (!platform_directory_ensure(dst, 0700))
        LOG_ERR("snapshot", "snapshot_import: refusing unsafe blocks destination %s",
                dst);
    snprintf(src, sizeof(src), "%s/blocks", snapshot_dir);
    block_files_clean(dst);
    int copied = block_files_copy(src, dst);
    if (copied < 0) {
        LOG_ERR("snapshot", "snapshot_import: block file copy failed from %s to %s",
                src, dst);
    }
    if (copied == 0) {
        LOG_ERR("snapshot", "snapshot_import: failed to sync block files from %s to %s",
                src, dst);
    }

    /* Block index: clean copy */
    snprintf(dst, sizeof(dst), "%s/blocks/index", c23_datadir);
    dir_remove_tree(dst);
    if (!platform_directory_ensure(dst, 0700))
        LOG_ERR("snapshot", "snapshot_import: refusing unsafe block index destination %s",
                dst);
    snprintf(src, sizeof(src), "%s/blocks/index", snapshot_dir);
    if (!dir_copy(src, dst)) {
        LOG_ERR("snapshot", "snapshot_import: failed to sync block index from %s to %s",
                src, dst);
    }

    /* Chainstate: clean copy */
    snprintf(dst, sizeof(dst), "%s/chainstate", c23_datadir);
    dir_remove_tree(dst);
    if (!platform_directory_ensure(dst, 0700))
        LOG_ERR("snapshot", "snapshot_import: refusing unsafe chainstate destination %s",
                dst);
    snprintf(src, sizeof(src), "%s/chainstate", snapshot_dir);
    if (!dir_copy(src, dst)) {
        LOG_ERR("snapshot", "snapshot_import: failed to sync chainstate from %s to %s",
                src, dst);
    }

    struct timespec t2_end;
    platform_time_monotonic_timespec(&t2_end);
    double total_time = (double)(t2_end.tv_sec - t0.tv_sec) +
                        (double)(t2_end.tv_nsec - t0.tv_nsec) / 1e9;

    printf("snapshot_import: COMPLETE in %.1fs (import %.1fs, copy %.1fs)\n",
           total_time, import_time, total_time - import_time);
    fflush(stdout);

    return 0;
}
