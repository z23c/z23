/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Snapshot controller — background transaction-index builder.
 *
 * Reads block positions from the SQLite blocks table, parses the
 * block files to extract txids, and inserts them into the tx_index
 * table. Falls back to a raw blk*.dat walk if the SQLite-driven walk
 * skips blocks. Runs on a caller-owned thread via the job API.
 *
 * See snapshot_controller.c for the shared SQLite transaction helpers
 * used here. */

#pragma GCC diagnostic ignored "-Wformat-truncation"
#include "platform/time_compat.h"
#include "platform/read_mapping.h"
#include "controllers/snapshot_controller.h"
#include "snapshot_controller_internal.h"
#include "models/block.h"
#include "models/tx_index.h"
#include "core/serialize.h"
#include "core/hash.h"
#include "primitives/block.h"
#include "crypto/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"

#define TX_INDEX_BATCH_TXS 1000
#define TX_INDEX_BATCH_YIELD_MS 100

static bool snapshot_stat_mapping_size(const struct stat *st,
                                       size_t *size_out)
{
    if (!st || !size_out || st->st_size <= 0)
        return false;
    if ((uintmax_t)st->st_size > (uintmax_t)SIZE_MAX)
        return false;
    *size_out = (size_t)st->st_size;
    return true;
}

static bool snapshot_deserialize_index_block(const uint8_t *data,
                                             size_t avail,
                                             int height,
                                             struct block *blk,
                                             struct uint256 *hash_out)
{
    if (!data || avail == 0 || !blk || !hash_out)
        return false;

    block_init(blk);
    struct byte_stream bs;
    stream_init_from_data(&bs, data, avail);
    bool ok = block_deserialize(blk, &bs);
    stream_free(&bs);
    if (!ok) {
        LOG_WARN("tx_index", "tx_index: skipping block after full deserialize failure " "height=%d", height);
        block_free(blk);
        return false;
    }

    block_get_hash(blk, hash_out);
    return true;
}

static bool snapshot_block_file_magic_ok(const uint8_t *p)
{
    if (!p)
        return false;
    return (p[0] == 0x24 && p[1] == 0xe9 &&
            p[2] == 0x27 && p[3] == 0x64) ||
           (p[0] == 0xfa && p[1] == 0x1a &&
            p[2] == 0xf9 && p[3] == 0xbf) ||
           (p[0] == 0xaa && p[1] == 0xe8 &&
            p[2] == 0x3f && p[3] == 0x5f);
}

static bool snapshot_block_file_size_ok(uint32_t block_size,
                                        size_t file_size,
                                        size_t envelope_pos)
{
    return block_size > 0 &&
           block_size <= MAX_BLOCK_SIZE &&
           envelope_pos <= file_size &&
           file_size - envelope_pos >= 8 &&
           (size_t)block_size <= file_size - envelope_pos - 8;
}

static bool snapshot_locate_block_payload(const uint8_t *file_data,
                                          size_t file_size,
                                          size_t stored_pos,
                                          int height,
                                          const uint8_t **payload_out,
                                          size_t *payload_len_out)
{
    if (!file_data || !payload_out || !payload_len_out ||
        stored_pos >= file_size)
        return false;

    *payload_out = NULL;
    *payload_len_out = 0;

    uint32_t block_size = 0;
    if (stored_pos + 8 <= file_size &&
        snapshot_block_file_magic_ok(file_data + stored_pos)) {
        memcpy(&block_size, file_data + stored_pos + 4, 4);
        if (snapshot_block_file_size_ok(block_size, file_size, stored_pos)) {
            *payload_out = file_data + stored_pos + 8;
            *payload_len_out = block_size;
            return true;
        }
    }

    if (stored_pos >= 8 &&
        snapshot_block_file_magic_ok(file_data + stored_pos - 8)) {
        memcpy(&block_size, file_data + stored_pos - 4, 4);
        if (snapshot_block_file_size_ok(block_size, file_size,
                                        stored_pos - 8)) {
            *payload_out = file_data + stored_pos;
            *payload_len_out = block_size;
            return true;
        }
    }

    if (height >= 0)
        LOG_WARN("tx_index", "tx_index: cannot locate block payload height=%d pos=%zu " "file_size=%zu", height, stored_pos, file_size);
    return false;
}

static int snapshot_extract_bip34_height_from_block(const struct block *blk)
{
    if (!blk || blk->num_vtx == 0 || blk->vtx[0].num_vin == 0)
        return -1; // raw-return-ok:bin-parser-empty-vin

    const struct script *sig = &blk->vtx[0].vin[0].script_sig;
    if (sig->size == 0)
        return -1; // raw-return-ok:bin-parser-bounds

    uint8_t nbytes = sig->data[0];
    if (nbytes == 0x00)
        return 0;
    if (nbytes >= 0x51 && nbytes <= 0x60)
        return nbytes - 0x50;
    if (nbytes > 8 || (size_t)nbytes + 1 > sig->size)
        return -1; // raw-return-ok:bin-parser-bounds

    int64_t h = 0;
    for (uint8_t i = 0; i < nbytes; i++)
        h |= (int64_t)sig->data[1 + i] << (8 * i);
    if (sig->data[nbytes] & 0x80)
        h = -(h & ~((int64_t)0x80 << (8 * (nbytes - 1))));
    if (h < 0 || h > INT32_MAX)
        return -1; // raw-return-ok:bin-parser-bounds
    return (int)h;
}

static bool snapshot_tx_index_maybe_commit(struct node_db *ndb,
                                           bool *tx_open,
                                           int indexed,
                                           int64_t t_start)
{
    if (!ndb || !tx_open)
        return false;
    if (indexed <= 0 || (indexed % TX_INDEX_BATCH_TXS) != 0)
        return true;

    if (!snapshot_tx_commit_checked(ndb, "tx_index batch commit")) {
        *tx_open = false;
        return false;
    }
    *tx_open = false;
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    int rate = elapsed > 0 ? indexed / (int)elapsed : indexed;
    printf("tx_index: %d transactions (%d/s)\n", indexed, rate);
    fflush(stdout);
    /* txindex is a background convenience index. Release node.db long enough
     * for chain evidence, tip cursors, and other liveness writes to drain. */
    platform_sleep_ms(TX_INDEX_BATCH_YIELD_MS);
    if (!snapshot_tx_begin_checked(ndb, "tx_index batch reopen"))
        return false; // raw-return-ok:snapshot_tx_begin_checked already LOG_FAILs with label+errmsg
    *tx_open = true;
    return true;
}

static bool snapshot_tx_index_save_block_txs(struct node_db *ndb,
                                             struct block *blk,
                                             const struct uint256 *block_hash,
                                             int height,
                                             int file_num,
                                             int file_pos,
                                             int *indexed,
                                             int64_t t_start,
                                             bool *tx_open)
{
    if (!ndb || !blk || !block_hash || !indexed || !tx_open)
        return false;
    if (height < 0)
        return false;

    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        transaction_compute_hash(&blk->vtx[ti]);

        struct db_tx_index dt;
        memset(&dt, 0, sizeof(dt));
        memcpy(dt.txid, blk->vtx[ti].hash.data, 32);
        memcpy(dt.block_hash, block_hash->data, 32);
        dt.block_height = height;
        dt.tx_index = (int)ti;
        dt.file_num = file_num;
        dt.file_pos = file_pos;
        dt.is_coinbase = (ti == 0);
        if (!db_tx_save(ndb, &dt)) {
            LOG_FAIL("snapshot", "tx_index: failed to save tx index at height %d tx %zu",
                    height, ti);
        }
        (*indexed)++;
        if (!snapshot_tx_index_maybe_commit(ndb, tx_open, *indexed,
                                            t_start))
            return false;
    }
    return true;
}

/* Process one magic-located block in the raw fallback walk: deserialize,
 * take the BIP34 height, save its txs. Undecodable or height-less blocks
 * are skip-counted and the walk continues; false is only a save failure
 * (callee logs), which aborts the build. */
static bool snapshot_tx_index_raw_save_one(struct node_db *ndb,
                                           const uint8_t *file_data,
                                           uint32_t block_size,
                                           int file_num, size_t pos,
                                           int *indexed, int *skipped,
                                           int64_t t_start, bool *tx_open)
{
    struct block blk;
    struct uint256 block_hash;
    if (!snapshot_deserialize_index_block(file_data + pos + 8,
                                          block_size, -1,
                                          &blk, &block_hash)) {
        (*skipped)++;
        return true;
    }
    int height = snapshot_extract_bip34_height_from_block(&blk);
    if (height < 0) {
        (*skipped)++;
        block_free(&blk);
        return true;
    }
    bool saved = snapshot_tx_index_save_block_txs(
        ndb, &blk, &block_hash, height, file_num, (int)(pos + 8),
        indexed, t_start, tx_open);
    block_free(&blk);
    return saved;
}

/* Scan one mapped blk file for magic-framed blocks and index each. False is
 * only a save failure (callee logged), which aborts the build. */
static bool snapshot_tx_index_raw_walk_file(struct node_db *ndb,
                                            const uint8_t *file_data,
                                            size_t file_size, int file_num,
                                            int *indexed, int *skipped,
                                            int64_t t_start, bool *tx_open)
{
    size_t pos = 0;
    while (pos + 8 <= file_size) {
        if (!snapshot_block_file_magic_ok(file_data + pos)) {
            pos++;
            continue;
        }
        uint32_t block_size = 0;
        memcpy(&block_size, file_data + pos + 4, 4);
        if (!snapshot_block_file_size_ok(block_size, file_size, pos)) {
            pos++;
            continue;
        }

        if (!snapshot_tx_index_raw_save_one(ndb, file_data, block_size,
                                            file_num, pos, indexed,
                                            skipped, t_start, tx_open))
            return false; // raw-return-ok:callee-logged
        pos += 8 + block_size;
    }
    return true;
}

static bool snapshot_tx_index_build_from_block_files(struct node_db *ndb,
                                                     const char *datadir,
                                                     int *indexed,
                                                     int *skipped,
                                                     int64_t t_start,
                                                     bool *tx_open)
{
    if (!ndb || !datadir || !indexed || !skipped || !tx_open)
        return false;

    int files_seen = 0;
    for (int file_num = 0; file_num < 100000; file_num++) {
        /* Shutdown poll (per blk file): the raw walk below scans whole
         * block files byte-by-byte; without a stop check a SIGTERM during
         * the fallback held the zcl_snap_txidx thread past the registry
         * shutdown join. Returning false marks the build incomplete — the
         * caller rolls back and leaves the completion marker unset, so the
         * next boot retries. A stop abort is not an index failure. */
        if (thread_registry_shutdown_requested()) {
            LOG_INFO("snapshot",
                     "tx_index: raw fallback aborted: shutdown requested");
            return false;
        }
        char path[512];
        snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                 datadir, file_num);
        int fd = open(path, O_RDONLY);
        if (fd < 0)
            return files_seen > 0;

        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            return false;
        }
        size_t file_size = 0;
        if (!snapshot_stat_mapping_size(&st, &file_size)) {
            close(fd);
            return false;
        }
        struct platform_read_mapping mapping;
        platform_read_mapping_init(&mapping);
        if (!platform_read_mapping_open(&mapping, fd, file_size)) {
            close(fd);
            return false;
        }
        const uint8_t *file_data = mapping.data;
        files_seen++;

        bool walked = snapshot_tx_index_raw_walk_file(
            ndb, file_data, file_size, file_num, indexed, skipped,
            t_start, tx_open);
        platform_read_mapping_close(&mapping);
        close(fd);
        if (!walked) {
            /* raw-return-ok:callee-logged */
            return false;
        }
    }

    return files_seen > 0;
}

/* (Re)map blkNNNNN.dat into the read cache when the row's file changes.
 * The descriptor stays open for the mapping's full lifetime. Returns false
 * (logged) on any open/stat/map failure with the cache reset to empty; the
 * caller aborts the build. */
static bool snapshot_tx_index_refresh_mapping(const char *datadir,
                                              int file_num,
                                              int *cached_file,
                                              int *cached_fd,
                                              const uint8_t **cached_data,
                                              size_t *cached_size,
                                              struct platform_read_mapping *cached_mapping)
{
    platform_read_mapping_close(cached_mapping);
    if (*cached_fd >= 0)
        close(*cached_fd);
    *cached_fd = -1;
    *cached_data = NULL;
    *cached_size = 0;
    *cached_file = -1;
    char path[512];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", datadir, file_num);
    *cached_fd = open(path, O_RDONLY);
    if (*cached_fd < 0) {
        LOG_WARN("tx_index", "tx_index: failed to open %s", path);
        return false;
    }
    struct stat st;
    if (fstat(*cached_fd, &st) != 0) {
        LOG_WARN("tx_index", "tx_index: failed to stat %s", path);
        close(*cached_fd);
        *cached_fd = -1;
        return false;
    }
    if (!snapshot_stat_mapping_size(&st, cached_size) ||
        !platform_read_mapping_open(cached_mapping, *cached_fd,
                                    *cached_size)) {
        LOG_WARN("tx_index", "tx_index: failed to map %s", path);
        close(*cached_fd);
        *cached_fd = -1;
        return false;
    }
    *cached_data = cached_mapping->data;
    *cached_file = file_num;
    return true;
}

enum tx_index_setup_stage {
    TX_SETUP_OK = 0,
    TX_SETUP_SKIP_COMPLETE,
    TX_SETUP_CONFIG_FAIL,
    TX_SETUP_READ_OPEN_FAIL,
    TX_SETUP_PREPARE_FAIL,
    TX_SETUP_BEGIN_FAIL
};

/* What the thread must log for one block-index row. Skips that are not
 * log-due (or have no log at all) come back as TX_ROW_DONE. */
enum tx_index_row_status {
    TX_ROW_DONE = 0,
    TX_ROW_BAD_OFFSET,
    TX_ROW_UNLOCATABLE,
    TX_ROW_HASH_MISMATCH
};

/* Read-only blk file cache for the block-index row walk. */
struct tx_index_walk {
    struct node_db *ndb;
    const char *datadir;
    int64_t t_start;
    bool *tx_open;
    int cached_file;
    int cached_fd;
    const uint8_t *cached_data;
    size_t cached_size;
    struct platform_read_mapping cached_mapping;
};

static bool snapshot_tx_index_open_read_db(const char *db_path,
                                           sqlite3 **read_db)
{
    if (sqlite3_open_v2(db_path, read_db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                        NULL) != SQLITE_OK || !*read_db)
        return false; // raw-return-ok:thread logs the open failure with the sqlite errmsg
    sqlite3_busy_timeout(*read_db, 30000);
    return true;
}

/* Everything before the row walk: completion marker, additive configure,
 * read-only handle, scan statement, bulk transaction. The stage names the
 * first step that failed; the thread logs and cleans up. */
static int snapshot_tx_index_setup(struct node_db *ndb, const char *db_path,
                                   sqlite3 **read_db, sqlite3_stmt **query,
                                   int64_t *t_start, bool *tx_open)
{
    /* Check how many transactions already indexed. A nonzero count is not
     * proof that the index is complete; older boots skipped on a count
     * heuristic, which left historical spends unrecoverable during replay.
     * The explicit completion marker is the authority; ZClassic's historical
     * transaction count can legitimately be far below arbitrary large
     * thresholds. */
    int existing = db_tx_count(ndb);
    int64_t complete = 0;
    node_db_state_get_int(ndb, "tx_index_complete", &complete);
    if (complete >= 3) {
        printf("tx_index: complete marker v%lld present (%d transactions), skipping\n",
               (long long)complete, existing);
        return TX_SETUP_SKIP_COMPLETE;
    }

    printf("tx_index: additive build from block files (existing=%d, marker=%lld)...\n",
           existing, (long long)complete);
    fflush(stdout);
    *t_start = (int64_t)platform_time_wall_time_t();

    if (!db_tx_configure_additive_build(ndb))
        return TX_SETUP_CONFIG_FAIL; // raw-return-ok:thread closes the db; configure failure is the stage
    if (!snapshot_tx_index_open_read_db(db_path, read_db))
        return TX_SETUP_READ_OPEN_FAIL; // raw-return-ok:thread logs the open failure
    if (!db_block_prepare_file_position_scan(*read_db, query))
        return TX_SETUP_PREPARE_FAIL; // raw-return-ok:prepare failure is the stage
    if (!snapshot_tx_begin_checked(ndb,
            "tx_index begin bulk load transaction"))
        return TX_SETUP_BEGIN_FAIL; // raw-return-ok:snapshot_tx_begin_checked already LOG_FAILs
    *tx_open = true;
    return TX_SETUP_OK;
}

/* Release what the failed setup stage had opened, in the original order. */
static void snapshot_tx_index_setup_cleanup(struct snapshot_tx_index_job *job,
                                            struct node_db *ndb,
                                            sqlite3 *read_db,
                                            sqlite3_stmt *query, int stage)
{
    if (stage == TX_SETUP_BEGIN_FAIL)
        sqlite3_finalize(query);
    if (stage == TX_SETUP_BEGIN_FAIL || stage == TX_SETUP_PREPARE_FAIL)
        sqlite3_close(read_db);
    if (stage == TX_SETUP_READ_OPEN_FAIL && read_db)
        sqlite3_close(read_db);
    node_db_close(ndb);
    if (stage == TX_SETUP_SKIP_COMPLETE)
        job->result = 0;
}

static void snapshot_tx_index_walk_init(struct tx_index_walk *w,
                                        struct node_db *ndb,
                                        const char *datadir, int64_t t_start,
                                        bool *tx_open)
{
    w->ndb = ndb;
    w->datadir = datadir;
    w->t_start = t_start;
    w->tx_open = tx_open;
    w->cached_file = -1;
    w->cached_fd = -1;
    w->cached_data = NULL;
    w->cached_size = 0;
    platform_read_mapping_init(&w->cached_mapping);
}

/* Poll every 4096 rows (first row included). */
static bool snapshot_tx_index_row_poll_stop(int *rows_seen)
{
    return ((*rows_seen)++ & 4095) == 0 && thread_registry_shutdown_requested();
}

/* Stop stepping once the build has failed: the loop then ends without the
 * extra sqlite3_step a failed row would otherwise cost. */
static int snapshot_tx_index_next_row(sqlite3_stmt *query, bool ok)
{
    if (!ok)
        return SQLITE_ABORT;
    return AR_STEP_ROW_READONLY(query);
}

static bool snapshot_tx_index_skip_log_due(int skipped)
{
    return skipped < 20 || (skipped % 10000) == 0;
}

/* Count one skipped row; report the logged status only while the log is due. */
static int snapshot_tx_index_skip_row(int *skipped, int logged_status)
{
    bool due = snapshot_tx_index_skip_log_due(*skipped);
    (*skipped)++;
    return due ? logged_status : TX_ROW_DONE;
}

/* Save the first num_tx transactions of a verified block (all when num_tx is
 * not positive or exceeds the block), then release it. */
static bool snapshot_tx_index_save_row_block(struct tx_index_walk *w,
                                             struct block *blk,
                                             const struct uint256 *block_hash,
                                             int height, int file_num,
                                             int data_pos, int num_tx,
                                             int *indexed)
{
    size_t tx_limit = blk->num_vtx;
    if (num_tx > 0 && (size_t)num_tx < tx_limit)
        tx_limit = (size_t)num_tx;

    size_t saved_num_vtx = blk->num_vtx;
    blk->num_vtx = tx_limit;
    bool saved = snapshot_tx_index_save_block_txs(
        w->ndb, blk, block_hash, height, file_num, data_pos,
        indexed, w->t_start, w->tx_open);
    blk->num_vtx = saved_num_vtx;
    block_free(blk);
    return saved;
}

/* Process one block-index row. *ok goes false when the build must abort
 * (mapping or save failure); every other outcome is a TX_ROW_* status. */
static int snapshot_tx_index_row_process(struct tx_index_walk *w,
                                         const uint8_t *block_hash,
                                         int height, int file_num,
                                         int data_pos, int num_tx,
                                         int *indexed, int *skipped,
                                         bool *ok, char *got, char *want)
{
    if (!block_hash || file_num < 0 || data_pos < 0)
        return TX_ROW_DONE;

    /* Keep the descriptor alive for the mapping's full lifetime. */
    if (file_num != w->cached_file &&
        !snapshot_tx_index_refresh_mapping(w->datadir, file_num,
                                           &w->cached_file, &w->cached_fd,
                                           &w->cached_data, &w->cached_size,
                                           &w->cached_mapping)) {
        /* raw-return-ok:callee-logged */
        *ok = false;
        return TX_ROW_DONE;
    }

    if (!w->cached_data || (size_t)data_pos >= w->cached_size)
        return snapshot_tx_index_skip_row(skipped, TX_ROW_BAD_OFFSET);

    const uint8_t *bdata = NULL;
    size_t bavail = 0;
    if (!snapshot_locate_block_payload(w->cached_data, w->cached_size,
                                       (size_t)data_pos, height,
                                       &bdata, &bavail))
        return snapshot_tx_index_skip_row(skipped, TX_ROW_UNLOCATABLE);

    struct block blk;
    struct uint256 disk_hash;
    if (!snapshot_deserialize_index_block(bdata, bavail, height,
                                          &blk, &disk_hash)) {
        (*skipped)++;
        return TX_ROW_DONE;
    }
    struct uint256 expected_hash;
    memcpy(expected_hash.data, block_hash, 32);
    if (uint256_cmp(&disk_hash, &expected_hash) != 0) {
        uint256_get_hex(&disk_hash, got);
        uint256_get_hex(&expected_hash, want);
        block_free(&blk);
        return snapshot_tx_index_skip_row(skipped, TX_ROW_HASH_MISMATCH);
    }

    *ok = snapshot_tx_index_save_row_block(w, &blk, &expected_hash, height,
                                           file_num, data_pos, num_tx,
                                           indexed);
    return TX_ROW_DONE;
}

static bool snapshot_tx_index_query_failed(int rc, bool ok)
{
    return rc != SQLITE_DONE && ok;
}

static bool snapshot_tx_index_has_skips(bool ok, int skipped)
{
    return ok && skipped > 0;
}

/* Close the row-walk transaction after the loop: roll back on failure,
 * otherwise commit; returns the build's ok flag. */
static bool snapshot_tx_index_end_scan_tx(struct node_db *ndb, bool tx_open,
                                          bool ok)
{
    if (tx_open && !ok)
        snapshot_tx_rollback_best_effort(ndb, "tx_index rollback after failure");
    else if (tx_open && !snapshot_tx_commit_checked(ndb, "tx_index final commit")) {
        ok = false;
        snapshot_tx_rollback_best_effort(ndb, "tx_index rollback after final commit failure");
    }
    return ok;
}

static void snapshot_tx_index_release_scan(struct tx_index_walk *w,
                                           sqlite3_stmt *query,
                                           sqlite3 *read_db)
{
    platform_read_mapping_close(&w->cached_mapping);
    if (w->cached_fd >= 0)
        close(w->cached_fd);
    sqlite3_finalize(query);
    sqlite3_close(read_db);
}

/* Raw blk*.dat walk in its own transaction after the row walk skipped
 * blocks; returns the build's ok flag. */
static bool snapshot_tx_index_run_raw_fallback(struct node_db *ndb,
                                               const char *datadir,
                                               int *indexed, int *skipped,
                                               int64_t t_start,
                                               bool *tx_open)
{
    bool ok = true;
    if (!snapshot_tx_begin_checked(ndb,
            "tx_index raw fallback begin")) {
        ok = false;
    } else {
        *tx_open = true;
    }
    if (ok)
        ok = snapshot_tx_index_build_from_block_files(
            ndb, datadir, indexed, skipped, t_start, tx_open);
    return ok;
}

/* Close the fallback transaction; returns the build's ok flag. */
static bool snapshot_tx_index_end_fallback_tx(struct node_db *ndb,
                                              bool *tx_open, bool ok)
{
    if (*tx_open && !ok) {
        snapshot_tx_rollback_best_effort(ndb,
            "tx_index raw fallback rollback after failure");
        *tx_open = false;
    } else if (*tx_open && !snapshot_tx_commit_checked(ndb,
                   "tx_index raw fallback final commit")) {
        ok = false;
        snapshot_tx_rollback_best_effort(ndb,
            "tx_index raw fallback rollback after final commit failure");
        *tx_open = false;
    } else {
        *tx_open = false;
    }
    return ok;
}

static bool snapshot_tx_index_finalize_failed(struct node_db *ndb, bool ok)
{
    return ok && !db_tx_finalize_bulk_load(ndb);
}

/* Record the completion marker only for a fully successful build. */
static void snapshot_tx_index_mark_complete(struct node_db *ndb, bool ok)
{
    if (ok)
        node_db_state_set_int(ndb, "tx_index_complete", 3);
}

static void snapshot_tx_index_report(struct snapshot_tx_index_job *job,
                                     bool ok, int indexed, int skipped,
                                     int64_t t_start)
{
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    if (ok) {
        printf("tx_index: complete — %d transactions indexed, %d blocks "
               "skipped in %llds\n",
               indexed, skipped, (long long)elapsed);
        fflush(stdout);
        job->result = 0;
    } else {
        printf("tx_index: failed after %d transactions in %llds\n",
               indexed, (long long)elapsed);
        fflush(stdout);
    }
}

static void *build_tx_index_thread(void *arg)
{
    struct snapshot_tx_index_job *job = arg;
    const char *datadir;
    const char *db_path;
    bool ok = false;
    bool tx_open = false;
    int rc;
    sqlite3 *read_db = NULL;
    sqlite3_stmt *query = NULL;

    if (!job) {
        LOG_NULL("snapshot", "build_tx_index_thread called with NULL job");
    }

    job->result = -1;
    datadir = job->args.datadir;
    db_path = job->args.db_path;

    struct node_db ndb;
    if (!node_db_open_runtime(&ndb, db_path,
                              "snapshot.tx_index_build")) {
        LOG_NULL("snapshot", "tx_index: failed to open SQLite");
    }

    int64_t t_start = 0;
    int stage = snapshot_tx_index_setup(&ndb, db_path, &read_db, &query,
                                        &t_start, &tx_open);
    if (stage == TX_SETUP_READ_OPEN_FAIL)
        LOG_WARN("tx_index", "tx_index: failed to open read-only SQLite: %s", read_db ? sqlite3_errmsg(read_db) : "db unavailable");
    if (stage != TX_SETUP_OK) {
        snapshot_tx_index_setup_cleanup(job, &ndb, read_db, query, stage);
        return NULL;
    }

    int indexed = 0;
    int skipped = 0;
    struct tx_index_walk walk;
    snapshot_tx_index_walk_init(&walk, &ndb, datadir, t_start, &tx_open);
    ok = true;

    /* Shutdown poll: the row loop walks every block-index row and maps each
     * referenced blk file — minutes on a full datadir with no other stop
     * check, so a SIGTERM mid-build held the zcl_snap_txidx thread past the
     * registry shutdown join. Poll every 4096 rows (first row included): on
     * abort, log and break to the shared !ok path — the open bulk
     * transaction rolls back and the completion marker stays unset, so the
     * next boot retries. A stop abort is not an index failure. */
    int rows_seen = 0;
    for (rc = AR_STEP_ROW_READONLY(query);
         rc == SQLITE_ROW;
         rc = snapshot_tx_index_next_row(query, ok)) {
        if (snapshot_tx_index_row_poll_stop(&rows_seen)) {
            LOG_INFO("snapshot",
                     "tx_index: aborted: shutdown requested (%d indexed)",
                     indexed);
            ok = false;
            break;
        }
        const uint8_t *block_hash = sqlite3_column_blob(query, 0);
        int height = sqlite3_column_int(query, 1);
        int file_num = sqlite3_column_int(query, 2);
        int data_pos = sqlite3_column_int(query, 3);
        int num_tx = sqlite3_column_int(query, 4);
        char got[65] = "", want[65] = "";

        int row = snapshot_tx_index_row_process(
            &walk, block_hash, height, file_num, data_pos, num_tx,
            &indexed, &skipped, &ok, got, want);
        size_t cached_size = walk.cached_size;
        if (row == TX_ROW_BAD_OFFSET)
            LOG_WARN("tx_index", "tx_index: skipping invalid block offset file=%d " "height=%d pos=%d size=%zu", file_num, height, data_pos, cached_size);
        if (row == TX_ROW_UNLOCATABLE)
            LOG_WARN("tx_index", "tx_index: skipping unlocatable block file=%d " "height=%d pos=%d size=%zu", file_num, height, data_pos, cached_size);
        if (row == TX_ROW_HASH_MISMATCH)
            LOG_WARN("tx_index", "tx_index: skipping block hash mismatch height=%d " "got=%s want=%s", height, got, want);
    }

    if (snapshot_tx_index_query_failed(rc, ok)) {
        LOG_WARN("tx_index", "tx_index: block query failed: %s", sqlite3_errmsg(read_db));
        ok = false;
    }

    ok = snapshot_tx_index_end_scan_tx(&ndb, tx_open, ok);

    snapshot_tx_index_release_scan(&walk, query, read_db);
    query = NULL;
    read_db = NULL;
    tx_open = false;

    if (snapshot_tx_index_has_skips(ok, skipped)) {
        LOG_WARN("tx_index", "tx_index: SQLite block rows skipped %d blocks; falling " "back to raw blk*.dat walk", skipped);
        skipped = 0;
        ok = snapshot_tx_index_run_raw_fallback(&ndb, datadir, &indexed,
                                                &skipped, t_start, &tx_open);
    }

    if (snapshot_tx_index_has_skips(ok, skipped)) {
        LOG_WARN("tx_index", "tx_index: incomplete — raw block-file walk skipped %d " "blocks; leaving marker unset so a safer builder can retry", skipped);
        ok = false;
    }

    ok = snapshot_tx_index_end_fallback_tx(&ndb, &tx_open, ok);

    if (snapshot_tx_index_finalize_failed(&ndb, ok)) {
        LOG_WARN("tx_index", "tx_index: failed to finalize bulk load indexes");
        ok = false;
    }
    snapshot_tx_index_mark_complete(&ndb, ok);

    node_db_close(&ndb);

    snapshot_tx_index_report(job, ok, indexed, skipped, t_start);
    return NULL;
}

void snapshot_tx_index_job_init(struct snapshot_tx_index_job *job)
{
    if (!job)
        return;
    memset(job, 0, sizeof(*job));
    job->result = -1;
}

bool snapshot_tx_index_job_start(struct snapshot_tx_index_job *job,
                                 const char *c23_datadir)
{
    if (!job || job->started || !c23_datadir)
        LOG_FAIL("snapshot", "tx_index_job_start: invalid args job=%p started=%d datadir=%p",
                 (void *)job, job ? job->started : 0, (void *)c23_datadir);

    if (snprintf(job->args.db_path, sizeof(job->args.db_path),
                 "%s/node.db", c23_datadir) >=
        (int)sizeof(job->args.db_path)) {
        LOG_FAIL("snapshot", "tx_index_job_start: db_path truncated for datadir %s", c23_datadir);
    }
    job->args.datadir = c23_datadir;
    job->result = -1;
    if (thread_registry_spawn("zcl_snap_txidx",
                                  build_tx_index_thread, job,
                                  &job->thread) != 0) {
        LOG_FAIL("snapshot", "tx_index_job_start: thread_registry_spawn failed for datadir %s", c23_datadir);
    }
    job->started = true;
    return true;
}

bool snapshot_tx_index_job_join(struct snapshot_tx_index_job *job,
                                int *result_out)
{
    int join_rc;

    if (!job || !job->started)
        LOG_FAIL("snapshot", "tx_index_job_join: invalid state job=%p started=%d",
                 (void *)job, job ? job->started : 0);

    join_rc = pthread_join(job->thread, NULL);
    if (join_rc != 0)
        LOG_FAIL("snapshot", "tx_index_job_join: pthread_join failed rc=%d", join_rc);

    job->started = false;
    if (result_out)
        *result_out = job->result;
    return true;
}

bool snapshot_tx_index_job_is_started(const struct snapshot_tx_index_job *job)
{
    return job && job->started;
}
