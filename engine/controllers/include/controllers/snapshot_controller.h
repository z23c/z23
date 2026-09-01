/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SNAPSHOT_CONTROLLER_H
#define ZCL_SNAPSHOT_CONTROLLER_H

#include "models/database.h"
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

struct wallet;

struct snapshot_tx_index_job {
    pthread_t thread;
    bool started;
    int result;
    struct {
        const char *datadir;
        char db_path[1024];
    } args;
};

/* Create a snapshot of a legacy C++ node's data directory.
 * Hard-links blk*.dat/rev*.dat (instant), copies LevelDB dirs.
 * Stores in c23_datadir/snapshots/YYYYMMDD_HHMMSS/.
 * Rotates old snapshots, keeping max_keep most recent.
 * Returns path to new snapshot dir, or NULL on error. The returned string
 * points to a static buffer overwritten by the next snapshot_create call —
 * use or copy it before calling again; do not free it. */
const char *snapshot_create(const char *legacy_datadir,
                            const char *c23_datadir,
                            int max_keep);

/* Import a snapshot into the C23 node in parallel.
 * Reads block index + chainstate LevelDB from snapshot,
 * imports into SQLite ActiveRecord database.
 * Also scans block files for wallet transactions.
 *
 * Three parallel threads, each with own SQLite connection:
 *   T1: block index LevelDB → blocks table
 *   T2: chainstate LevelDB  → utxos table
 *   T3: wallet scan          → wallet_* tables
 *
 * After import, copies block files + LevelDB to c23_datadir
 * for ongoing consensus operation.
 *
 * Returns 0 on success, -1 on error. */
int snapshot_import(const char *snapshot_dir,
                    const char *c23_datadir,
                    struct node_db *ndb,
                    struct wallet *w);

/* Import ONLY the block index (headers) from snapshot_dir/blocks/index into
 * the SQLite blocks table. snapshot_dir is the parent of blocks/index (e.g.
 * ~/.zclassic for a running zclassicd — the on-disk CDiskBlockIndex format is
 * shared). header_only=true clears HAVE_DATA/HAVE_UNDO + file positions so the
 * node keeps the header (incl. nSolution) but fetches bodies lazily via P2P —
 * the fast-sync path that lets an already-imported UTXO set anchor become the
 * tip in seconds instead of waiting on P2P header sync.
 * Returns true on success; *out_count = number of headers imported. */
bool snapshot_import_block_index(const char *snapshot_dir, const char *db_path,
                                 bool header_only, int *out_count);

/* Process-lifetime count of rows quarantined by the per-row hash-bind /
 * PoW-target verify inside snapshot_import_block_index() (see the
 * import_row_verify block comment in snapshot_controller_import.c). A
 * quarantined row is skipped (not written) and never aborts the bulk
 * import; this counter plus the "importblockindex_row_quarantine" typed
 * blocker are how a caller notices it happened. Monotonic within one
 * process — a fresh CLI process starts at 0. */
uint64_t snapshot_import_block_index_quarantine_total(void);

/* Build transaction index from block files on a caller-owned thread.
 * Reads block positions from blocks table, parses block files
 * to extract txids, inserts into transactions table.
 * Returns true when the worker thread was started successfully. */
void snapshot_tx_index_job_init(struct snapshot_tx_index_job *job);
bool snapshot_tx_index_job_start(struct snapshot_tx_index_job *job,
                                 const char *c23_datadir);
bool snapshot_tx_index_job_join(struct snapshot_tx_index_job *job,
                                int *result_out);
bool snapshot_tx_index_job_is_started(const struct snapshot_tx_index_job *job);

#endif
