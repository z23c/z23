/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Pruning Service
 *
 * Reclaims disk space by deleting block data (blkXXXXX.dat) and undo
 * data (revXXXXX.dat) for blocks that are deeply buried in the chain.
 * Headers are never pruned — they remain in the block index forever.
 *
 * Strategy
 * --------
 * Blocks are stored in numbered files (blk00000.dat .. blk99999.dat),
 * each up to 128 MB. The service prunes at file granularity: a file
 * is deleted only when ALL blocks in it are deeper than the retention
 * depth. This avoids the complexity of sparse-punching individual
 * blocks out of shared files.
 *
 * After deleting a file, the service clears BLOCK_HAVE_DATA (and
 * BLOCK_HAVE_UNDO) from every block_index whose nFile pointed at
 * the pruned file. The block_index entry and all header fields are
 * preserved — only the raw block bytes on disk are gone.
 *
 * Configuration
 * -------------
 *   ZCL_PRUNE_KEEP_BLOCKS — env var, default 1000. Minimum number
 *     of blocks from the tip that must be kept on disk.
 *   tick_seconds — how often the thread wakes to check for work.
 *
 * Safety
 * ------
 * - Never prunes while syncing (must be SYNC_AT_TIP).
 * - Never prunes blk_sync.dat (file 255, used by fast sync).
 * - Never prunes file 0 (contains genesis block).
 * - Logs every file deletion as an event.
 *
 * API
 * ---
 *   block_pruning_init(svc, ms, datadir)  — init struct
 *   block_pruning_start(svc)              — launch background thread
 *   block_pruning_stop(svc)               — join thread
 *   block_pruning_run_once(svc)           — synchronous single pass (for tests)
 *   block_pruning_get_status(svc, out)    — snapshot progress
 */

#ifndef ZCL_SERVICES_BLOCK_PRUNING_SERVICE_H
#define ZCL_SERVICES_BLOCK_PRUNING_SERVICE_H

#include "util/result.h"
#include "validation/main_state.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

/* ── Defaults ──────────────────────────────────────────────── */

#define BLOCK_PRUNING_DEFAULT_KEEP_BLOCKS  1000
#define BLOCK_PRUNING_DEFAULT_TICK_SECONDS 300   /* 5 minutes */
#define BLOCK_PRUNING_MIN_KEEP_BLOCKS      288   /* ~1 day of blocks */

/* ── Status ────────────────────────────────────────────────── */

enum block_pruning_state {
    BLOCK_PRUNING_IDLE = 0,
    BLOCK_PRUNING_RUNNING,
    BLOCK_PRUNING_STOPPED,
};

struct block_pruning_status {
    int state;
    int64_t files_pruned;        /* total blk+rev files deleted */
    int64_t blocks_pruned;       /* total block_index entries cleared */
    int64_t bytes_reclaimed;     /* total bytes freed */
    int     lowest_have_data;    /* lowest height with BLOCK_HAVE_DATA */
    int     chain_height;        /* chain height at last check */
    int     keep_blocks;         /* configured retention depth */
};

/* ── Service ───────────────────────────────────────────────── */

struct block_pruning_service {
    /* References (not owned) */
    struct main_state *ms;
    const char *datadir;

    /* Config */
    int keep_blocks;
    int tick_seconds;

    /* Thread management */
    pthread_t thread;
    bool thread_started;
    _Atomic bool stop_requested;

    /* Startup synchronization: start() blocks until thread is live. */
    pthread_mutex_t ready_mutex;
    pthread_cond_t  ready_cond;
    bool            ready;

    /* Progress (atomics for lock-free reads from RPC) */
    _Atomic int state;
    _Atomic int64_t files_pruned;
    _Atomic int64_t blocks_pruned;
    _Atomic int64_t bytes_reclaimed;
    _Atomic int     lowest_have_data;
};

/* Global pointer for RPC/native access. Set by boot, NULL before init. */
extern struct block_pruning_service *g_block_pruning;

/* ── Lifecycle ─────────────────────────────────────────────── */

/* Initialize the service struct. Reads ZCL_PRUNE_KEEP_BLOCKS env.
 * Does NOT start the thread. */
void block_pruning_init(struct block_pruning_service *svc,
                        struct main_state *ms,
                        const char *datadir);

/* Launch the background thread. Returns a non-ok zcl_result if
 * already running or if ms/datadir are NULL. */
struct zcl_result block_pruning_start(struct block_pruning_service *svc);

/* Signal and join the background thread. Safe to call if not started. */
void block_pruning_stop(struct block_pruning_service *svc);

/* Run a single pruning pass synchronously. Returns the number of
 * files pruned in this pass. For use in tests. */
int block_pruning_run_once(struct block_pruning_service *svc);

/* Prune-after-seal: a SEPARATE, segment-gated entry point from run_once's
 * keep_blocks-depth cadence. Prunes only blk*.dat/rev*.dat files whose
 * highest contained block height is strictly below `sealed_verified_top_excl`
 * — the exclusive top of a range the CALLER has itself just sealed into the
 * immutable ROM segment store AND re-verified (re-opened + digest-checked)
 * in this same call chain, so the blk*.dat bytes being deleted are already
 * durably redundant. The result additionally respects the existing
 * keep_blocks retention floor (never prunes more recent than
 * chain_height - keep_blocks), so a shallow sealer finality depth can never
 * outrun the operator's configured retention. Returns the number of files
 * pruned, 0 on no-op/null args — never prunes anything the caller has not
 * itself just proven sealed+verified. */
int block_pruning_prune_sealed_range(struct block_pruning_service *svc,
                                     uint32_t sealed_verified_top_excl);

/* Snapshot current status into *out. Thread-safe (atomic reads). */
void block_pruning_get_status(const struct block_pruning_service *svc,
                              struct block_pruning_status *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * Wired into `z23 dumpstate block_pruning`. */
struct json_value;
bool block_pruning_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_BLOCK_PRUNING_SERVICE_H */
