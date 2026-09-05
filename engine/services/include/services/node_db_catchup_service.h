/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_catchup_service — bulk-index blocks (sqlite_tip+1 → chain_tip)
 * into SQLite, optionally scanning for wallet transactions.
 *
 * This is the orchestration body lifted verbatim out of the sync
 * controller (sync_controller_catchup.c). The controller
 * (node_db_sync_catchup) keeps its parse/validate front matter and now
 * delegates the turbo-mode scope, DB verify, Sapling-tree init, the main
 * transaction/commit block loop, and turbo end to this service.
 *
 * Contract (LOCKED): returns a plain int — the number of blocks indexed,
 * or -1 on a setup failure. The single caller is the catchup job thread
 * (sync_controller_catchup_jobs.c), which stores the int into job->result.
 * Do NOT migrate to zcl_result: the recovery-primitive int contract is
 * consumed across the coins-wedge recovery surface and a result type buys
 * nothing here while forcing a job-struct rewrite. */

#ifndef ZCL_SERVICES_NODE_DB_CATCHUP_SERVICE_H
#define ZCL_SERVICES_NODE_DB_CATCHUP_SERVICE_H

#include "services/node_db_catchup_lock_guard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct active_chain;
struct wallet;

/* ── Post-commit reopen retry ────────────────────────────────────────
 *
 * After a clean batch COMMIT the walk reopens its write transaction with
 * BEGIN IMMEDIATE. Another writer that holds the node.db write lock for
 * longer than this handle's 10 s busy timeout makes that BEGIN return a
 * plain SQLITE_BUSY — db_maintenance's periodic wal/analyze/vacuum op is
 * the writer that does it, and under memory pressure it does it often.
 *
 * That is the WAIT-CURABLE busy class: the committed batches are durable
 * and the walk holds no read snapshot, so a later attempt can simply
 * succeed. Aborting the pass on the first one instead cost the node
 * everything downstream of catchup — the boot watchdog withholds its ping
 * with catchup stopped, systemd kills the node, and the walk restarts from
 * a random height forever.
 *
 * One policy with the BUSY_SNAPSHOT whole-walk restart in
 * services/node_db_catchup_lock_guard.h. That guard spends
 * NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS whole re-walks on the class no
 * wait can cure; this one spends twice as many cheap in-place BEGINs on
 * the class a wait can. A BUSY_SNAPSHOT observed here is handed to that
 * guard rather than retried, so each class is answered in exactly one
 * place. Worst case is ~60 s of reopen effort (six attempts, each
 * honouring the 10 s busy timeout) before the unchanged fail-closed
 * abort. */
#define NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS \
    (2 * NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS)
#define NODE_DB_CATCHUP_REOPEN_MAX_RETRIES \
    (NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS - 1)

/* Backoff before each retry: doubles from BASE, capped at MAX. The 10 s
 * busy handler inside BEGIN IMMEDIATE is the real wait; this only spaces
 * attempts that a busy handler returning immediately would otherwise burn
 * back to back. */
#define NODE_DB_CATCHUP_REOPEN_BACKOFF_BASE_MS 250
#define NODE_DB_CATCHUP_REOPEN_BACKOFF_MAX_MS  2000

/* True while a bulk catchup projection walk is running — it holds the
 * node.db write lock in batch-length bursts, so db_maintenance defers its
 * housekeeping tick on this rather than racing it for the lock. */
bool node_db_catchup_service_active(void);

/* A verified body-less snapshot may publish its derived projection cursor up
 * to the last resolvable active-chain slot. When the very next slot the
 * projection needs (projection_tip + 1) is a missing active-chain index —
 * regardless of how many further slots above it are also missing — a fresh
 * catchup pass cannot advance the cursor, so the backfill watcher waits
 * instead of retrying the same no-progress catchup transaction every loop.
 * next_slot_present must reflect presence at height projection_tip + 1
 * (not chain_tip). See node_db_catchup_sparse.c for the full rationale. */
bool node_db_catchup_sparse_tip_slot_pending(bool sparse_prefix,
                                             int projection_tip,
                                             int chain_tip,
                                             bool next_slot_present);

/* The SQLite node.db projection is derived state. It must not occupy the
 * serialized DB service while the canonical reducer frontier is folding
 * toward the validated-header target. A one-block edge is the normal live-tip
 * shape; only a target gap of two or more is deferred. */
bool node_db_catchup_tail_fold_in_progress(int64_t canonical_target,
                                           int hstar);

#ifdef ZCL_TESTING
bool node_db_catchup_test_block_mapping_open(
    const char *datadir, int file_num, void **mapping_out,
    const uint8_t **data_out, size_t *size_out, int *error_out);
void node_db_catchup_test_block_mapping_close(void *mapping);

int node_db_catchup_test_sparse_prefix_target(int indexed,
                                              int total,
                                              int lean_holes,
                                              int first_hole_h,
                                              int start,
                                              int chain_tip,
                                              int suspicious_holes,
                                              int missing_index_holes,
                                              int first_missing_index_h,
                                              bool proven_authority,
                                              int32_t proven_applied);

/* Direct entry to the per-block lean-index writer so a torn block_index
 * (BLOCK_HAVE_DATA set but phashBlock == NULL) can be proven to fail-closed
 * with a named log instead of dereferencing NULL. */
struct block;
struct block_index;
bool node_db_catchup_test_sync_block_lean(struct node_db *ndb,
                                          const struct block *blk,
                                          const struct block_index *pindex);

/* Arm n test-injected SQLITE_BUSY failures on the post-batch-commit
 * BEGIN IMMEDIATE, consumed one per attempt, and zero the retry backoff so
 * a test never sleeps the production budget. n <= 0 disarms. */
void node_db_catchup_test_force_reopen_busy(int n);

/* Post-batch-commit BEGIN IMMEDIATE attempts since the last reset. */
int node_db_catchup_test_reopen_attempts(void);

/* Force node_db_catchup_service_active() for a test that drives
 * db_maintenance without running a walk. */
void node_db_catchup_test_set_active(bool active);

/* Raw begin/finish depth counter behind node_db_catchup_service_active()'s
 * `> 0` test. That test alone cannot tell a healthy 0 apart from a -1 left
 * by a begin paired with two finishes, so a regression test that must
 * catch the double-finish class reads this directly. */
int node_db_catchup_test_active_depth(void);

/* Clear every reopen override and counter above. */
void node_db_catchup_test_reset_reopen(void);
#endif

/* Indexes blocks from (sqlite_tip+1) to chain_tip into SQLite. Also scans
 * for wallet transactions if a wallet is provided. Returns the number of
 * blocks indexed, or -1 on a setup failure (turbo enter / BEGIN / COMMIT).
 * Logs every failure path internally. */
int node_db_catchup_service_run(struct node_db *ndb,
                                const struct active_chain *chain,
                                struct wallet *w,
                                const char *datadir);

#endif /* ZCL_SERVICES_NODE_DB_CATCHUP_SERVICE_H */
