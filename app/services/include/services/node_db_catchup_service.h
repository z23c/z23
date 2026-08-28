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

#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct active_chain;
struct wallet;

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
