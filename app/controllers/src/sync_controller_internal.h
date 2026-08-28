/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal cross-translation-unit glue for the sync controller.
 *
 * The public surface lives in controllers/sync_controller.h. This
 * header is private to app/controllers/src/sync_controller*.c and
 * declares helpers that needed to become non-static so the sync
 * controller could be split across multiple files. Do not include
 * from outside app/controllers/src/. */

#ifndef ZCL_APP_CONTROLLERS_SRC_SYNC_CONTROLLER_INTERNAL_H
#define ZCL_APP_CONTROLLERS_SRC_SYNC_CONTROLLER_INTERNAL_H

#include "controllers/sync_controller.h"
#include "config/db_service.h"
#include "models/database.h"
#include "models/db_txn.h"
#include "platform/read_mapping.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "wallet/wallet.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Atomic job-status globals (definitions live in sync_controller.c) ── */
extern _Atomic bool g_catchup_active;
extern _Atomic int g_catchup_height;
extern _Atomic int g_catchup_target_height;
extern _Atomic int64_t g_catchup_started_at;
extern _Atomic int64_t g_catchup_last_progress_at;
extern _Atomic bool g_import_active;
extern _Atomic int g_import_rows_written;
extern _Atomic int64_t g_import_started_at;
extern _Atomic int64_t g_import_last_progress_at;

/* ── Job-status setters (definitions in sync_controller.c) ── */
int64_t sync_job_now(void);
void sync_job_catchup_begin(int start_height, int target_height);
void sync_job_catchup_progress(int height);
void sync_job_catchup_finish(void);
void sync_job_import_begin(void);
void sync_job_import_progress(int total_rows);
void sync_job_import_finish(int total_rows);

/* ── DB-service helpers (definitions in sync_controller.c) ── */
struct db_service *sync_db_service_for(struct node_db *ndb);
bool sync_db_enter_turbo_mode(struct node_db *ndb);
bool sync_db_restore_normal_mode(struct node_db *ndb);

struct sync_db_turbo_scope {
    struct node_db *ndb;
    bool entered;
};

bool sync_db_turbo_scope_begin(struct sync_db_turbo_scope *scope,
                               struct node_db *ndb,
                               bool enabled);
bool sync_db_turbo_scope_end(struct sync_db_turbo_scope *scope);

bool sync_run_write(struct node_db *ndb,
                    db_service_write_fn fn,
                    void *ctx);

/* ── Cross-file context structs ── */
struct wallet_tx_sync_ctx {
    const struct transaction *tx;
    const struct wallet *wallet;
    int block_height;
    const uint8_t *block_hash;
    int64_t block_time;
    bool is_ours;
    bool ok;
};

/* ── Helpers exposed across sync_controller_*.c files ── */

/* Defined in sync_controller_writers.c — used by sync_controller.c
 * (in node_db_sync_wallet_tx_checked). */
bool node_db_sync_wallet_tx_write(struct node_db *ndb, void *ctx);

/* Defined in sync_controller_writers.c — used by sync_controller_blocks.c
 * (the async connect_block projection, which folds the per-tx wallet
 * projection into the same db-service job after the block write, so the
 * block row exists for its time_received lookup). */
bool node_db_sync_wallet_tx_local(struct node_db *ndb,
                                  const struct transaction *tx,
                                  const struct wallet *w,
                                  int block_height,
                                  const uint8_t block_hash[32],
                                  int64_t block_time,
                                  bool *is_ours_out);

/* Defined in sync_controller.c — used by sync_controller_catchup.c. */
bool node_db_sync_wallet_tx_checked(struct node_db *ndb,
                                    const struct transaction *tx,
                                    const struct wallet *w,
                                    int block_height,
                                    bool *is_ours_out,
                                    bool *success_out);

/* Defined in sync_controller_blocks.c — used by sync_controller_catchup.c
 * (advance_wallet_witnesses) and sync_controller_catchup.c (serialize_tx
 * via the mempool_save path that lives in sync_controller_catchup.c). */
uint8_t *serialize_tx(const struct transaction *tx, size_t *out_len);
bool advance_wallet_witnesses(struct node_db *ndb,
                              const struct block *blk,
                              struct incremental_merkle_tree *tree,
                              int height, struct wallet *wallet);
/* Own the descriptor and mapping as one lifetime.  This is required on
 * Windows and avoids relying on POSIX's close-after-mmap behavior. */
struct sync_block_file_mapping {
    int fd;
    struct platform_read_mapping view;
};

void sync_block_file_mapping_init(struct sync_block_file_mapping *mapping);
bool sync_block_file_mapping_open(struct sync_block_file_mapping *mapping,
                                  const char *datadir, int file_num);
void sync_block_file_mapping_close(struct sync_block_file_mapping *mapping);

/* ── Sapling-tree persist (definitions in sync_controller_sapling_tree_persist.c) ──
 * Tri-state outcome of a persist attempt. DEFERRED is distinct from FAILED:
 * it means "wrote nothing on purpose, retry later" (a foreign open tx owned
 * the connection), NOT a derived-state error — the rebuild loop must not
 * fail-close on it. */
enum sapling_persist_status {
    SAPLING_PERSIST_OK = 0,
    SAPLING_PERSIST_DEFERRED,
    SAPLING_PERSIST_FAILED,
};

/* Persist node_state["sapling_tree"] + ["sapling_tree_rebuild_height"] as ONE
 * atomic write. Shared between the rebuild replay (sync_controller_sapling_tree.c)
 * and the public bool wrapper. See the definition for the DEFERRED/BEGIN-nesting
 * contract. */
enum sapling_persist_status
sapling_tree_persist_pair_status(struct node_db *ndb,
                                 const void *blob, size_t blob_len,
                                 int64_t height);
bool sapling_tree_open_persist_lane(struct node_db *reducer_ndb,
                                    struct node_db *persist_ndb,
                                    int height);

/* ── Sapling-tree resume + fail-closed accounting ────────────────────────
 * Definitions in sync_controller_sapling_tree_resume.c; the replay loop in
 * sync_controller_sapling_tree.c is the only caller. */

struct active_chain;
struct block_index;

/* True when the header chain committed a (non-zero) hashFinalSaplingRoot at
 * `bi` — i.e. the block can be used to bind a frontier fail-closed. */
bool sapling_rebuild_header_root_known(const struct block_index *bi);

/* Tolerated-skip tally handed to the fail-closed classifier. Non-zero only on
 * the header-tip endpoint: the coins-applied endpoint fails closed AT the
 * first skip, so a walk that reached a root check with skips > 0 is provably
 * a walk over an INCOMPLETE body set. */
struct sapling_rebuild_skip_tally {
    int total;
    int first_height;
    int last_height;
    char classes[64];   /* comma-separated names of the non-zero classes */
};

/* fail_reason for the header-only pre-flight refusal below. Classified exactly
 * like a root mismatch over tolerated skips: a body-availability DEPENDENCY. */
#define SAPLING_REBUILD_REASON_REPLAY_IMPOSSIBLE \
    "replay_impossible_bodies_absent_below_first_foldable_body"

void sapling_tree_rebuild_raise_fail_blocker(
        const char *fail_reason, int fail_height, int total_commitments,
        int mismatches, const struct sapling_rebuild_skip_tally *skips);

/* Findings of the pre-flight below: the first foldable height (-1 when there is
 * none in range), the last height of the absent run, and that run's per-class
 * counts. Only written when the pre-flight returns true. */
struct sapling_rebuild_impossible {
    int first_body_h;
    int gap_last_h;
    int no_index;
    int no_data;
};

/* Pre-flight: true when the replay from `start_tree` at `start_height` is
 * PROVABLY unable to reproduce a header-committed root, proven from headers
 * alone before any block is read (and logged at that point). False whenever the
 * proof does not hold — no absent run, no committed root to prove against, or
 * an absent run that carried no commitments — so a recoverable walk always
 * still runs. */
bool sapling_rebuild_replay_is_impossible(
        const struct active_chain *chain,
        const struct incremental_merkle_tree *start_tree,
        int start_height, int chain_tip,
        struct sapling_rebuild_impossible *out);

/* Count + name one block the replay could not fold. Returns true when the
 * caller MUST fail-closed (the coins-applied endpoint). */
bool sapling_rebuild_account_skip(const char *reason_tag, int h,
                                  bool fatal, int *counter,
                                  int *first_skip_h, int *last_skip_h);

/* Resume candidate (0): the header-root-bound anchor_kv Sapling frontier.
 * Returns false (and leaves the outputs untouched) when the store is closed,
 * no frontier exists, it sits above `chain_tip`, or it fails its binding. */
bool sapling_rebuild_anchor_seed(const struct active_chain *chain,
                                 int chain_tip, int sapling_height,
                                 struct incremental_merkle_tree *tree_out,
                                 int64_t *height_out);

#endif
