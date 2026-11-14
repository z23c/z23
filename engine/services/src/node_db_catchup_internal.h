/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_NODE_DB_CATCHUP_INTERNAL_H
#define ZCL_NODE_DB_CATCHUP_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>
#include "base/result.h"
#include "platform/read_mapping.h"

/* Contention-safe proven-authority read for the catchup walk. Defined in
 * node_db_catchup_proven.c; see its doc comment for the TRYLOCK contract.
 * Returns false (and leaves *applied_out untouched) when the progress tx is
 * contended. */
bool node_db_catchup_read_current_proven(int32_t *proven_applied);
bool node_db_catchup_read_proven_authority(sqlite3 *progress_db,
                                           int32_t *applied_out);

struct node_db_catchup_block_mapping {
    struct platform_read_mapping mapping;
    int fd;
};

void node_db_catchup_block_mapping_init(
    struct node_db_catchup_block_mapping *block_mapping);
/* Quiet mapping open. On refusal the result carries the exact errno in
 * `code` — ENOENT/ENOTDIR mean the blk file was never written, which the
 * catchup walk treats as a lean hole rather than an incident. */
struct zcl_result node_db_catchup_block_mapping_open_quiet(
    struct node_db_catchup_block_mapping *block_mapping,
    const char *datadir, int file_num);
void node_db_catchup_block_mapping_close(
    struct node_db_catchup_block_mapping *block_mapping);

struct block;
struct uint256;
/* Caller initializes and frees block, including on refusal. */
struct zcl_result node_db_catchup_read_authenticated_block(const char *datadir, int file,
    unsigned int offset, const struct uint256 *expected_hash, struct block *block);

/* Sparse-prefix projection-cursor classifier. Defined in
 * node_db_catchup_sparse.c; see its doc comment for the contract. */
int node_db_catchup_sparse_prefix_target(int indexed,
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

struct node_db;
struct transaction;
struct wallet;
struct wallet_scan_snapshot;
enum catchup_scan_snapshot_status { CATCHUP_SCAN_OK, CATCHUP_SCAN_BUSY, CATCHUP_SCAN_REFUSED };
/* Captures the expected public scan identity under all three wallet locks. */
enum catchup_scan_snapshot_status node_db_catchup_scan_snapshot(
    struct wallet *wallet, const uint8_t expected[32], struct wallet_scan_snapshot **out);

struct sapling_key_entry;
struct sapling_replay_delivery;
struct catchup_parallel;
struct catchup_parallel_state { struct catchup_parallel *pool; bool attempted; };
void node_db_catchup_parallel_free(struct catchup_parallel_state *state);
bool node_db_catchup_replay_sapling_decrypt_parallel(struct node_db *ndb,
    struct transaction *tx, const struct sapling_key_entry *keys, size_t key_count,
    int height, int *found_out, struct sapling_replay_delivery *delivery,
    struct catchup_parallel_state *state);
#ifdef ZCL_TESTING
void node_db_transparent_replay_test_after_read(void (*hook)(void *), void *ctx);
#endif
#if defined(ZCL_TESTING) && !defined(_WIN32)
void node_db_sapling_replay_test_crash_before_delivery(void);
#endif

/* Caller owns the serialized node.db transaction and supplies a validated
 * public-key snapshot; this path preserves existing note state. */
bool node_db_catchup_replay_sapling_decrypt(struct node_db *ndb,
    struct transaction *tx, const struct sapling_key_entry *keys, size_t key_count,
    int height, int *found_out, struct sapling_replay_delivery *delivery);

/* Try-decrypt Sapling outputs in a transaction and save to SQLite
 * (returns notes found). Defined in node_db_catchup_decrypt.c. */
int node_db_catchup_try_sapling_decrypt(struct node_db *ndb,
                                        const struct transaction *tx,
                                        const struct wallet *w,
                                        int height,
                                        bool *ok_out);

struct sqlite3;
struct active_chain;
#include "sapling/incremental_merkle_tree.h"

/* Catchup view of node_state["sapling_tree"]: the tree, the height it covers
 * (-1 = none recorded), whether the walk may append to it, and whether it
 * was replaced from the reducer frontier (dirty = not yet persisted). Defined in
 * node_db_catchup_sapling_tree.c. */
struct catchup_sapling_tree {
    struct incremental_merkle_tree tree;
    struct uint256 root;
    int64_t height;
    bool root_valid;
    bool usable;
    bool dirty;
    int64_t anchor_retry_h;
    int skipped;
};

void catchup_sapling_tree_load(struct node_db *ndb,
                               const struct active_chain *chain,
                               struct catchup_sapling_tree *ct);
bool catchup_sapling_tree_prepare(struct catchup_sapling_tree *ct,
                                  const struct active_chain *chain, int h);
void catchup_sapling_tree_note_advanced(struct catchup_sapling_tree *ct, int h);
void catchup_sapling_tree_note_skipped(struct catchup_sapling_tree *ct, int h);
void catchup_sapling_tree_persist_dirty(struct node_db *ndb,
                                        struct catchup_sapling_tree *ct);

/* Reorg rewind with the cursor already read (node_db_catchup_fork_rewind.c); the
 * public wrapper is node_db_catchup_service_rewind_stale_fork. */
bool node_db_catchup_fork_rewind_at(struct node_db *ndb,
                                  const struct active_chain *chain,
                                  int cursor);

#endif /* ZCL_NODE_DB_CATCHUP_INTERNAL_H */
