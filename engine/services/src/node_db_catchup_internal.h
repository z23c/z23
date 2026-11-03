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
