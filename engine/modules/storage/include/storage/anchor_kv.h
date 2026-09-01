/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * anchor_kv -- durable Sprout/Sapling note-commitment anchors in progress.kv.
 *
 * zclassicd stores every active-chain commitment-tree root in chainstate and
 * HaveShieldedRequirements rejects a spend whose root is absent.  These
 * tables are the C23 equivalent.  A row contains the complete incremental
 * frontier, not only the root: Sprout permits a later JoinSplit in the SAME
 * transaction to spend against the intermediate root produced by an earlier
 * JoinSplit, so the validator must be able to append to an historical tree.
 *
 * Writes participate in the caller's progress.kv transaction.  The reducer
 * inserts anchors before committing its cursor/log/coins state, and every
 * rewind deletes abandoned-branch rows in that same transaction.
 *
 * HISTORY GAP: an existing snapshot/import datadir has no historical anchor
 * rows.  anchor_state.activation_cursor records the first height for which
 * this store can derive anchors.  Zero means a from-genesis history.  A
 * missing root while activation_cursor > 0 is INCOMPLETE, never proof that
 * the root was forged; callers must fail closed with a named blocker until a
 * body replay backfills [0, activation_cursor). */

#ifndef STORAGE_ANCHOR_KV_H
#define STORAGE_ANCHOR_KV_H

#include "core/uint256.h"
#include "sapling/incremental_merkle_tree.h"

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* Durable values: never renumber.  They intentionally match nullifier_kv. */
#define ANCHOR_POOL_SPROUT  0
#define ANCHOR_POOL_SAPLING 1

enum anchor_kv_lookup_result {
    ANCHOR_KV_ERROR = -1,
    ANCHOR_KV_MISSING = 0,
    ANCHOR_KV_FOUND = 1,
    ANCHOR_KV_HISTORY_INCOMPLETE = 2,
};

/* Create sprout_anchors, sapling_anchors and anchor_state. */
bool anchor_kv_ensure_schema(struct sqlite3 *db);

/* Ensure both anchor_state rows exist.  `activation_cursor` is the reducer's
 * next-height cursor at first adoption (0 on a from-genesis store).  Existing
 * rows are never overwritten. */
bool anchor_kv_initialize_history(struct sqlite3 *db,
                                  int64_t activation_cursor);

/* Read the adoption cursor.  Returns false on store/argument error. */
bool anchor_kv_activation_cursor(struct sqlite3 *db, int pool,
                                 int64_t *cursor_out, bool *found_out);

/* Point lookup.  Empty roots are protocol-defined and always FOUND.  For a
 * stored root, `tree_out` (optional) receives a verified/deserialized tree.
 * The row is rejected as ERROR if its blob does not hash back to `root`.
 * A missing non-empty root reports HISTORY_INCOMPLETE when the store was
 * adopted above genesis, otherwise MISSING (positive proof of absence). */
enum anchor_kv_lookup_result anchor_kv_get(
    struct sqlite3 *db, int pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out, int64_t *height_out);

/* Current active-chain frontier: highest-height stored row, or the empty tree
 * when history is complete and the pool has not changed yet. */
enum anchor_kv_lookup_result anchor_kv_latest_tree(
    struct sqlite3 *db, int pool, struct incremental_merkle_tree *tree_out,
    struct uint256 *root_out, int64_t *height_out);

/* Insert a newly-derived active-chain frontier.  Idempotent for a root already
 * present (the earliest creation height is preserved). */
bool anchor_kv_add_tree(struct sqlite3 *db, int pool,
                        const struct incremental_merkle_tree *tree,
                        int64_t height);

/* Cheap MAX(height) over the pool's anchor table (indexed — no tree
 * deserialization, unlike anchor_kv_latest_tree). Fills *out_height with the
 * highest stored creation height, or -1 when the table is empty. Returns false
 * only on a store error / bad args. Used by the commit-invariant append-only
 * check to seed the per-batch monotonic baseline without a full-table scan. */
bool anchor_kv_max_height(struct sqlite3 *db, int pool, int64_t *out_height);

/* Remove roots first created in the abandoned height range. */
bool anchor_kv_delete_range(struct sqlite3 *db, int64_t first_height,
                            int64_t last_height);

/* Reset primitives — clear both root sets and stamp their adoption cursor.
 * The cursor value selects one of two OPPOSITE completeness semantics, so the
 * choice is named at the call site rather than encoded in a bare integer.
 * Neither opens a transaction: boot/refold callers already own one (each falls
 * back to its own IMMEDIATE tx only when invoked in autocommit).
 *
 * mark_complete: adoption cursor 0 — a from-genesis COMPLETE history.  A later
 * missing root is positive proof of absence (ANCHOR_KV_MISSING) and an empty
 * table folds forward as the protocol-empty frontier (ANCHOR_KV_FOUND). */
bool anchor_kv_reset_mark_complete_in_tx(struct sqlite3 *db);

/* mark_empty_below: adoption cursor `below_height` — history is UNKNOWN below
 * `below_height` (the marker every above-genesis seed/refold installs).  A
 * missing root below the cursor is ANCHOR_KV_HISTORY_INCOMPLETE (fail-closed),
 * never proof of absence, and an empty table fails closed until a body replay
 * backfills [0, below_height).  This is the marker class behind the H* wedge.
 * `below_height` must be >= 0 (a negative height is refused); passing 0 is
 * accepted and is equivalent to mark_complete. */
bool anchor_kv_reset_mark_empty_below_in_tx(struct sqlite3 *db,
                                            int64_t below_height);

/* Change BOTH durable anchor-history markers from `expected_boundary` to zero
 * in the caller's ALREADY-OPEN transaction, without clearing the replayed
 * roots.  This is deliberately an in-tx primitive so the shielded-history
 * owner can publish Sprout, Sapling, and nullifier completeness together.
 * Both rows must exist and still equal the positive expected boundary; any
 * mismatch refuses before either marker changes. */
bool anchor_kv_publish_full_replay_complete_in_tx(
    struct sqlite3 *db, int64_t expected_boundary);

/* Report whether `pool`'s anchor table has zero rows.  Distinguishes the
 * birth-defect state (a nonzero activation cursor over an EMPTY table — no
 * initial frontier was ever seeded) from a genuine historical gap (rows exist
 * but a specific below-cursor root is absent).  Returns false on store error
 * (and leaves *empty_out false). */
bool anchor_kv_table_is_empty(struct sqlite3 *db, int pool, bool *empty_out);

/* Durable row count for `pool`'s anchor table (sprout_anchors / sapling_anchors).
 * Diagnostic-only: an operator/dumper's observable proof of HOW MANY historical
 * frontier roots a completed import (shielded_history_import_service.c) or a
 * from-genesis fold has actually written, independent of and cross-checkable
 * against the activation cursor. Returns false on store error and leaves
 * *count_out at 0. */
bool anchor_kv_row_count(struct sqlite3 *db, int pool, int64_t *count_out);

/* Seed ONE frontier row for `pool` at `height`, but ONLY after verifying the
 * frontier's own computed root equals `expected_root` (the block's
 * hashFinalSaplingRoot / hashFinalSproutRoot at that height).  This is the
 * auto-terminating cure for a snapshot/refold seed that reset the adoption
 * cursor above genesis WITHOUT an initial frontier: the first shielded-output
 * block then finds an empty table and fails closed forever.  A verified insert
 * makes anchor_kv_latest_tree return ANCHOR_KV_FOUND so the fold resumes.
 *
 * NEVER inserts an unverified frontier: on any root mismatch it returns false,
 * logs, and writes nothing (fail-closed, so consensus accept/reject is
 * unchanged).  An empty tree whose root already matches `expected_root` is a
 * no-op success (the empty frontier is protocol-implicit).  Participates in the
 * caller's transaction scope (autocommit for a single-statement caller). */
bool anchor_kv_seed_frontier_row(struct sqlite3 *db, int pool,
                                 const struct incremental_merkle_tree *tree,
                                 int64_t height,
                                 const struct uint256 *expected_root);

#endif /* STORAGE_ANCHOR_KV_H */
