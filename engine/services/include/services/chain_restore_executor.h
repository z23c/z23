/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain restore executor — mutable execution helpers for restore plans. */

#ifndef ZCL_CHAIN_RESTORE_EXECUTOR_H
#define ZCL_CHAIN_RESTORE_EXECUTOR_H

#include <stdbool.h>
#include <stddef.h>

#include "util/result.h"

struct main_state;
struct block_index;
struct uint256;
struct chain_restore_plan;

struct zcl_result chain_restore_commit_tip_via_csr(struct main_state *ms,
                                                   struct block_index *target,
                                                   bool update_header_tip,
                                                   const char *reason);

struct zcl_result chain_restore_commit_header_via_csr(struct main_state *ms,
                                                      struct block_index *target,
                                                      const char *reason);

/* Create a placeholder anchor block_index at `height` with `hash`.
 * Inserts it into ms->map_block_index as metadata only. The anchor is
 * deliberately not marked BLOCK_HAVE_DATA and receives no synthetic
 * chainwork; it must never win chain selection or become active consensus
 * tip until real block bytes arrive and normal validation fills it in. */
struct block_index *chain_restore_create_anchor(
    struct main_state *ms,
    const struct uint256 *hash,
    int height);

/* Apply the plan: create anchor if needed, set chain tip, etc.
 * Returns the anchor or found block_index, NULL on failure. */
struct block_index *chain_restore_execute(
    const struct chain_restore_plan *plan,
    struct main_state *ms);

/* Gate for engaging the trust-index fastpath on recovery: the block-index
 * repair passes proved the in-memory index fully consistent (index_repaired
 * == 0) over a non-trivial index (index_size > 1000, so the tiny-datadir noise
 * cases are excluded). When true, the disk-backed active-chain rebuild is pure
 * waste — the in-memory pprev walk slots every ancestor in O(tip) with zero
 * disk reads. This is the precondition the unclean-restart O(delta) fix
 * (engine/composition/src/boot.c restore branch) and chain_restore_finalize_verified share.
 * Pure predicate; no side effects. */
bool chain_restore_index_verified_consistent(int index_repaired,
                                             size_t index_size);

/* Boot-path wrapper around chain_restore_finalize. When the block-index
 * repair passes just proved the in-memory index fully consistent
 * (index_repaired == 0 over a non-trivial index, index_size > 1000), trust
 * it for this finalize call: finalize takes the O(tip) in-memory pprev walk
 * instead of a ~74s disk header re-read + block-file rescan. The post-restore
 * integrity check inside finalize stays the fail-safe; the trust flag is
 * scoped to this call so the chain_integrity_failed remedy keeps its
 * authoritative disk rebuild. Falls straight through to a plain finalize when
 * the index was NOT verified clean. */
struct zcl_result chain_restore_finalize_verified(struct main_state *ms,
                                                  const char *datadir,
                                                  int index_repaired,
                                                  size_t index_size);

#endif /* ZCL_CHAIN_RESTORE_EXECUTOR_H */
