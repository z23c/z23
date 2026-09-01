/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_catchup_sparse: pure projection-catchup boundary classifiers.
 * The sparse-prefix helpers were split from node_db_catchup_service.c to keep
 * that file under the E1 line ceiling; tail-fold ownership lives here beside
 * them because it is likewise side-effect-free policy. */

// one-result-type-ok:pure-classifiers — every function here is a pure,
// side-effect-free bool/int classifier (no I/O, no DB, nothing fallible to
// report). node_db_catchup_sparse_prefix_target's -1 sentinel is a normal
// "no safe sparse prefix" outcome, not a failure; a zcl_result would give
// callers nothing they don't already get from the int.

#include "node_db_catchup_internal.h"
#include "services/node_db_catchup_service.h"
#include <stdbool.h>
#include <stdint.h>

/* A verified body-less snapshot may publish its derived projection cursor up
 * to the last resolvable active-chain slot. node_db_catchup_sparse_prefix_target
 * always publishes target = first_missing_index_h - 1, so a fresh catchup
 * pass can only make progress when the very next slot the projection needs
 * (projection_tip + 1) is itself present: if THAT slot is the missing one,
 * target collapses back to projection_tip (no advance) no matter how many
 * further slots above it are also missing. In that shape the backfill
 * watcher waits instead of restarting catchup service every loop — a
 * restart cannot help until the reducer/indexer produces that next slot.
 * next_slot_present is whether active_chain_at(projection_tip + 1) resolves;
 * the caller derives it that way (not chain_tip), which is what makes this
 * correct for two-or-more missing top slots, not just exactly one. */
bool node_db_catchup_sparse_tip_slot_pending(bool sparse_prefix,
                                             int projection_tip,
                                             int chain_tip,
                                             bool next_slot_present)
{
    return sparse_prefix && projection_tip >= 0 &&
           projection_tip < chain_tip && !next_slot_present;
}

bool node_db_catchup_tail_fold_in_progress(int64_t canonical_target, int hstar)
{
    return canonical_target >= 0 && hstar >= 0 &&
           canonical_target > (int64_t)hstar + 1;
}

/* Return the highest projection cursor that a body-less, proven snapshot
 * prefix may publish, or -1 when no safe prefix exists. A freshly seeded
 * active-chain window can temporarily omit its FINAL slot while the durable
 * reducer already proves the same height. Refusing the entire 3M-block sparse
 * prefix in that shape makes the watcher rescan every missing body forever.
 * Advance only to the slot immediately BEFORE the first missing index: every
 * slot in [start..target] was observed, the proven coins authority covers the
 * target, and no undecodable/hash-mismatched body was encountered. The
 * unresolved suffix remains pending and is retried normally. */
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
                                         int32_t proven_applied)
{
    if (total <= 0 || indexed != 0 || lean_holes != total ||
        first_hole_h != start || start > chain_tip ||
        suspicious_holes != 0 || !proven_authority)
        return -1; // raw-return-ok:pure classifier; -1 = no safe sparse prefix, a normal per-pass outcome

    int target = chain_tip;
    if (missing_index_holes > 0) {
        if (first_missing_index_h < start ||
            first_missing_index_h > chain_tip)
            return -1; // raw-return-ok:pure classifier; caller logs the decision it acts on
        target = first_missing_index_h - 1;
    }
    if (target < start || proven_applied < target)
        return -1; // raw-return-ok:pure classifier; caller logs the decision it acts on
    return target;
}

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
                                               int32_t proven_applied)
{
    return node_db_catchup_sparse_prefix_target(indexed, total, lean_holes,
                                         first_hole_h, start, chain_tip,
                                         suspicious_holes,
                                         missing_index_holes,
                                         first_missing_index_h,
                                         proven_authority, proven_applied);
}
#endif
