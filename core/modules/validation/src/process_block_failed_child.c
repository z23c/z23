/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Failed-child propagation for process_block.
 *
 * A failed block invalidates descendants, but a full block-map walk is
 * expensive at live chain size. This file owns the bounded propagation helper
 * and its OOM-amplifier guards. */

#include <stdlib.h>
#include <time.h>

#include "chain/chain.h"
#include "util/safe_alloc.h"

#include "process_block_internal.h"

/* BLOCK_FAILED_CHILD propagation with OOM-amplifier guards.
 *
 * A naive full block_map scan + qsort on every failed connect_block is
 * O(N log N) work plus ~24 MB of scratch at a ~3M-entry tip. Under a
 * retry storm (repeated FSM flaps re-propagating from the same stuck
 * block), that repeated walk drives RSS to the cgroup limit. The two
 * early returns below bound this.
 *
 * The two early returns are part of the production contract; see the header
 * for the full guard description. */
enum propagate_failed_child_result
process_block_propagate_failed_child(struct block_map *map,
                                      const struct block_index *pindex_root,
                                      time_t now_sec,
                                      time_t *last_propagate_sec,
                                      size_t *propagated_out)
{
    /* Guard A: parent already failed. A prior propagation
     * from the failed ancestor already covered this subtree, so the
     * descendant CHILD marks are already in place; walking the map
     * again is pure allocator + qsort amplification. */
    if (pindex_root && pindex_root->pprev &&
        (pindex_root->pprev->nStatus & BLOCK_FAILED_MASK))
        return PROPAGATE_FAILED_CHILD_SKIP_PARENT_FAILED;

    /* Guard B: per-retry rate limit. When the caller opts in
     * with a persistent timestamp, refuse back-to-back walks inside
     * PROPAGATE_FAILED_CHILD_MIN_INTERVAL_SEC.  The worst a flap can
     * do under this guard is one 24 MB + O(N log N) walk per
     * interval.  Callers that need an unconditional walk (tests,
     * explicit flush paths) pass NULL. */
    if (last_propagate_sec) {
        if (now_sec - *last_propagate_sec <
            PROPAGATE_FAILED_CHILD_MIN_INTERVAL_SEC)
            return PROPAGATE_FAILED_CHILD_SKIP_RATE_LIMITED;
        *last_propagate_sec = now_sec;
    }

    size_t map_sz = block_map_count(map);
    struct block_index **all = zcl_malloc(
        map_sz * sizeof(struct block_index *), "failed_child_all");
    if (!all)
        return PROPAGATE_FAILED_CHILD_MALLOC_FAILED;

    size_t n = 0, iter = 0;
    struct block_index *ch;
    while (block_map_next(map, &iter, NULL, &ch)) {
        if (ch && ch->nHeight > pindex_root->nHeight)
            all[n++] = ch;
    }
    /* Sort by height ascending — parents before children. */
    qsort(all, n, sizeof(struct block_index *),
          block_index_cmp_height);
    /* Single pass: if parent is failed, child is failed. */
    size_t propagated = 0;
    for (size_t i = 0; i < n; i++) {
        if (!all[i]->pprev) continue;
        if (all[i]->nStatus & BLOCK_FAILED_MASK) continue;
        if (all[i]->pprev->nStatus & BLOCK_FAILED_MASK) {
            all[i]->nStatus |= BLOCK_FAILED_CHILD;
            propagated++;
        }
    }
    free(all);
    if (propagated_out) *propagated_out = propagated;
    return PROPAGATE_FAILED_CHILD_OK;
}
