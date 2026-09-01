/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet Sapling extension (Sapling Lane C) — implementation.
 * See engine/modules/sim/include/sim/simnet_sapling.h for the contract.
 *
 * These helpers only manage the sim's OWN note-commitment tree and toggle
 * flags read by sim_mint_block (simnet.c). No consensus predicate is touched:
 * the mint path drives the real connect_block + contextual_check_block, and a
 * rejected block means the harness built the wrong block, not that the
 * validator is wrong.
 */

#include "sim/simnet_sapling.h"

#include "sapling/incremental_merkle_tree.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <stdlib.h>

bool simnet_enable_sapling_tree(struct simnet *s)
{
    if (!s || !s->initialized)
        LOG_FAIL("simnet", "enable_sapling_tree: uninitialized simnet");
    if (s->sapling_tree)
        return true;   /* idempotent */

    struct incremental_merkle_tree *t =
        zcl_calloc(1, sizeof(*t), "simnet_sapling_tree");
    if (!t)
        LOG_FAIL("simnet", "enable_sapling_tree: OOM allocating tree");

    /* Depth-32 Pedersen tree — the consensus Sapling note-commitment tree. */
    sapling_tree_init(t);
    s->sapling_tree = t;
    return true;
}

void simnet_enable_contextual_check(struct simnet *s, bool on)
{
    if (!s || !s->initialized) {
        LOG_WARN("simnet",
                 "cannot toggle contextual check on uninitialized simnet");
        return;
    }
    s->run_contextual_check = on;
}

bool simnet_sapling_tree_root(const struct simnet *s, struct uint256 *out)
{
    if (!s || !s->initialized || !out)
        LOG_FAIL("simnet", "sapling_tree_root: invalid request");
    if (!s->sapling_tree)
        return false;
    incremental_tree_root(s->sapling_tree, out);
    return true;
}

size_t simnet_sapling_tree_size(const struct simnet *s)
{
    if (!s || !s->initialized || !s->sapling_tree)
        return 0;
    return incremental_tree_size(s->sapling_tree);
}

bool simnet_sapling_witness_last(const struct simnet *s,
                                 struct incremental_witness *w)
{
    if (!s || !s->initialized || !w)
        LOG_FAIL("simnet", "sapling_witness_last: invalid request");
    if (!s->sapling_tree)
        LOG_FAIL("simnet", "sapling_witness_last: tree not enabled");
    if (incremental_tree_size(s->sapling_tree) == 0)
        LOG_FAIL("simnet", "sapling_witness_last: tree is empty (no leaf)");

    /* Snapshot the authentication path of the last appended leaf. This
     * minimal harness appends no further notes before building the spend, so
     * the witness needs no replay and its root equals the current tree root
     * (the anchor). */
    incremental_witness_init(w, s->sapling_tree);
    return true;
}
