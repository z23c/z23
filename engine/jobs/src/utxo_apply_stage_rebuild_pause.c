/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Cross-owner pause seam for the Sapling commitment-tree rebuild. The replay
 * publishes one verified frontier as a unit; utxo_apply must not persist even
 * one anchor derived from the obsolete frontier while that work is in flight. */

#include "jobs/utxo_apply_stage.h"

#include <stdatomic.h>

/* Defined by the one Sapling rebuild authority in sync_controller.c. */
extern _Atomic bool g_sapling_tree_rebuilding;

bool utxo_apply_sapling_rebuild_paused(void)
{
    return atomic_load(&g_sapling_tree_rebuilding);
}
