/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Missing-UTXO self-heal scan counters and operator tunables.
 *
 * Recovery sources update these atomics directly from hot paths; this file
 * owns initialization, public snapshots, and environment parsing. */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "validation/process_block.h"

#include "process_block_internal.h"

_Atomic uint64_t g_self_heal_tx_index_hits;
_Atomic uint64_t g_self_heal_scan_hits;
_Atomic uint64_t g_self_heal_scan_exhausted;
_Atomic uint64_t g_self_heal_scan_blocks_checked_total;

int process_block_self_heal_scan_depth_limit(void)
{
    const char *depth_env = getenv("ZCL_SELF_HEAL_SCAN_DEPTH");
    char *end = NULL;
    long depth_limit;

    if (!depth_env || depth_env[0] == '\0')
        return SELF_HEAL_SCAN_DEFAULT_DEPTH;

    depth_limit = strtol(depth_env, &end, 10);
    if (end == depth_env || *end != '\0' ||
        depth_limit <= 0 || depth_limit > INT_MAX)
        return SELF_HEAL_SCAN_DEFAULT_DEPTH;

    if (depth_limit < SELF_HEAL_SCAN_DEFAULT_DEPTH)
        return SELF_HEAL_SCAN_DEFAULT_DEPTH;

    return (int)depth_limit;
}

bool process_block_self_heal_scan_enabled(void)
{
    const char *scan_env = getenv("ZCL_SELF_HEAL_SCAN_ENABLE");
    if (!scan_env || scan_env[0] == '\0')
        return false;
    return strcmp(scan_env, "1") == 0 ||
           strcmp(scan_env, "true") == 0 ||
           strcmp(scan_env, "yes") == 0;
}

void process_block_self_heal_stats_snapshot(
    struct self_heal_scan_stats *out)
{
    if (!out) return;
    out->tx_index_hits =
        atomic_load_explicit(&g_self_heal_tx_index_hits,
                             memory_order_relaxed);
    out->scan_hits =
        atomic_load_explicit(&g_self_heal_scan_hits,
                             memory_order_relaxed);
    out->scan_exhausted =
        atomic_load_explicit(&g_self_heal_scan_exhausted,
                             memory_order_relaxed);
    out->scan_blocks_checked_total =
        atomic_load_explicit(&g_self_heal_scan_blocks_checked_total,
                             memory_order_relaxed);
}
