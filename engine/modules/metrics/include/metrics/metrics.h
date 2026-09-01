/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_METRICS_H
#define ZCL_METRICS_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include "metrics/stage_metrics.h"

struct main_state;
struct chain_params;

struct metrics_external_gauges {
    int64_t utxo_count;
    int sync_state;
    char sync_state_name[32];
    int64_t tip_advance_age_seconds;
    int64_t mirror_lag_blocks;
    int64_t mirror_lag_breach_seconds;
    int64_t mirror_lag_critical_seconds;
    int64_t magicbean_peer_count;
    int64_t zclassic_c23_peer_count;
    /* Best-known header height minus served height H* (reducer_frontier
     * provable tip). -1 when the header tip is not yet known (cold boot
     * before the chain-state repository initializes). Feeds the
     * `header_gap_growing` metric alert. */
    int64_t header_gap_blocks;
    /* Active-chain tip height + its nTime, and the live peer count.
     * These arrive through the seam for the same reason everything else
     * in this struct does: engine/modules/metrics must not link against
     * core/modules/validation (active_chain_tip) or core/modules/net (connman_get_node_count).
     * boot_metrics_external_gauges() reads the tip under cs_main, exactly
     * as the metrics tick used to. tip_height/tip_time are 0 and
     * connection_count is 0 before the chain/connman exist — the same
     * values the old direct calls produced on a NULL tip. */
    int64_t tip_height;
    int64_t tip_time;
    int64_t connection_count;
    /* The 8 reducer stages' live cursor + step_us_ewma, indexed in the
     * fixed METRICS_STAGE_COUNT order (metrics_stage_name()). Filled by
     * boot_metrics_external_gauges() (engine/composition/src/boot_node_utilities.c,
     * the only writer with app/jobs visibility) and forwarded to
     * engine/modules/metrics/src/stage_metrics.c by the metrics tick — see
     * stage_metrics.h for why this indirection exists (lib/ cannot
     * include app/jobs headers). Zero-initialized (all-zero cursor/ewma)
     * is a valid pre-boot default, not a sentinel. */
    int64_t stage_cursor[METRICS_STAGE_COUNT];
    int64_t stage_step_us_ewma[METRICS_STAGE_COUNT];
};

typedef void (*metrics_external_gauges_fn)(
    struct metrics_external_gauges *out,
    void *ctx);

extern _Atomic uint64_t g_transactions_validated;
extern _Atomic uint64_t g_eh_solver_runs;

struct metrics_context {
    struct main_state *ms;
    const struct chain_params *params;
    bool mining;
    metrics_external_gauges_fn external_gauges;
    void *external_gauges_ctx;
    _Atomic bool running;
    bool thread_started;
};

void metrics_print_art(void);
bool metrics_start(struct metrics_context *ctx);
void metrics_stop(struct metrics_context *ctx);

/* O(1) atomic counter bump; thread-safe, callable from any thread. */
static inline void metrics_increment_tx_validated(void)
{
    atomic_fetch_add(&g_transactions_validated, 1);
}

/* O(1) atomic counter bump; thread-safe, callable from any thread. */
static inline void metrics_increment_eh_solver_runs(void)
{
    atomic_fetch_add(&g_eh_solver_runs, 1);
}

#endif
