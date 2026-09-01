/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * hodl_history_service — see header.
 *
 * The SQL for one snapshot at height H:
 *   total_zat = SUM(o.value) where o is "alive at H"
 *   older_*_zat = SUM(o.value) where also b.time(o.block_height) <=
 *                 T_H - threshold_seconds
 *
 * "Alive at H" means o was created on a block ≤ H and not spent on a
 * block ≤ H. tx_inputs holds (prev_txid, prev_vout, block_height) for
 * every spend; we LEFT JOIN to find unspent.
 *
 * Storage is reached ONLY through hodl_history_port — the raw sqlite
 * queries live in the sqlite adapter. This file is pure domain logic:
 * cutoff arithmetic, the older<=total clamp, the percentage, sample
 * striding, and the projection event emit. The public functions still
 * accept a sqlite3* so callers (boot_services, explorer, tests) are
 * unchanged; each binds the default sqlite adapter and drives the port.
 */

#include "services/hodl_history_service.h"

#include "adapters/outbound/persistence/hodl_history_sqlite.h"
#include "ports/hodl_history_port.h"
#include "storage/small_projections.h"
#include "util/log_macros.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* struct hodl_history_row (public service type) and struct
 * hodl_history_snapshot (port type) are deliberately kept layout-
 * identical so load_all can fill the caller's buffer in one shot with
 * no per-row copy. These asserts fail the build if either drifts. */
_Static_assert(sizeof(struct hodl_history_row) ==
                   sizeof(struct hodl_history_snapshot),
               "hodl_history_row size must match hodl_history_snapshot");
_Static_assert(offsetof(struct hodl_history_row, height) ==
                   offsetof(struct hodl_history_snapshot, height) &&
               offsetof(struct hodl_history_row, time) ==
                   offsetof(struct hodl_history_snapshot, time) &&
               offsetof(struct hodl_history_row, total_zat) ==
                   offsetof(struct hodl_history_snapshot, total_zat) &&
               offsetof(struct hodl_history_row, older_6m_zat) ==
                   offsetof(struct hodl_history_snapshot, older_6m_zat) &&
               offsetof(struct hodl_history_row, older_1y_zat) ==
                   offsetof(struct hodl_history_snapshot, older_1y_zat) &&
               offsetof(struct hodl_history_row, older_2y_zat) ==
                   offsetof(struct hodl_history_snapshot, older_2y_zat) &&
               offsetof(struct hodl_history_row, older_5y_zat) ==
                   offsetof(struct hodl_history_snapshot, older_5y_zat) &&
               offsetof(struct hodl_history_row, older_6m_pct) ==
                   offsetof(struct hodl_history_snapshot, older_6m_pct) &&
               offsetof(struct hodl_history_row, older_1y_pct) ==
                   offsetof(struct hodl_history_snapshot, older_1y_pct) &&
               offsetof(struct hodl_history_row, older_2y_pct) ==
                   offsetof(struct hodl_history_snapshot, older_2y_pct) &&
               offsetof(struct hodl_history_row, older_5y_pct) ==
                   offsetof(struct hodl_history_snapshot, older_5y_pct),
               "hodl_history_row fields must match hodl_history_snapshot");

static double hodl_history_pct(int64_t older, int64_t total)
{
    if (older > total)
        older = total;
    if (total < 0)
        total = 0;
    if (older < 0)
        older = 0;
    return total > 0 ? (double)older / (double)total * 100.0 : 0.0;
}

/* Compute and persist one snapshot via the storage port. This is the
 * port-driven core that hodl_history_fill_one wraps once it has bound
 * the default adapter to a sqlite3*. */
static bool fill_one_via_port(struct hodl_history_port *port, int64_t height)
{
    /* Resolve block timestamp first. If we don't have the block,
     * the chain hasn't reached this height yet and we can't sample. */
    int64_t block_time = 0;
    if (!port->block_time(port->self, height, &block_time))
        return false;
    if (block_time <= 0)
        return false;

    int64_t cutoff_times[HODL_HISTORY_THRESHOLDS] = {
        block_time - HODL_HISTORY_HALF_YEAR_SECONDS,
        block_time - HODL_HISTORY_ONE_YEAR_SECONDS,
        block_time - HODL_HISTORY_TWO_YEAR_SECONDS,
        block_time - HODL_HISTORY_FIVE_YEAR_SECONDS,
    };

    int64_t total = 0;
    int64_t older[HODL_HISTORY_THRESHOLDS] = {0};
    if (!port->compute_snapshot(port->self, height, cutoff_times,
                                &total, older))
        return false;

    if (total < 0) total = 0;
    for (int i = 0; i < HODL_HISTORY_THRESHOLDS; i++) {
        if (older[i] > total)
            older[i] = total;
        if (older[i] < 0)
            older[i] = 0;
    }

    struct hodl_history_snapshot row = {
        .height       = height,
        .time         = block_time,
        .total_zat    = total,
        .older_6m_zat = older[HODL_HISTORY_THRESHOLD_6M],
        .older_1y_zat = older[HODL_HISTORY_THRESHOLD_1Y],
        .older_2y_zat = older[HODL_HISTORY_THRESHOLD_2Y],
        .older_5y_zat = older[HODL_HISTORY_THRESHOLD_5Y],
        .older_6m_pct = hodl_history_pct(older[HODL_HISTORY_THRESHOLD_6M],
                                          total),
        .older_1y_pct = hodl_history_pct(older[HODL_HISTORY_THRESHOLD_1Y],
                                          total),
        .older_2y_pct = hodl_history_pct(older[HODL_HISTORY_THRESHOLD_2Y],
                                          total),
        .older_5y_pct = hodl_history_pct(older[HODL_HISTORY_THRESHOLD_5Y],
                                          total),
    };
    if (!port->upsert_snapshot(port->self, &row)) {
        /* upsert already logged the failure context. */
        return false;
    }

    if (height > INT32_MAX || block_time > UINT32_MAX ||
        !hodl_history_projection_emit_snapshot(
            (int32_t)height, (uint32_t)block_time, total,
            row.older_1y_zat, row.older_1y_pct)) {
        LOG_WARN("service", "hodl history projection emit failed for snapshot");
    }
    return true;
}

struct zcl_result hodl_history_fill_one(sqlite3 *db, int64_t height)
{
    if (!db || height < 1)
        return ZCL_ERR(-1, "bad args: db=%p height=%" PRId64,
                       (void *)db, height);
    struct hodl_history_port port;
    if (!hodl_history_sqlite_bind(db, &port)) {
        /* Preserves the prior LOG_FAIL("hodl_history", ...) line and its
         * early-return-on-bind-failure behavior, now carrying the reason. */
        fprintf(stderr, // obs-ok:paired-with-ZCL_ERR-return
                "[hodl_history] %s:%d %s(): failed to bind sqlite port\n",
                __FILE__, __LINE__, __func__);
        return ZCL_ERR(-3, "failed to bind sqlite port");
    }
    if (!fill_one_via_port(&port, height))
        return ZCL_ERR(-2, "no snapshot written for height %" PRId64
                           " (block not yet indexed or compute miss)",
                       height);
    return ZCL_OK;
}

int hodl_history_fill_pending(sqlite3 *db, int64_t chain_tip, int max_rows)
{
    if (!db || chain_tip < HODL_HISTORY_SAMPLE_STRIDE || max_rows <= 0)
        return 0;

    struct hodl_history_port port;
    if (!hodl_history_sqlite_bind(db, &port)) {
        LOG_RETURN(0, "hodl_history", "failed to bind sqlite port");
    }

    /* The most recent useful sample is (chain_tip - 1y_blocks) — beyond
     * that "older than 1y" can't be true. We do still sample within the
     * last year so the chart's right edge follows tip. */
    int64_t target = chain_tip - (chain_tip % HODL_HISTORY_SAMPLE_STRIDE);

    int filled = 0;
    while (filled < max_rows) {
        int64_t next = 0;
        if (port.next_fill_height) {
            if (!port.next_fill_height(port.self,
                                       HODL_HISTORY_SAMPLE_STRIDE,
                                       target, &next))
                break;
        } else {
            int64_t last_filled = port.max_filled_height(port.self);
            next = last_filled > 0
                ? last_filled + HODL_HISTORY_SAMPLE_STRIDE
                : HODL_HISTORY_SAMPLE_STRIDE;
        }
        if (next <= 0 || next > target)
            break;

        /* Break on first failure rather than skip — fill_one fails when
         * the source index (tx_outputs) doesn't cover the sample. If we
         * advanced past the failed height we'd create a permanent gap
         * that later passes couldn't retry. Asking the port for the
         * lowest missing/stale sample on each iteration also repairs
         * rows that were cached as total_zat=0 before tx_outputs caught
         * up, which keeps the explorer chart anchored from genesis after
         * projection rebuilds. */
        if (!fill_one_via_port(&port, next))
            break;
        filled++;
    }
    return filled;
}

int hodl_history_load_all(sqlite3 *db, struct hodl_history_row *out,
                          int max_rows)
{
    if (!db || !out || max_rows <= 0)
        return 0;
    struct hodl_history_port port;
    if (!hodl_history_sqlite_bind(db, &port))
        return 0;
    /* Layout-identical to struct hodl_history_snapshot (asserted at the
     * top of this file); load directly into the caller's buffer. */
    return port.load_all(port.self,
                         (struct hodl_history_snapshot *)out, max_rows);
}
