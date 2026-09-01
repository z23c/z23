/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * hodl_history_port — storage interface for the explorer-side HODL-wave
 * history (the HODL-wave time series).
 *
 * This is a read-mostly, NON-CONSENSUS projection: it reads the block
 * timestamp index and the tx_outputs / tx_inputs indices to compute one
 * supply-age snapshot per sample height, then persists that snapshot to
 * a small side table. hodl_history_service.c is the only domain logic;
 * everything below this interface is storage.
 *
 * The seam exists so the service never names sqlite. The five methods
 * here capture exactly the queries the service issues:
 *
 *   block_time(h)            "SELECT time FROM blocks WHERE height = ?"
 *   compute_snapshot(h, cuts) the single-pass alive-at-H aggregate that
 *                             yields total_zat plus age-threshold totals
 *   upsert_snapshot(row)     "INSERT OR REPLACE INTO hodl_history ..."
 *   max_filled_height()      "SELECT COALESCE(MAX(height),0) FROM ..."
 *   next_fill_height()       first missing/stale sample height in stride order
 *   load_all(out, max)       "SELECT ... FROM hodl_history ORDER BY height"
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite
 * for this subsystem.
 *
 * Threading: the live adapter wraps a single sqlite3* opened by boot.
 * The HODL history worker thread is the only writer; explorer reads run
 * on request threads. sqlite's own locking serializes them — the same
 * concurrency contract the raw code had before the seam.
 */

#ifndef ZCL_PORTS_HODL_HISTORY_PORT_H
#define ZCL_PORTS_HODL_HISTORY_PORT_H

#include <stdbool.h>
#include <stdint.h>

/* Bump when the persisted HODL snapshot calculation semantics change.
 * Rows with an older version are lazily recomputed by the background
 * filler. */
enum {
    HODL_HISTORY_THRESHOLD_6M = 0,
    HODL_HISTORY_THRESHOLD_1Y = 1,
    HODL_HISTORY_THRESHOLD_2Y = 2,
    HODL_HISTORY_THRESHOLD_5Y = 3,
    HODL_HISTORY_THRESHOLDS = 4
};

#define HODL_HISTORY_SNAPSHOT_CALC_VERSION 2

/* One persisted supply-age snapshot. Mirrors struct hodl_history_row in
 * services/hodl_history_service.h field-for-field; declared here so the
 * port has no dependency on the service header. */
struct hodl_history_snapshot {
    int64_t height;
    int64_t time;            /* unix seconds at this block */
    int64_t total_zat;
    int64_t older_6m_zat;
    int64_t older_1y_zat;
    int64_t older_2y_zat;
    int64_t older_5y_zat;
    double  older_6m_pct;
    double  older_1y_pct;
    double  older_2y_pct;
    double  older_5y_pct;
};

struct hodl_history_port {
    void *self;

    /* Block timestamp at `height`. Sets *out_time and returns true on a
     * hit. Returns false if the block isn't indexed yet (chain hasn't
     * reached this height) or on any storage error. *out_time is left
     * untouched on false. */
    bool (*block_time)(void *self, int64_t height, int64_t *out_time);

    /* Single-pass "alive at H" aggregate. Computes:
     *   *out_total = SUM(value) of outputs created on a block <= height
     *                and not spent on a block <= height.
     *   out_older[i] = the subset of that whose creation block time
     *                  <= cutoff_times[i].
     * Returns true on success (including the all-zero case). On storage
     * error returns false and leaves *out_total / out_older untouched. */
    bool (*compute_snapshot)(void *self,
                             int64_t height,
                             const int64_t cutoff_times[HODL_HISTORY_THRESHOLDS],
                             int64_t *out_total,
                             int64_t out_older[HODL_HISTORY_THRESHOLDS]);

    /* Persist (insert-or-replace) one snapshot row keyed by height.
     * Returns true on success. */
    bool (*upsert_snapshot)(void *self,
                            const struct hodl_history_snapshot *row);

    /* Highest height already persisted, or 0 if the table is empty.
     * (COALESCE(MAX(height),0).) */
    int64_t (*max_filled_height)(void *self);

    /* Lowest expected sample height that should be computed or refreshed.
     * A height needs fill when its row is missing, was written by an older
     * calculation version, or was written before the source projection proved
     * coverage through that sample. Sets *out_height to 0 when no work is
     * pending. */
    bool (*next_fill_height)(void *self,
                             int64_t stride,
                             int64_t target,
                             int64_t *out_height);

    /* Load all persisted snapshots in ascending height order into the
     * caller-owned `out` buffer. Returns the number of rows written
     * (<= max_rows). Returns 0 on storage error or empty table. */
    int (*load_all)(void *self,
                    struct hodl_history_snapshot *out,
                    int max_rows);
};

#endif /* ZCL_PORTS_HODL_HISTORY_PORT_H */
