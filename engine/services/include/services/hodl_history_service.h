/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * hodl_history_service — populates the hodl_history table with
 * HODL-wave snapshots at regular height intervals.
 *
 * The fill is lazy + idempotent:
 *  - hodl_history_fill_one(db, height_h) computes one row, INSERT OR
 *    REPLACE so re-running on the same height re-evaluates.
 *  - hodl_history_fill_pending(db, chain_tip) walks expected sample
 *    heights up to (chain_tip - 1y_blocks) and fills any missing rows.
 *    Returns the count filled this call. Designed to be invoked from
 *    a background thread on a slow tick (~once per minute).
 *
 * Sample spacing: HODL_HISTORY_SAMPLE_STRIDE blocks. Defaults to one
 * sample per ~day at the post-Buttercup 75s spacing (4320 blocks).
 */

#ifndef ZCL_SERVICES_HODL_HISTORY_SERVICE_H
#define ZCL_SERVICES_HODL_HISTORY_SERVICE_H

#include "util/result.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#define HODL_HISTORY_SAMPLE_STRIDE 4320  /* ~1 day at 75s/block */
#define HODL_HISTORY_BLOCKS_PER_YEAR 420768  /* 365.25d * 86400s / 75s */
#define HODL_HISTORY_HALF_YEAR_SECONDS 15778800LL
#define HODL_HISTORY_ONE_YEAR_SECONDS 31557600LL
#define HODL_HISTORY_TWO_YEAR_SECONDS 63115200LL
#define HODL_HISTORY_FIVE_YEAR_SECONDS 157788000LL

struct hodl_history_row {
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

/* Compute and persist one snapshot. Returns a non-ok zcl_result on SQL
 * error or if the height predates enough chain history to be meaningful
 * (the message names the failing reason; the bare no-op cases — bad
 * args, block not yet indexed, snapshot compute miss — carry distinct
 * codes so the caller's log explains why no row was written). */
struct zcl_result hodl_history_fill_one(sqlite3 *db, int64_t height);

/* Walk from the most recent filled sample up to (chain_tip - stride),
 * filling at most max_rows new rows. Returns rows filled. */
int  hodl_history_fill_pending(sqlite3 *db, int64_t chain_tip,
                               int max_rows);

/* Read all samples in time order. Caller owns the buffer. Returns
 * number of rows written (≤ max_rows). */
int  hodl_history_load_all(sqlite3 *db, struct hodl_history_row *out,
                           int max_rows);

#endif
