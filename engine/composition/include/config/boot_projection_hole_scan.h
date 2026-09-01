/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: schedule isolated interior-hole audits for the block projection. */
#ifndef ZCL_CONFIG_BOOT_PROJECTION_HOLE_SCAN_H
#define ZCL_CONFIG_BOOT_PROJECTION_HOLE_SCAN_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;

struct boot_projection_hole_scan {
    int last_stall_scanned_cursor;
    int64_t next_scan_unix;
};

void boot_projection_hole_scan_init(
    struct boot_projection_hole_scan *state);

bool boot_projection_sparse_prefix_is_expected(int projection_tip,
                                               int chain_tip);

/* Run a scan when the startup/hourly cadence is due or a behind-tip cursor has
 * newly frozen. `ran_out` distinguishes "not due" from a completed no-hole
 * proof; a discovered hole becomes due again immediately so the caller keeps
 * its historical five-second repair loop. */
bool boot_projection_hole_scan_if_due(
    struct boot_projection_hole_scan *state,
    struct node_db *canonical,
    int max_height,
    bool sparse_prefix,
    bool behind,
    bool cursor_frozen,
    int projection_cursor,
    int64_t now_unix,
    bool *ran_out,
    int *missing_height_out);

#endif
