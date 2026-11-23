/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: a lock-free, read-only view of the dev land queue and its recent
 * outcomes for projections that hold no state of their own
 * (fleet.mission.board). It never opens step.lock or queue.lock and never
 * creates anything: land rewrites queue.jsonl by atomic rename, so a plain
 * read sees either the old or the new file, whole. */

#ifndef ZCL_NATIVE_DEV_LAND_READ_H
#define ZCL_NATIVE_DEV_LAND_READ_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_dl_row_view {
    long long seq;
    long long landed_at; /* Positive root integer for landed rows; 0 unknown. */
    char tip12[13];
    char state[16]; /* queued, inflight, landed, failed, ... */
    char phase[16];
    char dimension[48];
    char note[64]; /* truncated */
    char ts[64];
};

/* Fills *rows (caller frees; NULL when empty): the active queue rows in
 * file order, then the outcome rows from the last 2 MiB of outcomes.jsonl
 * (oldest first, at most 4096). A line that does not parse is skipped and
 * counted in *skipped (may be NULL). A missing root or file is empty.
 * Returns false only on a read error or allocation failure. */
bool zcl_dev_land_rows_read(struct zcl_dl_row_view **rows, size_t *n,
                            size_t *skipped);

#endif
