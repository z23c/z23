/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_internal — private cross-TU helpers shared by the focused
 * stage_repair translation units (header_solution / body_fetch / rewind /
 * the tip-finalize clamp coordinator). NOT part of the public API: only the
 * stage_repair_*.c files in engine/jobs/src include this. Public callers use
 * jobs/stage_repair.h.
 *
 * These were file-scope statics in the original single stage_repair.c. The
 * split relocates the four public concerns into separate TUs; the small set
 * of progress.kv accessors below are read/written from more than one of those
 * TUs, so they are declared here (definitions stay in exactly one TU) rather
 * than widening the public surface. */

#ifndef ZCL_JOBS_STAGE_REPAIR_INTERNAL_H
#define ZCL_JOBS_STAGE_REPAIR_INTERNAL_H

#include <stdbool.h>

struct sqlite3;

#define STAGE_REPAIR_SOLUTIONLESS_REASON "no-header-solution-backfill-required"

/* A row read from validate_headers_log for `height`. `found` distinguishes a
 * missing row from a present row; `ok` mirrors the column, `hash` binds the
 * verdict to exact header identity, and `fail_reason` is the possibly-empty
 * reason text. */
struct validate_row {
    bool found;
    bool has_hash;
    int ok;
    unsigned char hash[32];
    char fail_reason[96];
};

/* Read the validate_headers_log row for `height`. Caller holds the
 * progress_store tx lock. Returns false only on a SQL error (a missing row is
 * success with out->found == false). Defined in stage_repair_body_fetch.c. */
bool stage_repair_read_validate_row(struct sqlite3 *db, int height,
                                    struct validate_row *out);

/* Read the `cursor` for stage `name` from stage_cursor (or -1 if absent).
 * Caller holds the progress_store tx lock. Returns false on SQL error.
 * Defined in stage_repair_body_fetch.c. */
bool stage_repair_cursor_at_unlocked(struct sqlite3 *db, const char *name,
                                     int *out);

/* Upsert the stage_cursor row for `name` to `height` (with updated_at).
 * Caller holds the progress_store tx lock AND an open transaction. Returns
 * false on SQL error. Defined in stage_repair_rewind.c. */
bool stage_repair_force_stage_cursor(struct sqlite3 *db, const char *name,
                                     int height);

#endif /* ZCL_JOBS_STAGE_REPAIR_INTERNAL_H */
