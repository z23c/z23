/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate NULL-block_hash re-arm — CONTAINED, recovery-gated
 * re-derive-in-place for the pre-stamping script_validate_log artifact. Twin of
 * proof_validate_null_hash_rearm.h.
 *
 * Background
 * ----------
 * script_validate_log_insert learned to stamp the block's hash into the row's
 * block_hash column; rows authored before that carry block_hash=NULL.
 * utxo_apply's label_splice guard (engine/jobs/src/utxo_apply_stage.c) CORRECTLY
 * refuses a hashless script verdict — a NULL-block_hash row at or above
 * utxo_apply's cursor is a hard wedge, and script_validate's own cursor has
 * already passed those heights so it never re-stamps them on its own.
 *
 * This module rewinds script_validate's cursor down to the lowest
 * NULL-block_hash height that a downstream consumer still needs (never below
 * MIN(utxo_apply, tip_finalize) — the LCC invariant) and deletes the
 * NULL-block_hash suffix, so the CURRENT binary re-derives and re-stamps
 * block_hash on the next fold. It is a re-derive-in-place rung, NOT a
 * borrowed-seed install: no state is imported, every re-stamped verdict is
 * recomputed from the local block body by the same verifier the live reducer
 * runs.
 *
 * Containment
 * -----------
 * The mutation is gated through struct recovery_policy (validation_rebind cap):
 * with the built-in / env defaults a rewind beyond the cap is REFUSED, so a
 * naive or autonomous caller CANNOT silently mutate a public/dev node. A NULL
 * policy is loaded from the environment (default-refuse beyond the cap).
 *
 * Intended callers: the reducer_frontier_reconcile_light label-splice re-bind
 * arm, a boot-time detection pass, or the shielded-state cure. Run it when the
 * script_validate stage is NOT concurrently stepping (boot / import / healer
 * context).
 */

#ifndef ZCL_JOBS_SCRIPT_VALIDATE_NULL_HASH_REARM_H
#define ZCL_JOBS_SCRIPT_VALIDATE_NULL_HASH_REARM_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct recovery_policy;

enum script_validate_rearm_outcome {
    SV_REARM_NOT_NEEDED = 0, /* no ok=1/NULL-block_hash row above the floor */
    SV_REARM_REFUSED,        /* recovery policy declined (default containment) */
    SV_REARM_ERROR,          /* a scan/delete/rewind step failed (logged) */
    SV_REARM_REARMED,        /* cursor rewound + NULL suffix deleted */
};

struct script_validate_rearm_report {
    enum script_validate_rearm_outcome outcome;
    uint64_t sv_cursor_before;   /* script_validate cursor at entry */
    uint64_t consumer_floor;     /* MIN(utxo_apply, tip_finalize) rewind floor */
    int      lowest_null_height; /* lowest ok=1/NULL-block_hash height, or -1 */
    int64_t  null_row_count;     /* ok=1/NULL rows in [floor, sv_cursor) */
    uint64_t rewound_to;         /* sv cursor after re-arm (== lowest_null) */
    int64_t  deleted_rows;       /* NULL-block_hash rows deleted */
};

/* Detect and (if the recovery policy allows) re-arm the pre-stamping
 * NULL-block_hash artifact. `policy` may be NULL — it is then loaded from the
 * environment (default-refuse for a rewind beyond the cap). `report` is
 * optional and is always fully populated when non-NULL. Never mutates on the
 * SV_REARM_NOT_NEEDED / SV_REARM_REFUSED / SV_REARM_ERROR outcomes. */
enum script_validate_rearm_outcome script_validate_null_hash_rearm(
    struct sqlite3 *db, const struct recovery_policy *policy,
    struct script_validate_rearm_report *report);

#endif /* ZCL_JOBS_SCRIPT_VALIDATE_NULL_HASH_REARM_H */
