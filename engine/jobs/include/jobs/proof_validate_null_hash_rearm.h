/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate NULL-block_hash re-arm — CONTAINED, recovery-gated
 * re-derive-in-place for the pre-stamping proof_validate_log artifact.
 *
 * Background
 * ----------
 * proof_validate_log_insert stamps bi->phashBlock into the row's
 * block_hash column. proof_validate_log
 * rows authored before that stamping existed carry block_hash=NULL. utxo_apply's label_splice guard
 * (engine/jobs/src/utxo_apply_stage.c) CORRECTLY refuses a hashless proof verdict
 * — a NULL-block_hash row at or above utxo_apply's cursor is a hard wedge, and
 * proof_validate's own cursor has already passed those heights so it never
 * re-stamps them on its own.
 *
 * This module rewinds proof_validate's cursor down to the lowest NULL-block_hash
 * height that utxo_apply still needs (never below utxo_apply's cursor — the LCC
 * invariant: we never rewind a height a downstream consumer already applied) and
 * deletes the NULL-block_hash suffix, so the CURRENT binary re-derives and
 * re-stamps block_hash on the next fold. It is a re-derive-in-place rung, NOT a
 * borrowed-seed install: no state is imported, every re-stamped verdict is
 * recomputed from the local block body by the same verifier the live reducer
 * runs.
 *
 * Containment
 * -----------
 * The mutation is gated through struct recovery_policy (block_rollback cap): with
 * the built-in / env defaults a rewind beyond the small cap is REFUSED, so a
 * naive or autonomous caller CANNOT silently mutate a public/dev node. The
 * operator raises the cap / supplies the ack file to authorise it after a copy
 * proof, exactly like every other recovery-apply path. A NULL policy is loaded
 * from the environment (default-refuse) rather than treated as unconditional
 * allow.
 *
 * Intended callers: a boot-time detection pass, or the shielded-state cure
 * once it has just cleared the anchor_backfill_gap. Run it when the
 * proof_validate stage is NOT concurrently stepping (boot / import context).
 */

#ifndef ZCL_JOBS_PROOF_VALIDATE_NULL_HASH_REARM_H
#define ZCL_JOBS_PROOF_VALIDATE_NULL_HASH_REARM_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct recovery_policy;

enum proof_validate_rearm_outcome {
    PV_REARM_NOT_NEEDED = 0, /* no ok=1/NULL-block_hash row above utxo_apply */
    PV_REARM_REFUSED,        /* recovery policy declined (default containment) */
    PV_REARM_ERROR,          /* a scan/delete/rewind step failed (logged) */
    PV_REARM_REARMED,        /* cursor rewound + NULL suffix deleted */
};

struct proof_validate_rearm_report {
    enum proof_validate_rearm_outcome outcome;
    uint64_t pv_cursor_before;   /* proof_validate cursor at entry */
    uint64_t ua_cursor_floor;    /* utxo_apply cursor = rewind floor (LCC) */
    int      lowest_null_height; /* lowest ok=1/NULL-block_hash height, or -1 */
    int64_t  null_row_count;     /* ok=1/NULL rows in [floor, pv_cursor) */
    uint64_t rewound_to;         /* pv cursor after re-arm (== lowest_null) */
    int64_t  deleted_rows;       /* NULL-block_hash rows deleted */
};

/* Detect and (if the recovery policy allows) re-arm the pre-stamping
 * NULL-block_hash artifact. `policy` may be NULL — it is then loaded from the
 * environment (default-refuse for a rewind beyond the cap). `report` is
 * optional and is always fully populated when non-NULL. Never mutates on the
 * PV_REARM_NOT_NEEDED / PV_REARM_REFUSED / PV_REARM_ERROR outcomes. */
enum proof_validate_rearm_outcome proof_validate_null_hash_rearm(
    struct sqlite3 *db, const struct recovery_policy *policy,
    struct proof_validate_rearm_report *report);

#endif /* ZCL_JOBS_PROOF_VALIDATE_NULL_HASH_REARM_H */
