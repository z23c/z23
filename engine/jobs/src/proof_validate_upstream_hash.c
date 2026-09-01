/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Name and deduplicate proof-stage waits on a stale script receipt. */

#include "proof_validate_stage_internal.h"

#include "core/uint256.h"
#include "jobs/proof_validate_stage.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>

#include <stdio.h>

bool proof_validate_upstream_hash_ready(
    int height, const struct uint256 *selected_hash, bool receipt_has_hash,
    const struct uint256 *receipt_hash)
{
    if (selected_hash && receipt_has_hash && receipt_hash &&
        uint256_eq(receipt_hash, selected_hash)) {
        proof_validate_upstream_hash_clear();
        return true;
    }

    char selected_hex[65] = {0};
    char receipt_hex[65] = "MISSING";
    if (selected_hash)
        uint256_get_hex(selected_hash, selected_hex);
    if (receipt_has_hash && receipt_hash)
        uint256_get_hex(receipt_hash, receipt_hex);
    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d script_validate_log block_hash %.16s != selected "
             "block %.16s..; proof validation holds until script validation "
             "publishes a receipt for the selected branch",
             height, receipt_hex, selected_hex);
    if (blocker_init(&rec, PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID,
                     "proof_validate", BLOCKER_DEPENDENCY, reason)) {
        snprintf(rec.escape_action, sizeof(rec.escape_action),
                 "re-run script_validate for selected block hash");
        (void)blocker_set(&rec);
    }
    /* A blocker alone is in-process state: it dies with the node and never
     * reaches the log an operator actually reads. This hold pins
     * proof_validate, and everything downstream behind it, so it has to be
     * legible after the fact. Deduplicated on height — a long hold costs one
     * line, not a flood. */
    static _Atomic int64_t last_noted_h = -1;
    if (atomic_exchange(&last_noted_h, (int64_t)height) != (int64_t)height)
        LOG_WARN("proof_validate", "[proof_validate] %s", reason);
    return false;
}

void proof_validate_upstream_hash_clear(void)
{
    blocker_clear(PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID);
}

job_result_t proof_validate_upstream_verdict_refuse(
    struct stage_step_ctx *ctx, int height, int verdict)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d script_validate_log ok=%d is outside canonical "
             "{0,1}; proof validation holds until script validation "
             "re-publishes an exact typed verdict",
             height, verdict);
    if (!ctx)
        return JOB_FATAL;
    if (!blocker_init(&ctx->blocker,
            PROOF_VALIDATE_INVALID_UPSTREAM_BLOCKER_ID, "proof_validate",
            BLOCKER_DEPENDENCY, reason))
        return JOB_FATAL;
    snprintf(ctx->blocker.escape_action, sizeof(ctx->blocker.escape_action),
             "re-run script_validate for selected block hash");
    ctx->blocker.retry_budget = -1;
    return JOB_BLOCKED;
}

void proof_validate_upstream_verdict_clear(void)
{
    blocker_clear(PROOF_VALIDATE_INVALID_UPSTREAM_BLOCKER_ID);
}

job_result_t proof_validate_upstream_evidence_refuse(
    struct stage_step_ctx *ctx, int height,
    enum mint_validation_evidence expected,
    enum mint_validation_evidence got)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d script_validate_log success evidence=%s, expected=%s; "
             "proof validation holds instead of crossing validation profiles",
             height, mint_validation_evidence_status(got),
             mint_validation_evidence_status(expected));
    if (!ctx || !blocker_init(&ctx->blocker,
            PROOF_VALIDATE_UPSTREAM_EVIDENCE_BLOCKER_ID, "proof_validate",
            BLOCKER_DEPENDENCY, reason))
        return JOB_FATAL;
    snprintf(ctx->blocker.escape_action, sizeof(ctx->blocker.escape_action),
             "resume the matching offline producer or replay script_validate");
    ctx->blocker.retry_budget = -1;
    return JOB_BLOCKED;
}

void proof_validate_upstream_evidence_clear(void)
{
    blocker_clear(PROOF_VALIDATE_UPSTREAM_EVIDENCE_BLOCKER_ID);
}
