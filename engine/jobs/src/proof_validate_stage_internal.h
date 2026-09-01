/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sibling-private declarations shared between proof_validate_stage.c (the Job
 * state owner) and proof_validate_stage_dump.c (the read-only dump-state JSON
 * dump). Not a public header.
 */

#ifndef ZCL_JOBS_PROOF_VALIDATE_STAGE_INTERNAL_H
#define ZCL_JOBS_PROOF_VALIDATE_STAGE_INTERNAL_H

#include "jobs/mint_skip_crypto.h"
#include "util/stage.h"

#include <stdbool.h>
#include <stdint.h>

struct uint256;

stage_t *proof_validate_stage_handle(void);
int64_t proof_validate_stage_last_step_unix(void);
int64_t proof_validate_stage_last_blocked_unix(void);
int64_t proof_validate_stage_last_advance_height(void);

bool proof_validate_upstream_hash_ready(
    int height, const struct uint256 *selected_hash, bool receipt_has_hash,
    const struct uint256 *receipt_hash);
void proof_validate_upstream_hash_clear(void);
job_result_t proof_validate_upstream_verdict_refuse(
    struct stage_step_ctx *ctx, int height, int verdict);
void proof_validate_upstream_verdict_clear(void);
job_result_t proof_validate_upstream_evidence_refuse(
    struct stage_step_ctx *ctx, int height,
    enum mint_validation_evidence expected,
    enum mint_validation_evidence got);
void proof_validate_upstream_evidence_clear(void);

#endif /* ZCL_JOBS_PROOF_VALIDATE_STAGE_INTERNAL_H */
