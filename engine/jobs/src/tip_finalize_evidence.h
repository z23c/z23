/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Declare fail-closed serving-evidence checks for tip finalization. */
#ifndef ZCL_JOBS_TIP_FINALIZE_EVIDENCE_H
#define ZCL_JOBS_TIP_FINALIZE_EVIDENCE_H

#include "core/uint256.h"
#include "jobs/mint_skip_crypto.h"
#include "jobs/tip_finalize_stage.h"
#include "util/stage.h"

struct sqlite3;

int tip_finalize_script_evidence_at(struct sqlite3 *db, int height,
                                    const struct uint256 *block_hash);
int tip_finalize_trusted_anchor_at(struct sqlite3 *db, int height,
                                   const struct uint256 *block_hash);
job_result_t tip_finalize_evidence_refuse(
    struct stage_step_ctx *ctx, int height,
    enum mint_validation_evidence utxo_evidence);
void tip_finalize_evidence_clear(void);

#ifdef ZCL_TESTING
/* WARNs emitted for trusted-anchor metadata mismatches, and a reset of that
 * count plus its throttle. */
uint64_t tip_finalize_trusted_mismatch_warn_count_for_testing(void);
void tip_finalize_trusted_mismatch_reset_for_testing(void);
#endif

#endif /* ZCL_JOBS_TIP_FINALIZE_EVIDENCE_H */
