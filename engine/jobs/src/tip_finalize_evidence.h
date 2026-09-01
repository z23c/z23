/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Declare fail-closed serving-evidence checks for tip finalization. */
#ifndef ZCL_JOBS_TIP_FINALIZE_EVIDENCE_H
#define ZCL_JOBS_TIP_FINALIZE_EVIDENCE_H

#include "core/uint256.h"
#include "jobs/mint_skip_crypto.h"
#include "util/stage.h"

struct sqlite3;

/* 1 = exact verified script+proof receipts for this block, 0 = mismatch or
 * absence, -1 = store error. Checkpoint-fold evidence is never finalizable. */
int tip_finalize_full_evidence_at(struct sqlite3 *db, int height,
                                  const struct uint256 *block_hash);
int tip_finalize_script_evidence_at(struct sqlite3 *db, int height,
                                    const struct uint256 *block_hash);
int tip_finalize_trusted_anchor_at(struct sqlite3 *db, int height,
                                   const struct uint256 *block_hash);
job_result_t tip_finalize_evidence_refuse(
    struct stage_step_ctx *ctx, int height,
    enum mint_validation_evidence utxo_evidence);
void tip_finalize_evidence_clear(void);

#endif /* ZCL_JOBS_TIP_FINALIZE_EVIDENCE_H */
