/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_observe — sibling-private observability helpers for
 * utxo_apply_stage.c. These helpers own warning/reject dedup memos and touch
 * only counters/blockers; they do not author consensus state. */

#ifndef ZCL_JOBS_UTXO_APPLY_STAGE_OBSERVE_H
#define ZCL_JOBS_UTXO_APPLY_STAGE_OBSERVE_H

#include "jobs/mint_skip_crypto.h"
#include "util/stage.h"

#include <stdatomic.h>
#include <stdint.h>

struct uint256;

void utxo_apply_reject_count_and_emit(int height, const char *status,
                                      _Atomic uint64_t *counter,
                                      const char *label);
void utxo_apply_reject_memo_clear(void);

void utxo_apply_upstream_hole_note(int height, uint64_t pv_cursor);
void utxo_apply_upstream_hole_healed(int height);

job_result_t utxo_apply_label_splice_refuse(struct stage_step_ctx *c,
                                            int height,
                                            const char *verdict_source,
                                            const struct uint256 *applying,
                                            const struct uint256 *verdict);
void utxo_apply_label_splice_healed(int height);

job_result_t utxo_apply_evidence_refuse(
    struct stage_step_ctx *c, int height,
    enum mint_validation_evidence expected,
    enum mint_validation_evidence proof,
    enum mint_validation_evidence script);
void utxo_apply_evidence_clear(void);

void utxo_apply_progress_note(int applied_height, uint64_t next_cursor);
void utxo_apply_observe_reset(void);

#endif /* ZCL_JOBS_UTXO_APPLY_STAGE_OBSERVE_H */
