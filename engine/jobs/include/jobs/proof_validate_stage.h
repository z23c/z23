/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate_stage — reducer Job stage.
 *
 * Consumes `script_validate_log`; for each height where script validation
 * passed, verifies shielded proofs and Sapling binding signatures, then logs
 * the result. */

#ifndef ZCL_SERVICES_PROOF_VALIDATE_STAGE_H
#define ZCL_SERVICES_PROOF_VALIDATE_STAGE_H

#include "core/uint256.h"
#include "jobs/stage_helpers.h"
#include "util/stage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID \
    "proof_validate.stale_upstream_hash"
#define PROOF_VALIDATE_INVALID_UPSTREAM_BLOCKER_ID \
    "proof_validate.invalid_upstream_verdict"
#define PROOF_VALIDATE_UPSTREAM_EVIDENCE_BLOCKER_ID \
    "proof_validate.upstream_evidence_mode"

struct block;
struct block_index;
struct json_value;
struct main_state;
struct transaction;

#define PROOF_VALIDATE_BATCH_PER_TICK 100

struct proof_validate_tx_report {
    bool ok;
    bool internal_error;
    size_t sapling_spends_total;
    size_t sapling_outputs_total;
    size_t sprout_joinsplits_total;
    const char *first_failure_proof_type;
};

/* Alias onto the shared stage reader type (jobs/stage_helpers.h); the public
 * setter name proof_validate_stage_set_reader is unchanged. */
typedef stage_block_reader_fn proof_validate_reader_fn;

typedef bool (*proof_validate_tx_verify_fn)(
    const struct transaction *tx,
    int height,
    struct proof_validate_tx_report *out,
    void *user);

bool proof_validate_stage_init(struct main_state *ms);
void proof_validate_stage_shutdown(void);

job_result_t proof_validate_stage_step_once(void);
int proof_validate_stage_drain(int max_steps);

uint64_t proof_validate_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  proof_validate_stage_step_us_ewma(void);
uint64_t proof_validate_stage_verified_total(void);
uint64_t proof_validate_stage_proof_invalid_total(void);
uint64_t proof_validate_stage_internal_error_total(void);
uint64_t proof_validate_stage_upstream_failed_total(void);

uint64_t proof_validate_stage_sapling_spends_verified_total(void);
uint64_t proof_validate_stage_sapling_spends_failed_total(void);
uint64_t proof_validate_stage_sapling_outputs_verified_total(void);
uint64_t proof_validate_stage_sapling_outputs_failed_total(void);
uint64_t proof_validate_stage_sprout_groth16_verified_total(void);
uint64_t proof_validate_stage_sprout_groth16_failed_total(void);
uint64_t proof_validate_stage_sprout_phgr13_verified_total(void);
uint64_t proof_validate_stage_sprout_phgr13_failed_total(void);
uint64_t proof_validate_stage_binding_sig_verified_total(void);
uint64_t proof_validate_stage_binding_sig_failed_total(void);

void proof_validate_stage_set_reader(proof_validate_reader_fn fn, void *user);
void proof_validate_stage_set_tx_verifier(proof_validate_tx_verify_fn fn,
                                          void *user);

/* Cross-height proof pre-verification pool (jobs/pv_lookahead.h): start/stop
 * the pool bound to this stage's exact (main_state, datadir, reader, verifier)
 * tuple. Production callers of the start are engine/composition/src/boot_mint_anchor.c
 * (the offline -mint-anchor fold) and engine/composition/src/boot_pv_lookahead.c (the
 * live/replay path, only under -pv-lookahead, default off). A not-started pool
 * leaves the verify path unchanged: take is a single atomic-load miss and the
 * step verifies inline. Stop is idempotent and also runs in stage shutdown. */
bool proof_validate_lookahead_start(void);
void proof_validate_lookahead_stop(void);

bool proof_validate_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_PROOF_VALIDATE_STAGE_H */
