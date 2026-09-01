/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate_verify — block-level shielded-proof verification for the
 * proof_validate reducer stage, in two verdict-identical modes.
 *
 * Each transaction's shielded proofs (Sapling spend/output Groth16, the binding
 * signature, Sprout Groth16/PHGR13, JoinSplit Ed25519) verify independently of
 * every other tx in the block — each call builds its own Sapling verification
 * context and reads only global, immutable verifying keys — so the parallel
 * mode fans the per-tx verification across a supervised worker pool
 * (validate_work_pool) and then REDUCES the per-tx results in original tx order.
 * The reduce reproduces the serial sweep exactly: the same stop-at-first-failing
 * tx verdict, the same first-failing txid + proof-type, the same accumulated
 * proof totals, and the same per-tx success/failure counter application (routed
 * back to the stage through the on_success / on_failure callbacks in original
 * order).
 *
 * The serial and parallel entry points share one summary type; a test drives
 * both over the same fixtures and asserts byte-identical summaries. */

#ifndef ZCL_JOBS_PROOF_VALIDATE_VERIFY_H
#define ZCL_JOBS_PROOF_VALIDATE_VERIFY_H

#include "jobs/proof_validate_stage.h"

#include "core/uint256.h"
#include "primitives/block.h"

#include <stdbool.h>
#include <stddef.h>

struct proof_verify_summary {
    int ok;
    int internal_error;
    size_t sapling_spends_total;
    size_t sapling_outputs_total;
    size_t sprout_joinsplits_total;
    struct uint256 first_failure_txid;
    const char *first_failure_proof_type;   /* stable literal or verifier's */
};

/* Applied in ORIGINAL tx order during the (serial) reduce, never from a worker,
 * so the stage's counter atomics see exactly the serial-sweep ordering. */
typedef void (*proof_verify_success_cb)(const struct transaction *tx,
                                        const struct proof_validate_tx_report *r,
                                        void *user);
typedef void (*proof_verify_failure_cb)(const char *type, void *user);

void proof_verify_summary_init(struct proof_verify_summary *s);

/* Verify every tx of `blk` at `height`. `verifier`/`verifier_user` is the
 * effective tx verifier (the stage passes its installed override, or NULL to
 * use the built-in real-proof verifier). When `parallel` is true the per-tx
 * verification fans across the shared pool (falling back to the serial sweep on
 * any pool/alloc failure — verdict-identical); when false it runs serially.
 * on_success/on_failure (may be NULL) fire in original order during the reduce. */
void proof_verify_block(const struct block *blk, int height,
                        proof_validate_tx_verify_fn verifier,
                        void *verifier_user,
                        bool parallel,
                        proof_verify_success_cb on_success,
                        proof_verify_failure_cb on_failure,
                        void *cb_user,
                        struct proof_verify_summary *out);

/* True if any tx in the block carries shielded proofs (used by the stage's
 * sapling-params wait gate). */
bool proof_verify_block_has_shielded_proofs(const struct block *blk);

/* Stop + join the shared proof-verify worker pool (stage shutdown / test
 * teardown). Idempotent. */
void proof_verify_pool_shutdown(void);

#ifdef ZCL_TESTING
/* Test-only: force the shielded-tx-count threshold below which
 * proof_verify_block's parallel path folds serially instead of fanning the
 * worker pool. 0 => always fan (exercise the pool); a large value => always
 * serial; <0 restores the env/default routing. Perf-only — the verdict is
 * identical either way. */
void proof_verify_set_parallel_min_shielded_for_test(int v);
#endif

#endif /* ZCL_JOBS_PROOF_VALIDATE_VERIFY_H */
