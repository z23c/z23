/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_verify — block-level ECDSA script verification for the
 * script_validate reducer stage, in two verdict-identical modes.
 *
 * The per-input verify_script sweep is order-independent (each input reads its
 * own script_sig + resolved prevout + read-only tx/txdata; the C verify path
 * has no signature cache and no shared mutable state), so the parallel mode
 * fans the inputs of a SINGLE block across a supervised worker pool
 * (validate_work_pool) and then REDUCES the per-input results in original
 * (tx, vin) order. The reduce reproduces the serial sweep exactly: the same
 * stop-at-first-failure verdict, the same first-failing (txid, vin), the same
 * ScriptError, and the same reached-input counts. Prevout resolution stays
 * strictly serial in the build phase, so any in-order resolver dependency is
 * preserved and only the pure verify_script work runs concurrently.
 *
 * The serial and parallel entry points share one summary type; a test drives
 * both over the same fixtures and asserts byte-identical summaries. */

#ifndef ZCL_JOBS_SCRIPT_VALIDATE_VERIFY_H
#define ZCL_JOBS_SCRIPT_VALIDATE_VERIFY_H

#include "jobs/script_validate_stage.h"

#include "core/uint256.h"
#include "primitives/block.h"
#include "script/script_error.h"

#include <stdbool.h>
#include <stddef.h>

struct script_verify_summary {
    int ok;
    int internal_error;       /* umbrella: block_decode OR prevout_unresolved */
    size_t tx_count;
    size_t input_count;       /* inputs that reached verify_script */
    /* Reached-input tallies, computed in original order up to the first
     * failure — the caller folds these into the stage's global atomics only
     * when it is the live counting pass (never on a dry run). */
    size_t inputs_verified;
    size_t inputs_failed;     /* 0 or 1 (serial stops at the first bad input) */
    struct uint256 first_failure_txid;
    int first_failure_vin;
    ScriptError first_failure_serror;
    char reason[128];
};

void script_verify_summary_init(struct script_verify_summary *s);

/* Verify every input of `blk` at `height`. `resolver_default`/`user` and the
 * `override_*` pair carry the same resolver-selection contract the stage used
 * inline (override wins; else resolver_default; else the created-index resolver
 * seeded with a per-block view). When `parallel` is true the pure verify_script
 * work fans across the shared pool (falling back to the serial sweep on any
 * pool/alloc failure — verdict-identical); when false it runs the serial
 * in-order sweep. Either way `out` is filled identically. */
void script_verify_block(const struct block *blk, int height,
                         script_validate_prevout_fn resolver_default,
                         void *resolver_default_user,
                         script_validate_prevout_fn override_prevout,
                         void *override_user,
                         bool parallel,
                         struct script_verify_summary *out);

/* Stop + join the shared script-verify worker pool (called from stage
 * shutdown and test teardown). Idempotent. */
void script_verify_pool_shutdown(void);

#ifdef ZCL_TESTING
/* Test-only: force the input-count threshold below which script_verify_block's
 * parallel path folds serially instead of fanning the worker pool. 0 => always
 * fan (exercise the pool); a large value => always serial; <0 restores the
 * env/default routing. Perf-only — the verdict is identical either way. */
void script_verify_set_parallel_min_inputs_for_test(int v);
#endif

#endif /* ZCL_JOBS_SCRIPT_VALIDATE_VERIFY_H */
