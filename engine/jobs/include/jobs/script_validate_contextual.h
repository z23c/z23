/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_contextual — the #26 at-tip contextual gate, extracted
 * from script_validate_stage.c along the step seam (E1 file-size ceiling).
 *
 * The c23 analogue of zclassicd AcceptBlock → ContextualCheckBlock
 * (main.cpp:4203): per-tx contextual rules (Overwinter expiry, NU version
 * gating, pre-Sapling oversize), per-tx finality (header-time cutoff) and
 * BIP34 coinbase height — run against a block body BEFORE script
 * verification and the downstream coins commit. Fires only near the live
 * finalized tip (tip-proximity window + IBD latch + sparse-tail skip), so
 * historical replay is byte-identical to zclassicd's own IBD short-circuit.
 */
#ifndef JOBS_SCRIPT_VALIDATE_CONTEXTUAL_H
#define JOBS_SCRIPT_VALIDATE_CONTEXTUAL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct block_index;
struct block;

/* Gate verdict for one block at one height. The gate never frees blk;
 * the caller owns it on every verdict. */
enum script_validate_ctx_verdict {
    SV_CTX_PASS,        /* gate closed or block passed — proceed to verify */
    SV_CTX_WAIT_PARAMS, /* zk params still loading — recoverable, JOB_IDLE */
    SV_CTX_REJECTED,    /* ok=0 row written; advance cursor (JOB_ADVANCED) */
    SV_CTX_FATAL,       /* log insert failed — JOB_FATAL */
};

/* Runs the #26 gate. On SV_CTX_REJECTED, *out_internal tells the caller
 * whether the reject was a transient infra failure persisted under the
 * resurrectable "internal_error" status (caller counts it in its own
 * internal_error total) or a final consensus verdict (counted here in
 * the contextual reject total). */
enum script_validate_ctx_verdict script_validate_contextual_gate(
    struct main_state *ms, sqlite3 *db, int next_h,
    const struct block_index *bi, const struct block *blk,
    bool *out_internal);

/* Final consensus contextual rejects (excludes internal_error rejects). */
uint64_t script_validate_contextual_reject_total(void);

/* Reset counters (stage shutdown / test hygiene). */
void script_validate_contextual_counters_reset(void);

#endif /* JOBS_SCRIPT_VALIDATE_CONTEXTUAL_H */
