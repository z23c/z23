/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_pv_lookahead — the PRODUCTION wiring for the cross-block shielded-proof
 * pre-verification pool (app/jobs/pv_lookahead.c). The pool itself was already
 * built, supervised, instrumented and differentially tested; until now its only
 * production start was the offline -mint-anchor drive
 * (config/src/boot_mint_anchor.c), so on an ordinary replay the consume hook in
 * proof_validate's step (app/jobs/src/proof_validate_stage.c) ran on every
 * height and missed on every height.
 *
 * Why it belongs on the live path: proof verification is a pure function of
 * (transaction, height). Sprout and Sapling anchors and nullifiers enter
 * default_verify_tx (app/jobs/src/proof_validate_verify.c) as Groth16 PUBLIC
 * INPUTS read straight out of the transaction bytes — there is no
 * commitment-tree lookup. Anchor membership and nullifier double-spend are
 * decided downstream in utxo_apply. So a verdict computed ahead of the fold
 * cursor is the same verdict the serial drive would compute, and the ordering
 * the reducer depends on is untouched: nothing is persisted ahead of the
 * cursor, the step still advances by exactly one height, and the verdict ring
 * is RAM-only.
 *
 * FAIL-SAFE in both directions: a failed start is logged and ignored, and a
 * cache miss verifies inline exactly as today. The pool can cost throughput.
 * It cannot change a verdict — pv_lookahead_take consumes only on an exact
 * (height, 32-byte block hash, verifier pair) match, so a reorg, a verifier
 * swap or a stale slot all fall through to the inline verify.
 *
 * Default OFF: only started when -pv-lookahead was passed (the -prefetch-blocks
 * posture).
 *
 * ORDERING: boot_services.c calls the start beside boot_block_prefetch_start,
 * which is after staged_sync_supervisor_register ran proof_validate_stage_init.
 * That matters — proof_validate_lookahead_start snapshots the stage's
 * (main_state, datadir, reader, verifier) tuple under the stage lock, and an
 * unbound stage would make the start a logged no-op. */

#include "config/boot_internal.h"

#include "jobs/proof_validate_stage.h"   /* proof_validate_lookahead_start/stop */
#include "util/log_macros.h"

#include <stddef.h>

/* Whether this process started the pool, so stop stays a no-op otherwise.
 * proof_validate_stage_shutdown also stops it; both paths are idempotent. */
static bool g_pvla_started = false;

void boot_pv_lookahead_start(const struct app_context *ctx,
                             struct main_state *ms)
{
    if (!ctx || !ctx->pv_lookahead)
        return; /* lever OFF (default) — proof_validate verifies inline as today */
    if (!ms) {
        LOG_WARN("pv_lookahead",
                 "[pv_lookahead] -pv-lookahead set but no main_state; skipping "
                 "(proof_validate verifies inline)");
        return;
    }

    if (!proof_validate_lookahead_start()) {
        LOG_WARN("pv_lookahead",
                 "[pv_lookahead] start failed — proof_validate verifies inline "
                 "(fail-safe)");
        return;
    }
    g_pvla_started = true;
    LOG_INFO("pv_lookahead",
             "[pv_lookahead] cross-block proof pre-verification pool started "
             "(-pv-lookahead)");
}

void boot_pv_lookahead_stop(void)
{
    if (!g_pvla_started)
        return;
    proof_validate_lookahead_stop();
    g_pvla_started = false;
}
