/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_contextual — implementation. See
 * jobs/script_validate_contextual.h for the gate contract and
 * docs/CONSENSUS_PARITY_DOCTRINE.md ("Landed parity fixes" / the
 * rule-to-zclassicd map) and docs/AGENT_TRAPS.md (the IBD/tip-window gating
 * rationale) for the fork-safety analysis behind the gating conditions.
 */

#include "jobs/script_validate_contextual.h"
#include "script_validate_log_store.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "event/event.h"
#include "jobs/tip_finalize_stage.h"
#include "primitives/block.h"
#include "sapling/params_init.h"
#include "script/script_error.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_logic.h"
#include "validation/main_state.h"
#include "validation/process_block.h"

#include <stdatomic.h>
/* <string.h> is gone with the reject-reason strcmp it existed for: the
 * transient-vs-consensus distinction is a type now, not a string match. */

/* Blocks rejected by the at-tip contextual gate (#26): per-tx contextual
 * rules / finality / BIP34 via contextual_check_block before script verify.
 * Excludes internal_error-classified rejects (counted by the stage). */
static _Atomic uint64_t g_contextual_reject_total = 0;

/* Same predicate as proof_validate's static of the same name: any tx with
 * JoinSplits or Sapling spends/outputs needs the zk verification keys. */
static bool block_has_shielded_proofs(const struct block *blk)
{
    if (!blk)
        return false;
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        if (tx->num_joinsplit > 0 || tx->num_shielded_spend > 0 ||
            tx->num_shielded_output > 0)
            return true;
    }
    return false;
}

/* Infra failures inside contextual_check_transaction — transient alloc /
 * sighash plumbing / absent verifying keys, NOT consensus verdicts. They
 * must never persist as a permanent reject: the stale-script-hole repair
 * only resurrects the 'internal_error'/'prevout_unresolved'/
 * 'block_decode_failed' statuses (stage_repair_reducer_frontier_coin.c),
 * so a misclassified transient failure would wedge a valid canonical
 * block forever.
 *
 * This used to be decided by string-comparing reject reasons. That test
 * was silent rot waiting to happen: it enumerated two reason strings by
 * hand, so any new transient failure — or any rewording of an existing
 * one — would have been filed as a permanent consensus reject with no
 * compiler complaint. The distinction is now carried by
 * enum contextual_check_verdict, produced at the site that actually knows
 * which kind of failure occurred. */

enum script_validate_ctx_verdict script_validate_contextual_gate(
    struct main_state *ms, sqlite3 *db, int next_h,
    const struct block_index *bi, const struct block *blk,
    bool *out_internal)
{
    if (out_internal)
        *out_internal = false;

    /* #26 — per-tx contextual block checks: the c23 analogue of zclassicd
     * AcceptBlock → ContextualCheckBlock (main.cpp:4203), which runs BEFORE
     * ConnectBlock/coins commit. Fires only near the live tip:
     *   - tip_h == -1 (unseeded finalized tip, early/cold replay) keeps the
     *     gate CLOSED — without that guard the proximity window would be
     *     always-true at genesis and the history-safety gate defeated;
     *   - next_h far below the finalized tip (historical replay on a
     *     restored datadir with the IBD latch already false) keeps it
     *     closed, structurally reproducing zclassicd's "ContextualCheckBlock
     *     runs at the contemporaneous tip" condition;
     *   - sparse snapshot tails bypass via
     *     process_block_should_skip_contextual_header, mirroring the
     *     contextual-header path.
     * Inside the gate, is_initial_block_download() reproduces zclassicd's
     * ContextualCheckTransaction IBD short-circuit (per-tx rules only;
     * finality + BIP34 always run — see contextual_check_block). */
    const struct chain_params *cp = chain_params_get();
    int64_t tip_h = tip_finalize_stage_last_height();  /* -1 when unseeded */
    const int64_t CTX_TIP_WINDOW = 16;  /* >= max legit pipeline depth */
    if (!cp || !bi || !bi->pprev || tip_h < 0 ||
        next_h < tip_h - CTX_TIP_WINDOW ||
        process_block_should_skip_contextual_header(ms, bi->pprev,
                                                    &cp->consensus))
        return SV_CTX_PASS;

    bool is_ibd = is_initial_block_download(ms);
    /* The !is_ibd branch of contextual_check_block runs FULL shielded
     * verification, which is fail-closed when the zk params are absent
     * (they load in a background boot thread, and boot merely warns on
     * a load failure — boot_services.c). Wait with the same recoverable
     * JOB_IDLE shape proof_validate uses, instead of letting a params
     * race surface as a permanent consensus reject of a valid block. */
    if (!is_ibd && block_has_shielded_proofs(blk) &&
        !sapling_params_loaded())
        return SV_CTX_WAIT_PARAMS;

    struct validation_state cstate;
    validation_state_init(&cstate);
    enum contextual_check_verdict cv =
        contextual_check_block_verdict(blk, &cstate, cp, bi->pprev, is_ibd);
    if (cv == CONTEXTUAL_CHECK_PASS)
        return SV_CTX_PASS;

    const char *reason = cstate.reject_reason[0] ? cstate.reject_reason
                                                 : "contextual-invalid";
    /* Transient infra failures persist under the resurrectable
     * "internal_error" status (repair re-attempts them); genuine
     * consensus verdicts keep their typed reason and stay final. */
    bool internal = (cv == CONTEXTUAL_CHECK_UNVERIFIABLE);
    const char *status = internal ? "internal_error" : reason;
    if (out_internal)
        *out_internal = internal;
    if (!internal)
        atomic_fetch_add(&g_contextual_reject_total, 1);
    LOG_WARN("script_validate",
             "[script_validate] contextual_%s height=%d reason=%s",
             internal ? "internal" : "invalid", next_h, reason);
    event_emitf(EV_BLOCK_REJECTED, 0,
                "script_validate contextual_%s h=%d reason=%s",
                internal ? "internal" : "invalid", next_h, reason);
    /* Hash-stamped ok=0 row → proof_validate ok=0 → utxo_apply
     * JOB_BLOCKED: coins never mutate, tip_finalize stays idle.
     * The hash stamp lets a legitimate replacement block at next_h
     * get a fresh verdict (reorg-safe). Same fail-closed shape as
     * the spend_unknown/value_overflow rejects. */
    if (!script_validate_log_insert(db, next_h, status, false, 0, 0,
                                    NULL, -1, SCRIPT_ERR_OK,
                                    bi->phashBlock)) {
        LOG_WARN("script_validate",
                 "[script_validate] contextual reject log insert FAILED "
                 "height=%d", next_h);
        return SV_CTX_FATAL;
    }
    return SV_CTX_REJECTED;
}

uint64_t script_validate_contextual_reject_total(void)
{
    return atomic_load(&g_contextual_reject_total);
}

void script_validate_contextual_counters_reset(void)
{
    atomic_store(&g_contextual_reject_total, (uint64_t)0);
}
