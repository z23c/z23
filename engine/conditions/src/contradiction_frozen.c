/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include "config/runtime.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"

#include <stdio.h>

static enum chain_evidence_controller_state current_state(void)
{
    struct chain_evidence_controller cec;
    chain_evidence_controller_init(&cec, app_runtime_node_db(), csr_instance());
    return chain_evidence_controller_load_state(&cec);
}

static bool detect_contradiction_frozen(void)
{
    return current_state() == CEC_CONTRADICTION_FROZEN;
}

static enum condition_remedy_result remedy_contradiction_frozen(void)
{
    /* No automatic repair: a frozen contradiction means the evidence
     * sources disagree and needs operator review, not a blind restore.
     * The reconstruction primitive (cec_reconstruct_active_tip_evidence,
     * engine/services/src/chain_evidence_reconstruct.c) is intentionally
     * not invoked here.
     *
     * Law 7 ("heal in the open, page when stuck"): because this remedy
     * makes NO forward progress, it must report FAILED — not SKIP. A SKIP
     * paired with a pure-inverse witness would let the engine mark the
     * condition "cleared" the instant the contradiction flapped away for
     * an unrelated reason, falsely crediting a no-op remedy. FAILED keeps
     * the attempt counted so it accrues toward operator escalation. */
    LOG_WARN("condition", "[condition:contradiction_frozen] no auto-repair; "
             "operator follow-up required");
    return COND_REMEDY_FAILED;
}

static bool witness_contradiction_frozen(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: remedy returns COND_REMEDY_FAILED (a no-op repair),
    // so the engine can never credit this FSM read as a remedy-caused clear
    // (the Law-7 trap). This read serves the !detected deactivation path.
    /* Witness = "did the contradiction actually leave the frozen state?"
     * This observes the real symptom moving, not the absence of a poison we
     * deleted. The Law-7 honesty fix lives in remedy_contradiction_frozen():
     * it returns FAILED (not SKIP/OK), so the no-op repair can never be
     * credited with a clear. The engine only treats this witness as success
     * AFTER a remedy ran (condition.c: post-remedy re-check), where FAILED
     * means the attempt is counted toward operator escalation rather than
     * marking ok. On the !detected path the engine also consults this witness
     * to deactivate the condition once the contradiction genuinely resolves,
     * so it must remain a truthful read of cec state — never a constant. */
    return current_state() != CEC_CONTRADICTION_FROZEN;
}

static struct condition c_contradiction_frozen = {
    .name = "contradiction_frozen",
    .severity = COND_CRITICAL,
    .poll_secs = 10,
    .backoff_secs = 60,
    .max_attempts = 1,
    .detect = detect_contradiction_frozen,
    .remedy = remedy_contradiction_frozen,
    .witness = witness_contradiction_frozen,
    .witness_window_secs = 60,
};

void register_contradiction_frozen(void)
{
    (void)condition_register(&c_contradiction_frozen);
}
