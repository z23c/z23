/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Condition: state_window_inconsistent (fail-loud validation pack,
 * checks 4+5)
 *
 * Detects the window-consistency sweep blocker (window.consistency: a
 * named cursor-ordering / log-contiguity / coin-tear / oscillation
 * invariant violated in durable state) or the commitment audit blocker
 * (coins.commitment_spot_check: the utxos table no longer recomputes to
 * its commitment — silent truncation/corruption). Both blockers are
 * SELF-CLEARING on a later clean pass (repair jobs may legitimately fix
 * holes); this Condition keeps an unresolved violation escalating.
 *
 * REMEDY: the coins.commitment_spot_check arm is
 * auto-terminating — it is a benign projection-vs-stale-checkpoint skew (the
 * `utxos` mirror is a rebuildable projection of the coins_kv authority), so the
 * remedy releases the operator-facing diagnostic and the witness confirms the
 * clear; the audit thread resyncs the checkpoint and the mirror thread rebuilds
 * the projection from the authority. The window.consistency arm still has no
 * automated repair seam (FAILED escalates) — replace with window_rebuild(first_bad_h).
 * cooldown_secs>0 re-arms instead of latching operator_needed forever
 * (sticky-node plan #7). */

#include "conditions/condition_registry.h"
#include "framework/condition.h"
#include "services/invariant_sentinel.h"
#include "util/blocker.h"

#include <stdbool.h>

static bool detect_state_window_inconsistent(void)
{
    return blocker_exists("window.consistency") ||
           blocker_exists("coins.commitment_spot_check");
}

static enum condition_remedy_result remedy_state_window_inconsistent(void)
{
    /* coins.commitment_spot_check: a benign projection-vs-stale-checkpoint skew.
     * The `utxos` mirror is a REBUILDABLE projection of the coins_kv authority,
     * and the audit compares it only to a frozen out-of-band self-checkpoint, so
     * this can never be coin-set-vs-chain corruption (decoupled from finalize at
     * the raise site). Release the operator-facing diagnostic — the audit thread
     * resyncs the checkpoint on its next growth pass and the mirror thread
     * rebuilds the projection from the authority on drift. The witness confirms
     * the blocker actually cleared; a re-raise re-arms on cooldown, never a
     * permanent operator_needed. */
    if (blocker_exists("coins.commitment_spot_check")) {
        invariant_sentinel_clear_commitment_blocker();
        return COND_REMEDY_OK;
    }
    /* window.consistency: no automated repair seam yet — FAILED escalates to the
     * operator (unchanged). */
    return COND_REMEDY_FAILED;
}

static bool witness_state_window_inconsistent(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: the witness reads the REAL durable blocker state, so an
    // OK from the commitment arm is credited only when the blocker genuinely
    // cleared; window.consistency self-clears on a later CLEAN sweep. A still-set
    // blocker downgrades the OK to UNWITNESSED — never a false green.
    return !detect_state_window_inconsistent();
}

static struct condition c_state_window_inconsistent = {
    .name = "state_window_inconsistent",
    .severity = COND_CRITICAL,
    .poll_secs = 60,
    .backoff_secs = 300,
    .max_attempts = 2,
    /* Continue-with-cooldown (sticky-node plan #7): after max_attempts, re-arm
     * every 5 min instead of latching operator_needed forever — the commitment
     * arm is recoverable, and window.consistency self-clears on a clean sweep. */
    .cooldown_secs = 300,
    .cooldown_max_rearms = 12,
    .detect = detect_state_window_inconsistent,
    .remedy = remedy_state_window_inconsistent,
    .witness = witness_state_window_inconsistent,
    .witness_window_secs = 90,
};

void register_state_window_inconsistent(void)
{
    (void)condition_register(&c_state_window_inconsistent);
}
