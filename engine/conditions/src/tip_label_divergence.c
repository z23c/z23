/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Condition: tip_label_divergence (fail-loud validation pack, checks 1+2)
 *
 * Detects the HOLD latch raised by the per-connect linkage check
 * (chain.linkage_violation) or the coinbase-height label check
 * (chain.coinbase_label_mismatch): OUR height labels diverged from the
 * chain's own structure. The blocker + EV_OPERATOR_NEEDED already fired
 * at detection; this Condition keeps the divergence VISIBLE in the
 * condition engine, `z23 dumpstate`, and health until repaired,
 * and escalates through the engine's attempt ladder.
 *
 * WINDOW_REBUILD TRIGGER SEAM (wired): the remedy consumes the latch's
 * refuse_from_h and re-derives [refuse_from_h, tip] from PoW-verified
 * on-disk bodies via stage_rederive_range() (THE universal re-derive
 * primitive — it rewinds the body-dependent stage cursors + inverse-
 * rewinds coins in one transaction, then the forward fold rewrites the
 * SAME verdicts; consensus-parity-neutral). It then releases the linkage
 * holds so the forward fold re-connects those blocks and re-runs the O(1)
 * linkage/coinbase-label checks: a genuinely repaired label passes and
 * stays clear; a persistent divergence RE-RAISES the hold+blocker at the
 * first offending connect, which the witness reads as still-present. The
 * repair is bounded (max_attempts) and loud (WARN + EV_RECOVERY_ACTION);
 * an LCC refusal or a store error escalates to the operator. */

#include "conditions/condition_registry.h"
#include "framework/condition.h"
#include "jobs/rewind_driver.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chain_linkage_check.h"
#include "event/event.h"

#include <stdbool.h>
#include <stdint.h>

static bool detect_tip_label_divergence(void)
{
    return blocker_exists("chain.linkage_violation") ||
           blocker_exists("chain.coinbase_label_mismatch");
}

static enum condition_remedy_result remedy_tip_label_divergence(void)
{
    /* WINDOW_REBUILD TRIGGER SEAM, routed through the ONE generic recovery
     * driver: rewind to the NEAREST SELF-VERIFIED base at or below the linkage
     * hold's refuse_from height, re-derive forward to H* (O(delta) from a
     * sovereign rung, never a full-chain redo), then release the linkage holds
     * so the forward fold re-runs the O(1) linkage/coinbase-label checks. The
     * driver owns base selection, the LCC-safe rewind, and the escalate-once
     * naming; this remedy owns only the trigger-specific hold release. */
    int refuse_from = chain_linkage_hold_refuse_from();
    if (refuse_from < 0) {
        /* The blocker is present but no hold latch carries a refuse_from height
         * (the production raiser chain_linkage_hold_raise always sets both, so
         * this is either a test-injected bare blocker or a lingering blocker
         * whose hold was cleared out-of-band). Without a refuse_from there is no
         * rebuild window to open — report FAILED so the engine escalates rather
         * than pretend a repair we could not attempt. */
        LOG_WARN("tip_label_divergence",
                 "[tip_label_divergence] window_rebuild: blocker present but no "
                 "linkage hold latch carries a refuse_from height — cannot "
                 "locate a rebuild window, escalating");
        return COND_REMEDY_FAILED;
    }

    struct rewind_driver_result rr = {0};
    if (!rewind_to_nearest_self_verified_base(
            (int32_t)refuse_from, "tip_label_divergence",
            "tip_label_divergence.rewind_refused", &rr)) {
        /* Hard store error (progress db / H* unavailable). NOT LOG_FAIL: that
         * macro returns and would be read as a value; return the typed FAILED
         * so the engine escalates. */
        LOG_WARN("tip_label_divergence",
                 "[tip_label_divergence] window_rebuild: driver hit a store "
                 "error re-deriving from refuse_from=%d — escalating",
                 refuse_from);
        return COND_REMEDY_FAILED;
    }
    if (rr.escalated) {
        /* LCC refusal or no reachable self-verified base — the driver already
         * named the typed blocker. This class needs a refold-from-anchor (or
         * operator); the in-place re-derive cannot open the window. */
        LOG_WARN("tip_label_divergence",
                 "[tip_label_divergence] window_rebuild: driver escalated "
                 "(refuse_from=%d base=%s@%d hstar=%d) — refold-from-anchor / "
                 "operator", refuse_from, rr.base_kind, (int)rr.base_height,
                 (int)rr.hstar);
        return COND_REMEDY_FAILED;
    }

    /* Rewind committed (or nothing to do — the self-verified base already sits
     * at/above H*): release the linkage holds so the forward fold re-connects
     * those blocks and re-runs the O(1) linkage/coinbase-label checks. A
     * genuinely repaired label stays clear; a persistent divergence re-raises
     * the hold+blocker at the first offending connect, which the witness reads
     * as still-present (UNWITNESSED) — the engine escalates. */
    LOG_WARN("tip_label_divergence",
             "[tip_label_divergence] window_rebuild: re-derived from "
             "self-verified base %s@%d to H*=%d (refuse_from=%d rewound=%d "
             "coins_rewound=%d) — releasing linkage holds for the forward "
             "re-fold re-check", rr.base_kind, (int)rr.base_height,
             (int)rr.hstar, refuse_from, (int)rr.rewound,
             (int)rr.coins_rewound);
    chain_linkage_hold_clear("linkage");
    chain_linkage_hold_clear("coinbase_label");
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=tip-label-window-rebuild base=%s base_h=%d hstar=%d "
                "refuse_from=%d rewound=%d coins_rewound=%d", rr.base_kind,
                (int)rr.base_height, (int)rr.hstar, refuse_from,
                (int)rr.rewound, (int)rr.coins_rewound);
    return COND_REMEDY_OK;
}

static bool witness_tip_label_divergence(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: the remedy triggers a REAL repair — it re-derives
    // [refuse_from, tip] from on-disk bodies and releases the linkage holds so
    // the forward fold re-runs the O(1) linkage/coinbase-label checks. Those
    // checks RE-RAISE the PERMANENT blocker at the first still-divergent connect,
    // so a blocker read as absent here means the re-fold re-connected the range
    // cleanly (a true "divergence actually repaired"), and a still-present
    // blocker downgrades the OK to UNWITNESSED. The remedy never deletes the
    // blocker except via chain_linkage_hold_clear, which only opens the door for
    // the re-check to re-raise — this is not poison-absence we manufactured.
    return !detect_tip_label_divergence();
}

static struct condition c_tip_label_divergence = {
    .name = "tip_label_divergence",
    .severity = COND_CRITICAL,
    .poll_secs = 60,
    .backoff_secs = 300,
    .max_attempts = 2,
    .detect = detect_tip_label_divergence,
    .remedy = remedy_tip_label_divergence,
    .witness = witness_tip_label_divergence,
    .witness_window_secs = 60,
};

void register_tip_label_divergence(void)
{
    (void)condition_register(&c_tip_label_divergence);
}
