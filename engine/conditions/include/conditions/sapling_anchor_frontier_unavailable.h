/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_SAPLING_ANCHOR_FRONTIER_UNAVAILABLE_H
#define ZCL_CONDITIONS_SAPLING_ANCHOR_FRONTIER_UNAVAILABLE_H

#include "controllers/shielded_gap_remedy_controller.h" /* enum shielded_gap_kind */

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* Classification of the durable Sapling anchor-history gap, used both by the
 * condition's detect and by the hermetic tests.  Pure over the store. */
enum sapling_anchor_gap_class {
    /* No curable gap: from-genesis store (activation==0), no HISTORY_INCOMPLETE
     * symptom, or a store-read error. */
    SAPLING_ANCHOR_GAP_NONE = 0,
    /* The birth defect: adoption cursor > 0 over an EMPTY anchor table, so the
     * latest-frontier lookup returns HISTORY_INCOMPLETE.  Seed-curable — a
     * header-verified initial frontier resumes the fold. */
    SAPLING_ANCHOR_GAP_EMPTY_TABLE = 1,
    /* Rows exist but a specific below-cursor historical root is absent.  NOT
     * seed-curable: the owner-gated genesis-to-cursor backfill is required. */
    SAPLING_ANCHOR_GAP_HISTORICAL = 2,
};

/* Classify the SAPLING pool's anchor gap from the progress store.  Reentrant;
 * no allocation.  See enum above. */
enum sapling_anchor_gap_class sapling_anchor_frontier_classify(struct sqlite3 *db);

void register_sapling_anchor_frontier_unavailable(void);

/* ── Sovereign shielded-gap self-heal ladder (Move 2a) ──────────────────────
 * The NAMED-REMEDY gap (a genuine below-cursor historical anchor gap and/or a
 * standalone nullifier gap) is healed by a bounded, self-terminating,
 * auto-executing 3-rung ladder that RE-DERIVES proven state or
 * CHECKPOINT-verifies — never forges, borrows-unverified, or relaxes a check:
 *
 *   Rung A  sovereign re-derive from LOCAL block bodies (PREFERRED,
 *           consensus-neutral):
 *             NULLIFIER_ONLY -> the in-process populate-only walker
 *               (nullifier_backfill_service_run), resumable + self-terminating.
 *             ANCHOR / BOTH  -> the from-anchor/genesis refold (arm + supervised
 *               respawn) that recomputes the SAME anchors the fold would. A
 *               Sapling anchor is a CUMULATIVE incremental Merkle tree, so it
 *               cannot be back-filled row-by-row outside a replay session — the
 *               refold IS the sovereign anchor re-derive over local bodies.
 *   Rung B  checkpoint-verified install (bodies absent): arm the durable
 *           install-on-next-boot request against a ROM-matching
 *           <datadir>/bundles/<name>.sqlite via the atomic keystone installer
 *           (fail-closed; rolls back on any anomaly to the safe positive-cursor
 *           wedge). Never invents a parallel cure.
 *   Rung C  self-terminating named need (neither): name the EXACT first missing
 *           body height and let the bounded page fire — never a spin.
 */
enum shielded_selfheal_rung {
    SHIELDED_SELFHEAL_RUNG_NONE = 0,
    SHIELDED_SELFHEAL_RUNG_A_NULLIFIER,  /* nullifier-only gap + local bodies */
    SHIELDED_SELFHEAL_RUNG_A_ANCHOR,     /* anchor gap + reachable refold base */
    SHIELDED_SELFHEAL_RUNG_B_INSTALL,    /* no re-derive base + a bundle present */
    SHIELDED_SELFHEAL_RUNG_C_NAMED_NEED, /* neither: name the exact need */
};

/* Pure rung selection from explicit observations — no IO, unit-testable. */
enum shielded_selfheal_rung shielded_selfheal_select_rung(
    enum shielded_gap_kind gap, bool nullifier_bodies_ok,
    bool anchor_refold_reachable, bool bundle_present);

/* SEPARATE authorization for the SOVEREIGN auto path (Rungs A/B only). DISTINCT
 * from the BORROWED-import containment (shielded_gap_remedy_eval_containment /
 * auto_execute), which stays owner-gated and UNTOUCHED. Returns false only on a
 * throwaway -COPY- copy-prove datadir (where an operator runs the borrowed
 * -import-complete-shielded by hand); true on any live/canonical/soak/dev
 * datadir, where the consensus-neutral re-derive/checkpoint path is safe to
 * auto-run. This TU never references the borrowed importer, so a future edit
 * cannot silently route it through the sovereign door. */
bool shielded_selfheal_sovereign_authorized(void);

/* Compose the exact first-missing named need (Rung C) from the two evidence
 * sources — the nullifier walker's blocked height and the blocks-projection
 * body hole; returns the lowest non-negative, or -1 when neither is known.
 * Pure. */
int64_t shielded_selfheal_named_need(int64_t nullifier_missing,
                                     int64_t body_missing);

#ifdef ZCL_TESTING
/* Zero this condition's module-static episode bookkeeping (at-detect H*,
 * episode kind, at-detect blocker flags, the tier1b borrow-attempt counter,
 * and the remedy-call counter). condition_engine_reset_for_testing() clears
 * the SHARED condition_state atoms; this clears the module's OWN statics —
 * a test must call both between cases. */
void sapling_anchor_frontier_test_reset(void);

/* Number of times remedy_sapling_anchor_frontier() has run since the last
 * sapling_anchor_frontier_test_reset(). */
int sapling_anchor_frontier_test_remedy_calls(void);

/* Number of times the remedy reached the EMPTY_TABLE-first tier1 seed attempt
 * since the last reset — proves the routing order (tier1 before the
 * named-remedy ladder) in dual anchor+nullifier episodes. */
int sapling_anchor_frontier_test_tier1_attempts(void);

/* Force a NAMED_REMEDY episode and reset the .progressing baseline, so the
 * progressing hook can be exercised in isolation (without a full detect/remedy
 * round wiring up an app_runtime db). */
void sapling_anchor_frontier_test_force_named_episode(void);

/* Invoke the registered .progressing hook directly (reads the durable heal
 * cursor from the open progress store). */
bool sapling_anchor_frontier_test_progressing(void);
#endif

#endif /* ZCL_CONDITIONS_SAPLING_ANCHOR_FRONTIER_UNAVAILABLE_H */
