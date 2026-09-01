/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal seam: startup reconcile + active-tip evidence reconstruction
 * (the recovery half of the chain evidence controller). Implemented in
 * chain_evidence_reconstruct.c; called only by the controller's init
 * path. Not part of the public service API.
 */

#ifndef ZCL_SERVICES_CHAIN_EVIDENCE_RECONSTRUCT_H
#define ZCL_SERVICES_CHAIN_EVIDENCE_RECONSTRUCT_H

#include "services/chain_evidence_authority_service.h"

/* Startup reconciliation of the persisted evidence keys against the
 * in-memory active tip. Runs at most ONCE per process lifetime: the
 * controller is constructed by every health probe / condition poll /
 * diagnostics dump, and re-running the reconcile per construction re-fired
 * identical drift warnings forever at a held tip. The once-guard is claimed
 * only when a real tip is visible, so an early empty-view construction
 * cannot consume the only run. Freezes (with a named reason) only when the
 * tip genuinely cannot be proven; lifts a stale persisted freeze when it
 * can — including when a higher persisted tip refuses the rewind
 * persist-update. */
void cec_reconcile_startup(struct chain_evidence_controller *authority);

/* chain_evidence_request_startup_reconcile (the runtime re-arm of the
 * once-guard) is declared in services/chain_evidence_authority_service.h
 * — it is a public surface (band closure + tests), not an init seam. */

/* Reconstruct publishable LOCAL_IMPORT evidence for a hash-consistent
 * active tip recovered from disk. Recomputes ancestry/chainwork when
 * recoverable; returns true and persists the evidence (idempotently — a
 * persisted record already equal to the reconstruction skips the
 * rewrites). With drift_refused (the caller refused to rewind a HIGHER
 * persisted tip) the proof still runs but NOTHING is persisted, so a
 * downward tip is never written. On a genuine contradiction returns false
 * and fills reason_out (always non-empty) with the precise invariant that
 * failed, so the caller can freeze with a named reason. */
bool cec_reconstruct_active_tip_evidence(
    struct chain_evidence_controller *authority,
    struct block_index *active_tip,
    const struct chain_state_view *csv,
    bool drift_refused,
    char reason_out[192]);

#endif /* ZCL_SERVICES_CHAIN_EVIDENCE_RECONSTRUCT_H */
