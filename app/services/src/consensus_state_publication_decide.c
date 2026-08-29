/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The pure publication CAS decision: assert each receipt is complete
 * and self-bound, then emit one ADMIT/typed-refusal record. Total over its
 * inputs — no I/O, no node state, no allocation (E1 file-size split out of
 * consensus_state_publication_cas.c). */

// one-result-type-ok:pure-total-decision — every surface here is a TOTAL
// predicate or a void decision writer over caller-owned inputs; nothing in
// this file can fail in a way that needs struct zcl_result.

#include "services/consensus_state_publication_cas.h"

#include "consensus_state_publication_cas_internal.h"
#include "config/consensus_state_snapshot_install.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool digest_nonzero(const uint8_t d[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= d[i];
    return any != 0;
}

/* Re-derive the manifest's own artifact digest and assert the complete/self-
 * bound shape the chain binder and exporter both require. Pure. */
static bool manifest_complete_self_bound(
    const struct consensus_state_bundle_manifest *m)
{
    if (!m || m->height < 0 || !m->history_complete || !m->source_clean ||
        m->activation_boundary != 0 || m->sprout_source_cursor != 0 ||
        m->sapling_source_cursor != 0 || m->nullifier_source_cursor != 0 ||
        m->source_fold_cursor != (int64_t)m->height + 1 ||
        m->sapling_frontier_height < 0 ||
        m->sapling_frontier_height > m->height ||
        (m->validation_profile != CONSENSUS_STATE_VALIDATION_FULL &&
         m->validation_profile != CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) ||
        !digest_nonzero(m->block_hash) ||
        !digest_nonzero(m->sapling_frontier_root) ||
        !digest_nonzero(m->proof_manifest_digest) ||
        !digest_nonzero(m->source_digest) ||
        !digest_nonzero(m->artifact_digest))
        return false;
    uint8_t computed[32];
    consensus_state_bundle_artifact_digest(m, computed);
    return memcmp(computed, m->artifact_digest, 32) == 0;
}

/* Publication-safe producer receipt: completed source capture, recomputed
 * epoch + receipt digests, a serving profile, and fold cursor bound to H+1.
 * Pure. */
static bool source_receipt_self_consistent(
    const struct consensus_state_source_receipt *r, int32_t bundle_height)
{
    /* V1 remains decodable for historical inspection, but its Git-SHA-1-
     * derived claim is never publication authority. */
    if (r->schema_version != CONSENSUS_STATE_SOURCE_RECEIPT_V2 ||
        !r->source_clean ||
        !digest_nonzero(r->source_epoch_digest) ||
        !digest_nonzero(r->source_tree_root) ||
        !digest_nonzero(r->toolchain_digest) ||
        !digest_nonzero(r->build_inputs_digest) ||
        !digest_nonzero(r->chain_corpus_digest) ||
        !digest_nonzero(r->receipt_digest) ||
        !consensus_state_source_receipt_commit_valid(
            r->schema_version, r->producer_commit,
            strnlen(r->producer_commit, sizeof(r->producer_commit))) ||
        r->validation_profile != CONSENSUS_STATE_VALIDATION_FULL ||
        r->fold_cursor != (int64_t)bundle_height + 1)
        return false;
    uint8_t epoch[32];
    uint8_t receipt[32];
    consensus_state_source_epoch_digest(r, epoch);
    consensus_state_source_receipt_digest(r, receipt);
    return memcmp(epoch, r->source_epoch_digest, 32) == 0 &&
           memcmp(receipt, r->receipt_digest, 32) == 0;
}

/* ── the pure decision ────────────────────────────────────────────────── */
static void set_reason(struct consensus_state_publication_decision_record *out,
                       const char *msg)
{
    snprintf(out->reason, sizeof(out->reason), "%s", msg);
}

static void finish(struct consensus_state_publication_decision_record *out,
                   enum consensus_state_publication_decision decision,
                   enum consensus_state_publication_refusal refusal,
                   const char *msg)
{
    out->decision = decision;
    out->refusal = refusal;
    set_reason(out, msg);
    (void)consensus_state_publication_decision_digest(out,
                                                      out->decision_digest);
}

void consensus_state_publication_cas_decide(
    const struct consensus_state_publication_cas_inputs *in,
    struct consensus_state_publication_decision_record *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!in) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_NULL_INPUT,
               "no inputs provided");
        return;
    }

    /* Copy every observed identity into the record up front so a refusal still
     * binds what it saw (and the frontier is always bound for staleness). */
    memcpy(out->artifact_receipt_digest, in->artifact_receipt_digest, 32);
    memcpy(out->chain_evidence_digest, in->chain_evidence_digest, 32);
    memcpy(out->source_receipt_digest, in->source_receipt.receipt_digest, 32);
    memcpy(out->source_epoch_digest, in->source_receipt.source_epoch_digest,
           32);
    out->bundle_height = in->manifest.height;
    memcpy(out->bundle_hash, in->manifest.block_hash, 32);
    out->validation_profile = in->manifest.validation_profile;
    out->target_lane = in->target_lane;
    out->expected_frontier_height = in->frontier_known ? in->frontier_height
                                                       : -1;
    if (in->frontier_known)
        memcpy(out->expected_frontier_hash, in->frontier_hash, 32);

    if (!lane_name(in->target_lane)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_LANE_UNKNOWN,
               "target lane is not a canonical lane tag");
        return;
    }
    if (!manifest_complete_self_bound(&in->manifest)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST,
               "artifact manifest is not complete/self-bound");
        return;
    }
    /* (a) same artifact logical identity: the opaque artifact's logical digest
     * must equal the manifest it exposed. */
    if (!digest_nonzero(in->artifact_logical_digest) ||
        memcmp(in->artifact_logical_digest, in->manifest.artifact_digest,
               32) != 0) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_DIGEST_MISMATCH,
               "artifact logical digest does not match its manifest");
        return;
    }
    /* (b) same artifact file/inode identity + lane: the selected-chain evidence
     * must be bound to THIS artifact receipt digest and target lane. */
    if (!in->chain_evidence_present || !in->chain_bound_to_artifact ||
        !digest_nonzero(in->chain_evidence_digest) ||
        !digest_nonzero(in->artifact_receipt_digest)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH,
               "selected-chain evidence is absent or not bound to this "
               "artifact identity/lane");
        return;
    }
    /* (c) producer source receipt present + self-consistent. */
    if (!in->source_receipt_present) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MISSING,
               "producer source receipt is absent");
        return;
    }
    if (!source_receipt_self_consistent(&in->source_receipt,
                                        in->manifest.height)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED,
               "producer source receipt is malformed, capture-incomplete, "
               "non-serving, or its fold cursor is not bound to H+1");
        return;
    }
    /* same source epoch: the receipt embedded in the artifact (manifest
     * source_digest == source receipt digest) must be exactly this receipt. */
    if (memcmp(in->source_receipt.receipt_digest, in->manifest.source_digest,
               32) != 0) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_SOURCE_ARTIFACT_MISMATCH,
               "source receipt digest does not equal the artifact's bound "
               "source digest");
        return;
    }
    /* Canonical publication is FULL-profile only; a checkpoint-fold state is
     * non-serving evidence. Manifest and receipt must agree. */
    if (in->manifest.validation_profile != CONSENSUS_STATE_VALIDATION_FULL ||
        in->source_receipt.validation_profile !=
            CONSENSUS_STATE_VALIDATION_FULL) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_PROFILE_NOT_SERVING,
               "validation profile is not FULL (non-serving state)");
        return;
    }
    /* CAS frontier binding: ordinary state replacement may not move ahead of
     * durable H*. Two headers-first paths are different: their opaque chain-
     * evidence digest already binds the PoW authority and proves the selected
     * header while the current frontier is still below the bundle —
     *   (a) the compiled-checkpoint path (checkpoint_authority_used), and
     *   (b) the ASSISTED above-checkpoint tier (assisted_authority_used): the
     *       bundle LOCATION + shielded TIP root are PoW-bound in the evidence
     *       even though the CONTENT below the seam is borrowed and the install
     *       lands at the non-sovereign RELEASE_ASSISTED tier.
     * Keep unknown frontiers fail-closed; permit a known, stable below-bundle
     * frontier only when one of those evidence flags is present. */
    if (!in->frontier_known) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN,
               "current durable frontier could not be captured");
        return;
    }
    if (in->frontier_height < in->manifest.height &&
        !in->checkpoint_authority_used && !in->assisted_authority_used) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND,
               "bundle height exceeds the durable node frontier");
        return;
    }
    finish(out, CONSENSUS_PUBLICATION_ADMIT,
           CONSENSUS_PUBLICATION_REFUSAL_NONE,
           "all evidence present and mutually binding");
}
