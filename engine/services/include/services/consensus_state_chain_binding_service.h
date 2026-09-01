/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fail-closed binding of a contained consensus-state bundle to the node's
 * selected, durably validated ZClassic header chain. */

#ifndef ZCL_SERVICES_CONSENSUS_STATE_CHAIN_BINDING_SERVICE_H
#define ZCL_SERVICES_CONSENSUS_STATE_CHAIN_BINDING_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "storage/consensus_state_bundle_codec.h"
#include "util/result.h"

struct main_state;
struct consensus_state_artifact_evidence;
struct consensus_state_chain_evidence;

enum consensus_state_target_lane {
    CONSENSUS_STATE_TARGET_LANE_UNKNOWN = 0,
    CONSENSUS_STATE_TARGET_LANE_COPY_PROOF,
    CONSENSUS_STATE_TARGET_LANE_DEV,
    CONSENSUS_STATE_TARGET_LANE_SOAK,
    CONSENSUS_STATE_TARGET_LANE_CANONICAL,
};

/* Compiled-checkpoint content authority. The compiled SHA3/ROM checkpoint is
 * the sovereignty anchor: its block_hash and Sapling frontier root are baked
 * into the binary and re-derivable by an independent from-genesis fold, so
 * they are a STRONGER trust root than a snapshot-seeded target's materialized
 * block index — which floors ABOVE the checkpoint height and therefore never
 * materializes the checkpoint block or its Sapling source. When a bundle sits
 * at EXACTLY this height and its own block_hash + Sapling frontier match this
 * authority byte-for-byte, the below-checkpoint materialized-index predicates
 * (bundle/sapling-source presence, durable validation, and their ancestry
 * links) are authorized from this content instead of the absent index. Filled
 * by the boot install verb from get_sha3_utxo_checkpoint() (height/block_hash)
 * and get_rom_state_checkpoint() (Sapling frontier root/height); `available`
 * is false when no checkpoint is compiled in, which restores the pure
 * target-derived gate. Bundles at any OTHER height ignore this authority
 * entirely — the gate then stays byte-for-byte as before. The target-derived
 * frontier durability (-3), durable served H* (-4), and the target's own
 * materialized header-tip validity remain enforced regardless. */
struct consensus_state_checkpoint_authority {
    bool available;
    int32_t height;
    uint8_t block_hash[32];
    int32_t sapling_frontier_height;
    uint8_t sapling_frontier_root[32];
};

/* Public only so the fail-closed decision matrix can be tested without a
 * process-global progress store.  This structure is never publication
 * authority: only consensus_state_chain_evidence_build() can create the
 * opaque evidence object, and no publisher currently consumes it. */
struct consensus_state_chain_binding_observation {
    bool before_frontier_consistent;
    bool after_frontier_consistent;
    bool frontier_unchanged;
    int32_t durable_served_height;

    /* Clean-genesis instant-on eligibility (the -3 fresh-genesis-bootstrap
     * relaxation input). True ONLY on a genuinely quiescent PRE-FOLD node:
     * served H* is genesis (0) under a coherent RUNTIME authority (no durable
     * finalization has run because zero bodies folded) AND there is no partial
     * fold state (no durable finalized tip; coins not applied above genesis).
     * A mid-fold / drifted / partial-state node has this false and refuses at -3
     * exactly as before. decide() additionally gates the relaxation on
     * compiled-checkpoint authority (cp_auth), and the -4 header-bootstrap bind
     * (the full-Equihash-PoW crypto anchor) plus the -11 header-tip validity
     * remain fully enforced — this field ONLY relaxes -3's durable-frontier gate,
     * never the crypto anchor. Collected by consensus_state_chain_evidence_build
     * from the two frontier samples + the durable tip / coins frontier. */
    bool fresh_genesis_bootstrap;

    bool selected_bundle_known;
    int32_t selected_bundle_height;
    uint8_t selected_bundle_hash[32];
    bool selected_bundle_valid_scripts;
    bool selected_bundle_failure_free;
    bool bundle_header_pass_record;

    bool selected_sapling_source_known;
    int32_t selected_sapling_source_height;
    uint8_t selected_sapling_source_hash[32];
    bool selected_sapling_source_valid_scripts;
    bool selected_sapling_source_failure_free;
    bool sapling_source_header_pass_record;
    uint8_t selected_sapling_source_root[32];
    uint8_t selected_bundle_sapling_root[32];

    bool selected_header_known;
    int32_t selected_header_height;
    uint8_t selected_header_hash[32];
    uint8_t selected_header_chainwork[32];
    bool selected_header_valid_tree;
    bool selected_header_failure_free;
    bool header_descends_from_bundle;
    bool bundle_descends_from_sapling_source;

    /* Compiled-checkpoint content authority carried through from the request.
     * When it authorizes (see consensus_state_checkpoint_authority above and
     * consensus_state_chain_binding_uses_checkpoint_authority), the decision
     * satisfies the below-checkpoint materialized-index predicates from this
     * content. Constant across the before/after chain samples, so it does not
     * perturb the frontier-unchanged byte comparison. */
    struct consensus_state_checkpoint_authority checkpoint_authority;

    /* Assisted ABOVE-checkpoint admission opt-in, carried through from the
     * request (request->allow_assisted_above_checkpoint). When true AND the
     * bundle sits ABOVE the compiled checkpoint on this node's validated header
     * chain (see consensus_state_chain_binding_uses_assisted_authority), the
     * decision admits a FRESHEST, borrowed-state bundle: the bundle LOCATION
     * (block on the PoW header chain) and shielded TIP root (header-committed)
     * are authenticated, but the transparent/shielded CONTENT below the seam is
     * explicitly NOT — that is what the RELEASE_ASSISTED tier records. Set on the
     * FINAL observation only (after the before/after determinism comparison), so
     * it never perturbs the frontier-unchanged byte compare. */
    bool assisted_mode_requested;
};

struct consensus_state_chain_binding_request {
    struct main_state *main;
    /* Must originate from the strict external-bundle validator. A manifest
     * copy is intentionally insufficient to construct chain evidence. */
    const struct consensus_state_artifact_evidence *artifact;
    /* A canonical lane tag is included in the evidence digest. It is
     * descriptive binding, not permission to activate that lane. */
    enum consensus_state_target_lane target_lane;
    /* Compiled-checkpoint content authority (the sovereignty anchor). Filled
     * from the compiled SHA3/ROM checkpoint by the boot install verb. Left
     * zeroed (available=false) by callers that want the pure target-derived
     * gate. */
    struct consensus_state_checkpoint_authority checkpoint_authority;
    /* Opt in to admitting a FRESHEST, ABOVE-checkpoint borrowed-state bundle
     * (the assisted RELEASE_ASSISTED tier). Default false: callers that only
     * want the sovereign (compiled-checkpoint / self-validated) gate leave it
     * zeroed and an above-checkpoint bundle then refuses at -4 exactly as
     * before. See consensus_state_chain_binding_uses_assisted_authority. */
    bool allow_assisted_above_checkpoint;
};

/* Pure refusal decision. A passing result is diagnostic only and cannot be
 * converted into publication evidence by callers. */
struct zcl_result consensus_state_chain_binding_decide(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_chain_binding_observation *observation);

/* Pure predicate: true iff the decision authorizes the below-checkpoint
 * materialized-index predicates (-5/-6/-7/-8/-9/-10 and the -11 ancestry
 * links) from compiled-checkpoint content rather than the target's index.
 * Requires the observation's checkpoint authority to be available AND the
 * manifest to sit at exactly the authority height with a byte-for-byte
 * matching block_hash + Sapling frontier (root and height). Any mismatch
 * returns false, restoring the pure target-derived gate. Callers use this to
 * record — auditably — that checkpoint-content authority was exercised. */
bool consensus_state_chain_binding_uses_checkpoint_authority(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_chain_binding_observation *observation);

/* Pure predicate mirroring uses_checkpoint_authority for the ASSISTED tier:
 * true iff the decision admitted this bundle SOLELY via the above-checkpoint
 * borrowed-state relaxation. Requires observation->assisted_mode_requested, a
 * compiled checkpoint the bundle sits strictly ABOVE (checkpoint_authority
 * available, manifest.height > authority.height), that the sovereign paths do
 * NOT apply (NOT uses_checkpoint_authority; durable served H* is BELOW the
 * bundle height so the node did not self-validate through it), the bundle-height
 * block is the selected-chain block with a durable full-Equihash header pass
 * record (LOCATION is PoW-committed), and the Sapling frontier root matches the
 * header-committed root at both the frontier source height and the bundle height
 * (shielded TIP root is PoW-committed). CONTENT below the seam is deliberately
 * unauthenticated. Any mismatch returns false (fail closed to the sovereign
 * gate). Folded into the evidence digest so the audit trail is honest about the
 * tier that admitted the install. */
bool consensus_state_chain_binding_uses_assisted_authority(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_chain_binding_observation *observation);

/* Process-singleton selected-chain evidence. The artifact must be an opaque
 * strict-validator receipt. Capture selected-chain state before and after all
 * checks, require durable exact-hash header-pass rows, and issue immutable
 * opaque evidence only when every predicate passes. No bundle or node state is
 * mutated. This API does not support arbitrary copy/lane store contexts: its
 * reducer/progress authority is the open process singleton. The evidence is
 * diagnostic, not activation authority and can become stale immediately. A
 * publisher must re-capture inside its own quiesced publication transaction. */
struct zcl_result consensus_state_chain_evidence_build(
    const struct consensus_state_chain_binding_request *request,
    struct consensus_state_chain_evidence **out);

void consensus_state_chain_evidence_free(
    struct consensus_state_chain_evidence *evidence);
bool consensus_state_chain_evidence_matches_artifact(
    const struct consensus_state_chain_evidence *evidence,
    const struct consensus_state_artifact_evidence *artifact,
    enum consensus_state_target_lane target_lane);
bool consensus_state_chain_evidence_digest(
    const struct consensus_state_chain_evidence *evidence,
    uint8_t out[32]);

/* True iff this evidence was decided using compiled-checkpoint content
 * authority (see consensus_state_chain_binding_uses_checkpoint_authority).
 * The flag is also folded into the evidence digest, so it is cryptographically
 * bound into the durable publication decision record — the audit trail cannot
 * later claim a target-index binding it did not have. Returns false on NULL. */
bool consensus_state_chain_evidence_used_checkpoint_authority(
    const struct consensus_state_chain_evidence *evidence);

/* True iff this evidence was decided using the ASSISTED above-checkpoint
 * borrowed-state relaxation (see consensus_state_chain_binding_uses_assisted_
 * authority). Mutually exclusive with used_checkpoint_authority. Also folded
 * into the evidence digest. The install runtime uses this to set the borrowed
 * (RELEASE_ASSISTED) tier: stamp migration-complete but withhold self_folded
 * until background promotion re-derives the seam. Returns false on NULL. */
bool consensus_state_chain_evidence_used_assisted_authority(
    const struct consensus_state_chain_evidence *evidence);

#endif /* ZCL_SERVICES_CONSENSUS_STATE_CHAIN_BINDING_SERVICE_H */
