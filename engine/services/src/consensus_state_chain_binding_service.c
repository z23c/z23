/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bind contained state manifests to stable selected-chain evidence. */

// one-result-type-ok:opaque-read-only-evidence-accessors — fallible capture
// and decision surfaces return zcl_result; bool exports are total predicates.

#include "services/consensus_state_chain_binding_service.h"

#include "base/bytes.h"
#include "chain/chain.h"
#include "config/consensus_state_snapshot_install.h"
#include "core/arith_uint256.h"
#include "crypto/sha3.h"
#include "framework/condition.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/validate_headers_stage.h"
#include "services/chain_frontier_snapshot_service.h"
#include "services/chain_state_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"

#include <stdlib.h>
#include <string.h>

struct consensus_state_chain_evidence {
    uint8_t artifact_receipt_digest[32];
    uint8_t evidence_digest[32];
    enum consensus_state_target_lane target_lane;
    /* Recorded (and folded into evidence_digest) so the durable publication
     * decision auditably reflects whether the below-checkpoint predicates were
     * satisfied from compiled-checkpoint content instead of the target index. */
    bool checkpoint_authority_used;
    /* Recorded (and folded into evidence_digest) so the decision auditably
     * reflects the ASSISTED above-checkpoint borrowed-state tier: the install
     * runtime reads it to withhold the sovereign self_folded marker until
     * background promotion re-derives the seam. */
    bool assisted_authority_used;
};

static const char *target_lane_name(enum consensus_state_target_lane lane)
{
    switch (lane) {
    case CONSENSUS_STATE_TARGET_LANE_COPY_PROOF: return "copy-proof";
    case CONSENSUS_STATE_TARGET_LANE_DEV: return "dev";
    case CONSENSUS_STATE_TARGET_LANE_SOAK: return "soak";
    case CONSENSUS_STATE_TARGET_LANE_CANONICAL: return "canonical";
    case CONSENSUS_STATE_TARGET_LANE_UNKNOWN: return NULL;
    }
    return NULL;
}

static void digest_u32(struct sha3_256_ctx *ctx, uint32_t value)
{
    uint8_t encoded[4];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, encoded, sizeof(encoded));
}

static void digest_i32(struct sha3_256_ctx *ctx, int32_t value)
{
    digest_u32(ctx, (uint32_t)value);
}

static bool manifest_is_complete_and_self_bound(
    const struct consensus_state_bundle_manifest *manifest)
{
    if (!manifest || manifest->height < 0 ||
        manifest->sapling_frontier_height < 0 ||
        manifest->sapling_frontier_height > manifest->height ||
        !manifest->history_complete || manifest->activation_boundary != 0 ||
        manifest->sprout_source_cursor != 0 ||
        manifest->sapling_source_cursor != 0 ||
        manifest->nullifier_source_cursor != 0 ||
        manifest->source_fold_cursor != (int64_t)manifest->height + 1 ||
        (manifest->validation_profile != CONSENSUS_STATE_VALIDATION_FULL &&
         manifest->validation_profile !=
             CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) ||
        !zcl_bytes_any_set(manifest->block_hash, 32) ||
        !zcl_bytes_any_set(manifest->sapling_frontier_root, 32) ||
        !zcl_bytes_any_set(manifest->proof_manifest_digest, 32) ||
        !zcl_bytes_any_set(manifest->source_digest, 32) ||
        !zcl_bytes_any_set(manifest->artifact_digest, 32))
        return false;
    uint8_t computed[32];
    consensus_state_bundle_artifact_digest(manifest, computed);
    return memcmp(computed, manifest->artifact_digest, 32) == 0;
}

bool consensus_state_chain_binding_uses_checkpoint_authority(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_chain_binding_observation *observation)
{
    if (!manifest || !observation)
        return false;
    const struct consensus_state_checkpoint_authority *cp =
        &observation->checkpoint_authority;
    /* Authority applies ONLY at exactly the compiled checkpoint height, and
     * only when the bundle's own content reproduces the compiled checkpoint
     * byte-for-byte: same block, same Sapling frontier (root AND height). A
     * bundle that disagrees with the compiled keystone gets no substitution
     * and falls through to the pure target-derived gate (which refuses). */
    return cp->available &&
        zcl_bytes_any_set(cp->block_hash, 32) &&
        zcl_bytes_any_set(cp->sapling_frontier_root, 32) &&
        manifest->height == cp->height &&
        (int64_t)manifest->sapling_frontier_height ==
            (int64_t)cp->sapling_frontier_height &&
        memcmp(manifest->block_hash, cp->block_hash, 32) == 0 &&
        memcmp(manifest->sapling_frontier_root,
               cp->sapling_frontier_root, 32) == 0;
}

bool consensus_state_chain_binding_uses_assisted_authority(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_chain_binding_observation *observation)
{
    if (!manifest || !observation || !observation->assisted_mode_requested)
        return false;
    /* Assisted admission is the ABOVE-checkpoint borrowed-state relaxation. It
     * needs a compiled checkpoint to eventually re-derive FROM (the promotion
     * anchor) and the bundle must sit strictly above it; without a compiled
     * checkpoint there is no anchor, so fail closed to the sovereign gate. */
    const struct consensus_state_checkpoint_authority *cp =
        &observation->checkpoint_authority;
    if (!cp->available || manifest->height <= cp->height)
        return false;
    /* Mutually exclusive with the two SOVEREIGN paths:
     *  - the compiled-checkpoint content substitution (cp_auth), and
     *  - the self-validated path: a node whose durable served H* reached the
     *    bundle height re-derived and served that state itself, so it earns
     *    sovereignty through the full below-checkpoint gate, not this borrowed
     *    relaxation. Excluding served-coverage here keeps assisted_tier off a
     *    node that legitimately folded through the seam. */
    if (consensus_state_chain_binding_uses_checkpoint_authority(manifest,
                                                                observation))
        return false;
    if (observation->durable_served_height >= manifest->height)
        return false;
    /* Bundle LOCATION is PoW-committed: the bundle-height block is the selected-
     * chain block with a durable full-Equihash validate_headers pass record.
     * (This is the header-only subset of -5/-6; the script/failure-free body
     * predicates are structurally impossible on borrowed state and are skipped
     * — that is exactly what the tier withholds sovereignty for.) */
    if (!observation->selected_bundle_known ||
        observation->selected_bundle_height != manifest->height ||
        memcmp(observation->selected_bundle_hash, manifest->block_hash, 32) != 0 ||
        !observation->bundle_header_pass_record)
        return false;
    /* Shielded TIP root is PoW-committed: the Sapling source header at the
     * frontier height commits the manifest frontier root (the -9 comparison) and
     * the bundle-height header still carries it (the -10 comparison). Ancestry
     * back to the source is enforced by -11 in decide(). */
    if (!observation->selected_sapling_source_known ||
        (int64_t)observation->selected_sapling_source_height !=
            (int64_t)manifest->sapling_frontier_height ||
        memcmp(observation->selected_sapling_source_root,
               manifest->sapling_frontier_root, 32) != 0 ||
        memcmp(observation->selected_bundle_sapling_root,
               manifest->sapling_frontier_root, 32) != 0)
        return false;
    return true;
}

struct zcl_result consensus_state_chain_binding_decide(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_chain_binding_observation *observation)
{
    if (!manifest || !observation)
        return ZCL_ERR(-1, "chain binding: null manifest/observation");
    if (!manifest_is_complete_and_self_bound(manifest))
        return ZCL_ERR(-2, "chain binding: manifest is not complete/self-bound");

    /* Below-checkpoint predicates (-5/-6/-7/-8/-9/-10 and the -11 ancestry
     * links) reference the checkpoint block and its Sapling source, both AT OR
     * BELOW the checkpoint height. A snapshot-seeded target floors its index
     * above the checkpoint, so those blocks are never materialized there. When
     * the bundle is exactly the compiled checkpoint content, the compiled
     * checkpoint (a stronger, PoW-committed, independently re-derivable trust
     * root) authorizes them in place of the absent target index. The same
     * authority also enables the -4 header-bootstrap (instant-on) path and the
     * -3 fresh-genesis-bootstrap relaxation below. */
    bool cp_auth =
        consensus_state_chain_binding_uses_checkpoint_authority(manifest,
                                                                observation);

    /* Assisted ABOVE-checkpoint borrowed-state admission (the RELEASE_ASSISTED
     * tier), disjoint from cp_auth. When set it relaxes exactly the predicates
     * that are structurally impossible on borrowed state — the -4 served-coverage
     * requirement and the -5/-6/-8 body self-validation — while KEEPING every
     * PoW fact: -3 frontier determinism, the bundle-height header pass record +
     * Sapling-tip root binding (both folded into the predicate itself), and the
     * -11 header work + ancestry. It admits a usable-but-not-sovereign node; the
     * install runtime withholds the self_folded marker so mine/spend/export/seed
     * stay denied until background promotion re-derives the seam. */
    bool assisted =
        consensus_state_chain_binding_uses_assisted_authority(manifest,
                                                              observation);

    /* -3 selected-frontier durability. The target's frontier must be durable and
     * consistent across the two samples (before AND after). The ONE relaxation is
     * the clean-genesis instant-on bootstrap: a node that has folded ZERO bodies
     * has no durable tip_finalize authority yet, but genesis finality is a
     * compiled constant, so a coherent RUNTIME authority at served H* = 0 with no
     * partial fold state (fresh_genesis_bootstrap, collected below) is
     * admissible — ONLY under compiled-checkpoint authority (cp_auth). The
     * frontier must STILL be byte-unchanged across the two samples (determinism)
     * on both paths, and the relaxation touches ONLY -3's durable-frontier gate:
     * the -4 header-bootstrap crypto anchor and -11 header-tip validity below are
     * re-established in full. A mid-fold / drifted / partial-state node has
     * fresh_genesis_bootstrap false and refuses here exactly as before. */
    bool frontier_durable = observation->before_frontier_consistent &&
                            observation->after_frontier_consistent;
    /* The clean-genesis relaxation also covers the assisted tier: a genuinely
     * fresh node that installs a FRESHEST above-checkpoint bundle has folded
     * zero bodies, so — exactly like the compiled-checkpoint instant-on path —
     * it has no durable tip_finalize authority yet, but its crypto anchor (the
     * bundle-height header pass record + the -11 header work/ancestry below) is
     * re-established in full. Determinism (frontier_unchanged) is NEVER relaxed
     * on either path. A mid-fold / partial-state node has fresh_genesis_bootstrap
     * false and refuses here regardless. */
    bool fresh_genesis_admissible =
        (cp_auth || assisted) && observation->fresh_genesis_bootstrap;
    if ((!frontier_durable && !fresh_genesis_admissible) ||
        !observation->frontier_unchanged)
        return ZCL_ERR(-3,
                       "chain binding: selected frontier changed or is not "
                       "durable (before_consistent=%d after_consistent=%d "
                       "checkpoint_authority=%d fresh_genesis=%d unchanged=%d "
                       "durable_served_height=%d)",
                       observation->before_frontier_consistent ? 1 : 0,
                       observation->after_frontier_consistent ? 1 : 0,
                       cp_auth ? 1 : 0,
                       observation->fresh_genesis_bootstrap ? 1 : 0,
                       observation->frontier_unchanged ? 1 : 0,
                       observation->durable_served_height);

    /* -4 admits on EITHER of two sovereign paths:
     *
     *  (a) state-replacement: the target has already folded and durably served
     *      bodies THROUGH the bundle height (durable H* >= bundle height) — it
     *      re-derived and served the chain across the checkpoint itself.
     *
     *  (b) header-bootstrap (instant-on): under compiled-checkpoint authority
     *      (cp_auth — the manifest byte-reproduces the baked ROM checkpoint:
     *      block_hash + Sapling frontier root+height at exactly the checkpoint
     *      height), a node that has independently PoW-validated the header at
     *      EXACTLY the checkpoint height whose hash equals the baked block_hash
     *      has established the SAME sovereign fact -4 was a proxy for — "the
     *      baked checkpoint block is on my most-work PoW-validated chain" —
     *      directly, and WITHOUT the expensive body fold. selected_bundle_* are
     *      the checkpoint-height block on the node's selected chain and
     *      bundle_header_pass_record is a durable validate_headers pass row
     *      (full Equihash PoW + header validity, see
     *      validate_headers_default_validator -> block_row_verify) for exactly
     *      that (height, hash). Gated on cp_auth, so a NON-checkpoint bundle can
     *      never bootstrap. To forge admission an attacker would need a most-
     *      work Equihash chain through a DIFFERENT block at the checkpoint
     *      height (the same 51% PoW cost as attacking the real chain) — and even
     *      then the hash would not equal the baked value the pass record is
     *      keyed on. -3 (frontier durability) and the -11 header-tip validity
     *      below remain enforced on BOTH paths. */
    bool served_covers_bundle =
        observation->durable_served_height >= manifest->height;
    bool header_bootstrap_bind =
        cp_auth &&
        observation->selected_bundle_known &&
        observation->selected_bundle_height == manifest->height &&
        memcmp(observation->selected_bundle_hash,
               manifest->block_hash, 32) == 0 &&
        observation->bundle_header_pass_record;
    if (!served_covers_bundle && !header_bootstrap_bind && !assisted)
        return ZCL_ERR(-4,
                       "chain binding: bundle height=%d exceeds durable H*=%d "
                       "and no compiled-checkpoint header-bootstrap or assisted "
                       "above-checkpoint bind",
                       manifest->height, observation->durable_served_height);

    /* Assisted admission (like cp_auth) skips the -5..-10 body/index self-
     * validation: those predicates require folded bodies below the seam that a
     * borrowed-state node structurally lacks. The bundle LOCATION and Sapling
     * TIP root are still PoW-bound (verified inside the assisted predicate) and
     * the -11 header work + ancestry below remain enforced. */
    if (!cp_auth && !assisted) {
        if (!observation->selected_bundle_known ||
            observation->selected_bundle_height != manifest->height ||
            memcmp(observation->selected_bundle_hash,
                   manifest->block_hash, 32) != 0)
            return ZCL_ERR(-5, "chain binding: bundle block is not the selected-chain block");
        if (!observation->selected_bundle_valid_scripts ||
            !observation->selected_bundle_failure_free ||
            !observation->bundle_header_pass_record)
            return ZCL_ERR(-6, "chain binding: bundle block lacks durable validation");
        if (!observation->selected_sapling_source_known ||
            observation->selected_sapling_source_height !=
                manifest->sapling_frontier_height ||
            !zcl_bytes_any_set(observation->selected_sapling_source_hash, 32))
            return ZCL_ERR(-7, "chain binding: Sapling source height unavailable");
        if (!observation->selected_sapling_source_valid_scripts ||
            !observation->selected_sapling_source_failure_free ||
            !observation->sapling_source_header_pass_record)
            return ZCL_ERR(-8, "chain binding: Sapling source lacks durable validation");
        if (memcmp(observation->selected_sapling_source_root,
                   manifest->sapling_frontier_root, 32) != 0)
            return ZCL_ERR(-9, "chain binding: Sapling frontier disagrees with source header");
        /* A sparse frontier can originate below H only when no later block has
         * changed it. Requiring the same root in H's header closes that gap. */
        if (memcmp(observation->selected_bundle_sapling_root,
                   manifest->sapling_frontier_root, 32) != 0)
            return ZCL_ERR(-10, "chain binding: Sapling frontier is not current at bundle height");
    }

    /* -11 header-tip validity is ALWAYS target-derived: the target must have a
     * real, failure-free, valid-tree selected header at or above the bundle
     * height with nonzero work — this proves the target IS a live chain above
     * the checkpoint. Only the ancestry LINKS back down to the (possibly
     * unmaterialized) checkpoint block and its Sapling source are authorized by
     * checkpoint content. */
    if (!observation->selected_header_known ||
        observation->selected_header_height < manifest->height ||
        !zcl_bytes_any_set(observation->selected_header_hash, 32) ||
        !zcl_bytes_any_set(observation->selected_header_chainwork, 32) ||
        !observation->selected_header_valid_tree ||
        !observation->selected_header_failure_free)
        return ZCL_ERR(-11, "chain binding: selected-header work/validity missing");
    if (!cp_auth &&
        (!observation->header_descends_from_bundle ||
         !observation->bundle_descends_from_sapling_source))
        return ZCL_ERR(-11, "chain binding: selected-header ancestry missing");
    return ZCL_OK;
}

static bool capture_equal(const struct chain_state_frontier_view *a,
                          const struct chain_state_frontier_view *b)
{
    return a && b && a->initialized == b->initialized &&
        a->bound_to_expected_state == b->bound_to_expected_state &&
        a->window.height == b->window.height &&
        a->window.requested_height == b->window.requested_height &&
        a->window.tip == b->window.tip &&
        a->window.requested == b->window.requested &&
        a->header_tip == b->header_tip;
}

static bool index_matches_frontier_value(
    const struct block_index *index, const struct chain_frontier_value *value)
{
    if (!index || !index->phashBlock || !value || !value->height_known ||
        !value->binding_known || index->nHeight != value->height)
        return false;
    char hash[65];
    char work[65];
    uint256_get_hex(index->phashBlock, hash);
    arith_uint256_get_hex(&index->nChainWork, work);
    return strcmp(hash, value->hash) == 0 &&
        strcmp(work, value->chain_work) == 0;
}

static bool capture_matches_frontier(
    const struct chain_state_frontier_view *view,
    const struct chain_frontier_snapshot *frontier)
{
    return view && frontier &&
        index_matches_frontier_value(view->window.tip, &frontier->indexed) &&
        index_matches_frontier_value(view->header_tip, &frontier->header);
}

static bool index_descends_from(struct block_index *higher,
                                struct block_index *lower)
{
    if (!higher || !lower || !higher->phashBlock || !lower->phashBlock ||
        higher->nHeight < lower->nHeight)
        return false;
    struct block_index *ancestor = block_index_get_ancestor(
        higher, lower->nHeight);
    return ancestor && ancestor->phashBlock &&
        uint256_eq(ancestor->phashBlock, lower->phashBlock);
}

static void encode_chainwork(const struct arith_uint256 *work, uint8_t out[32])
{
    for (size_t limb = 0; limb < ARITH_UINT256_WIDTH; limb++) {
        uint32_t value = work->pn[limb];
        for (size_t byte = 0; byte < 4; byte++)
            out[limb * 4u + byte] = (uint8_t)(value >> (8u * byte));
    }
}

static void capture_binding_predicates(
    const struct chain_state_frontier_view *view,
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_checkpoint_authority *authority,
    struct consensus_state_chain_binding_observation *observation)
{
    memset(observation, 0, sizeof(*observation));
    /* Constant across both chain samples (compiled content), so it never
     * perturbs the before/after byte comparison in the caller. */
    if (authority)
        observation->checkpoint_authority = *authority;
    struct block_index *bundle = view ? view->window.requested : NULL;
    struct block_index *header = view ? view->header_tip : NULL;
    /* Gap B — headers-first fallback. active_chain_capture_window only returns a
     * bundle slot for heights AT OR BELOW the connected chain tip. On a headers-
     * first (--importblockindex / fast-sync) node the bundle height sits far
     * above the connected tip (which may be genesis), so window.requested is
     * NULL even though the checkpoint-height block IS present as a header-only
     * entry on the selected header chain. Resolve it by a READ-ONLY ancestor walk
     * from the header tip (never mutating chain_active, so the -3 frontier
     * snapshot is untouched) so selected_bundle_* / bundle_header_pass_record
     * populate for the -4 header-bootstrap bind. The walk is deterministic, so
     * the before/after samples stay byte-identical. */
    if (!bundle && header && manifest->height >= 0 &&
        header->nHeight >= manifest->height)
        bundle = block_index_get_ancestor(header, (int)manifest->height);
    struct block_index *sapling_source = bundle
        ? block_index_get_ancestor(
              bundle, (int)manifest->sapling_frontier_height)
        : NULL;
    if (bundle && bundle->phashBlock) {
        observation->selected_bundle_known = true;
        observation->selected_bundle_height = bundle->nHeight;
        memcpy(observation->selected_bundle_hash, bundle->phashBlock->data, 32);
        memcpy(observation->selected_bundle_sapling_root,
               bundle->hashFinalSaplingRoot.data, 32);
        observation->selected_bundle_valid_scripts =
            block_index_is_valid(bundle, BLOCK_VALID_SCRIPTS);
        observation->selected_bundle_failure_free =
            !block_has_any_failure(bundle);
        observation->bundle_header_pass_record =
            validate_headers_stage_has_pass_record(bundle->nHeight,
                                                    bundle->phashBlock);
    }
    if (sapling_source && sapling_source->phashBlock) {
        observation->selected_sapling_source_known = true;
        observation->selected_sapling_source_height = sapling_source->nHeight;
        memcpy(observation->selected_sapling_source_hash,
               sapling_source->phashBlock->data, 32);
        memcpy(observation->selected_sapling_source_root,
               sapling_source->hashFinalSaplingRoot.data, 32);
        observation->selected_sapling_source_valid_scripts =
            block_index_is_valid(sapling_source, BLOCK_VALID_SCRIPTS);
        observation->selected_sapling_source_failure_free =
            !block_has_any_failure(sapling_source);
        observation->sapling_source_header_pass_record =
            validate_headers_stage_has_pass_record(
                sapling_source->nHeight, sapling_source->phashBlock);
    }
    if (header && header->phashBlock) {
        observation->selected_header_known = true;
        observation->selected_header_height = header->nHeight;
        memcpy(observation->selected_header_hash, header->phashBlock->data, 32);
        encode_chainwork(&header->nChainWork,
                         observation->selected_header_chainwork);
        observation->selected_header_valid_tree =
            block_index_is_valid(header, BLOCK_VALID_TREE);
        observation->selected_header_failure_free =
            !block_has_any_failure(header);
    }
    observation->header_descends_from_bundle =
        index_descends_from(header, bundle);
    observation->bundle_descends_from_sapling_source =
        index_descends_from(bundle, sapling_source);
}

/* Gap A — the "no partial fold state" half of fresh_genesis_bootstrap. A clean
 * pre-fold node must have (1) no durable finalized tip at all (nothing has been
 * folded/finalized), and (2) coins not applied above genesis (applied is the
 * NEXT height to apply, so <= 1 means at most the genesis coinbase). A mid-fold /
 * partially-folded node fails one of these, so it is NEVER eligible for the -3
 * relaxation even if its runtime frontier momentarily reads H*=0. Caller holds
 * progress_store_tx_lock(); both reads are SELECT-only and lock-reentrant. */
static bool fresh_genesis_quiescent(sqlite3 *db)
{
    if (!db)
        return false;
    int durable_h = -1;
    uint8_t durable_hash[32];
    if (tip_finalize_stage_resolve_durable_tip(db, &durable_h, durable_hash))
        return false; /* a durable finalized tip exists → not pre-fold */
    int32_t applied = -1;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found))
        return false; // raw-return-ok:eligibility-probe-fails-closed-refuses-at-minus3
    return !found || applied <= 1;
}

static void evidence_digest_build(
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t artifact_receipt_digest[32],
    const struct consensus_state_chain_binding_observation *observation,
    const struct chain_frontier_snapshot *frontier,
    const char *target_lane, bool checkpoint_authority_used,
    bool assisted_authority_used, uint8_t out[32])
{
    static const char domain[] =
        CONSENSUS_STATE_BUNDLE_SCHEMA "/selected-chain-evidence";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&ctx, manifest->artifact_digest, 32);
    sha3_256_write(&ctx, artifact_receipt_digest, 32);
    digest_i32(&ctx, manifest->height);
    sha3_256_write(&ctx, observation->selected_bundle_hash, 32);
    digest_i32(&ctx, observation->selected_sapling_source_height);
    sha3_256_write(&ctx, observation->selected_sapling_source_hash, 32);
    sha3_256_write(&ctx, manifest->sapling_frontier_root, 32);
    digest_i32(&ctx, observation->durable_served_height);
    sha3_256_write(&ctx, (const uint8_t *)frontier->served.hash, 64);
    sha3_256_write(&ctx, (const uint8_t *)frontier->served.chain_work, 64);
    digest_i32(&ctx, observation->selected_header_height);
    sha3_256_write(&ctx, observation->selected_header_hash, 32);
    sha3_256_write(&ctx, observation->selected_header_chainwork, 32);
    size_t lane_len = strlen(target_lane);
    digest_u32(&ctx, (uint32_t)lane_len);
    sha3_256_write(&ctx, (const uint8_t *)target_lane, lane_len);
    /* Bind whether compiled-checkpoint content authorized the below-checkpoint
     * predicates: an evidence digest — and thus the durable decision record it
     * feeds — can never claim a target-index binding it did not have. */
    uint8_t authority_flag = checkpoint_authority_used ? 1u : 0u;
    sha3_256_write(&ctx, &authority_flag, 1);
    /* Bind the ASSISTED tier the same way: the durable decision record can never
     * claim a sovereign install for a borrowed above-checkpoint one, or vice
     * versa. */
    uint8_t assisted_flag = assisted_authority_used ? 1u : 0u;
    sha3_256_write(&ctx, &assisted_flag, 1);
    sha3_256_finalize(&ctx, out);
}

struct zcl_result consensus_state_chain_evidence_build(
    const struct consensus_state_chain_binding_request *request,
    struct consensus_state_chain_evidence **out)
{
    if (out)
        *out = NULL;
    if (!request || !out || !request->main || !request->artifact)
        return ZCL_ERR(-20, "chain evidence: null request member");
    const char *target_lane = target_lane_name(request->target_lane);
    if (!target_lane)
        return ZCL_ERR(-21, "chain evidence: target lane is not canonical");
    /* This implementation reads the process-global reducer/progress authority.
     * Refuse an API-shaped copy context rather than mixing its chain pointers
     * with another store's H-star/proof rows. A future copy binder needs one opaque
     * target context owning both CSR and progress-store identity. */
    if (condition_engine_main_state() != request->main ||
        !progress_store_db())
        return ZCL_ERR(-22,
                       "chain evidence: request is not the open process singleton");
    /* Only the strict validator can create artifact evidence. The builder
     * reasons over its copied manifest while the exact descriptor/read txn
     * remains pinned by the caller-owned opaque receipt. */
    struct consensus_state_bundle_manifest manifest_copy;
    uint8_t artifact_receipt_digest[32];
    if (!consensus_state_artifact_evidence_manifest_copy(
            request->artifact, &manifest_copy) ||
        !consensus_state_artifact_evidence_receipt_digest(
            request->artifact, artifact_receipt_digest))
        return ZCL_ERR(-23, "chain evidence: artifact receipt is stale");
    const struct consensus_state_bundle_manifest *manifest = &manifest_copy;

    /* Lock order is progress -> CSR/window. Header-pass reads recursively take
     * this same progress lock, keeping every durable predicate in one store
     * generation throughout the two chain samples. */
    progress_store_tx_lock();
    struct chain_frontier_snapshot frontier_before;
    struct chain_frontier_snapshot frontier_after;
    chain_frontier_snapshot_collect(&frontier_before, request->main);

    struct chain_state_frontier_view view_before;
    struct zcl_result captured = csr_capture_frontiers(
        csr_instance(), &request->main->chain_active,
        &request->main->pindex_best_header, manifest->height,
        &view_before);
    if (!captured.ok) {
        progress_store_tx_unlock();
        return ZCL_ERR(-24, "chain evidence: initial capture failed: %s",
                       captured.message);
    }

    struct consensus_state_chain_binding_observation sampled_before;
    capture_binding_predicates(&view_before, manifest,
                               &request->checkpoint_authority, &sampled_before);

    struct chain_state_frontier_view view_after;
    captured = csr_capture_frontiers(
        csr_instance(), &request->main->chain_active,
        &request->main->pindex_best_header, manifest->height,
        &view_after);
    if (!captured.ok) {
        progress_store_tx_unlock();
        return ZCL_ERR(-25, "chain evidence: final capture failed: %s",
                       captured.message);
    }
    chain_frontier_snapshot_collect(&frontier_after, request->main);
    struct consensus_state_chain_binding_observation sampled_after;
    capture_binding_predicates(&view_after, manifest,
                               &request->checkpoint_authority, &sampled_after);

    /* Both samples were zero-initialized before field assignment, so the
     * byte comparison also covers every root/hash/validity/pass predicate
     * without padding carrying indeterminate data. */
    bool predicates_unchanged =
        memcmp(&sampled_before, &sampled_after,
               sizeof(sampled_before)) == 0;
    struct consensus_state_chain_binding_observation observation =
        sampled_after;
    observation.before_frontier_consistent =
        chain_frontier_snapshot_consistent(&frontier_before);
    observation.after_frontier_consistent =
        chain_frontier_snapshot_consistent(&frontier_after);
    observation.durable_served_height = frontier_after.served.height;
    observation.frontier_unchanged = capture_equal(&view_before, &view_after) &&
        chain_frontier_snapshot_equal(&frontier_before, &frontier_after) &&
        capture_matches_frontier(&view_before, &frontier_before) &&
        capture_matches_frontier(&view_after, &frontier_after) &&
        predicates_unchanged;
    /* Gap A — clean-genesis instant-on eligibility. True ONLY when BOTH frontier
     * samples are clean-genesis-coherent (served H*=0 under a genuine runtime
     * authority, every other consistency gate satisfied) AND the store carries no
     * partial fold state. decide() gates this on cp_auth and re-enforces the -4
     * crypto anchor, so this never bypasses the checkpoint PoW bind. Computed
     * under the still-held progress lock so it reflects the same store generation
     * as the two frontier samples. */
    observation.fresh_genesis_bootstrap =
        chain_frontier_snapshot_clean_genesis(&frontier_before) &&
        chain_frontier_snapshot_clean_genesis(&frontier_after) &&
        fresh_genesis_quiescent(progress_store_db());
    /* Request-level assisted opt-in, set on the FINAL observation only (never on
     * the two sampled captures, whose byte compare above must not see it), so it
     * cannot perturb frontier_unchanged. decide() gates the actual admission on
     * the full assisted predicate (above-checkpoint + PoW binds). */
    observation.assisted_mode_requested =
        request->allow_assisted_above_checkpoint;

    struct zcl_result decision = consensus_state_chain_binding_decide(
        manifest, &observation);
    if (!decision.ok) {
        progress_store_tx_unlock();
        /* Propagate the decide CODE (-3..-11), not a generic wrapper: the install
         * runtime classifies retriable-vs-.fail from it (a -3 frontier-durability
         * refusal is a solution-independent node-side deferral that must never
         * .fail a byte-good bundle). The specific reason stays in the message. */
        return ZCL_ERR(decision.code, "chain evidence refused: %s",
                       decision.message);
    }
    progress_store_tx_unlock();

    uint8_t final_receipt_digest[32];
    if (!consensus_state_artifact_evidence_receipt_digest(
            request->artifact, final_receipt_digest) ||
        memcmp(final_receipt_digest, artifact_receipt_digest, 32) != 0)
        return ZCL_ERR(-27,
                       "chain evidence: artifact changed during chain capture");

    struct consensus_state_chain_evidence *evidence = zcl_malloc(
        sizeof(*evidence), "consensus state chain evidence");
    if (!evidence)
        return ZCL_ERR(-28, "chain evidence: allocation failed");
    memset(evidence, 0, sizeof(*evidence));
    memcpy(evidence->artifact_receipt_digest, artifact_receipt_digest, 32);
    evidence->target_lane = request->target_lane;
    evidence->checkpoint_authority_used =
        consensus_state_chain_binding_uses_checkpoint_authority(manifest,
                                                                &observation);
    evidence->assisted_authority_used =
        consensus_state_chain_binding_uses_assisted_authority(manifest,
                                                              &observation);
    evidence_digest_build(manifest, artifact_receipt_digest, &observation,
                          &frontier_before, target_lane,
                          evidence->checkpoint_authority_used,
                          evidence->assisted_authority_used,
                          evidence->evidence_digest);
    *out = evidence;
    return ZCL_OK;
}

void consensus_state_chain_evidence_free(
    struct consensus_state_chain_evidence *evidence)
{
    free(evidence);
}

bool consensus_state_chain_evidence_matches_artifact(
    const struct consensus_state_chain_evidence *evidence,
    const struct consensus_state_artifact_evidence *artifact,
    enum consensus_state_target_lane target_lane)
{
    uint8_t artifact_receipt_digest[32];
    if (!evidence || !artifact || !target_lane_name(target_lane) ||
        !consensus_state_artifact_evidence_receipt_digest(
            artifact, artifact_receipt_digest))
        return false;
    return memcmp(evidence->artifact_receipt_digest,
                  artifact_receipt_digest, 32) == 0 &&
        evidence->target_lane == target_lane;
}

bool consensus_state_chain_evidence_digest(
    const struct consensus_state_chain_evidence *evidence, uint8_t out[32])
{
    if (!evidence || !out)
        return false;
    memcpy(out, evidence->evidence_digest, 32);
    return true;
}

bool consensus_state_chain_evidence_used_checkpoint_authority(
    const struct consensus_state_chain_evidence *evidence)
{
    return evidence && evidence->checkpoint_authority_used;
}

bool consensus_state_chain_evidence_used_assisted_authority(
    const struct consensus_state_chain_evidence *evidence)
{
    return evidence && evidence->assisted_authority_used;
}
