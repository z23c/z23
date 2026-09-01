/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_snapshot_install_checkpoint_authority.c — the ACTIVATE
 * authority lattice for the sovereign shielded-state cure. Split from
 * consensus_state_snapshot_install_activate.c (one focused responsibility): it
 * decides WHICH authority, if any, may lift ACTIVATE containment. The atomic
 * cutover engine lives in install_activate.c; this file never touches state.
 *
 * Three independent authorities can lift containment, each binding the bundle to
 * something OUTSIDE the bundle's own self-asserted digests. ZClassic headers do
 * not commit the transparent/shielded state sets, so the bundle's self-recomputed
 * digests cannot authorize a live state replacement even when every internal
 * digest and selected-chain height/hash check passes:
 *
 *   RECEIPT — an independent replay-derived receipt on THIS datadir re-derived
 *   every component digest from its own folded tables and bound this exact
 *   bundle whole-file digest + artifact + anchor + component digests + the
 *   running binary image (config/consensus_state_replay_receipt.h).
 *
 *   CHECKPOINT_ROM — the bundle's manifest reproduces EVERY component of the
 *   compiled-in shielded ROM state checkpoint (g_rom_state_checkpoint) at the
 *   checkpoint height: transparent coins (utxo_root/count/supply) PLUS the
 *   Sprout/Sapling anchor history, both commitment-tree frontier roots+heights,
 *   and the full nullifier history. The admission validator already re-derives
 *   the installed rows against these same manifest digests, so binding the
 *   manifest to the compiled keystone transitively binds the installed state to
 *   the sovereign keystone. This needs NO peer and NO validated header — it is
 *   the complete-state extension of the transparent SHA3 checkpoint, the same
 *   sovereign trust model the transparent -refold-from-anchor path already uses,
 *   and it closes the hole where the historical Sprout anchors and the full
 *   nullifier set were unbound under CHECKPOINT_CONTENT (which binds only coins +
 *   the Sapling tip frontier root).
 *
 *   CHECKPOINT_CONTENT — the bundle's coins reproduce the compiled SHA3 UTXO
 *   checkpoint (sha3 + count at the checkpoint height) AND its Sapling tip
 *   frontier Pedersen-roots to the caller's validated-header committed
 *   hashFinalSaplingRoot. Bound to the compiled binary + PoW, this is
 *   cryptographically STRONGER than a fold-process receipt — the state's
 *   authority is the compiled checkpoint content, not a producer attestation.
 *   Retained as the fallback for header-carrying nodes and for candidates that
 *   are not at the ROM checkpoint height.
 *
 * Precedence: RECEIPT first (unchanged byte-for-byte), then CHECKPOINT_ROM
 * (header-independent, at the checkpoint height), then CHECKPOINT_CONTENT.
 * Without any of the three the install stays VERIFIED_CONTAINED and writes
 * nothing. */

#include "consensus_state_snapshot_install_internal.h"

#include "config/consensus_state_replay_receipt.h" /* replay-receipt authority */
#include "chain/checkpoints.h"           /* get_sha3_utxo_checkpoint,
                                          * get_rom_state_checkpoint */
#include "storage/consensus_state_bundle_codec.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

const char *consensus_state_activate_authority_name(
    enum consensus_state_activate_authority authority)
{
    switch (authority) {
    case CONSENSUS_STATE_ACTIVATE_AUTHORITY_RECEIPT:
        return "receipt";
    case CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_ROM:
        return "checkpoint_rom";
    case CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_CONTENT:
        return "checkpoint_content";
    case CONSENSUS_STATE_ACTIVATE_AUTHORITY_ASSISTED:
        return "assisted";
    default:
        return "none";
    }
}

#ifdef ZCL_TESTING
static _Atomic bool g_activate_test_independent_authority = false;

void consensus_state_snapshot_install_activate_test_set_independent_authority(
    bool available)
{
    atomic_store(&g_activate_test_independent_authority, available);
}
#endif

/* RECEIPT authority: a valid on-disk replay receipt binding this exact bundle
 * whole-file digest. The ZCL_TESTING seam lets the hermetic copy-proof harness
 * stand in for one. */
static bool activate_receipt_authority_available(
    const struct consensus_state_artifact_evidence *evidence, int datadir_fd,
    const struct consensus_state_bundle_manifest *manifest)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_activate_test_independent_authority))
        return true;
#endif
    uint8_t bundle_file_digest[32];
    if (!consensus_state_artifact_evidence_file_digest(evidence,
                                                       bundle_file_digest))
        return false;
    return consensus_state_replay_receipt_authority_available(
        manifest, bundle_file_digest, datadir_fd);
}

/* CHECKPOINT_CONTENT verdict for a receipt-less activation. */
enum activate_checkpoint_content_verdict {
    /* Not a checkpoint-content bundle here: no compiled checkpoint, a height off
     * the checkpoint, or coins that do not reproduce the compiled SHA3. */
    ACTIVATE_CC_NONMATCH = 0,
    /* Coins reproduce the compiled checkpoint, but the Sapling tip frontier is
     * not bound to a validated-header hashFinalSaplingRoot on this datadir. */
    ACTIVATE_CC_CONTAIN,
    /* Coins reproduce the compiled checkpoint AND the Sapling tip frontier
     * Pedersen-roots to the caller's validated-header hashFinalSaplingRoot. */
    ACTIVATE_CC_ACTIVATE,
};

/* Evaluate the CHECKPOINT_CONTENT authority from the content-bound manifest.
 *
 * manifest->utxo_root / utxo_count / sapling_frontier_root were re-derived from
 * the bundle's OWN coins + Sapling anchor rows by the admission validator
 * (consensus_state_bundle_validate: utxo_commitment_sha3_write_record over the
 * coins, incremental_tree_root over the highest Sapling frontier — the SAME
 * digest primitives the exporter's coins_kv_commitment / anchor tree-root use),
 * and consensus_state_artifact_evidence_revalidate pins that whole-file digest.
 * install_activate.c's activate_verify_destination independently re-folds the
 * INSTALLED destination (coins_kv_commitment + destination anchor tree roots)
 * and requires it to reproduce these exact manifest values before COMMIT. So
 * asserting the manifest reproduces the compiled checkpoint transitively binds
 * the live installed coins/frontier to the compiled binary's SHA3 UTXO
 * checkpoint and the PoW header's final Sapling root — one canonical fold, no
 * second digest implementation, no producer-trusted claim.
 *
 * The Sapling root binding requires a validated-header source: ZClassic headers
 * commit hashFinalSaplingRoot (PoW-protected) but the compiled UTXO checkpoint
 * does not carry it, so an installer without a validated header at the
 * checkpoint height can only CONTAIN, never activate on an unverifiable root. */
static enum activate_checkpoint_content_verdict
activate_checkpoint_content_evaluate(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_activate_request *request)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp || manifest->height != cp->height ||
        manifest->utxo_count != cp->utxo_count ||
        memcmp(manifest->utxo_root, cp->sha3_hash, 32) != 0)
        return ACTIVATE_CC_NONMATCH;
    /* Coins reproduce the compiled checkpoint. The Sapling tip frontier must
     * Pedersen-root to a PoW-committed hashFinalSaplingRoot the CALLER read
     * from its own validated header chain — never a bundle-carried root. */
    if (!request->checkpoint_sapling_root_from_validated_header ||
        memcmp(manifest->sapling_frontier_root,
               request->checkpoint_sapling_root, 32) != 0)
        return ACTIVATE_CC_CONTAIN;
    return ACTIVATE_CC_ACTIVATE;
}

/* An all-zero transparent OR shielded component means the compiled ROM keystone
 * is an UNBAKED placeholder (a dev build that has not yet baked the shielded
 * fold). Such a checkpoint is not a trust root: component-wise equality against a
 * zeroed field would falsely "match" an empty/crafted bundle. Mirror the
 * admission validator's rom_keystone_is_placeholder guard and grant no ROM
 * authority in that case (fail-closed). */
static bool activate_rom_checkpoint_is_placeholder(
    const struct rom_state_checkpoint *rom)
{
    static const uint8_t zero32[32] = {0};
    return memcmp(rom->utxo_root, zero32, 32) == 0 ||
           memcmp(rom->anchor_digest, zero32, 32) == 0 ||
           memcmp(rom->sprout_frontier_root, zero32, 32) == 0 ||
           memcmp(rom->sapling_frontier_root, zero32, 32) == 0 ||
           memcmp(rom->nullifier_digest, zero32, 32) == 0 ||
           memcmp(rom->rom_state_root, zero32, 32) == 0;
}

/* CHECKPOINT_ROM authority — does the content-bound manifest reproduce EVERY
 * component of the compiled shielded ROM keystone at the checkpoint height?
 *
 * This is the complete-state extension of activate_checkpoint_content_evaluate:
 * CHECKPOINT_CONTENT binds only the transparent coins + the Sapling tip frontier
 * root (and needs a validated header for the latter); CHECKPOINT_ROM binds ALL
 * of the transparent coins (utxo_root/count/supply), the Sprout+Sapling anchor
 * history, both commitment-tree frontier roots+heights, and the full nullifier
 * history to the compiled keystone. The admission validator
 * (consensus_state_bundle_validate) re-derived these manifest digests from the
 * bundle's OWN rows, and install_activate.c's activate_verify_destination
 * independently re-folds the INSTALLED destination against the same manifest
 * values before COMMIT, so matching the manifest to the compiled keystone
 * transitively binds the live installed COMPLETE state to the sovereign compiled
 * checkpoint — with no peer and no PoW header. Component-wise equality (not a
 * re-folded rom_state_root hash) keeps the binding auditable field by field and
 * needs no second digest implementation.
 *
 * Returns true ONLY on a full, byte-for-byte component match at the checkpoint
 * height against a fully-baked keystone; false (fail-closed) otherwise — no baked
 * ROM, a height off the checkpoint, an unbaked placeholder, or any single
 * component mismatch. block_hash is bound separately (the activate request's
 * expected_block_hash and the admission keystone binding both pin it). */
static bool activate_rom_checkpoint_content_evaluate(
    const struct consensus_state_bundle_manifest *manifest)
{
    const struct rom_state_checkpoint *rom = get_rom_state_checkpoint();
    if (!rom || manifest->height != rom->height)
        return false; /* not the checkpoint-height candidate: nothing to bind */
    if (activate_rom_checkpoint_is_placeholder(rom))
        return false; /* an unbaked dev keystone is never a trust root */
    return manifest->utxo_count == rom->utxo_count &&
           manifest->total_supply == rom->total_supply &&
           manifest->anchor_count == rom->anchor_count &&
           manifest->sprout_frontier_height == rom->sprout_frontier_height &&
           manifest->sapling_frontier_height == rom->sapling_frontier_height &&
           manifest->nullifier_count == rom->nullifier_count &&
           memcmp(manifest->utxo_root, rom->utxo_root, 32) == 0 &&
           memcmp(manifest->anchor_digest, rom->anchor_digest, 32) == 0 &&
           memcmp(manifest->sprout_frontier_root,
                  rom->sprout_frontier_root, 32) == 0 &&
           memcmp(manifest->sapling_frontier_root,
                  rom->sapling_frontier_root, 32) == 0 &&
           memcmp(manifest->nullifier_digest, rom->nullifier_digest, 32) == 0;
}

/* ASSISTED authority — the FRESHEST above-checkpoint borrowed-state tier.
 *
 * The install runtime sets request->assisted_tier ONLY when its chain-binding
 * decision admitted the bundle via the assisted relaxation (bundle LOCATION
 * PoW-bound to a validated header at the bundle height; shielded TIP root
 * header-committed; NOT compiled-checkpoint / self-validated). This authority
 * re-checks the shielded-tip PoW bind here — at the BUNDLE height, not forced to
 * the compiled-checkpoint height — from the validated-header hashFinalSaplingRoot
 * the runtime read from THIS node's own header chain. It never binds the
 * transparent/shielded CONTENT below the seam; that is exactly what the tier
 * withholds sovereignty for (self_folded stays unset until promotion). Fail-
 * closed: no assisted_tier request, a bundle at/below the compiled checkpoint,
 * no compiled checkpoint at all, or a Sapling root not bound to a validated
 * header → no ASSISTED authority. */
static bool activate_assisted_authority_available(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_activate_request *request)
{
    if (!request->assisted_tier)
        return false;
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp || manifest->height <= cp->height)
        return false; /* assisted is strictly ABOVE a compiled checkpoint */
    if (!request->assisted_sapling_root_from_validated_header ||
        memcmp(manifest->sapling_frontier_root,
               request->assisted_sapling_root, 32) != 0)
        return false; /* shielded tip not bound to a PoW-committed header root */
    return true;
}

/* Resolve the CONTENT-bound ACTIVATE authority (everything after the RECEIPT
 * gate): CHECKPOINT_ROM (header-independent, at the checkpoint height) first,
 * then CHECKPOINT_CONTENT (coins + validated-header Sapling root), then the
 * ASSISTED above-checkpoint tier (lowest precedence). Fills contained_reason on
 * a NONE verdict. */
static enum consensus_state_activate_authority
activate_resolve_content_authority(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_activate_request *request,
    char *contained_reason, size_t reason_cap)
{
    if (activate_rom_checkpoint_content_evaluate(manifest))
        return CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_ROM;

    switch (activate_checkpoint_content_evaluate(manifest, request)) {
    case ACTIVATE_CC_ACTIVATE:
        return CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_CONTENT;
    case ACTIVATE_CC_CONTAIN:
        if (contained_reason && reason_cap)
            snprintf(contained_reason, reason_cap,
                     "bundle coins reproduce the compiled SHA3 UTXO checkpoint "
                     "but its Sapling tip frontier is not bound to a validated-"
                     "header hashFinalSaplingRoot on this datadir; import the "
                     "header chain to the checkpoint height, or supply an "
                     "independent replay-derived receipt (install stays "
                     "contained)");
        return CONSENSUS_STATE_ACTIVATE_AUTHORITY_NONE;
    default:
        /* Not a compiled-checkpoint content bundle. It may still be the FRESHEST
         * above-checkpoint bundle admitted at the RELEASE_ASSISTED tier. */
        if (activate_assisted_authority_available(manifest, request))
            return CONSENSUS_STATE_ACTIVATE_AUTHORITY_ASSISTED;
        if (contained_reason && reason_cap)
            snprintf(contained_reason, reason_cap,
                     "no independent replay-derived receipt, shielded-ROM "
                     "keystone match, checkpoint-content proof, or assisted "
                     "above-checkpoint header bind authorizes this bundle; run "
                     "-verify-consensus-bundle against a datadir folded to the "
                     "anchor first (install stays contained)");
        return CONSENSUS_STATE_ACTIVATE_AUTHORITY_NONE;
    }
}

enum consensus_state_activate_authority
consensus_state_activate_resolve_authority(
    const struct consensus_state_artifact_evidence *evidence, int datadir_fd,
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_activate_request *request,
    char *contained_reason, size_t reason_cap)
{
    if (contained_reason && reason_cap)
        contained_reason[0] = '\0';
    if (!evidence || !manifest || !request)
        return CONSENSUS_STATE_ACTIVATE_AUTHORITY_NONE;
    if (activate_receipt_authority_available(evidence, datadir_fd, manifest))
        return CONSENSUS_STATE_ACTIVATE_AUTHORITY_RECEIPT;
    return activate_resolve_content_authority(manifest, request,
                                              contained_reason, reason_cap);
}

#ifdef ZCL_TESTING
/* Test seam: resolve the CONTENT-bound ACTIVATE authority (CHECKPOINT_ROM then
 * CHECKPOINT_CONTENT) for a SYNTHETIC manifest+request, bypassing the
 * evidence/receipt gate, and return the authority NAME ("checkpoint_rom",
 * "checkpoint_content", or "none"). Lets a focused unit test assert the
 * shielded-ROM keystone binding (paired with
 * checkpoints_set_rom_state_override_for_test) without standing up a bundle
 * file, datadir, or replay receipt. Never returns "receipt" — the receipt gate
 * is intentionally not exercised here. */
const char *consensus_state_activate_resolve_content_authority_name_for_test(
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_activate_request *request)
{
    char contained_reason[192];
    if (!manifest || !request)
        return consensus_state_activate_authority_name(
            CONSENSUS_STATE_ACTIVATE_AUTHORITY_NONE);
    return consensus_state_activate_authority_name(
        activate_resolve_content_authority(manifest, request, contained_reason,
                                           sizeof(contained_reason)));
}
#endif
