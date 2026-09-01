/* Internal contracts for the contained consensus-state candidate builder. */

#ifndef ZCL_CONSENSUS_STATE_SNAPSHOT_INSTALL_INTERNAL_H
#define ZCL_CONSENSUS_STATE_SNAPSHOT_INSTALL_INTERNAL_H

#include "config/consensus_state_snapshot_install.h"
#include "consensus_state_snapshot_export_internal.h"

#include <sqlite3.h>
#include <stddef.h>

struct consensus_state_candidate_output {
    struct consensus_export_output_binding binding;
};

/* Serialized immutable read-transaction lease.  A successful begin holds the
 * evidence mutex until end, so one NOMUTEX SQLite handle is never shared by
 * concurrent candidate builders. */
bool consensus_state_artifact_evidence_candidate_lease_begin(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_bundle_manifest *manifest,
    uint8_t receipt_digest[32], sqlite3 **db);
void consensus_state_artifact_evidence_candidate_lease_end(
    const struct consensus_state_artifact_evidence *evidence);

bool consensus_state_candidate_validate_reopened(
    sqlite3 *candidate,
    const struct consensus_state_bundle_manifest *expected,
    const uint8_t expected_admission_receipt[32],
    struct consensus_state_candidate_result *result);

/* Canonical destination readback shared by candidate validation and live
 * activation. These recompute the logical bundle digests/frontiers from the
 * destination tables; row counts alone are never state authority. */
bool consensus_state_snapshot_destination_anchors_valid(
    sqlite3 *db, const struct consensus_state_bundle_manifest *expected);
bool consensus_state_snapshot_destination_nullifiers_valid(
    sqlite3 *db, const struct consensus_state_bundle_manifest *expected);

bool consensus_state_candidate_fail(
    struct consensus_state_candidate_result *result,
    enum consensus_state_candidate_status status,
    const char *fmt, ...);

bool consensus_state_candidate_output_open(
    const struct consensus_state_candidate_request *request,
    struct consensus_state_candidate_output *output,
    struct consensus_state_candidate_result *result);
void consensus_state_candidate_output_cleanup(
    struct consensus_state_candidate_output *output);
bool consensus_state_candidate_output_sqlite_open(
    struct consensus_state_candidate_output *output, sqlite3 **db);
bool consensus_state_candidate_sqlite_close_strict(
    struct consensus_state_candidate_output *output, sqlite3 **db);
bool consensus_state_candidate_output_finalize(
    struct consensus_state_candidate_output *output,
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t admission_receipt[32],
    enum consensus_state_candidate_failpoint failpoint,
    struct consensus_state_candidate_result *result);

/* ── ACTIVATE authority lattice ─────────────────────────────────────────────
 * Which authority (if any) lifted ACTIVATE containment; named in the activation
 * log line. Implemented in consensus_state_snapshot_install_checkpoint_authority.c. */
enum consensus_state_activate_authority {
    CONSENSUS_STATE_ACTIVATE_AUTHORITY_NONE = 0,
    /* Independent replay-derived receipt on this datadir. */
    CONSENSUS_STATE_ACTIVATE_AUTHORITY_RECEIPT,
    /* The bundle's manifest reproduces EVERY component of the compiled-in
     * shielded ROM state checkpoint (g_rom_state_checkpoint) byte-for-byte:
     * transparent coins (utxo_root/count/supply) PLUS the Sprout/Sapling anchor
     * history, both frontier roots+heights, and the full nullifier history. The
     * installer re-derives the installed rows against these same manifest
     * digests, so binding the manifest to the compiled keystone transitively
     * binds the installed state to the sovereign keystone WITHOUT any peer or
     * PoW-header input — header-independent, fail-closed. */
    CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_ROM,
    /* The bundle's coins reproduce the compiled SHA3 UTXO checkpoint AND its
     * Sapling tip frontier Pedersen-roots to the caller's validated-header
     * hashFinalSaplingRoot — bound to the compiled binary + PoW. */
    CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_CONTENT,
    /* The FRESHEST (RELEASE_ASSISTED) tier: a bundle ABOVE the compiled
     * checkpoint on this node's validated header chain. The install runtime set
     * request->assisted_tier from the chain-binding assisted admission, and its
     * shielded TIP frontier Pedersen-roots to the bundle-height header's PoW-
     * committed hashFinalSaplingRoot the runtime read from this datadir's own
     * validated header chain (request->assisted_sapling_root). This binds the
     * bundle LOCATION + shielded TIP root to PoW, but NOT the transparent/shielded
     * CONTENT below the seam — so the activate stamps only migration-complete
     * (operational) and records the seam; self_folded (sovereign) is withheld
     * until background promotion re-derives the seam. Lowest precedence: a bundle
     * that qualifies for any sovereign authority never resolves to ASSISTED. */
    CONSENSUS_STATE_ACTIVATE_AUTHORITY_ASSISTED,
};

const char *consensus_state_activate_authority_name(
    enum consensus_state_activate_authority authority);

/* Resolve the ACTIVATE authority from the admitted `evidence` (whole-file digest
 * → replay-receipt lookup on `datadir_fd`) and the content-bound `manifest`.
 * Precedence: RECEIPT (byte-unchanged) → CHECKPOINT_ROM (manifest reproduces the
 * compiled shielded ROM keystone, header-independent) → CHECKPOINT_CONTENT
 * (coins reproduce the SHA3 UTXO checkpoint + a validated-header Sapling root).
 * When no authority applies the return is CONSENSUS_STATE_ACTIVATE_AUTHORITY_NONE
 * and contained_reason is filled with a typed VERIFIED_CONTAINED explanation. */
enum consensus_state_activate_authority
consensus_state_activate_resolve_authority(
    const struct consensus_state_artifact_evidence *evidence, int datadir_fd,
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_activate_request *request,
    char *contained_reason, size_t reason_cap);

#endif /* ZCL_CONSENSUS_STATE_SNAPSHOT_INSTALL_INTERNAL_H */
