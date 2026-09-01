/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_replay_receipt — the independent replay-derived receipt that
 * lifts the bundle-ACTIVATE production containment.
 *
 * A zcl.consensus_state_bundle.v1 file is self-asserted: it can recompute its
 * own digests, and a ZClassic header commits neither the UTXO set nor the
 * Sprout/Sapling anchor or nullifier CONTENTS, so matching a bundle's
 * height/hash to a validated local header authenticates only WHERE the bundle
 * claims to sit, never WHAT it contains. This module closes that gap: given a
 * datadir whose OWN genesis->anchor reducer fold has completed and parked at
 * the bundle's anchor height, it re-derives the transparent + shielded
 * component digests from that datadir's own folded tables (the bundle's tables
 * are NEVER read as derivation input) and, only if every re-derived digest
 * equals the bundle's, writes a receipt OUTSIDE the bundle binding the bundle
 * whole-file digest, the anchor, each independently re-derived component
 * digest, and the verifying binary's own image digest.
 *
 * ACTIVATE consults consensus_state_replay_receipt_authority_available(): the
 * transactional install stays CONTAINED (VERIFIED_CONTAINED, nothing written)
 * unless a valid receipt for EXACTLY this bundle + anchor + component digests
 * exists in the datadir. */

#ifndef ZCL_CONSENSUS_STATE_REPLAY_RECEIPT_H
#define ZCL_CONSENSUS_STATE_REPLAY_RECEIPT_H

#include <stdbool.h>
#include <stdint.h>

#include "storage/consensus_state_bundle_codec.h"

struct sqlite3;

#define CONSENSUS_STATE_REPLAY_RECEIPT_SCHEMA \
    "zcl.consensus_state_replay_receipt.v1"
/* Basename of the keyed receipt file written under the datadir. */
#define CONSENSUS_STATE_REPLAY_RECEIPT_NAME \
    "consensus_state_replay_receipt.v1"

struct consensus_state_replay_result {
    bool verified;
    int32_t height;
    uint64_t utxo_count;
    int64_t total_supply;
    uint64_t anchor_count;
    uint64_t nullifier_count;
    uint8_t bundle_file_digest[32];
    uint8_t verifier_binary_digest[32];
    char receipt_path[256];
    char reason[192];
};

/* Offline replay verifier (the -verify-consensus-bundle=PATH verb).
 *
 * `progress_db` is the datadir's OWN open progress store — the state produced
 * by this node's genesis->anchor reducer fold, parked EXACTLY at the bundle's
 * anchor height (coins_applied == height + 1). The verifier:
 *   1. admits + strictly validates the immutable bundle read-only (reusing the
 *      artifact-evidence validator) and copies its manifest;
 *   2. requires a complete genesis-derived history bundle (no mixed provenance);
 *   3. independently re-derives utxo root/count/supply, the pool-ordered anchor
 *      digest + frontiers, and the nullifier digest from `progress_db`'s own
 *      coins/sprout_anchors/sapling_anchors/nullifiers tables;
 *   4. requires every re-derived value to equal the bundle manifest;
 *   5. writes the fsync'd receipt binding all of the above plus SHA3 of the
 *      running executable image.
 * Fail-closed: any mismatch sets a typed reason and writes NOTHING. Returns
 * true only on a fully verified + persisted receipt. */
bool consensus_state_replay_verify_and_write_receipt(
    struct sqlite3 *progress_db, const char *bundle_path, const char *datadir,
    struct consensus_state_replay_result *out);

/* Fail-closed authority check consulted by ACTIVATE. Returns true iff the
 * datadir holds a well-formed receipt that binds EXACTLY this bundle whole-file
 * digest, this manifest's anchor + component digests, and the currently running
 * executable's image digest. Any missing/tampered/foreign receipt returns
 * false, keeping the install CONTAINED. */
bool consensus_state_replay_receipt_authority_available(
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t bundle_file_digest[32], int datadir_fd);
bool consensus_state_replay_receipt_authority_available_root(
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t bundle_file_digest[32], const char *trusted_root);

/* ── Bundle-binding-only reader (ROM catalog admission) ─────────────────────
 *
 * consensus_state_replay_receipt_authority_available() above is the ACTIVATE
 * authority: it additionally requires the manifest to match a live datadir's
 * OWN re-derived component digests AND the currently running binary image to
 * be the exact one that wrote the receipt. Neither requirement fits ROM
 * catalog admission (net/rom_seed.h serving) — a node offering a bundle for
 * P2P distribution generally is NOT the node that produced/verified it, and
 * has no live datadir folded to the bundle's anchor. Delivery is untrusted
 * transport either way (docs/ROM_DELIVERY.md): every fetcher re-verifies the
 * whole-file digest and re-derives the checkpoint content independently, so
 * this reader's only job is refusing to advertise a bundle no receipt was
 * ever written for. */
struct consensus_state_replay_receipt_binding {
    int32_t  height;
    uint64_t utxo_count;
    uint64_t anchor_count;
    uint64_t nullifier_count;
    uint8_t  verifier_binary_digest[32]; /* reported only, not compared here */
};

/* Reads and self-verifies the receipt file (schema string matches AND its own
 * receipt_digest self-binds every field — byte tampering fails here) inside
 * `datadir_fd`, and requires its bound bundle_file_digest to equal
 * `bundle_file_digest` (the caller's independently computed SHA3-256 of the
 * candidate bundle file). Fail-closed: a missing file, a structurally invalid
 * receipt, or a bundle-digest mismatch all return false and *out is left
 * zeroed. `out` may be NULL. */
bool consensus_state_replay_receipt_bundle_binding_verified(
    int datadir_fd, const uint8_t bundle_file_digest[32],
    struct consensus_state_replay_receipt_binding *out);
bool consensus_state_replay_receipt_bundle_binding_verified_root(
    const char *trusted_root, const uint8_t bundle_file_digest[32],
    struct consensus_state_replay_receipt_binding *out);

#ifdef ZCL_TESTING
/* Test-only: write a self-consistent receipt binding `bundle_file_digest`
 * with the given (otherwise arbitrary) component summary fields, without
 * requiring a live datadir/progress_db fold — used by fixture-level tests of
 * receipt-gated ROM catalog admission that do not want to stand up the full
 * consensus_state_replay_verify_and_write_receipt() genesis-fold harness. */
bool consensus_state_replay_receipt_write_for_test(
    const char *datadir, const uint8_t bundle_file_digest[32],
    int32_t height, uint64_t utxo_count, uint64_t anchor_count,
    uint64_t nullifier_count, char *out_path, size_t out_cap);
#endif

#endif /* ZCL_CONSENSUS_STATE_REPLAY_RECEIPT_H */
