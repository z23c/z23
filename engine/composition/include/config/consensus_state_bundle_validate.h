/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal external-bundle validation contract. */

#ifndef ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_H
#define ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_H

#include "config/consensus_state_snapshot_install.h"
#include "storage/consensus_state_bundle_codec.h"

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* `db` must be the separately opened read-only immutable bundle handle. Reads
 * and validates its complete transaction snapshot; never mutates it. */
bool consensus_state_bundle_validate(
    struct sqlite3 *db,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_install_result *result);

/* Same contract as consensus_state_bundle_validate(), plus `skip_deep_scan`.
 * When true, honor ONLY after an install-verify receipt has proven this
 * exact byte-identical bundle already passed this exact deterministic check
 * under this exact verifying binary (see
 * config/consensus_state_install_verify_receipt.h and the
 * consensus_state_artifact_evidence_open() seam that owns that decision —
 * this function never consults the receipt store itself). All O(1)-row
 * structural checks still run every time (schema catalog, bundle_meta,
 * source_receipt, bundle_proof, and the artifact digest recompute); only the
 * whole-file PRAGMA integrity_check and the O(bundle-size) coins/anchors/
 * nullifiers scans are skipped. `skip_deep_scan=false` is byte-for-byte the
 * same behavior as consensus_state_bundle_validate(). */
bool consensus_state_bundle_validate_ex(
    struct sqlite3 *db,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_install_result *result, bool skip_deep_scan);

#ifdef ZCL_TESTING
/* Incremented once every time the O(bundle-size) deep scan (coins/anchors/
 * nullifiers) is entered, i.e. every call with skip_deep_scan=false that got
 * past the cheap structural checks. Lets a receipt test assert the second
 * verify of an unchanged bundle+epoch did NOT re-enter the deep scan. */
uint64_t consensus_state_bundle_validate_deep_scan_calls_for_test(void);
void consensus_state_bundle_validate_deep_scan_calls_reset_for_test(void);
#endif

#endif /* ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_H */
