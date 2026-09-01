/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Objective evidence checks for signed shop fulfillment claims. */

#ifndef ZCL_SERVICE_SHOP_FULFILL_EVIDENCE_H
#define ZCL_SERVICE_SHOP_FULFILL_EVIDENCE_H

#include "models/database.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum shop_fulfill_receipt_kind {
    SHOP_FULFILL_RECEIPT_BUILD = 0,
    SHOP_FULFILL_RECEIPT_FUZZ,
    SHOP_FULFILL_RECEIPT_BENCH,
};

struct shop_fulfill_artifact_fact {
    bool manifest_root_valid;
    bool cas_bytes_present;
    bool artifact_sha3_valid;
    uint64_t size_bytes;
    char reason[96];
};

struct shop_fulfill_receipt_fact {
    bool present;
    bool canonical_id_valid;
    bool signature_valid;
    bool action_binding_valid;
    bool artifact_binding_valid; /* false: typed receipt root != raw SHA3 */
    bool passed;
    char action_kind[64];
    char signer_pubkey[65];
    char reason[96];
};

const char *shop_fulfill_receipt_kind_name(
    enum shop_fulfill_receipt_kind kind);

/* Read-only proof over <datadir>/zcode: content_root must name a canonical
 * single-file/single-chunk content.v2 manifest; its chunk hash must equal
 * artifact_root; and the CAS bytes are re-read and SHA3-256 checked. */
struct zcl_result shop_fulfill_artifact_verify(
    const char *datadir, const uint8_t content_root[32],
    const uint8_t artifact_root[32], struct shop_fulfill_artifact_fact *out);

/* Read-only proof over the node's build-fabric ledger. A receipt is valid
 * only when its canonical id, Ed25519 signature, approved worker, exact
 * action kind, action/job/lease binding, and success state all re-check now.
 * The receipt association is seller-signature-bound; typed candidate/output
 * roots are not falsely equated with raw artifact SHA3. */
struct zcl_result shop_fulfill_receipt_verify(
    struct node_db *ndb, const char *datadir, const uint8_t receipt_id[32],
    enum shop_fulfill_receipt_kind expected_kind,
    int64_t now_unix, struct shop_fulfill_receipt_fact *out);

#endif /* ZCL_SERVICE_SHOP_FULFILL_EVIDENCE_H */
