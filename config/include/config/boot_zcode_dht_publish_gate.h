/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Local evidence gates for package and attestation POINTER publishes. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_PUBLISH_GATE_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_PUBLISH_GATE_H

#include "vcs/zcode_dht_service.h"

#include <stdbool.h>

struct json_value;

/* A zclassic23.package POINTER record claims "this exact package_root is
 * discoverable and fetchable from me". That claim is only honest when this
 * node's own store holds a committed release naming the root AND the store's
 * receipts directory evidences reproduction: >= 2 distinct byte-identical
 * installable build receipts for the exact (package_root, recipe_root) pair
 * the signed release commits (vcs_package_reproduce_scan). Everything else
 * refuses BEFORE a plan token exists, so plan and commit are gated
 * identically. Returns true when the publish may proceed; on refusal result
 * carries the exact named code (NO_PACKAGE_STORE, PACKAGE_INDEX_UNAVAILABLE,
 * UNKNOWN_PACKAGE, RELEASE_UNREADABLE, REPRODUCTION_NOT_EVIDENCED) in the
 * ok/code/message shape every RPC refusal in this layer uses. */
bool boot_zcode_dht_package_pointer_publish_gate(
    const struct vcs_zcode_dht_publish_spec *spec, struct json_value *result);

/* An attestation POINTER record in VCS_PACKAGE_ATTEST_DHT_NAMESPACE claims
 * "the blob at transport_root is a signed ZCLATT attestation ABOUT the
 * package at semantic_root, and I hold those bytes". This gate refuses the
 * publish unless a package store exists and
 * vcs_package_attest_transport_admit(store, zcode_dir, transport_root,
 * semantic_root, &outcome) returns OK — one call that proves possession of
 * the blob, that the bytes parse as a canonical ZCLATT wire, that the
 * embedded secp256k1 signature verifies, and that the wire's package_root
 * equals the pointer's semantic_root. Refusals carry the named code
 * (NO_PACKAGE_STORE, ATTESTATION_NOT_HELD, ATTESTATION_INVALID,
 * ATTESTATION_BINDING_MISMATCH, ATTESTATION_ID_MISMATCH,
 * ATTESTATION_STORE_CONFLICT, ATTESTATION_UNPUBLISHABLE) plus the exact
 * transport/blob/attest rule string, in the ok/code/message shape every RPC
 * refusal in this layer uses.
 *
 * NOT READ-ONLY, AND IT RUNS ON mode=plan TOO: a successful check FILES the
 * attestation at <zcode_dir>/attestations/<id-hex>, because _admit() is the
 * single filer and a verify-without-file variant would fork the verification
 * logic into a second copy that drifts. Idempotent, and normally a no-op
 * because `zcode package attest offer` filed the bytes first — but not a
 * no-op if the blob arrived some other way. Acceptable because publishing
 * this pointer IS the node asserting it holds that attestation.
 *
 * READ THIS BEFORE TRUSTING IT: THIS GATE IS HYGIENE, NOT THE SECURITY
 * PROPERTY. It constrains only what THIS node advertises. A hostile node
 * runs its own build and publishes any pointer it likes in this namespace;
 * nothing here reaches it. The property that actually holds is the
 * RECEIVER-side binding check — vcs_package_attest_transport_admit() with a
 * non-NULL expect_package_root, which every puller MUST pass. Do not treat
 * a published attestation pointer as trustworthy because this gate exists.
 * PROVIDER records in the same namespace are deliberately NOT gated: a
 * false provider claim only fails the fetch, and gating it buys nothing. */
bool boot_zcode_dht_attestation_pointer_publish_gate(
    const struct vcs_zcode_dht_publish_spec *spec, struct json_value *result);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_PUBLISH_GATE_H */
