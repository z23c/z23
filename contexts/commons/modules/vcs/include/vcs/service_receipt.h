/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * service_receipt — the dual-signed verified-byte receipt (the open half
 * of the slice-11 ratio system). The local service book records what THIS
 * node observed; a receipt binds BOTH session endpoints to the same fact,
 * so a node can present portable evidence of its verified-byte ratio.
 *
 * TRUST MODEL (docs/P2P_SOURCE_HOSTING.md "Ratio"): receipts are advisory
 * reputation, never consensus facts, and every node may ignore them. A
 * signature establishes only that one key attests this exact byte count
 * for this exact package root in this day window. It proves nothing about
 * safety, usefulness, or identity beyond the two signing keys.
 *
 * WIRE (frozen v1, fixed 286 bytes):
 *   [ 4] magic "ZSR1"
 *   [33] uploader_pubkey      compressed secp256k1 (bytes the downloader
 *                             pulled FROM)
 *   [33] downloader_pubkey    compressed secp256k1 (distinct from uploader)
 *   [32] package_root         content.v2 root the bytes belong to
 *   [ 8] verified_bytes       u64 LE, > 0: verified bytes transferred
 *   [ 8] day_start            i64 LE civil day number, inclusive
 *   [ 8] day_end              i64 LE civil day number, >= day_start
 *   [32] session_nonce        opaque, not all-zero
 *   [64] uploader_signature   secp256k1 compact low-S over id
 *   [64] downloader_signature secp256k1 compact low-S over the SAME id
 *
 *   id = SHA3-256("zcl.zcode.service-receipt.v1\0" || wire without both
 *   signature fields) — both parties sign the identical digest, so the
 *   pair attests one shared fact.
 *
 * Pure codec: no socket, store, book, or engine authority. Signing takes
 * a caller-supplied secp256k1 context so tests and the wallet broker keep
 * their own key custody; verify uses an internal VERIFY-only context.
 */

#ifndef ZCL_VCS_SERVICE_RECEIPT_H
#define ZCL_VCS_SERVICE_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_SERVICE_RECEIPT_VERSION 1u
#define VCS_SERVICE_RECEIPT_DOMAIN "zcl.zcode.service-receipt.v1"
#define VCS_SERVICE_RECEIPT_MAGIC "ZSR1"
#define VCS_SERVICE_RECEIPT_PUBKEY_BYTES 33u
#define VCS_SERVICE_RECEIPT_ROOT_BYTES 32u
#define VCS_SERVICE_RECEIPT_NONCE_BYTES 32u
#define VCS_SERVICE_RECEIPT_SIG_BYTES 64u
#define VCS_SERVICE_RECEIPT_ID_BYTES 32u
#define VCS_SERVICE_RECEIPT_WIRE_BYTES                                \
    (4u + VCS_SERVICE_RECEIPT_PUBKEY_BYTES +                          \
     VCS_SERVICE_RECEIPT_PUBKEY_BYTES +                               \
     VCS_SERVICE_RECEIPT_ROOT_BYTES + 8u + 8u + 8u +                  \
     VCS_SERVICE_RECEIPT_NONCE_BYTES +                                \
     VCS_SERVICE_RECEIPT_SIG_BYTES + VCS_SERVICE_RECEIPT_SIG_BYTES)

enum vcs_service_receipt_role {
    VCS_SERVICE_RECEIPT_UPLOADER = 0,
    VCS_SERVICE_RECEIPT_DOWNLOADER = 1,
};

struct vcs_service_receipt {
    uint8_t uploader_pubkey[VCS_SERVICE_RECEIPT_PUBKEY_BYTES];
    uint8_t downloader_pubkey[VCS_SERVICE_RECEIPT_PUBKEY_BYTES];
    uint8_t package_root[VCS_SERVICE_RECEIPT_ROOT_BYTES];
    uint64_t verified_bytes;
    int64_t day_start;
    int64_t day_end;
    uint8_t session_nonce[VCS_SERVICE_RECEIPT_NONCE_BYTES];
    uint8_t uploader_signature[VCS_SERVICE_RECEIPT_SIG_BYTES];
    uint8_t downloader_signature[VCS_SERVICE_RECEIPT_SIG_BYTES];
};

enum vcs_service_receipt_error {
    VCS_SERVICE_RECEIPT_OK = 0,
    VCS_SERVICE_RECEIPT_ERR_NULL,
    VCS_SERVICE_RECEIPT_ERR_ARGS,      /* zero bytes / bad window / equal keys */
    VCS_SERVICE_RECEIPT_ERR_WIRE,      /* length or magic mismatch */
    VCS_SERVICE_RECEIPT_ERR_PUBKEY,    /* parse failed or keys not distinct */
    VCS_SERVICE_RECEIPT_ERR_SIG_LOW_S, /* malleated (non-low-S) signature */
    VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY,
    VCS_SERVICE_RECEIPT_ERR_SIGN,      /* signing context refused */
};

/* Domain-separated SHA3-256 receipt id over the canonical body (every
 * field except both signatures). Deterministic: same fields, same id. */
void vcs_service_receipt_id(const struct vcs_service_receipt *receipt,
                            uint8_t id_out[VCS_SERVICE_RECEIPT_ID_BYTES]);

/* Fill ONE party's signature over the receipt id using the caller's
 * signing context and secret key (32 bytes, libsecp256k1 convention).
 * The signature is stored compact and forced low-S. */
enum vcs_service_receipt_error vcs_service_receipt_sign(
    struct vcs_service_receipt *receipt,
    enum vcs_service_receipt_role role, void *secp_sign_ctx,
    const uint8_t secret_key[32]);

/* Canonical fixed-size wire, signatures included as-is. */
enum vcs_service_receipt_error vcs_service_receipt_serialize(
    const struct vcs_service_receipt *receipt, uint8_t *out,
    size_t cap);

/* Exact-length parse: magic, field bounds, distinct on-curve pubkeys,
 * nonzero nonce, sane day window. Signatures are parsed but NOT
 * verified here; use vcs_service_receipt_verify for that. */
enum vcs_service_receipt_error vcs_service_receipt_parse(
    const uint8_t *wire, size_t len,
    struct vcs_service_receipt *out);

/* Full admission: parse, then verify BOTH signatures (low-S enforced)
 * against their respective embedded pubkeys over the recomputed id. */
enum vcs_service_receipt_error vcs_service_receipt_verify(
    const uint8_t *wire, size_t len, struct vcs_service_receipt *out);

/* Verify ONE party's signature over the receipt id. Used for half-signed
 * offers (the counterparty field is still zeros). A missing or all-zero
 * signature is SIG_VERIFY, never a silent pass. */
enum vcs_service_receipt_error vcs_service_receipt_verify_role(
    const struct vcs_service_receipt *receipt,
    enum vcs_service_receipt_role role);

#endif /* ZCL_VCS_SERVICE_RECEIPT_H */
