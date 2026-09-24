/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Immutable signed publication intent, preceding remote mutation. */

#ifndef ZCL_VCS_ZCODE_PUBLICATION_H
#define ZCL_VCS_ZCODE_PUBLICATION_H

#include "vcs/zcode_dev.h"

/* Both domain strings include their terminating NUL in the hashed preimage. */
#define VCS_ZCODE_PUBLICATION_DOMAIN "zcl.zcode.publication.v1"
#define VCS_ZCODE_PUBLICATION_SIGNING_DOMAIN "zcl.zcode.publication.signing.v1"
#define VCS_ZCODE_PUBLICATION_REF_BYTES 128u
#define VCS_ZCODE_PUBLICATION_BODY_BYTES 376u
#define VCS_ZCODE_PUBLICATION_WIRE_BYTES 440u

enum vcs_zcode_publication_git_format {
    VCS_ZCODE_PUBLICATION_GIT_OID_20 = 1,
    VCS_ZCODE_PUBLICATION_GIT_OID_32 = 2,
};

/* Public identity only: target locators and private credentials remain local.
 * Git OIDs are external publication coordinates, never source-content
 * verification. Candidate and proof-set roots bind canonical evidence.
 * Twenty-byte identifiers require twelve trailing zero bytes.
 * target_ref is NUL-terminated and zero-padded: refs/ followed by nonempty
 * ASCII components using letters, digits, dash, underscore and dot. Components
 * cannot start/end with dot, contain two adjacent dots, or end with .lock.
 * The self root is derived from
 * the entire signed wire, not stored within it. No outcome mutates this object.
 * A valid signature is not a grant, proof qualification, or publication receipt. */
struct vcs_zcode_publication_v1 {
    uint16_t schema_version;
    uint8_t git_object_format;
    uint8_t candidate_root[32];
    uint8_t proof_set_root[32];
    uint8_t target_identity_root[32];
    uint8_t authority_root[32];
    char target_ref[VCS_ZCODE_PUBLICATION_REF_BYTES];
    uint8_t expected_base[32];
    uint8_t head_commit[32];
    int64_t created_unix;
    uint8_t author_pubkey[32];
    uint8_t signature[64];
};

/* Validate and parse check structure only; verify authenticates the pinned
 * signer. Neither establishes grants, ancestry, proof eligibility or storage. */
enum vcs_zcode_dev_error vcs_zcode_publication_validate(
    const struct vcs_zcode_publication_v1 *intent);
enum vcs_zcode_dev_error vcs_zcode_publication_serialize(
    const struct vcs_zcode_publication_v1 *intent,
    uint8_t out[VCS_ZCODE_PUBLICATION_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_publication_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_publication_v1 *out);
/* Root commits signature bytes. Signing uses a distinct domain over the body. */
enum vcs_zcode_dev_error vcs_zcode_publication_root(
    const struct vcs_zcode_publication_v1 *intent, uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_publication_seal(
    struct vcs_zcode_publication_v1 *intent,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_publication_verify(
    const struct vcs_zcode_publication_v1 *intent,
    const uint8_t expected_signer[32]);

/* Bounded CAS read, full signed-root check and pinned-signer verification.
 * Refusal clears output. This does not grant publication or prove durability. */
bool vcs_zcode_publication_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected_signer[32], struct vcs_zcode_publication_v1 *out);

/* Verify before writing into an initialized CAS, then reload and verify the
 * exact stored object. Retry initialization's directory barriers first;
 * directory existence alone cannot prove an earlier attempt succeeded.
 * Existing conflicting bytes remain untouched. Return
 * the root only on success; clear it on refusal. No dispatch or grant. */
bool vcs_zcode_publication_store_verified(
    const char *workspace, const struct vcs_zcode_publication_v1 *intent,
    const uint8_t expected_signer[32], uint8_t out_root[32]);

/* Immutable signed binding between a persisted publication intent and the
 * transferable Git bundle bytes. The intent supplies candidate, proof set,
 * target and authority roots; repeating the pair here makes mismatched or
 * stale attachments fail before dispatch. The bundle digest is SHA-256 over
 * the complete bundle file, not a Git object ID. A receiving publisher must
 * independently hash that file and qualify the intent and target grant;
 * storing this attachment alone never permits a push. */
#define VCS_ZCODE_PUBLICATION_ATTACHMENT_DOMAIN \
    "zcl.zcode.publication_attachment.v1"
#define VCS_ZCODE_PUBLICATION_ATTACHMENT_SIGNING_DOMAIN \
    "zcl.zcode.publication_attachment.signing.v1"
#define VCS_ZCODE_PUBLICATION_ATTACHMENT_BODY_BYTES 184u
#define VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES 248u

struct vcs_zcode_publication_attachment_v1 {
    uint16_t schema_version;
    uint8_t publication_root[32];
    uint8_t bundle_sha256[32];
    uint8_t expected_base[32];
    uint8_t head_commit[32];
    int64_t created_unix;
    uint8_t author_pubkey[32];
    uint8_t signature[64];
};

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_validate(
    const struct vcs_zcode_publication_attachment_v1 *attachment);
enum vcs_zcode_dev_error vcs_zcode_publication_attachment_serialize(
    const struct vcs_zcode_publication_attachment_v1 *attachment,
    uint8_t out[VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_publication_attachment_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_publication_attachment_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_publication_attachment_root(
    const struct vcs_zcode_publication_attachment_v1 *attachment,
    uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_publication_attachment_seal(
    struct vcs_zcode_publication_attachment_v1 *attachment,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_publication_attachment_verify(
    const struct vcs_zcode_publication_attachment_v1 *attachment,
    const uint8_t expected_signer[32]);
bool vcs_zcode_publication_attachment_store_verified(
    const char *workspace,
    const struct vcs_zcode_publication_attachment_v1 *attachment,
    const uint8_t expected_signer[32], uint8_t out_root[32]);
bool vcs_zcode_publication_attachment_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected_signer[32],
    struct vcs_zcode_publication_attachment_v1 *out);

/* One immutable observation of a publication attempt. ACCEPTED records the
 * client's acknowledgement, not an independently verified remote result.
 * UNKNOWN retains an ambiguous acknowledgement for later reconciliation.
 * The caller binds attempt_root to its existing action identity and keeps a
 * rebuildable intent-to-result projection; CAS storage alone cannot discover
 * results from an intent root. */
#define VCS_ZCODE_PUBLICATION_RESULT_DOMAIN "zcl.zcode.publication_result.v1"
#define VCS_ZCODE_PUBLICATION_RESULT_SIGNING_DOMAIN \
    "zcl.zcode.publication_result.signing.v1"
#define VCS_ZCODE_PUBLICATION_RESULT_BODY_BYTES 184u
#define VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES 248u

enum vcs_zcode_publication_outcome {
    VCS_ZCODE_PUBLICATION_ACCEPTED = 1,
    VCS_ZCODE_PUBLICATION_REJECTED = 2,
    VCS_ZCODE_PUBLICATION_UNKNOWN = 3,
};

struct vcs_zcode_publication_result_v1 {
    uint16_t schema_version;
    uint8_t outcome;
    uint8_t publication_root[32];
    uint8_t attempt_root[32];
    uint8_t diagnostics_root[32];
    uint8_t evidence_root[32];
    int64_t attempted_unix;
    uint8_t producer_pubkey[32];
    uint8_t signature[64];
};

enum vcs_zcode_dev_error vcs_zcode_publication_result_validate(
    const struct vcs_zcode_publication_result_v1 *result);
enum vcs_zcode_dev_error vcs_zcode_publication_result_serialize(
    const struct vcs_zcode_publication_result_v1 *result,
    uint8_t out[VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_publication_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_publication_result_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_publication_result_root(
    const struct vcs_zcode_publication_result_v1 *result, uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_publication_result_seal(
    struct vcs_zcode_publication_result_v1 *result,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_publication_result_verify(
    const struct vcs_zcode_publication_result_v1 *result,
    const uint8_t expected_signer[32]);
bool vcs_zcode_publication_result_store_verified(
    const char *workspace, const struct vcs_zcode_publication_result_v1 *result,
    const uint8_t publisher_signer[32], const uint8_t producer_signer[32],
    uint8_t out_root[32]);
bool vcs_zcode_publication_result_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t publisher_signer[32], const uint8_t producer_signer[32],
    struct vcs_zcode_publication_result_v1 *out);

/* An observer's immutable statement about a fetched remote ref. The producer
 * must independently fetch and verify the remote, source root, and ancestry
 * evidence before sealing; signature verification alone proves none of them.
 * V1 storage also requires fetched tip == intended head; advanced tips need a
 * new version with separately bound head-source and ancestry observations.
 * Store requires a previously persisted publication intent. The codec and CAS
 * checks below do not grant terminal lifecycle status: the receiving policy
 * must verify the referenced remote observations and ancestry separately. */
#define VCS_ZCODE_REMOTE_RECEIPT_DOMAIN "zcl.zcode.remote_receipt.v1"
#define VCS_ZCODE_REMOTE_RECEIPT_SIGNING_DOMAIN \
    "zcl.zcode.remote_receipt.signing.v1"
#define VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES 376u
#define VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES 440u

struct vcs_zcode_remote_receipt_v1 {
    uint16_t schema_version;
    uint8_t git_object_format;
    uint8_t publication_root[32];
    uint8_t target_identity_root[32];
    char target_ref[VCS_ZCODE_PUBLICATION_REF_BYTES];
    uint8_t fetched_main_tip[32];
    uint8_t fetched_main_source_root[32];
    uint8_t verified_ancestry_root[32];
    uint8_t evidence_root[32];
    int64_t observed_unix;
    uint8_t observer_pubkey[32];
    uint8_t signature[64];
};

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_validate(
    const struct vcs_zcode_remote_receipt_v1 *receipt);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_serialize(
    const struct vcs_zcode_remote_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_remote_receipt_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_root(
    const struct vcs_zcode_remote_receipt_v1 *receipt, uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_seal(
    struct vcs_zcode_remote_receipt_v1 *receipt,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_verify(
    const struct vcs_zcode_remote_receipt_v1 *receipt,
    const uint8_t expected_signer[32]);

/* Authenticate both signed statements and bind the immutable candidate's
 * source root to the observer's fetched source root. The v1 receipt requires
 * the fetched tip to equal the intended head; later remote advancement needs
 * separately bound intended-head source and ancestry evidence. This does not verify
 * that the remote ref was fetched, that ancestry was checked, or that the
 * receipt qualifies as terminal under the receiver's policy. */
bool vcs_zcode_remote_receipt_candidate_matches(
    const struct vcs_zcode_remote_receipt_v1 *receipt,
    const struct vcs_zcode_publication_v1 *intent,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t publisher_signer[32],
    const uint8_t observer_signer[32]);

/* Restart-safe CAS reload of the signed receipt, its signed intent, and the
 * exact canonical candidate named by that intent. Clears both outputs on
 * refusal. Success proves object identity and source-root binding only;
 * independent remote-ref and ancestry verification is still required. */
bool vcs_zcode_remote_receipt_load_candidate_bound(
    const char *workspace, const uint8_t receipt_root[32],
    const uint8_t publisher_signer[32],
    const uint8_t observer_signer[32],
    struct vcs_zcode_remote_receipt_v1 *out_receipt,
    struct vcs_zcode_candidate_v1 *out_candidate);

/* Both operations independently load the signed intent from the existing CAS.
 * Store refuses if intent persistence or target binding is missing. A repeated
 * exact store is idempotent; conflicting addressed bytes remain untouched.
 * Neither operation searches for receipts by intent or proves remote success. */
bool vcs_zcode_remote_receipt_store_verified(
    const char *workspace, const struct vcs_zcode_remote_receipt_v1 *receipt,
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    uint8_t out_root[32]);
bool vcs_zcode_remote_receipt_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    struct vcs_zcode_remote_receipt_v1 *out);

/* A later fetched tip may descend from the intended head. V2 separately
 * commits the independently checked intended-head source root; the fetched
 * tip's source root may differ. The ancestry and evidence roots name the
 * observer's exact observations, which a receiving policy must independently
 * verify before granting LANDED. These codecs/CAS calls grant no status. */
#define VCS_ZCODE_REMOTE_RECEIPT_V2_VERSION 2u
#define VCS_ZCODE_REMOTE_RECEIPT_V2_DOMAIN "zcl.zcode.remote_receipt.v2"
#define VCS_ZCODE_REMOTE_RECEIPT_V2_SIGNING_DOMAIN \
    "zcl.zcode.remote_receipt.signing.v2"
#define VCS_ZCODE_REMOTE_RECEIPT_V2_BODY_BYTES 408u
#define VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES 472u

struct vcs_zcode_remote_receipt_v2 {
    struct vcs_zcode_remote_receipt_v1 observation;
    uint8_t intended_head_source_root[32];
};

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_serialize(
    const struct vcs_zcode_remote_receipt_v2 *receipt,
    uint8_t out[VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_remote_receipt_v2 *out);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_root(
    const struct vcs_zcode_remote_receipt_v2 *receipt, uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_seal(
    struct vcs_zcode_remote_receipt_v2 *receipt,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_verify(
    const struct vcs_zcode_remote_receipt_v2 *receipt,
    const uint8_t expected_signer[32]);
bool vcs_zcode_remote_receipt_v2_candidate_matches(
    const struct vcs_zcode_remote_receipt_v2 *receipt,
    const struct vcs_zcode_publication_v1 *intent,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t publisher_signer[32],
    const uint8_t observer_signer[32]);
bool vcs_zcode_remote_receipt_v2_store_verified(
    const char *workspace, const struct vcs_zcode_remote_receipt_v2 *receipt,
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    uint8_t out_root[32]);
bool vcs_zcode_remote_receipt_v2_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    struct vcs_zcode_remote_receipt_v2 *out);

#endif /* ZCL_VCS_ZCODE_PUBLICATION_H */
