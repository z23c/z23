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

#endif /* ZCL_VCS_ZCODE_PUBLICATION_H */
