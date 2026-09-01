/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical human confirmation and inert build-release evidence. */

#ifndef ZCL_VCS_BUILD_RELEASE_QUALIFICATION_H
#define ZCL_VCS_BUILD_RELEASE_QUALIFICATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_BUILD_RELEASE_CONFIRMATION_VERSION 2u
#define VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES 448u
#define VCS_BUILD_RELEASE_QUALIFICATION_VERSION 2u
#define VCS_BUILD_RELEASE_QUALIFICATION_WIRE_BYTES 368u

enum vcs_build_release_confirmation_flags {
    VCS_BUILD_RELEASE_CONFIRM_HUMAN_PRESENT = 1u << 0,
    VCS_BUILD_RELEASE_CONFIRM_PHYSICAL_EVIDENCE_REVIEWED = 1u << 1,
    VCS_BUILD_RELEASE_CONFIRM_NO_PUBLICATION = 1u << 2,
    VCS_BUILD_RELEASE_CONFIRM_REGRESSION_EVIDENCE_REVIEWED = 1u << 3,
};

#define VCS_BUILD_RELEASE_CONFIRM_REQUIRED_FLAGS \
    (VCS_BUILD_RELEASE_CONFIRM_HUMAN_PRESENT | \
     VCS_BUILD_RELEASE_CONFIRM_PHYSICAL_EVIDENCE_REVIEWED | \
     VCS_BUILD_RELEASE_CONFIRM_NO_PUBLICATION | \
     VCS_BUILD_RELEASE_CONFIRM_REGRESSION_EVIDENCE_REVIEWED)

enum vcs_build_release_qualification_flags {
    VCS_BUILD_RELEASE_QUAL_EXACT_ACTION = 1u << 0,
    VCS_BUILD_RELEASE_QUAL_THREE_EXECUTIONS = 1u << 1,
    VCS_BUILD_RELEASE_QUAL_HUMAN_CONFIRMED = 1u << 2,
    VCS_BUILD_RELEASE_QUAL_NO_PUBLICATION = 1u << 3,
    VCS_BUILD_RELEASE_QUAL_REGRESSION_PROOF = 1u << 4,
};

#define VCS_BUILD_RELEASE_QUAL_REQUIRED_FLAGS \
    (VCS_BUILD_RELEASE_QUAL_EXACT_ACTION | \
     VCS_BUILD_RELEASE_QUAL_THREE_EXECUTIONS | \
     VCS_BUILD_RELEASE_QUAL_HUMAN_CONFIRMED | \
     VCS_BUILD_RELEASE_QUAL_NO_PUBLICATION | \
     VCS_BUILD_RELEASE_QUAL_REGRESSION_PROOF)

enum vcs_build_release_decision {
    VCS_BUILD_RELEASE_DECISION_CONFIRM = 1,
    VCS_BUILD_RELEASE_DECISION_CANCEL = 2,
};

enum vcs_build_release_evidence_error {
    VCS_BUILD_RELEASE_EVIDENCE_OK = 0,
    VCS_BUILD_RELEASE_EVIDENCE_NULL,
    VCS_BUILD_RELEASE_EVIDENCE_WIRE,
    VCS_BUILD_RELEASE_EVIDENCE_MAGIC,
    VCS_BUILD_RELEASE_EVIDENCE_VERSION,
    VCS_BUILD_RELEASE_EVIDENCE_FLAGS,
    VCS_BUILD_RELEASE_EVIDENCE_DECISION,
    VCS_BUILD_RELEASE_EVIDENCE_ROOT,
    VCS_BUILD_RELEASE_EVIDENCE_DUPLICATE,
    VCS_BUILD_RELEASE_EVIDENCE_TIME,
    VCS_BUILD_RELEASE_EVIDENCE_SIGNATURE,
};

/* The signer attests only that a human reviewed the named, externally
 * captured physical evidence and the bound regression proof. Software must
 * not infer physical independence from worker keys, hostnames, IP addresses,
 * or this signature alone. */
struct vcs_build_release_confirmation_v2 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t decision;
    uint8_t action_root[32];
    uint8_t artifact_root[32];
    uint8_t candidate_receipt_root[32];
    uint8_t shadow_receipt_root[32];
    uint8_t reproduction_receipt_root[32];
    uint8_t candidate_machine_evidence_root[32];
    uint8_t shadow_machine_evidence_root[32];
    uint8_t reproduction_machine_evidence_root[32];
    uint8_t regression_action_root[32];
    uint8_t regression_proof_set_root[32];
    int64_t confirmed_unix;
    uint8_t confirmer_pubkey[32];
    uint8_t signature[64];
};

/* Supervisor-derived, non-publishing qualification artifact. Its root is a
 * stable release candidate identity, never publication or deployment
 * authority. Reloading it still requires re-verifying the confirmation and
 * receipt ledger. */
struct vcs_build_release_qualification_v2 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t action_root[32];
    uint8_t artifact_root[32];
    uint8_t observation_root[32];
    uint8_t candidate_receipt_root[32];
    uint8_t shadow_receipt_root[32];
    uint8_t reproduction_receipt_root[32];
    uint8_t confirmation_root[32];
    uint8_t proof_set_root[32];
    uint8_t regression_action_root[32];
    uint8_t regression_proof_set_root[32];
    int64_t qualified_unix;
};

void vcs_build_release_confirmation_v2_init(
    struct vcs_build_release_confirmation_v2 *confirmation);
enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_root(
    const struct vcs_build_release_confirmation_v2 *confirmation,
    uint8_t out[32]);
enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_seal(
    struct vcs_build_release_confirmation_v2 *confirmation,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_verify(
    const struct vcs_build_release_confirmation_v2 *confirmation);
enum vcs_build_release_evidence_error
vcs_build_release_confirmation_v2_serialize(
    const struct vcs_build_release_confirmation_v2 *confirmation,
    uint8_t out[VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES]);
enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_release_confirmation_v2 *out);

enum vcs_build_release_evidence_error
vcs_build_release_qualification_v2_serialize(
    const struct vcs_build_release_qualification_v2 *qualification,
    uint8_t out[VCS_BUILD_RELEASE_QUALIFICATION_WIRE_BYTES]);
enum vcs_build_release_evidence_error
vcs_build_release_qualification_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_release_qualification_v2 *out);
enum vcs_build_release_evidence_error vcs_build_release_qualification_v2_root(
    const struct vcs_build_release_qualification_v2 *qualification,
    uint8_t out[32]);

#endif /* ZCL_VCS_BUILD_RELEASE_QUALIFICATION_H */
