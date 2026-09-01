/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: policy-bound, read-only reproduction qualification. */
#ifndef ZCL_VCS_ZCODE_REPRODUCTION_QUALIFICATION_H
#define ZCL_VCS_ZCODE_REPRODUCTION_QUALIFICATION_H

#include "vcs/package_reproduce.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum vcs_zcode_reproduction_qualification {
    VCS_ZCODE_QUALIFICATION_READY = 0,
    VCS_ZCODE_QUALIFICATION_NULL,
    VCS_ZCODE_QUALIFICATION_CAS,
    VCS_ZCODE_QUALIFICATION_POLICY,
    VCS_ZCODE_QUALIFICATION_SCORE,
    VCS_ZCODE_QUALIFICATION_REQUEST,
    VCS_ZCODE_QUALIFICATION_NO_RECEIPT,
    VCS_ZCODE_QUALIFICATION_RECEIPT,
    VCS_ZCODE_QUALIFICATION_OUTPUT_MISMATCH,
    VCS_ZCODE_QUALIFICATION_SIGNER_NOT_APPROVED,
    VCS_ZCODE_QUALIFICATION_SIGNER_NOT_DISTINCT,
    VCS_ZCODE_QUALIFICATION_APPROVAL_NOT_VALID,
    VCS_ZCODE_QUALIFICATION_CHALLENGE_EXPIRED,
    VCS_ZCODE_QUALIFICATION_CONFINEMENT_INSUFFICIENT,
    VCS_ZCODE_QUALIFICATION_DUPLICATE,
    VCS_ZCODE_QUALIFICATION_CONTRADICTION,
};

struct vcs_zcode_reproduction_qualification_report {
    enum vcs_zcode_reproduction_qualification verdict;
    bool exact_reproduction_match;
    bool distinct_signer;
    bool signer_policy_approved;
    bool declared_operator_group_distinct;
    bool remote_transport_used;
    bool physical_independence_proven;
    bool identity_linkage_complete;
    uint32_t reproduction_receipts;
    uint8_t reproduction_receipt_root[32];
    uint8_t reproducer_signer[32];
    uint8_t reproducer_contributor_binding_root[32];
    uint8_t operator_group_root[32];
    uint8_t reproduce_rule;
};

const char *vcs_zcode_reproduction_qualification_string(
    enum vcs_zcode_reproduction_qualification verdict);

/* Reloads and rederives every named authority from the existing workspace
 * CAS. It never creates a directory or object. `physical_independence_proven`
 * is deliberately false in v1: signatures cannot prove physical location. */
enum vcs_zcode_reproduction_qualification
vcs_zcode_reproduction_qualify_cas(
    const char *workspace, const uint8_t score_receipt_root[32],
    const uint8_t policy_candidate_root[32],
    const uint8_t reproduction_request_root[32],
    const uint8_t reproduction_proof_set_root[32],
    uint64_t epoch, int64_t now_unix,
    struct vcs_zcode_reproduction_qualification_report *out);

#endif /* ZCL_VCS_ZCODE_REPRODUCTION_QUALIFICATION_H */
