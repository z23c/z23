/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only package continuity policies. */
#ifndef ZCL_VCS_ZCODE_CONTINUITY_POLICY_H
#define ZCL_VCS_ZCODE_CONTINUITY_POLICY_H

#include "vcs/zcode_patronage.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_score_receipt.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CONTINUITY_POLICY_DOMAIN \
    "zcl.zcode.continuity_policy.v1"
#define VCS_ZCODE_CONTINUITY_POLICY_ROOT_DOMAIN \
    "zcl.zcode.continuity_policy.root.v1"
#define VCS_ZCODE_CONTINUITY_EVENT_KEY_DOMAIN \
    "zcl.zcode.continuity_event_key.v1"
#define VCS_ZCODE_CREATION_EVENT_KEY_DOMAIN \
    "zcl.zcode.creation_event_key.v1"
#define VCS_ZCODE_CONTINUITY_POLICY_VERSION 1u
#define VCS_ZCODE_CONTINUITY_POLICY_BODY_BYTES 352u
#define VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES 416u

#define VCS_ZCODE_CONTINUITY_BORN_RED_FIX UINT16_C(0x0001)
#define VCS_ZCODE_CONTINUITY_SECURITY_FIX UINT16_C(0x0002)
#define VCS_ZCODE_CONTINUITY_INDEPENDENT_REPRODUCTION UINT16_C(0x0004)
#define VCS_ZCODE_CONTINUITY_COMPATIBILITY UINT16_C(0x0008)
#define VCS_ZCODE_CONTINUITY_PRESERVATION UINT16_C(0x0010)
#define VCS_ZCODE_CONTINUITY_ALLOWED_EVENT_MASK \
    (VCS_ZCODE_CONTINUITY_BORN_RED_FIX | \
     VCS_ZCODE_CONTINUITY_SECURITY_FIX | \
     VCS_ZCODE_CONTINUITY_INDEPENDENT_REPRODUCTION | \
     VCS_ZCODE_CONTINUITY_COMPATIBILITY | \
     VCS_ZCODE_CONTINUITY_PRESERVATION)

#define VCS_ZCODE_CONTINUITY_NO_AUTHORITY 0x01u
#define VCS_ZCODE_CONTINUITY_SIMULATION_ONLY 0x02u
#define VCS_ZCODE_CONTINUITY_ANONYMOUS_DISPLAY 0x04u

enum vcs_zcode_continuity_error {
    VCS_ZCODE_CONTINUITY_OK = 0,
    VCS_ZCODE_CONTINUITY_NULL,
    VCS_ZCODE_CONTINUITY_WIRE_SIZE,
    VCS_ZCODE_CONTINUITY_MAGIC,
    VCS_ZCODE_CONTINUITY_VERSION,
    VCS_ZCODE_CONTINUITY_EVENT_MASK,
    VCS_ZCODE_CONTINUITY_FLAGS,
    VCS_ZCODE_CONTINUITY_ROOT,
    VCS_ZCODE_CONTINUITY_TRANSITION,
    VCS_ZCODE_CONTINUITY_CAP,
    VCS_ZCODE_CONTINUITY_TIME,
    VCS_ZCODE_CONTINUITY_SEQUENCE,
    VCS_ZCODE_CONTINUITY_SIGNATURE,
    VCS_ZCODE_CONTINUITY_CONTEXT,
    VCS_ZCODE_CONTINUITY_CAS,
    VCS_ZCODE_CONTINUITY_NETWORK,
    VCS_ZCODE_CONTINUITY_CONTRIBUTOR,
    VCS_ZCODE_CONTINUITY_PACKAGE,
    VCS_ZCODE_CONTINUITY_RELEASE,
    VCS_ZCODE_CONTINUITY_PROOF_POLICY,
};

struct vcs_zcode_continuity_policy_v1 {
    uint16_t schema_version;
    uint16_t event_mask;
    uint8_t flags;
    uint8_t network_genesis_root[32];
    uint8_t zc23_token_or_simulation_root[32];
    uint8_t patron_contributor_binding_root[32];
    uint8_t patron_zid_pubkey[32];
    uint8_t package_root[32];
    uint8_t current_release_root[32];
    uint8_t from_capsule_root[32];
    uint8_t to_capsule_root[32];
    uint8_t proof_policy_root[32];
    uint32_t maximum_cycles;
    uint64_t per_cycle_cap_atoms;
    uint64_t total_cap_atoms;
    int64_t created_unix;
    int64_t expires_unix;
    uint64_t sequence;
    uint8_t signature[64];
};

const char *vcs_zcode_continuity_error_string(
    enum vcs_zcode_continuity_error error);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_validate(
    const struct vcs_zcode_continuity_policy_v1 *policy);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_serialize(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    uint8_t out[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES]);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_continuity_policy_v1 *out);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_root(
    const struct vcs_zcode_continuity_policy_v1 *policy, uint8_t out[32]);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_seal(
    struct vcs_zcode_continuity_policy_v1 *policy,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_verify(
    const struct vcs_zcode_continuity_policy_v1 *policy, int64_t now_unix);
enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_verify_cas(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context);
enum vcs_zcode_continuity_error vcs_zcode_continuity_event_key(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_score_receipt_v1 *score, uint8_t out[32]);

/* Neutral duplicate identity for continuity creation.  It is derived only
 * from registered creation evidence and never from a patronage policy, so a
 * useful repair/reproduction/preservation exists independently of funding.
 * SECURITY_FIX deliberately aliases BORN_RED_FIX until a future wire binds
 * a structured security-finding authority. */
enum vcs_zcode_continuity_error vcs_zcode_creation_event_key(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_score_receipt_v1 *score, uint8_t out[32]);

#endif /* ZCL_VCS_ZCODE_CONTINUITY_POLICY_H */
