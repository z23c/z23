/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulated patronage settlement and refund receipts. */
#ifndef ZCL_VCS_ZCODE_PATRONAGE_SETTLEMENT_H
#define ZCL_VCS_ZCODE_PATRONAGE_SETTLEMENT_H

#include "vcs/zcode_patronage_funding.h"
#include "vcs/zcode_creation_attribution.h"

#define VCS_ZCODE_PATRONAGE_SETTLEMENT_DOMAIN \
    "zcl.zcode.patronage_settlement.v1"
#define VCS_ZCODE_PATRONAGE_SETTLEMENT_ROOT_DOMAIN \
    "zcl.zcode.patronage_settlement.root.v1"
#define VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION 1u
#define VCS_ZCODE_PATRONAGE_SETTLEMENT_BODY_BYTES 440u
#define VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES 504u

#define VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY 0x01u
#define VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS 0x02u
#define VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES 0x04u

enum vcs_zcode_patronage_settlement_action {
    VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED = 1,
    VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED = 2,
};

enum vcs_zcode_patronage_settlement_error {
    VCS_ZCODE_PATRONAGE_SETTLEMENT_OK = 0,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_MAGIC,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_ROOT,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_AMOUNT,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_SIGNATURE,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING,
    VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE,
};

struct vcs_zcode_patronage_settlement_v1 {
    uint16_t schema_version;
    uint8_t action;
    uint8_t flags;
    uint8_t network_genesis_root[32];
    uint8_t patronage_intent_root[32];
    uint8_t patronage_funding_root[32];
    uint8_t creation_attribution_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t proof_policy_root[32];
    uint8_t proof_set_root[32];
    uint8_t proven_lane_root[32];
    uint8_t score_receipt_root[32];
    uint8_t recipient_contributor_binding_root[32];
    uint8_t settler_zid_pubkey[32];
    uint64_t amount_atoms;
    int64_t created_unix;
    uint64_t observed_height;
    int64_t observed_mtp;
    uint64_t sequence;
    uint8_t signature[64];
};

struct vcs_zcode_patronage_settlement_validation_context {
    const struct vcs_zcode_patronage_validation_context *patronage;
    const struct vcs_zcode_creation_validation_context *creation;
    uint64_t active_height;
    int64_t active_mtp;
    int64_t now_unix;
};

const char *vcs_zcode_patronage_settlement_error_string(
    enum vcs_zcode_patronage_settlement_error error);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_validate(
    const struct vcs_zcode_patronage_settlement_v1 *settlement);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_serialize(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    uint8_t out[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES]);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_patronage_settlement_v1 *out);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_root(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    uint8_t out[32]);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_seal(
    struct vcs_zcode_patronage_settlement_v1 *settlement,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_verify(
    const struct vcs_zcode_patronage_settlement_v1 *settlement);
enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_verify_cas(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    const struct vcs_zcode_patronage_settlement_validation_context *context);

#endif
