/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical fully simulated ZC23 patronage funding receipts. */
#ifndef ZCL_VCS_ZCODE_PATRONAGE_FUNDING_H
#define ZCL_VCS_ZCODE_PATRONAGE_FUNDING_H

#include "vcs/zcode_patronage.h"

#define VCS_ZCODE_PATRONAGE_FUNDING_DOMAIN \
    "zcl.zcode.patronage_funding.v1"
#define VCS_ZCODE_PATRONAGE_FUNDING_ROOT_DOMAIN \
    "zcl.zcode.patronage_funding.root.v1"
#define VCS_ZCODE_PATRONAGE_SIMULATION_PLAN_DOMAIN \
    "zcl.zcode.patronage_simulation_plan.v1"
#define VCS_ZCODE_PATRONAGE_FUNDING_VERSION 1u
#define VCS_ZCODE_PATRONAGE_FUNDING_BODY_BYTES 200u
#define VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES 264u

#define VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS 0x01u
#define VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES 0x02u

enum vcs_zcode_patronage_funding_kind {
    VCS_ZCODE_PATRONAGE_FUNDING_FULLY_SIMULATED = 1,
};

enum vcs_zcode_patronage_funding_error {
    VCS_ZCODE_PATRONAGE_FUNDING_OK = 0,
    VCS_ZCODE_PATRONAGE_FUNDING_NULL,
    VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE,
    VCS_ZCODE_PATRONAGE_FUNDING_MAGIC,
    VCS_ZCODE_PATRONAGE_FUNDING_SHAPE,
    VCS_ZCODE_PATRONAGE_FUNDING_ROOT,
    VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT,
    VCS_ZCODE_PATRONAGE_FUNDING_TIME,
    VCS_ZCODE_PATRONAGE_FUNDING_SIGNATURE,
    VCS_ZCODE_PATRONAGE_FUNDING_INTENT,
    VCS_ZCODE_PATRONAGE_FUNDING_CONTEXT,
};

struct vcs_zcode_patronage_funding_v1 {
    uint16_t schema_version;
    uint8_t funding_kind;
    uint8_t flags;
    uint8_t network_genesis_root[32];
    uint8_t patronage_intent_root[32];
    uint8_t simulation_plan_root[32];
    uint8_t funder_contributor_binding_root[32];
    uint8_t funder_zid_pubkey[32];
    uint64_t amount_atoms;
    int64_t created_unix;
    uint64_t sequence;
    uint8_t signature[64];
};

const char *vcs_zcode_patronage_funding_error_string(
    enum vcs_zcode_patronage_funding_error error);
enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_simulation_plan_root(
    const uint8_t patronage_intent_root[32], uint64_t amount_atoms,
    uint8_t out[32]);
enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_funding_validate(
    const struct vcs_zcode_patronage_funding_v1 *funding);
enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_funding_serialize(
    const struct vcs_zcode_patronage_funding_v1 *funding,
    uint8_t out[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES]);
enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_patronage_funding_v1 *out);
enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_root(
    const struct vcs_zcode_patronage_funding_v1 *funding, uint8_t out[32]);
enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_seal(
    struct vcs_zcode_patronage_funding_v1 *funding,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_verify(
    const struct vcs_zcode_patronage_funding_v1 *funding);
enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_funding_verify_cas(
    const struct vcs_zcode_patronage_funding_v1 *funding,
    const struct vcs_zcode_patronage_validation_context *context);

#endif
