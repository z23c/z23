/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only ZC23 patronage intents. */
#ifndef ZCL_VCS_ZCODE_PATRONAGE_H
#define ZCL_VCS_ZCODE_PATRONAGE_H

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_PATRONAGE_INTENT_DOMAIN \
    "zcl.zcode.patronage_intent.v1"
#define VCS_ZCODE_PATRONAGE_INTENT_ROOT_DOMAIN \
    "zcl.zcode.patronage_intent.root.v1"
#define VCS_ZCODE_PATRONAGE_INTENT_VERSION 1u
#define VCS_ZCODE_PATRONAGE_INTENT_BODY_BYTES 328u
#define VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES 392u

#define VCS_ZCODE_PATRONAGE_NO_AUTHORITY 0x01u
#define VCS_ZCODE_PATRONAGE_ANONYMOUS_DISPLAY 0x02u
#define VCS_ZCODE_PATRONAGE_SIMULATION_ONLY 0x04u

enum vcs_zcode_patronage_mode {
    VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION = 1,
    VCS_ZCODE_PATRONAGE_PACKAGE_CONTINUITY = 2,
    VCS_ZCODE_PATRONAGE_DIRECT_GIFT = 3,
};

enum vcs_zcode_patronage_target_kind {
    VCS_ZCODE_PATRONAGE_TARGET_TASK = 1,
    VCS_ZCODE_PATRONAGE_TARGET_PACKAGE = 2,
    VCS_ZCODE_PATRONAGE_TARGET_CREATION = 3,
    VCS_ZCODE_PATRONAGE_TARGET_CONTRIBUTOR = 4,
};

enum vcs_zcode_patronage_trust_mode {
    VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER = 1,
    VCS_ZCODE_PATRONAGE_SIMULATED_FUNDING = 2,
    VCS_ZCODE_PATRONAGE_FUTURE_ASSISTED_2OF3 = 3,
};

enum vcs_zcode_patronage_error {
    VCS_ZCODE_PATRONAGE_OK = 0,
    VCS_ZCODE_PATRONAGE_NULL,
    VCS_ZCODE_PATRONAGE_WIRE_SIZE,
    VCS_ZCODE_PATRONAGE_MAGIC,
    VCS_ZCODE_PATRONAGE_VERSION,
    VCS_ZCODE_PATRONAGE_ENUM,
    VCS_ZCODE_PATRONAGE_FLAGS,
    VCS_ZCODE_PATRONAGE_ROOT,
    VCS_ZCODE_PATRONAGE_AMOUNT,
    VCS_ZCODE_PATRONAGE_TIME,
    VCS_ZCODE_PATRONAGE_SEQUENCE,
    VCS_ZCODE_PATRONAGE_SHAPE,
    VCS_ZCODE_PATRONAGE_SIGNATURE,
    VCS_ZCODE_PATRONAGE_CONTEXT,
    VCS_ZCODE_PATRONAGE_CAS,
    VCS_ZCODE_PATRONAGE_NETWORK,
    VCS_ZCODE_PATRONAGE_CONTRIBUTOR,
    VCS_ZCODE_PATRONAGE_TASK,
    VCS_ZCODE_PATRONAGE_POLICY,
    VCS_ZCODE_PATRONAGE_TARGET,
};

typedef bool (*vcs_zcode_patronage_binding_current_fn)(
    void *opaque, const uint8_t contributor_binding_root[32]);

struct vcs_zcode_patronage_validation_context {
    const char *workspace;
    const uint8_t *expected_network_genesis_root;
    int64_t now_unix;
    vcs_zcode_patronage_binding_current_fn binding_is_current;
    void *callback_opaque;
};

struct vcs_zcode_patronage_intent_v1 {
    uint16_t schema_version;
    uint8_t mode;
    uint8_t target_kind;
    uint8_t settlement_trust_mode;
    uint8_t flags;
    uint8_t network_genesis_root[32];
    uint8_t zc23_token_or_simulation_root[32];
    uint8_t patron_contributor_binding_root[32];
    uint8_t patron_zid_pubkey[32];
    uint8_t target_root[32];
    uint8_t task_root[32];
    uint8_t proof_policy_root[32];
    uint8_t intended_recipient_binding_root[32];
    uint64_t amount_atoms;
    int64_t created_unix;
    int64_t expires_unix;
    uint64_t refund_height;
    int64_t refund_unix;
    uint64_t sequence;
    uint64_t maximum_zcl_fee_zat;
    uint8_t signature[64];
};

const char *vcs_zcode_patronage_error_string(
    enum vcs_zcode_patronage_error error);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_validate(
    const struct vcs_zcode_patronage_intent_v1 *intent);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_serialize(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    uint8_t out[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES]);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_patronage_intent_v1 *out);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_signing_root(
    const struct vcs_zcode_patronage_intent_v1 *intent, uint8_t out[32]);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_root(
    const struct vcs_zcode_patronage_intent_v1 *intent, uint8_t out[32]);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_seal(
    struct vcs_zcode_patronage_intent_v1 *intent,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_verify(
    const struct vcs_zcode_patronage_intent_v1 *intent, int64_t now_unix);
enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_verify_cas(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const struct vcs_zcode_patronage_validation_context *context);

#endif
