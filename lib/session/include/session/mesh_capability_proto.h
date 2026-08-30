/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical bounded capability-lifecycle control frames. */

#ifndef ZCL_SESSION_MESH_CAPABILITY_PROTO_H
#define ZCL_SESSION_MESH_CAPABILITY_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define MESH_CAPABILITY_PROTO_VERSION 1u
#define MESH_CAPABILITY_PROTO_FLAGS_NONE 0u
#define MESH_CAPABILITY_MAX_LIFETIME_SECONDS UINT64_C(86400)
#define MESH_CAPABILITY_MAX_BYTES UINT64_C(1073741824)
#define MESH_CAPABILITY_MAX_CPU_MILLISECONDS UINT64_C(3600000)
#define MESH_CAPABILITY_MAX_MEMORY_BYTES UINT64_C(4294967296)
#define MESH_CAPABILITY_MAX_PROCESSES UINT32_C(64)
#define MESH_CAPABILITY_MAX_CONCURRENCY UINT32_C(64)
#define MESH_CAPABILITY_MAX_WALL_MILLISECONDS UINT64_C(86400000)

enum mesh_capability_kind {
    MESH_CAPABILITY_KIND_PRIVATE_OBJECT_RECEIVE = UINT64_C(1) << 0,
    MESH_CAPABILITY_KIND_REMOTE_BUILD = UINT64_C(1) << 1,
    MESH_CAPABILITY_KIND_REMOTE_TEST = UINT64_C(1) << 2,
    MESH_CAPABILITY_KIND_SERVICE_TUNNEL = UINT64_C(1) << 3,
    MESH_CAPABILITY_KIND_TERMINAL = UINT64_C(1) << 4,
    MESH_CAPABILITY_KIND_APP_ACTIVATE = UINT64_C(1) << 5,
};

#define MESH_CAPABILITY_KIND_KNOWN \
    (MESH_CAPABILITY_KIND_PRIVATE_OBJECT_RECEIVE | \
     MESH_CAPABILITY_KIND_REMOTE_BUILD | MESH_CAPABILITY_KIND_REMOTE_TEST | \
     MESH_CAPABILITY_KIND_SERVICE_TUNNEL | MESH_CAPABILITY_KIND_TERMINAL | \
     MESH_CAPABILITY_KIND_APP_ACTIVATE)

enum mesh_capability_result {
    MESH_CAPABILITY_RESULT_STORE = UINT64_C(1) << 0,
    MESH_CAPABILITY_RESULT_RETURN = UINT64_C(1) << 1,
};

#define MESH_CAPABILITY_RESULT_KNOWN \
    (MESH_CAPABILITY_RESULT_STORE | MESH_CAPABILITY_RESULT_RETURN)

enum mesh_capability_deny {
    MESH_CAPABILITY_POLICY_DENY_WALLET = UINT64_C(1) << 0,
    MESH_CAPABILITY_POLICY_DENY_CONSENSUS = UINT64_C(1) << 1,
    MESH_CAPABILITY_POLICY_DENY_CANONICAL_DATADIR = UINT64_C(1) << 2,
    MESH_CAPABILITY_POLICY_DENY_DEPLOYMENT = UINT64_C(1) << 3,
    MESH_CAPABILITY_POLICY_DENY_SECRETS = UINT64_C(1) << 4,
    MESH_CAPABILITY_POLICY_DENY_DELEGATION = UINT64_C(1) << 5,
    MESH_CAPABILITY_POLICY_DENY_EXECUTE = UINT64_C(1) << 6,
    MESH_CAPABILITY_POLICY_DENY_INSTALL = UINT64_C(1) << 7,
};

/* These bits deny ambient authority outside the one exact capability named
 * by the proposal. A future terminal or activation worker remains bounded by
 * that capability; it never acquires generic execute, install, deployment,
 * wallet, consensus, datadir, secret, or delegation authority. */
#define MESH_CAPABILITY_POLICY_DENY_REQUIRED \
    (MESH_CAPABILITY_POLICY_DENY_WALLET | \
     MESH_CAPABILITY_POLICY_DENY_CONSENSUS | \
     MESH_CAPABILITY_POLICY_DENY_CANONICAL_DATADIR | \
     MESH_CAPABILITY_POLICY_DENY_DEPLOYMENT | \
     MESH_CAPABILITY_POLICY_DENY_SECRETS | \
     MESH_CAPABILITY_POLICY_DENY_DELEGATION | \
     MESH_CAPABILITY_POLICY_DENY_EXECUTE | \
     MESH_CAPABILITY_POLICY_DENY_INSTALL)
#define MESH_CAPABILITY_POLICY_DENY_KNOWN \
    MESH_CAPABILITY_POLICY_DENY_REQUIRED

enum mesh_capability_frame_kind {
    MESH_CAPABILITY_FRAME_PROPOSAL = 1,
    MESH_CAPABILITY_FRAME_COMMIT = 2,
    MESH_CAPABILITY_FRAME_GRANT = 3,
    MESH_CAPABILITY_FRAME_REFUSAL = 4,
    MESH_CAPABILITY_FRAME_RENEW = 5,
    MESH_CAPABILITY_FRAME_CANCEL = 6,
    MESH_CAPABILITY_FRAME_ACK = 7,
};

enum mesh_capability_refusal_reason {
    MESH_CAPABILITY_REFUSAL_BAD_PROPOSAL = 1,
    MESH_CAPABILITY_REFUSAL_NOT_PAIRED = 2,
    MESH_CAPABILITY_REFUSAL_REVOKED = 3,
    MESH_CAPABILITY_REFUSAL_EXPIRED = 4,
    MESH_CAPABILITY_REFUSAL_SESSION_MISMATCH = 5,
    MESH_CAPABILITY_REFUSAL_OWNER_DECLINED = 6,
    MESH_CAPABILITY_REFUSAL_LIMIT = 7,
    MESH_CAPABILITY_REFUSAL_AUTHORITY_CHANGED = 8,
    MESH_CAPABILITY_REFUSAL_INTERNAL = 9,
};

enum mesh_capability_ack_status {
    MESH_CAPABILITY_ACK_APPLIED = 1,
    MESH_CAPABILITY_ACK_ALREADY_APPLIED = 2,
};

enum mesh_capability_proto_error {
    MESH_CAPABILITY_PROTO_OK = 0,
    MESH_CAPABILITY_PROTO_NULL,
    MESH_CAPABILITY_PROTO_SIZE,
    MESH_CAPABILITY_PROTO_MAGIC,
    MESH_CAPABILITY_PROTO_VERSION_INVALID,
    MESH_CAPABILITY_PROTO_FLAGS,
    MESH_CAPABILITY_PROTO_KIND_INVALID,
    MESH_CAPABILITY_PROTO_FIELD,
    MESH_CAPABILITY_PROTO_LIMIT,
    MESH_CAPABILITY_PROTO_TIME,
    MESH_CAPABILITY_PROTO_STATUS,
    MESH_CAPABILITY_PROTO_KEY_MISMATCH,
    MESH_CAPABILITY_PROTO_SIGNATURE,
};

#define MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES 440u
#define MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES 320u
#define MESH_CAPABILITY_GRANT_V1_WIRE_BYTES 360u
#define MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES 220u
#define MESH_CAPABILITY_RENEW_V1_WIRE_BYTES 320u
#define MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES 272u
#define MESH_CAPABILITY_ACK_V1_WIRE_BYTES 284u
#define MESH_CAPABILITY_FRAME_V1_MAX MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES

struct mesh_capability_proposal_v1 {
    uint8_t network_genesis[32];
    uint8_t proposal_id[32];
    uint8_t target_master_pubkey[32];
    uint8_t subject_master_pubkey[32];
    uint8_t subject_noise_static[32];
    uint8_t input_root[32];
    uint8_t nonce[32];
    uint8_t idempotency_key[32];
    uint64_t capability;
    uint64_t result_mask;
    uint64_t max_bytes;
    uint64_t max_cpu_milliseconds;
    uint64_t max_memory_bytes;
    uint32_t max_processes;
    uint32_t max_concurrency;
    uint64_t max_wall_milliseconds;
    uint64_t not_before_unix;
    uint64_t expires_unix;
    uint64_t deny_mask;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_commit_v1 {
    uint8_t proposal_id[32];
    uint8_t proposal_root[32];
    uint8_t commit_id[32];
    uint8_t target_master_pubkey[32];
    uint8_t subject_master_pubkey[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t plan_generation;
    uint64_t committed_unix;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_grant_v1 {
    uint8_t proposal_id[32];
    uint8_t proposal_root[32];
    uint8_t commit_id[32];
    uint8_t grant_id[32];
    uint8_t grant_nonce[32];
    uint8_t target_master_pubkey[32];
    uint8_t subject_master_pubkey[32];
    uint64_t issued_unix;
    uint64_t not_before_unix;
    uint64_t expires_unix;
    uint64_t revocation_generation;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_refusal_v1 {
    uint8_t request_id[32];
    uint8_t request_root[32];
    uint8_t target_master_pubkey[32];
    enum mesh_capability_refusal_reason reason;
    uint64_t observed_unix;
    uint64_t authority_generation;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_renew_v1 {
    uint8_t request_id[32];
    uint8_t prior_grant_id[32];
    uint8_t replacement_proposal_id[32];
    uint8_t replacement_proposal_root[32];
    uint8_t target_master_pubkey[32];
    uint8_t subject_master_pubkey[32];
    uint64_t requested_not_before_unix;
    uint64_t requested_expires_unix;
    uint64_t revocation_generation;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_cancel_v1 {
    uint8_t cancel_id[32];
    uint8_t grant_id[32];
    uint8_t operation_id[32];
    uint8_t target_master_pubkey[32];
    uint8_t subject_master_pubkey[32];
    uint64_t requested_unix;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_ack_v1 {
    uint8_t ack_id[32];
    uint8_t request_id[32];
    uint8_t request_root[32];
    uint8_t target_master_pubkey[32];
    uint8_t subject_master_pubkey[32];
    enum mesh_capability_frame_kind acknowledged_kind;
    enum mesh_capability_ack_status status;
    uint64_t observed_unix;
    uint64_t authority_generation;
    uint8_t signer_online_pubkey[32];
    uint8_t signature[64];
};

struct mesh_capability_frame_view_v1 {
    enum mesh_capability_frame_kind kind;
    union {
        struct mesh_capability_proposal_v1 proposal;
        struct mesh_capability_commit_v1 commit;
        struct mesh_capability_grant_v1 grant;
        struct mesh_capability_refusal_v1 refusal;
        struct mesh_capability_renew_v1 renew;
        struct mesh_capability_cancel_v1 cancel;
        struct mesh_capability_ack_v1 ack;
    } body;
};

const char *mesh_capability_proto_error_string(
    enum mesh_capability_proto_error error);
enum mesh_capability_proto_error mesh_capability_frame_v1_validate(
    const struct mesh_capability_frame_view_v1 *frame);
enum mesh_capability_proto_error mesh_capability_frame_v1_sign(
    struct mesh_capability_frame_view_v1 *frame,
    const uint8_t signer_online_seed[32]);
enum mesh_capability_proto_error mesh_capability_frame_v1_root(
    const struct mesh_capability_frame_view_v1 *frame, uint8_t out[32]);

#define MESH_CAPABILITY_DECLARE_ENCODER(name) \
    enum mesh_capability_proto_error mesh_capability_##name##_v1_encode( \
        const struct mesh_capability_##name##_v1 *frame, uint8_t *out, \
        size_t out_capacity, size_t *out_len)

MESH_CAPABILITY_DECLARE_ENCODER(proposal);
MESH_CAPABILITY_DECLARE_ENCODER(commit);
MESH_CAPABILITY_DECLARE_ENCODER(grant);
MESH_CAPABILITY_DECLARE_ENCODER(refusal);
MESH_CAPABILITY_DECLARE_ENCODER(renew);
MESH_CAPABILITY_DECLARE_ENCODER(cancel);
MESH_CAPABILITY_DECLARE_ENCODER(ack);
#undef MESH_CAPABILITY_DECLARE_ENCODER

enum mesh_capability_proto_error mesh_capability_frame_v1_decode(
    struct mesh_capability_frame_view_v1 *out, const uint8_t *wire,
    size_t wire_len);

#endif /* ZCL_SESSION_MESH_CAPABILITY_PROTO_H */
