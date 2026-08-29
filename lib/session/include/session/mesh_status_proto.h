/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical authenticated-machine status request and receipt wire. */

#ifndef ZCL_SESSION_MESH_STATUS_PROTO_H
#define ZCL_SESSION_MESH_STATUS_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_STATUS_PROTO_VERSION 1u
#define MESH_STATUS_PROTO_FLAGS_NONE 0u
#define MESH_STATUS_CAP_STATUS_READ UINT64_C(1)
#define MESH_STATUS_MAX_LIFETIME_SECONDS UINT64_C(60)
#define MESH_STATUS_CAPSULE_MAX 4096u

#define MESH_STATUS_REQUEST_V1_WIRE_BYTES 276u
#define MESH_STATUS_RECEIPT_V1_FIXED_BYTES 408u
#define MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES \
    (MESH_STATUS_RECEIPT_V1_FIXED_BYTES + MESH_STATUS_CAPSULE_MAX)

enum mesh_status_receipt_status {
    MESH_STATUS_RECEIPT_OK = 0,
    MESH_STATUS_RECEIPT_BAD_REQUEST = 1,
    MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE = 2,
    MESH_STATUS_RECEIPT_NOT_PAIRED = 3,
    MESH_STATUS_RECEIPT_REVOKED = 4,
    MESH_STATUS_RECEIPT_EXPIRED = 5,
    MESH_STATUS_RECEIPT_SESSION_MISMATCH = 6,
    MESH_STATUS_RECEIPT_AUTHORITY_CHANGED = 7,
    MESH_STATUS_RECEIPT_DELEGATION_INVALID = 8,
    MESH_STATUS_RECEIPT_INTERNAL = 9,
};

enum mesh_status_proto_error {
    MESH_STATUS_PROTO_OK = 0,
    MESH_STATUS_PROTO_NULL,
    MESH_STATUS_PROTO_SIZE,
    MESH_STATUS_PROTO_MAGIC,
    MESH_STATUS_PROTO_VERSION_INVALID,
    MESH_STATUS_PROTO_FLAGS,
    MESH_STATUS_PROTO_CAPABILITY,
    MESH_STATUS_PROTO_FIELD,
    MESH_STATUS_PROTO_TIME,
    MESH_STATUS_PROTO_STATUS,
    MESH_STATUS_PROTO_CAPSULE_ROOT,
    MESH_STATUS_PROTO_KEY_MISMATCH,
    MESH_STATUS_PROTO_SIGNATURE,
};

struct mesh_status_request_v1 {
    uint16_t version;
    uint16_t flags;
    uint64_t capability;
    uint8_t request_id[32];
    uint8_t network_genesis[32];
    uint8_t target_master_pubkey[32];
    uint8_t requester_master_pubkey[32];
    uint8_t requester_noise_static[32];
    uint8_t pairing_id[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t connection_serial;
    uint64_t issued_unix;
    uint64_t expires_unix;
};

struct mesh_status_receipt_v1 {
    uint16_t version;
    uint16_t flags;
    enum mesh_status_receipt_status status;
    uint8_t request_id[32];
    uint8_t request_root[32];
    uint8_t network_genesis[32];
    uint8_t pairing_id[32];
    uint8_t responder_master_pubkey[32];
    uint8_t responder_online_pubkey[32];
    uint8_t responder_noise_static[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t connection_serial;
    uint64_t revocation_generation;
    uint64_t observed_unix;
    uint64_t expires_unix;
    uint16_t capsule_len;
    uint8_t capsule_root[32];
    uint8_t capsule[MESH_STATUS_CAPSULE_MAX];
    uint8_t signature[64];
};

const char *mesh_status_proto_error_string(enum mesh_status_proto_error error);
const char *mesh_status_receipt_status_string(
    enum mesh_status_receipt_status status);

enum mesh_status_proto_error mesh_status_request_v1_validate(
    const struct mesh_status_request_v1 *request);
enum mesh_status_proto_error mesh_status_request_v1_encode(
    const struct mesh_status_request_v1 *request,
    uint8_t out[MESH_STATUS_REQUEST_V1_WIRE_BYTES]);
enum mesh_status_proto_error mesh_status_request_v1_decode(
    struct mesh_status_request_v1 *out, const uint8_t *wire, size_t wire_len);
enum mesh_status_proto_error mesh_status_request_v1_root(
    const struct mesh_status_request_v1 *request, uint8_t out[32]);

size_t mesh_status_receipt_v1_wire_size(
    const struct mesh_status_receipt_v1 *receipt);
enum mesh_status_proto_error mesh_status_capsule_v1_root(
    const uint8_t *capsule, size_t capsule_len, uint8_t out[32]);
enum mesh_status_proto_error mesh_status_receipt_v1_validate(
    const struct mesh_status_receipt_v1 *receipt);
enum mesh_status_proto_error mesh_status_receipt_v1_sign(
    struct mesh_status_receipt_v1 *receipt,
    const uint8_t responder_online_seed[32]);
enum mesh_status_proto_error mesh_status_receipt_v1_encode(
    const struct mesh_status_receipt_v1 *receipt, uint8_t *out,
    size_t out_capacity, size_t *out_len);
enum mesh_status_proto_error mesh_status_receipt_v1_decode(
    struct mesh_status_receipt_v1 *out, const uint8_t *wire, size_t wire_len);
enum mesh_status_proto_error mesh_status_receipt_v1_root(
    const struct mesh_status_receipt_v1 *receipt, uint8_t out[32]);
enum mesh_status_proto_error mesh_status_receipt_v1_matches_request(
    const struct mesh_status_receipt_v1 *receipt,
    const struct mesh_status_request_v1 *request);

#endif /* ZCL_SESSION_MESH_STATUS_PROTO_H */
