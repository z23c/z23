/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical authenticated-machine terminal open/receipt and
 * bounded data/resize/close frame wire. Mirrors mesh_status_proto: fixed
 * wire sizes, strict decode-then-validate, domain-separated SHA3-256 roots,
 * and an Ed25519 receipt signature under the responder's online key. */

#ifndef ZCL_SESSION_MESH_TERMINAL_PROTO_H
#define ZCL_SESSION_MESH_TERMINAL_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_TERMINAL_PROTO_VERSION 1u
#define MESH_TERMINAL_PROTO_FLAGS_NONE 0u
/* The wire capability equals MESH_PAIRING_CAP_TERMINAL_EXEC (the pairing
 * authority bit); the test group pins the equality. */
#define MESH_TERMINAL_CAP_TERMINAL_EXEC UINT64_C(2)
#define MESH_TERMINAL_OPEN_MAX_LIFETIME_SECONDS UINT64_C(60)
#define MESH_TERMINAL_RECEIPT_MAX_LIFETIME_SECONDS UINT64_C(60)
#define MESH_TERMINAL_CAPSULE_MAX 4096u
#define MESH_TERMINAL_DATA_PAYLOAD_MAX 3072u
#define MESH_TERMINAL_MAX_COLS 512u
#define MESH_TERMINAL_MAX_ROWS 256u

#define MESH_TERMINAL_OPEN_V1_WIRE_BYTES 272u
#define MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES 400u
#define MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES \
    (MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES + MESH_TERMINAL_CAPSULE_MAX)
#define MESH_TERMINAL_DATA_V1_HEADER_BYTES 50u
#define MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES \
    (MESH_TERMINAL_DATA_V1_HEADER_BYTES + MESH_TERMINAL_DATA_PAYLOAD_MAX)
#define MESH_TERMINAL_RESIZE_V1_WIRE_BYTES 44u
#define MESH_TERMINAL_CLOSE_V1_WIRE_BYTES 41u

enum mesh_terminal_receipt_status {
    MESH_TERMINAL_RECEIPT_OK = 0,
    MESH_TERMINAL_RECEIPT_BAD_REQUEST = 1,
    MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE = 2,
    MESH_TERMINAL_RECEIPT_NOT_PAIRED = 3,
    MESH_TERMINAL_RECEIPT_REVOKED = 4,
    MESH_TERMINAL_RECEIPT_EXPIRED = 5,
    MESH_TERMINAL_RECEIPT_SESSION_MISMATCH = 6,
    MESH_TERMINAL_RECEIPT_AUTHORITY_CHANGED = 7,
    MESH_TERMINAL_RECEIPT_DELEGATION_INVALID = 8,
    MESH_TERMINAL_RECEIPT_CONCURRENCY_LIMIT = 9,
    MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE = 10,
    MESH_TERMINAL_RECEIPT_CLOSED = 11,
    MESH_TERMINAL_RECEIPT_INTERNAL = 12,
};

enum mesh_terminal_close_reason {
    MESH_TERMINAL_CLOSE_REQUESTED = 0,   /* the requester asked to close */
    MESH_TERMINAL_CLOSE_REVOKED = 1,     /* pairing revoked mid-session */
    MESH_TERMINAL_CLOSE_EXPIRED = 2,     /* pairing expired mid-session */
    MESH_TERMINAL_CLOSE_IDLE_TIMEOUT = 3,
    MESH_TERMINAL_CLOSE_LIFETIME_LIMIT = 4,
    MESH_TERMINAL_CLOSE_BYTE_LIMIT = 5,
    MESH_TERMINAL_CLOSE_SESSION_LOST = 6,
    MESH_TERMINAL_CLOSE_WORKER_EXITED = 7,
    MESH_TERMINAL_CLOSE_INTERNAL = 8,
    MESH_TERMINAL_CLOSE_SHUTDOWN = 9,
};

enum mesh_terminal_proto_error {
    MESH_TERMINAL_PROTO_OK = 0,
    MESH_TERMINAL_PROTO_NULL,
    MESH_TERMINAL_PROTO_SIZE,
    MESH_TERMINAL_PROTO_MAGIC,
    MESH_TERMINAL_PROTO_VERSION_INVALID,
    MESH_TERMINAL_PROTO_FLAGS,
    MESH_TERMINAL_PROTO_CAPABILITY,
    MESH_TERMINAL_PROTO_FIELD,
    MESH_TERMINAL_PROTO_TIME,
    MESH_TERMINAL_PROTO_GEOMETRY,
    MESH_TERMINAL_PROTO_STATUS,
    MESH_TERMINAL_PROTO_REASON,
    MESH_TERMINAL_PROTO_CAPSULE_ROOT,
    MESH_TERMINAL_PROTO_KEY_MISMATCH,
    MESH_TERMINAL_PROTO_SIGNATURE,
};

struct mesh_terminal_open_v1 {
    uint16_t version;
    uint16_t flags;
    uint64_t capability;
    uint8_t terminal_id[32];   /* also the request id the receipt binds */
    uint8_t pairing_id[32];
    uint8_t network_genesis[32];
    uint8_t target_master_pubkey[32];
    uint8_t requester_master_pubkey[32];
    uint8_t requester_noise_static[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t issued_unix;
    uint64_t expires_unix;
    uint16_t cols;
    uint16_t rows;
};

/* Same fixed layout as mesh_status_receipt_v1. OK carries the granted
 * session bounds ({"max_lifetime_s":...,"max_bytes":...,"cols":...,
 * "rows":...}); CLOSED carries the terminal close evidence
 * ({"bytes_in":N,"bytes_out":N,"duration_s":N,"reason":"..."}); every
 * refusal status carries no capsule. */
struct mesh_terminal_receipt_v1 {
    uint16_t version;
    uint16_t flags;
    enum mesh_terminal_receipt_status status;
    uint8_t request_id[32];    /* == the open's terminal_id */
    uint8_t request_root[32];  /* == the open's root */
    uint8_t network_genesis[32];
    uint8_t pairing_id[32];
    uint8_t responder_master_pubkey[32];
    uint8_t responder_online_pubkey[32];
    uint8_t responder_noise_static[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t revocation_generation;
    uint64_t observed_unix;
    uint64_t expires_unix;
    uint16_t capsule_len;
    uint8_t capsule_root[32];
    uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
    uint8_t signature[64];
};

struct mesh_terminal_data_v1 {
    uint8_t terminal_id[32];
    uint64_t seq;
    uint16_t payload_len;
    uint8_t payload[MESH_TERMINAL_DATA_PAYLOAD_MAX];
};

struct mesh_terminal_resize_v1 {
    uint8_t terminal_id[32];
    uint16_t cols;
    uint16_t rows;
};

struct mesh_terminal_close_v1 {
    uint8_t terminal_id[32];
    uint8_t reason; /* enum mesh_terminal_close_reason */
};

const char *mesh_terminal_proto_error_string(
    enum mesh_terminal_proto_error error);
const char *mesh_terminal_receipt_status_string(
    enum mesh_terminal_receipt_status status);
const char *mesh_terminal_close_reason_string(
    enum mesh_terminal_close_reason reason);

enum mesh_terminal_proto_error mesh_terminal_open_v1_validate(
    const struct mesh_terminal_open_v1 *open);
enum mesh_terminal_proto_error mesh_terminal_open_v1_encode(
    const struct mesh_terminal_open_v1 *open,
    uint8_t out[MESH_TERMINAL_OPEN_V1_WIRE_BYTES]);
enum mesh_terminal_proto_error mesh_terminal_open_v1_decode(
    struct mesh_terminal_open_v1 *out, const uint8_t *wire, size_t wire_len);
enum mesh_terminal_proto_error mesh_terminal_open_v1_root(
    const struct mesh_terminal_open_v1 *open, uint8_t out[32]);

size_t mesh_terminal_receipt_v1_wire_size(
    const struct mesh_terminal_receipt_v1 *receipt);
enum mesh_terminal_proto_error mesh_terminal_capsule_v1_root(
    const uint8_t *capsule, size_t capsule_len, uint8_t out[32]);
enum mesh_terminal_proto_error mesh_terminal_receipt_v1_validate(
    const struct mesh_terminal_receipt_v1 *receipt);
enum mesh_terminal_proto_error mesh_terminal_receipt_v1_sign(
    struct mesh_terminal_receipt_v1 *receipt,
    const uint8_t responder_online_seed[32]);
enum mesh_terminal_proto_error mesh_terminal_receipt_v1_encode(
    const struct mesh_terminal_receipt_v1 *receipt, uint8_t *out,
    size_t out_capacity, size_t *out_len);
enum mesh_terminal_proto_error mesh_terminal_receipt_v1_decode(
    struct mesh_terminal_receipt_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum mesh_terminal_proto_error mesh_terminal_receipt_v1_root(
    const struct mesh_terminal_receipt_v1 *receipt, uint8_t out[32]);
enum mesh_terminal_proto_error mesh_terminal_receipt_v1_matches_open(
    const struct mesh_terminal_receipt_v1 *receipt,
    const struct mesh_terminal_open_v1 *open);

enum mesh_terminal_proto_error mesh_terminal_data_v1_encode(
    const struct mesh_terminal_data_v1 *data, uint8_t *out,
    size_t out_capacity, size_t *out_len);
enum mesh_terminal_proto_error mesh_terminal_data_v1_decode(
    struct mesh_terminal_data_v1 *out, const uint8_t *wire, size_t wire_len);

enum mesh_terminal_proto_error mesh_terminal_resize_v1_encode(
    const struct mesh_terminal_resize_v1 *resize,
    uint8_t out[MESH_TERMINAL_RESIZE_V1_WIRE_BYTES]);
enum mesh_terminal_proto_error mesh_terminal_resize_v1_decode(
    struct mesh_terminal_resize_v1 *out, const uint8_t *wire,
    size_t wire_len);

enum mesh_terminal_proto_error mesh_terminal_close_v1_encode(
    const struct mesh_terminal_close_v1 *close_frame,
    uint8_t out[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES]);
enum mesh_terminal_proto_error mesh_terminal_close_v1_decode(
    struct mesh_terminal_close_v1 *out, const uint8_t *wire,
    size_t wire_len);

#endif /* ZCL_SESSION_MESH_TERMINAL_PROTO_H */
