/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical signed offer for one bounded private mesh object. */

#ifndef ZCL_SESSION_MESH_PRIVATE_OBJECT_PROTO_H
#define ZCL_SESSION_MESH_PRIVATE_OBJECT_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_PRIVATE_OBJECT_PROTO_VERSION 1u
#define MESH_PRIVATE_OBJECT_FLAGS_NONE 0u
#define MESH_PRIVATE_OBJECT_TAG_BYTES UINT32_C(16)
#define MESH_PRIVATE_OBJECT_CHUNK_BYTES UINT32_C(65536)
#define MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES \
    (MESH_PRIVATE_OBJECT_CHUNK_BYTES - MESH_PRIVATE_OBJECT_TAG_BYTES)
#define MESH_PRIVATE_OBJECT_MAX_OBJECT_BYTES UINT64_C(1073741824)
#define MESH_PRIVATE_OBJECT_MAX_CIPHERTEXT_BYTES UINT64_C(2147483648)
#define MESH_PRIVATE_OBJECT_MAX_LIFETIME_SECONDS UINT64_C(600)

enum mesh_private_object_deny {
    MESH_PRIVATE_OBJECT_DENY_WALLET = UINT64_C(1) << 0,
    MESH_PRIVATE_OBJECT_DENY_CONSENSUS = UINT64_C(1) << 1,
    MESH_PRIVATE_OBJECT_DENY_CANONICAL_DATADIR = UINT64_C(1) << 2,
    MESH_PRIVATE_OBJECT_DENY_DEPLOYMENT = UINT64_C(1) << 3,
    MESH_PRIVATE_OBJECT_DENY_SECRETS = UINT64_C(1) << 4,
    MESH_PRIVATE_OBJECT_DENY_DELEGATION = UINT64_C(1) << 5,
    MESH_PRIVATE_OBJECT_DENY_EXECUTE = UINT64_C(1) << 6,
    MESH_PRIVATE_OBJECT_DENY_INSTALL = UINT64_C(1) << 7,
};

#define MESH_PRIVATE_OBJECT_DENY_REQUIRED \
    (MESH_PRIVATE_OBJECT_DENY_WALLET | MESH_PRIVATE_OBJECT_DENY_CONSENSUS | \
     MESH_PRIVATE_OBJECT_DENY_CANONICAL_DATADIR | \
     MESH_PRIVATE_OBJECT_DENY_DEPLOYMENT | MESH_PRIVATE_OBJECT_DENY_SECRETS | \
     MESH_PRIVATE_OBJECT_DENY_DELEGATION | MESH_PRIVATE_OBJECT_DENY_EXECUTE | \
     MESH_PRIVATE_OBJECT_DENY_INSTALL)
#define MESH_PRIVATE_OBJECT_DENY_KNOWN MESH_PRIVATE_OBJECT_DENY_REQUIRED
#define MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES 556u

enum mesh_private_object_proto_error {
    MESH_PRIVATE_OBJECT_PROTO_OK = 0,
    MESH_PRIVATE_OBJECT_PROTO_NULL,
    MESH_PRIVATE_OBJECT_PROTO_SIZE,
    MESH_PRIVATE_OBJECT_PROTO_MAGIC,
    MESH_PRIVATE_OBJECT_PROTO_VERSION_INVALID,
    MESH_PRIVATE_OBJECT_PROTO_FLAGS,
    MESH_PRIVATE_OBJECT_PROTO_FIELD,
    MESH_PRIVATE_OBJECT_PROTO_TIME,
    MESH_PRIVATE_OBJECT_PROTO_LIMIT,
    MESH_PRIVATE_OBJECT_PROTO_CHUNKS,
    MESH_PRIVATE_OBJECT_PROTO_DENY,
    MESH_PRIVATE_OBJECT_PROTO_KEY_MISMATCH,
    MESH_PRIVATE_OBJECT_PROTO_SIGNATURE,
    MESH_PRIVATE_OBJECT_PROTO_EXPECTATION,
};

struct mesh_private_object_offer_v1 {
    uint16_t version;
    uint16_t flags;
    uint8_t network_genesis[32];
    uint8_t pairing_id[32];
    uint8_t grant_id[32];
    uint8_t source_master_pubkey[32];
    uint8_t source_noise_static[32];
    uint8_t source_online_pubkey[32];
    uint8_t target_master_pubkey[32];
    uint8_t target_noise_static[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t pairing_revocation_generation;
    uint8_t request_id[32];
    uint8_t plaintext_root[32];
    uint8_t ciphertext_root[32];
    uint64_t object_size_bytes;
    uint64_t ciphertext_size_bytes;
    uint32_t chunk_size;
    uint32_t chunk_count;
    uint8_t ephemeral_x25519_pubkey[32];
    uint64_t issued_unix;
    uint64_t expires_unix;
    uint64_t deny_mask;
    uint8_t signature[64];
};

/* Exact local authority and live-session facts against which an offer is
 * checked. This is a comparison value, not a wire capability or grant. */
struct mesh_private_object_offer_expectation_v1 {
    uint8_t network_genesis[32];
    uint8_t pairing_id[32];
    uint8_t grant_id[32];
    uint8_t source_master_pubkey[32];
    uint8_t source_noise_static[32];
    uint8_t source_online_pubkey[32];
    uint8_t target_master_pubkey[32];
    uint8_t target_noise_static[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint64_t pairing_revocation_generation;
    uint8_t request_id[32];
    uint8_t plaintext_root[32];
    uint8_t ciphertext_root[32];
    uint64_t exact_object_size_bytes;
    uint64_t exact_ciphertext_size_bytes;
    uint64_t required_deny_mask;
};

const char *mesh_private_object_proto_error_string(
    enum mesh_private_object_proto_error error);
/* Derive the request id from the target-local grant nonce and every unsigned
 * offer field except request_id itself. The sender must do this before sign;
 * the receiver re-derives it from its durable grant before claim. */
enum mesh_private_object_proto_error
mesh_private_object_offer_request_id_v1_derive(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t grant_nonce[32], uint8_t out[32]);
/* Stable pre-encryption context. It binds every offer field except the
 * ciphertext root, nonce-proving request id, and signature, which necessarily
 * become known only after ciphertext exists. */
enum mesh_private_object_proto_error
mesh_private_object_offer_key_context_v1(
    const struct mesh_private_object_offer_v1 *offer, uint8_t out[32]);
enum mesh_private_object_proto_error mesh_private_object_offer_v1_validate(
    const struct mesh_private_object_offer_v1 *offer);
enum mesh_private_object_proto_error mesh_private_object_offer_v1_sign(
    struct mesh_private_object_offer_v1 *offer,
    const uint8_t source_online_seed[32]);
enum mesh_private_object_proto_error mesh_private_object_offer_v1_encode(
    const struct mesh_private_object_offer_v1 *offer,
    uint8_t out[MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES]);
enum mesh_private_object_proto_error mesh_private_object_offer_v1_decode(
    struct mesh_private_object_offer_v1 *out, const uint8_t *wire,
    size_t wire_len);
enum mesh_private_object_proto_error mesh_private_object_offer_v1_root(
    const struct mesh_private_object_offer_v1 *offer, uint8_t out[32]);
enum mesh_private_object_proto_error mesh_private_object_offer_v1_matches(
    const struct mesh_private_object_offer_v1 *offer,
    const struct mesh_private_object_offer_expectation_v1 *expected,
    uint64_t now_unix);

#endif /* ZCL_SESSION_MESH_PRIVATE_OBJECT_PROTO_H */
