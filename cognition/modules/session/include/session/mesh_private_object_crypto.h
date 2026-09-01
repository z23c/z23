/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Allocation-free independently authenticated private-object chunks. */

#ifndef ZCL_SESSION_MESH_PRIVATE_OBJECT_CRYPTO_H
#define ZCL_SESSION_MESH_PRIVATE_OBJECT_CRYPTO_H

#include "session/mesh_private_object_proto.h"

#include <stddef.h>
#include <stdint.h>

enum mesh_private_object_chunk_error {
    MESH_PRIVATE_OBJECT_CHUNK_OK = 0,
    MESH_PRIVATE_OBJECT_CHUNK_NULL,
    MESH_PRIVATE_OBJECT_CHUNK_OFFER,
    MESH_PRIVATE_OBJECT_CHUNK_INDEX,
    MESH_PRIVATE_OBJECT_CHUNK_SIZE,
    MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH,
    MESH_PRIVATE_OBJECT_CHUNK_DH,
    MESH_PRIVATE_OBJECT_CHUNK_KDF,
    MESH_PRIVATE_OBJECT_CHUNK_AUTH,
};

const char *mesh_private_object_chunk_error_string(
    enum mesh_private_object_chunk_error error);

/* Return the exact plaintext and sealed lengths for one canonical chunk. */
enum mesh_private_object_chunk_error mesh_private_object_chunk_shape_v1(
    const struct mesh_private_object_offer_v1 *offer, uint32_t chunk_index,
    uint32_t *plaintext_bytes, uint32_t *sealed_bytes);

/* The sender's ephemeral secret and receiver's persistent Noise static secret
 * are accepted only at these narrow boundaries and cleansed from temporaries.
 * Caller buffers may alias neither input nor each other. */
enum mesh_private_object_chunk_error mesh_private_object_chunk_seal_v1(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t source_ephemeral_secret[32], uint32_t chunk_index,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *sealed, size_t sealed_cap, size_t *sealed_len);

enum mesh_private_object_chunk_error mesh_private_object_chunk_open_v1(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t target_noise_static_secret[32], uint32_t chunk_index,
    const uint8_t *sealed, size_t sealed_len,
    uint8_t *plaintext, size_t plaintext_cap, size_t *plaintext_len);

#endif /* ZCL_SESSION_MESH_PRIVATE_OBJECT_CRYPTO_H */
