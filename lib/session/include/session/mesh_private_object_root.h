/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical streaming roots for bounded private mesh objects. */

#ifndef ZCL_SESSION_MESH_PRIVATE_OBJECT_ROOT_H
#define ZCL_SESSION_MESH_PRIVATE_OBJECT_ROOT_H

#include "crypto/sha3.h"

#include <stddef.h>
#include <stdint.h>

enum mesh_private_object_root_kind {
    MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT = 1,
    MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT = 2,
};

enum mesh_private_object_root_error {
    MESH_PRIVATE_OBJECT_ROOT_OK = 0,
    MESH_PRIVATE_OBJECT_ROOT_NULL,
    MESH_PRIVATE_OBJECT_ROOT_PARAMETER,
    MESH_PRIVATE_OBJECT_ROOT_STATE,
    MESH_PRIVATE_OBJECT_ROOT_INDEX,
    MESH_PRIVATE_OBJECT_ROOT_LENGTH,
    MESH_PRIVATE_OBJECT_ROOT_OVERFLOW,
    MESH_PRIVATE_OBJECT_ROOT_INCOMPLETE,
};

struct mesh_private_object_root_v1 {
    struct sha3_256_ctx sha;
    uint64_t object_size_bytes;
    uint64_t ciphertext_size_bytes;
    uint64_t bytes_seen;
    uint32_t chunk_count;
    uint32_t next_chunk;
    enum mesh_private_object_root_kind kind;
    uint8_t state;
};

const char *mesh_private_object_root_error_string(
    enum mesh_private_object_root_error error);

/* The two sizes and chunk count must have canonical 65520-byte plaintext and
 * 16-byte tag geometry. Each update accepts exactly one complete chunk. */
enum mesh_private_object_root_error mesh_private_object_root_v1_init(
    struct mesh_private_object_root_v1 *root,
    enum mesh_private_object_root_kind kind, uint64_t object_size_bytes,
    uint64_t ciphertext_size_bytes, uint32_t chunk_count);

enum mesh_private_object_root_error mesh_private_object_root_v1_update(
    struct mesh_private_object_root_v1 *root, uint32_t chunk_index,
    const uint8_t *chunk, size_t chunk_len);

enum mesh_private_object_root_error mesh_private_object_root_v1_finalize(
    struct mesh_private_object_root_v1 *root, uint8_t out[32]);

#endif /* ZCL_SESSION_MESH_PRIVATE_OBJECT_ROOT_H */
