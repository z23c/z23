/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded wire frames for resumable private-object transfer. */

#ifndef ZCL_SESSION_MESH_PRIVATE_OBJECT_FRAME_H
#define ZCL_SESSION_MESH_PRIVATE_OBJECT_FRAME_H

#include "session/mesh_private_object_proto.h"

#include <stddef.h>
#include <stdint.h>

#define MESH_PRIVATE_OBJECT_FRAME_VERSION 1u
#define MESH_PRIVATE_OBJECT_FRAME_FLAGS_NONE 0u
#define MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES 8u
#define MESH_PRIVATE_OBJECT_FRAME_OFFER_BYTES \
    (MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES + \
     MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES)
#define MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES 84u
#define MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES 80u
#define MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES 88u
#define MESH_PRIVATE_OBJECT_FRAME_MAX \
    (MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES + \
     MESH_PRIVATE_OBJECT_CHUNK_BYTES)

enum mesh_private_object_frame_kind {
    MESH_PRIVATE_OBJECT_FRAME_OFFER = 1,
    MESH_PRIVATE_OBJECT_FRAME_REQUEST = 2,
    MESH_PRIVATE_OBJECT_FRAME_CHUNK = 3,
    MESH_PRIVATE_OBJECT_FRAME_CANCEL = 4,
};

enum mesh_private_object_frame_error {
    MESH_PRIVATE_OBJECT_FRAME_OK = 0,
    MESH_PRIVATE_OBJECT_FRAME_NULL,
    MESH_PRIVATE_OBJECT_FRAME_SIZE,
    MESH_PRIVATE_OBJECT_FRAME_MAGIC,
    MESH_PRIVATE_OBJECT_FRAME_VERSION_INVALID,
    MESH_PRIVATE_OBJECT_FRAME_FLAGS,
    MESH_PRIVATE_OBJECT_FRAME_KIND_INVALID,
    MESH_PRIVATE_OBJECT_FRAME_FIELD,
    MESH_PRIVATE_OBJECT_FRAME_PAYLOAD,
};

struct mesh_private_object_chunk_request_v1 {
    uint8_t transfer_id[32];
    uint8_t offer_request_id[32];
    uint64_t chunk_request_id;
    uint32_t chunk_index;
};

struct mesh_private_object_chunk_v1 {
    uint8_t transfer_id[32];
    uint8_t offer_request_id[32];
    uint64_t chunk_request_id;
    uint32_t chunk_index;
    const uint8_t *sealed;
    uint32_t sealed_len;
};

struct mesh_private_object_cancel_v1 {
    uint8_t transfer_id[32];
    uint8_t offer_request_id[32];
    uint64_t cancel_id;
};

struct mesh_private_object_frame_view_v1 {
    enum mesh_private_object_frame_kind kind;
    union {
        struct mesh_private_object_offer_v1 offer;
        struct mesh_private_object_chunk_request_v1 request;
        struct mesh_private_object_chunk_v1 chunk;
        struct mesh_private_object_cancel_v1 cancel;
    } body;
};

const char *mesh_private_object_frame_error_string(
    enum mesh_private_object_frame_error error);

enum mesh_private_object_frame_error mesh_private_object_frame_offer_v1_encode(
    const struct mesh_private_object_offer_v1 *offer, uint8_t *out,
    size_t out_cap, size_t *out_len);
enum mesh_private_object_frame_error
mesh_private_object_frame_request_v1_encode(
    const struct mesh_private_object_chunk_request_v1 *request, uint8_t *out,
    size_t out_cap, size_t *out_len);
enum mesh_private_object_frame_error mesh_private_object_frame_chunk_v1_encode(
    const struct mesh_private_object_chunk_v1 *chunk, uint8_t *out,
    size_t out_cap, size_t *out_len);
enum mesh_private_object_frame_error mesh_private_object_frame_cancel_v1_encode(
    const struct mesh_private_object_cancel_v1 *cancel, uint8_t *out,
    size_t out_cap, size_t *out_len);

/* A decoded chunk's sealed pointer borrows the input frame. The caller must
 * retain the frame unchanged until it has copied or consumed those bytes. */
enum mesh_private_object_frame_error mesh_private_object_frame_v1_decode(
    struct mesh_private_object_frame_view_v1 *out, const uint8_t *wire,
    size_t wire_len);

#endif /* ZCL_SESSION_MESH_PRIVATE_OBJECT_FRAME_H */
