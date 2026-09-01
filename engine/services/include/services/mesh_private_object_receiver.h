/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded receiver state for authorized private-object transfers. */

#ifndef ZCL_SERVICES_MESH_PRIVATE_OBJECT_RECEIVER_H
#define ZCL_SERVICES_MESH_PRIVATE_OBJECT_RECEIVER_H

#include "base/result.h"
#include "services/mesh_private_object_admission.h"
#include "session/mesh_private_object_frame.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS 4u

enum mesh_private_object_receiver_result {
    MESH_PRIVATE_OBJECT_RECEIVER_OK = 0,
    MESH_PRIVATE_OBJECT_RECEIVER_RESUME,
    MESH_PRIVATE_OBJECT_RECEIVER_WAIT,
    MESH_PRIVATE_OBJECT_RECEIVER_STAGED,
    MESH_PRIVATE_OBJECT_RECEIVER_EXHAUSTED,
    MESH_PRIVATE_OBJECT_RECEIVER_CANCELLED,
    MESH_PRIVATE_OBJECT_RECEIVER_NOT_FOUND,
    MESH_PRIVATE_OBJECT_RECEIVER_BUSY,
    MESH_PRIVATE_OBJECT_RECEIVER_BACKPRESSURE,
    MESH_PRIVATE_OBJECT_RECEIVER_BINDING,
    MESH_PRIVATE_OBJECT_RECEIVER_CORRELATION,
    MESH_PRIVATE_OBJECT_RECEIVER_AUTH,
    MESH_PRIVATE_OBJECT_RECEIVER_CORRUPT,
    MESH_PRIVATE_OBJECT_RECEIVER_INVALID,
};

struct mesh_private_object_receiver;

typedef bool (*mesh_private_object_request_emit_fn)(
    const struct mesh_private_object_chunk_request_v1 *request,
    void *context);

const char *mesh_private_object_receiver_result_string(
    enum mesh_private_object_receiver_result result);

struct zcl_result mesh_private_object_receiver_create(
    const char *private_root,
    const uint8_t target_noise_static_secret[32],
    struct mesh_private_object_receiver **out);
void mesh_private_object_receiver_free(
    struct mesh_private_object_receiver *receiver);

/* The caller serializes all calls on one worker. Every admit, drive, and
 * chunk operation carries a fresh successful target-local admission decision.
 * The emitter only enqueues bytes and must not re-enter the receiver. */
struct zcl_result mesh_private_object_receiver_admit(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_offer_v1 *offer,
    const struct mesh_private_object_admission *admission,
    uint64_t peer_token, uint64_t first_request_id,
    enum mesh_private_object_receiver_result *out);

struct zcl_result mesh_private_object_receiver_drive(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_admission *admission,
    uint64_t peer_token, uint64_t now_ms,
    mesh_private_object_request_emit_fn emit, void *emit_context,
    size_t *emitted_out, enum mesh_private_object_receiver_result *out);

struct zcl_result mesh_private_object_receiver_chunk(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_chunk_v1 *chunk,
    const struct mesh_private_object_admission *admission,
    uint64_t peer_token, enum mesh_private_object_receiver_result *out);

struct zcl_result mesh_private_object_receiver_cancel(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_cancel_v1 *cancel, uint64_t peer_token,
    enum mesh_private_object_receiver_result *out);

size_t mesh_private_object_receiver_active(
    const struct mesh_private_object_receiver *receiver);

#endif /* ZCL_SERVICES_MESH_PRIVATE_OBJECT_RECEIVER_H */
