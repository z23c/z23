/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Crash-safe authenticated staging for resumable private objects. */

#ifndef ZCL_SESSION_MESH_PRIVATE_OBJECT_STAGE_H
#define ZCL_SESSION_MESH_PRIVATE_OBJECT_STAGE_H

#include "session/mesh_private_object_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum mesh_private_object_stage_error {
    MESH_PRIVATE_OBJECT_STAGE_OK = 0,
    MESH_PRIVATE_OBJECT_STAGE_NULL,
    MESH_PRIVATE_OBJECT_STAGE_OFFER,
    MESH_PRIVATE_OBJECT_STAGE_MEMORY,
    MESH_PRIVATE_OBJECT_STAGE_BUSY,
    MESH_PRIVATE_OBJECT_STAGE_IO,
    MESH_PRIVATE_OBJECT_STAGE_IDENTITY,
    MESH_PRIVATE_OBJECT_STAGE_CORRUPT,
    MESH_PRIVATE_OBJECT_STAGE_INDEX,
    MESH_PRIVATE_OBJECT_STAGE_SIZE,
    MESH_PRIVATE_OBJECT_STAGE_AUTH,
    MESH_PRIVATE_OBJECT_STAGE_INCOMPLETE,
    MESH_PRIVATE_OBJECT_STAGE_ROOT,
};

struct mesh_private_object_stage;

const char *mesh_private_object_stage_error_string(
    enum mesh_private_object_stage_error error);

/* The root must already exist, be owned by the current user, and grant no
 * group/other permissions. One exclusive per-transfer lock prevents two
 * writers from racing the same journal. Existing set bits are trusted only
 * after every corresponding ciphertext chunk authenticates on reopen. */
enum mesh_private_object_stage_error mesh_private_object_stage_open_v1(
    struct mesh_private_object_stage **out, const char *private_root,
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t target_noise_static_secret[32]);

void mesh_private_object_stage_close(struct mesh_private_object_stage *stage);

enum mesh_private_object_stage_error mesh_private_object_stage_put_v1(
    struct mesh_private_object_stage *stage, uint32_t chunk_index,
    const uint8_t *sealed, size_t sealed_len);

bool mesh_private_object_stage_has_v1(
    const struct mesh_private_object_stage *stage, uint32_t chunk_index);
uint32_t mesh_private_object_stage_count_v1(
    const struct mesh_private_object_stage *stage);

/* Re-read all ciphertext in canonical order and compare its streaming root.
 * This proves only that the complete encrypted object is staged; plaintext
 * publication and grant completion remain separate, owner-gated steps. */
enum mesh_private_object_stage_error mesh_private_object_stage_verify_v1(
    struct mesh_private_object_stage *stage);

#endif /* ZCL_SESSION_MESH_PRIVATE_OBJECT_STAGE_H */
