/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded pipelined scheduling for private-object chunk requests. */

#ifndef ZCL_SESSION_MESH_PRIVATE_OBJECT_SCHEDULE_H
#define ZCL_SESSION_MESH_PRIVATE_OBJECT_SCHEDULE_H

#include "session/mesh_private_object_proto.h"

#include <stdbool.h>
#include <stdint.h>

#define MESH_PRIVATE_OBJECT_REQUEST_WINDOW 8u
#define MESH_PRIVATE_OBJECT_REQUEST_TIMEOUT_MS UINT64_C(5000)
#define MESH_PRIVATE_OBJECT_REQUEST_MAX_ATTEMPTS 5u
#define MESH_PRIVATE_OBJECT_SCHEDULE_BITMAP_BYTES \
    ((MESH_PRIVATE_OBJECT_MAX_CHUNKS + 7u) / 8u)

enum mesh_private_object_schedule_result {
    MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST = 0,
    MESH_PRIVATE_OBJECT_SCHEDULE_WAIT,
    MESH_PRIVATE_OBJECT_SCHEDULE_COMPLETE,
    MESH_PRIVATE_OBJECT_SCHEDULE_EXHAUSTED,
    MESH_PRIVATE_OBJECT_SCHEDULE_CANCELLED,
    MESH_PRIVATE_OBJECT_SCHEDULE_INVALID,
};

struct mesh_private_object_scheduled_request {
    uint64_t request_id;
    uint64_t deadline_ms;
    uint32_t chunk_index;
    uint8_t attempt;
};

struct mesh_private_object_request_slot {
    uint64_t request_id;
    uint64_t deadline_ms;
    uint32_t chunk_index;
    bool used;
};

struct mesh_private_object_schedule_v1 {
    struct mesh_private_object_request_slot
        slots[MESH_PRIVATE_OBJECT_REQUEST_WINDOW];
    uint8_t have[MESH_PRIVATE_OBJECT_SCHEDULE_BITMAP_BYTES];
    uint8_t inflight[MESH_PRIVATE_OBJECT_SCHEDULE_BITMAP_BYTES];
    uint8_t attempts[MESH_PRIVATE_OBJECT_MAX_CHUNKS];
    uint64_t next_request_id;
    uint32_t chunk_count;
    uint32_t have_count;
    uint32_t next_scan;
    uint8_t inflight_count;
    bool cancelled;
};

bool mesh_private_object_schedule_v1_init(
    struct mesh_private_object_schedule_v1 *schedule, uint32_t chunk_count,
    uint64_t first_request_id);

/* Mark a chunk already durable, including chunks restored from the staging
 * journal. */
bool mesh_private_object_schedule_v1_complete_chunk(
    struct mesh_private_object_schedule_v1 *schedule, uint32_t chunk_index);

/* A network response is accepted only while its exact request is in flight. */
bool mesh_private_object_schedule_v1_accepts_response(
    const struct mesh_private_object_schedule_v1 *schedule,
    uint32_t chunk_index, uint64_t request_id);

/* Roll back a locally reserved request that was never emitted. Request ids
 * stay monotonic, but an unsent request does not consume a retry attempt. */
bool mesh_private_object_schedule_v1_unissue(
    struct mesh_private_object_schedule_v1 *schedule, uint64_t request_id);

enum mesh_private_object_schedule_result
mesh_private_object_schedule_v1_next(
    struct mesh_private_object_schedule_v1 *schedule, uint64_t now_ms,
    struct mesh_private_object_scheduled_request *out);

void mesh_private_object_schedule_v1_cancel(
    struct mesh_private_object_schedule_v1 *schedule);

#endif /* ZCL_SESSION_MESH_PRIVATE_OBJECT_SCHEDULE_H */
