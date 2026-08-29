/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Allocation-free private-object request-window state machine. */

#include "session/mesh_private_object_schedule.h"

#include <limits.h>
#include <string.h>

_Static_assert(MESH_PRIVATE_OBJECT_REQUEST_WINDOW > 1u,
               "private transfer must pipeline more than one chunk");
_Static_assert(MESH_PRIVATE_OBJECT_REQUEST_WINDOW <= UINT8_MAX,
               "in-flight count must represent the request window");
_Static_assert(MESH_PRIVATE_OBJECT_MAX_CHUNKS <= UINT32_MAX,
               "chunk index must represent the protocol maximum");

static bool schedule_bit(const uint8_t *bits, uint32_t index)
{
    return (bits[index >> 3] & (uint8_t)(1u << (index & 7u))) != 0;
}

static void schedule_set(uint8_t *bits, uint32_t index)
{
    bits[index >> 3] |= (uint8_t)(1u << (index & 7u));
}

static void schedule_clear(uint8_t *bits, uint32_t index)
{
    bits[index >> 3] &= (uint8_t)~(1u << (index & 7u));
}

bool mesh_private_object_schedule_v1_init(
    struct mesh_private_object_schedule_v1 *schedule, uint32_t chunk_count,
    uint64_t first_request_id)
{
    if (!schedule || chunk_count == 0 ||
        chunk_count > MESH_PRIVATE_OBJECT_MAX_CHUNKS ||
        first_request_id == 0)
        return false;
    memset(schedule, 0, sizeof(*schedule));
    schedule->chunk_count = chunk_count;
    schedule->next_request_id = first_request_id;
    return true;
}

static void schedule_release_slot(
    struct mesh_private_object_schedule_v1 *schedule,
    struct mesh_private_object_request_slot *slot)
{
    if (!slot->used) return;
    schedule_clear(schedule->inflight, slot->chunk_index);
    memset(slot, 0, sizeof(*slot));
    schedule->inflight_count--;
}

bool mesh_private_object_schedule_v1_complete_chunk(
    struct mesh_private_object_schedule_v1 *schedule, uint32_t chunk_index)
{
    if (!schedule || chunk_index >= schedule->chunk_count ||
        schedule->cancelled)
        return false;
    if (!schedule_bit(schedule->have, chunk_index)) {
        schedule_set(schedule->have, chunk_index);
        schedule->have_count++;
    }
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_REQUEST_WINDOW; i++) {
        if (schedule->slots[i].used &&
            schedule->slots[i].chunk_index == chunk_index)
            schedule_release_slot(schedule, &schedule->slots[i]);
    }
    return true;
}

bool mesh_private_object_schedule_v1_accepts_response(
    const struct mesh_private_object_schedule_v1 *schedule,
    uint32_t chunk_index, uint64_t request_id)
{
    if (!schedule || request_id == 0 ||
        chunk_index >= schedule->chunk_count || schedule->cancelled)
        return false;
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_REQUEST_WINDOW; i++)
        if (schedule->slots[i].used &&
            schedule->slots[i].chunk_index == chunk_index &&
            schedule->slots[i].request_id == request_id)
            return true;
    return false;
}

bool mesh_private_object_schedule_v1_unissue(
    struct mesh_private_object_schedule_v1 *schedule, uint64_t request_id)
{
    if (!schedule || request_id == 0 || schedule->cancelled) return false;
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_REQUEST_WINDOW; i++) {
        struct mesh_private_object_request_slot *slot = &schedule->slots[i];
        if (!slot->used || slot->request_id != request_id) continue;
        if (schedule->attempts[slot->chunk_index] == 0) return false;
        schedule->next_scan = slot->chunk_index;
        schedule->attempts[slot->chunk_index]--;
        schedule_release_slot(schedule, slot);
        return true;
    }
    return false;
}

static void schedule_expire(
    struct mesh_private_object_schedule_v1 *schedule, uint64_t now_ms)
{
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_REQUEST_WINDOW; i++) {
        struct mesh_private_object_request_slot *slot = &schedule->slots[i];
        if (slot->used && now_ms >= slot->deadline_ms)
            schedule_release_slot(schedule, slot);
    }
}

static bool schedule_has_exhausted(
    const struct mesh_private_object_schedule_v1 *schedule)
{
    for (uint32_t i = 0; i < schedule->chunk_count; i++) {
        if (!schedule_bit(schedule->have, i) &&
            schedule->attempts[i] >=
                MESH_PRIVATE_OBJECT_REQUEST_MAX_ATTEMPTS)
            return true;
    }
    return false;
}

static bool schedule_find_chunk(
    struct mesh_private_object_schedule_v1 *schedule, uint32_t *out)
{
    for (uint32_t visited = 0; visited < schedule->chunk_count; visited++) {
        uint32_t index = schedule->next_scan++;
        if (schedule->next_scan == schedule->chunk_count)
            schedule->next_scan = 0;
        if (!schedule_bit(schedule->have, index) &&
            !schedule_bit(schedule->inflight, index) &&
            schedule->attempts[index] <
                MESH_PRIVATE_OBJECT_REQUEST_MAX_ATTEMPTS) {
            *out = index;
            return true;
        }
    }
    return false;
}

static struct mesh_private_object_request_slot *schedule_free_slot(
    struct mesh_private_object_schedule_v1 *schedule)
{
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_REQUEST_WINDOW; i++)
        if (!schedule->slots[i].used) return &schedule->slots[i];
    return NULL;
}

enum mesh_private_object_schedule_result
mesh_private_object_schedule_v1_next(
    struct mesh_private_object_schedule_v1 *schedule, uint64_t now_ms,
    struct mesh_private_object_scheduled_request *out)
{
    if (!schedule || !out || now_ms == 0 || schedule->chunk_count == 0)
        return MESH_PRIVATE_OBJECT_SCHEDULE_INVALID;
    memset(out, 0, sizeof(*out));
    if (schedule->cancelled)
        return MESH_PRIVATE_OBJECT_SCHEDULE_CANCELLED;
    schedule_expire(schedule, now_ms);
    if (schedule->have_count == schedule->chunk_count)
        return MESH_PRIVATE_OBJECT_SCHEDULE_COMPLETE;
    if (schedule->inflight_count >= MESH_PRIVATE_OBJECT_REQUEST_WINDOW)
        return MESH_PRIVATE_OBJECT_SCHEDULE_WAIT;
    uint32_t chunk_index = 0;
    if (!schedule_find_chunk(schedule, &chunk_index))
        return schedule_has_exhausted(schedule)
            ? MESH_PRIVATE_OBJECT_SCHEDULE_EXHAUSTED
            : MESH_PRIVATE_OBJECT_SCHEDULE_WAIT;
    if (now_ms > UINT64_MAX - MESH_PRIVATE_OBJECT_REQUEST_TIMEOUT_MS)
        return MESH_PRIVATE_OBJECT_SCHEDULE_INVALID;
    struct mesh_private_object_request_slot *slot =
        schedule_free_slot(schedule);
    if (!slot) return MESH_PRIVATE_OBJECT_SCHEDULE_INVALID;
    uint64_t request_id = schedule->next_request_id++;
    if (schedule->next_request_id == 0) schedule->next_request_id = 1;
    schedule->attempts[chunk_index]++;
    *slot = (struct mesh_private_object_request_slot){
        .request_id = request_id,
        .deadline_ms = now_ms + MESH_PRIVATE_OBJECT_REQUEST_TIMEOUT_MS,
        .chunk_index = chunk_index,
        .used = true,
    };
    schedule_set(schedule->inflight, chunk_index);
    schedule->inflight_count++;
    *out = (struct mesh_private_object_scheduled_request){
        .request_id = slot->request_id,
        .deadline_ms = slot->deadline_ms,
        .chunk_index = chunk_index,
        .attempt = schedule->attempts[chunk_index],
    };
    return MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST;
}

void mesh_private_object_schedule_v1_cancel(
    struct mesh_private_object_schedule_v1 *schedule)
{
    if (!schedule) return;
    schedule->cancelled = true;
    memset(schedule->slots, 0, sizeof(schedule->slots));
    memset(schedule->inflight, 0, sizeof(schedule->inflight));
    schedule->inflight_count = 0;
}
