/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Durable bounded state machine for incoming private objects. */

#include "services/mesh_private_object_receiver.h"

#include "base/cleanse.h"
#include "session/mesh_private_object_schedule.h"
#include "session/mesh_private_object_stage.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

struct mesh_private_object_receive_slot {
    bool used;
    uint64_t peer_token;
    uint8_t transfer_id[32];
    struct mesh_private_object_offer_v1 offer;
    struct mesh_private_object_admission admission;
    struct mesh_private_object_stage *stage;
    struct mesh_private_object_schedule_v1 schedule;
};

struct mesh_private_object_receiver {
    char private_root[4096];
    uint8_t target_secret[32];
    struct mesh_private_object_receive_slot
        slots[MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS];
};

const char *mesh_private_object_receiver_result_string(
    enum mesh_private_object_receiver_result result)
{
    switch (result) {
    case MESH_PRIVATE_OBJECT_RECEIVER_OK: return "ok";
    case MESH_PRIVATE_OBJECT_RECEIVER_RESUME: return "resume";
    case MESH_PRIVATE_OBJECT_RECEIVER_WAIT: return "wait";
    case MESH_PRIVATE_OBJECT_RECEIVER_STAGED: return "staged";
    case MESH_PRIVATE_OBJECT_RECEIVER_EXHAUSTED: return "exhausted";
    case MESH_PRIVATE_OBJECT_RECEIVER_CANCELLED: return "cancelled";
    case MESH_PRIVATE_OBJECT_RECEIVER_NOT_FOUND: return "not_found";
    case MESH_PRIVATE_OBJECT_RECEIVER_BUSY: return "busy";
    case MESH_PRIVATE_OBJECT_RECEIVER_BACKPRESSURE: return "backpressure";
    case MESH_PRIVATE_OBJECT_RECEIVER_BINDING: return "binding";
    case MESH_PRIVATE_OBJECT_RECEIVER_CORRELATION: return "correlation";
    case MESH_PRIVATE_OBJECT_RECEIVER_AUTH: return "auth";
    case MESH_PRIVATE_OBJECT_RECEIVER_CORRUPT: return "corrupt";
    case MESH_PRIVATE_OBJECT_RECEIVER_INVALID: return "invalid";
    }
    return "invalid";
}

static struct zcl_result receiver_reply(
    enum mesh_private_object_receiver_result *out,
    enum mesh_private_object_receiver_result result)
{
    if (!out) return ZCL_ERR(-1, "private-object receiver requires output");
    *out = result;
    return ZCL_OK;
}

struct zcl_result mesh_private_object_receiver_create(
    const char *private_root, const uint8_t target_secret[32],
    struct mesh_private_object_receiver **out)
{
    if (!out)
        return ZCL_ERR(-1, "private-object receiver requires output");
    *out = NULL;
    if (!private_root || !private_root[0] || !target_secret ||
        strlen(private_root) >= 4096)
        return ZCL_ERR(-1, "private-object receiver context is invalid");
    struct mesh_private_object_receiver *receiver =
        zcl_calloc(1, sizeof(*receiver), "mesh_private_object_receiver");
    if (!receiver)
        return ZCL_ERR(-2, "private-object receiver allocation failed");
    memcpy(receiver->private_root, private_root, strlen(private_root) + 1u);
    memcpy(receiver->target_secret, target_secret, 32);
    *out = receiver;
    return ZCL_OK;
}

static void receiver_slot_clear(struct mesh_private_object_receive_slot *slot)
{
    if (!slot) return;
    mesh_private_object_stage_close(slot->stage);
    memory_cleanse(slot, sizeof(*slot));
}

void mesh_private_object_receiver_free(
    struct mesh_private_object_receiver *receiver)
{
    if (!receiver) return;
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS; i++)
        receiver_slot_clear(&receiver->slots[i]);
    memory_cleanse(receiver, sizeof(*receiver));
    free(receiver);
}

static struct mesh_private_object_receive_slot *receiver_find(
    struct mesh_private_object_receiver *receiver,
    const uint8_t transfer_id[32])
{
    if (!receiver || !transfer_id) return NULL;
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS; i++)
        if (receiver->slots[i].used &&
            memcmp(receiver->slots[i].transfer_id, transfer_id, 32) == 0)
            return &receiver->slots[i];
    return NULL;
}

static struct mesh_private_object_receive_slot *receiver_free_slot(
    struct mesh_private_object_receiver *receiver)
{
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS; i++)
        if (!receiver->slots[i].used) return &receiver->slots[i];
    return NULL;
}

static bool receiver_admission_success(
    const struct mesh_private_object_admission *admission)
{
    return admission &&
        (admission->reason == MESH_PRIVATE_OBJECT_ADMISSION_NEW ||
         admission->reason == MESH_PRIVATE_OBJECT_ADMISSION_RESUME);
}

static bool receiver_admission_matches(
    const struct mesh_private_object_receive_slot *slot,
    const struct mesh_private_object_admission *admission)
{
    return slot && receiver_admission_success(admission) &&
        memcmp(slot->transfer_id, admission->transfer_id, 32) == 0 &&
        memcmp(slot->admission.offer_root, admission->offer_root, 32) == 0 &&
        slot->admission.pairing_revocation_generation ==
            admission->pairing_revocation_generation &&
        slot->admission.grant_revocation_generation ==
            admission->grant_revocation_generation;
}

static bool receiver_schedule_reset(
    struct mesh_private_object_receive_slot *slot, uint64_t first_request_id)
{
    if (!mesh_private_object_schedule_v1_init(
            &slot->schedule, slot->offer.chunk_count, first_request_id))
        return false;
    for (uint32_t i = 0; i < slot->offer.chunk_count; i++)
        if (mesh_private_object_stage_has_v1(slot->stage, i) &&
            !mesh_private_object_schedule_v1_complete_chunk(
                &slot->schedule, i))
            return false;
    return true;
}

static struct zcl_result receiver_staged_if_complete(
    struct mesh_private_object_receive_slot *slot,
    enum mesh_private_object_receiver_result *out)
{
    if (mesh_private_object_stage_count_v1(slot->stage) !=
        slot->offer.chunk_count)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_OK);
    enum mesh_private_object_stage_error verified =
        mesh_private_object_stage_verify_v1(slot->stage);
    if (verified != MESH_PRIVATE_OBJECT_STAGE_OK) {
        receiver_slot_clear(slot);
        return receiver_reply(
            out, verified == MESH_PRIVATE_OBJECT_STAGE_ROOT
                     ? MESH_PRIVATE_OBJECT_RECEIVER_AUTH
                     : MESH_PRIVATE_OBJECT_RECEIVER_CORRUPT);
    }
    receiver_slot_clear(slot);
    return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_STAGED);
}

static bool receiver_admission_binds_offer(
    const struct mesh_private_object_offer_v1 *offer,
    const struct mesh_private_object_admission *admission,
    uint8_t transfer_id[32])
{
    uint8_t offer_root[32];
    return receiver_admission_success(admission) &&
        mesh_private_object_offer_v1_validate(offer) ==
            MESH_PRIVATE_OBJECT_PROTO_OK &&
        mesh_private_object_offer_transfer_id_v1(offer, transfer_id) ==
            MESH_PRIVATE_OBJECT_PROTO_OK &&
        mesh_private_object_offer_v1_root(offer, offer_root) ==
            MESH_PRIVATE_OBJECT_PROTO_OK &&
        memcmp(transfer_id, admission->transfer_id, 32) == 0 &&
        memcmp(offer_root, admission->offer_root, 32) == 0;
}

struct zcl_result mesh_private_object_receiver_admit(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_offer_v1 *offer,
    const struct mesh_private_object_admission *admission,
    uint64_t peer_token, uint64_t first_request_id,
    enum mesh_private_object_receiver_result *out)
{
    if (!out) return ZCL_ERR(-1, "private-object admit requires output");
    *out = MESH_PRIVATE_OBJECT_RECEIVER_INVALID;
    if (!receiver || !offer || !admission || peer_token == 0 ||
        first_request_id == 0)
        return ZCL_ERR(-1, "private-object admit context is invalid");
    uint8_t transfer_id[32];
    if (!receiver_admission_binds_offer(offer, admission, transfer_id))
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
    struct mesh_private_object_receive_slot *slot =
        receiver_find(receiver, transfer_id);
    if (slot) {
        if (!receiver_admission_matches(slot, admission))
            return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
        slot->offer = *offer;
        slot->admission = *admission;
        slot->peer_token = peer_token;
        if (!receiver_schedule_reset(slot, first_request_id))
            return ZCL_ERR(-2, "private-object resume schedule failed");
        if (mesh_private_object_stage_count_v1(slot->stage) ==
            offer->chunk_count)
            return receiver_staged_if_complete(slot, out);
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_RESUME);
    }
    slot = receiver_free_slot(receiver);
    if (!slot) return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BUSY);
    struct mesh_private_object_stage *stage = NULL;
    enum mesh_private_object_stage_error opened =
        mesh_private_object_stage_open_v1(
            &stage, receiver->private_root, offer, receiver->target_secret);
    if (opened == MESH_PRIVATE_OBJECT_STAGE_BUSY)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BUSY);
    if (opened == MESH_PRIVATE_OBJECT_STAGE_AUTH)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
    if (opened == MESH_PRIVATE_OBJECT_STAGE_IDENTITY ||
        opened == MESH_PRIVATE_OBJECT_STAGE_CORRUPT)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_CORRUPT);
    if (opened != MESH_PRIVATE_OBJECT_STAGE_OK)
        return ZCL_ERR(-2, "private-object stage open failed: %s",
                       mesh_private_object_stage_error_string(opened));
    if (mesh_private_object_stage_cancelled_v1(stage, NULL)) {
        mesh_private_object_stage_close(stage);
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_CANCELLED);
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->peer_token = peer_token;
    memcpy(slot->transfer_id, transfer_id, 32);
    slot->offer = *offer;
    slot->admission = *admission;
    slot->stage = stage;
    uint32_t durable_chunks = mesh_private_object_stage_count_v1(stage);
    if (!receiver_schedule_reset(slot, first_request_id)) {
        receiver_slot_clear(slot);
        return ZCL_ERR(-2, "private-object stage schedule failed");
    }
    if (durable_chunks == offer->chunk_count)
        return receiver_staged_if_complete(slot, out);
    return receiver_reply(out, durable_chunks
        ? MESH_PRIVATE_OBJECT_RECEIVER_RESUME
        : MESH_PRIVATE_OBJECT_RECEIVER_OK);
}

struct zcl_result mesh_private_object_receiver_drive(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_admission *admission,
    uint64_t peer_token, uint64_t now_ms,
    mesh_private_object_request_emit_fn emit, void *emit_context,
    size_t *emitted_out, enum mesh_private_object_receiver_result *out)
{
    if (!out || !emitted_out)
        return ZCL_ERR(-1, "private-object drive requires outputs");
    *out = MESH_PRIVATE_OBJECT_RECEIVER_INVALID;
    *emitted_out = 0;
    if (!receiver || !admission || !emit || peer_token == 0 || now_ms == 0)
        return ZCL_ERR(-1, "private-object drive context is invalid");
    struct mesh_private_object_receive_slot *slot =
        receiver_find(receiver, admission->transfer_id);
    if (!slot) return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_NOT_FOUND);
    if (slot->peer_token != peer_token)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
    if (!receiver_admission_matches(slot, admission))
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
    for (;;) {
        struct mesh_private_object_scheduled_request scheduled;
        enum mesh_private_object_schedule_result next =
            mesh_private_object_schedule_v1_next(
                &slot->schedule, now_ms, &scheduled);
        if (next == MESH_PRIVATE_OBJECT_SCHEDULE_COMPLETE)
            return receiver_staged_if_complete(slot, out);
        if (next == MESH_PRIVATE_OBJECT_SCHEDULE_EXHAUSTED)
            return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_EXHAUSTED);
        if (next == MESH_PRIVATE_OBJECT_SCHEDULE_WAIT)
            return receiver_reply(out, *emitted_out
                ? MESH_PRIVATE_OBJECT_RECEIVER_OK
                : MESH_PRIVATE_OBJECT_RECEIVER_WAIT);
        if (next != MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST)
            return ZCL_ERR(-2, "private-object scheduler state is invalid");
        struct mesh_private_object_chunk_request_v1 request = {
            .chunk_request_id = scheduled.request_id,
            .chunk_index = scheduled.chunk_index,
        };
        memcpy(request.transfer_id, slot->transfer_id, 32);
        memcpy(request.offer_request_id, slot->offer.request_id, 32);
        if (!emit(&request, emit_context)) {
            if (!mesh_private_object_schedule_v1_unissue(
                    &slot->schedule, scheduled.request_id))
                return ZCL_ERR(-2,
                    "private-object unsent request rollback failed");
            return receiver_reply(
                out, MESH_PRIVATE_OBJECT_RECEIVER_BACKPRESSURE);
        }
        (*emitted_out)++;
    }
}

struct zcl_result mesh_private_object_receiver_chunk(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_chunk_v1 *chunk,
    const struct mesh_private_object_admission *admission,
    uint64_t peer_token, enum mesh_private_object_receiver_result *out)
{
    if (!out) return ZCL_ERR(-1, "private-object chunk requires output");
    *out = MESH_PRIVATE_OBJECT_RECEIVER_INVALID;
    if (!receiver || !chunk || !chunk->sealed || !admission ||
        chunk->chunk_request_id == 0 || peer_token == 0)
        return ZCL_ERR(-1, "private-object chunk context is invalid");
    struct mesh_private_object_receive_slot *slot =
        receiver_find(receiver, chunk->transfer_id);
    if (!slot) return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_NOT_FOUND);
    if (slot->peer_token != peer_token ||
        memcmp(slot->offer.request_id, chunk->offer_request_id, 32) != 0)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
    if (!receiver_admission_matches(slot, admission))
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
    if (!mesh_private_object_schedule_v1_accepts_response(
            &slot->schedule, chunk->chunk_index, chunk->chunk_request_id))
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_CORRELATION);
    enum mesh_private_object_stage_error stored =
        mesh_private_object_stage_put_v1(
            slot->stage, chunk->chunk_index, chunk->sealed,
            chunk->sealed_len);
    if (stored == MESH_PRIVATE_OBJECT_STAGE_AUTH)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
    if (stored == MESH_PRIVATE_OBJECT_STAGE_INDEX ||
        stored == MESH_PRIVATE_OBJECT_STAGE_SIZE)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
    if (stored == MESH_PRIVATE_OBJECT_STAGE_CORRUPT)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_CORRUPT);
    if (stored != MESH_PRIVATE_OBJECT_STAGE_OK)
        return ZCL_ERR(-2, "private-object stage write failed: %s",
                       mesh_private_object_stage_error_string(stored));
    if (!mesh_private_object_schedule_v1_complete_chunk(
            &slot->schedule, chunk->chunk_index))
        return ZCL_ERR(-2, "private-object durable schedule update failed");
    if (mesh_private_object_stage_count_v1(slot->stage) !=
        slot->offer.chunk_count)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_OK);
    return receiver_staged_if_complete(slot, out);
}

struct zcl_result mesh_private_object_receiver_cancel(
    struct mesh_private_object_receiver *receiver,
    const struct mesh_private_object_cancel_v1 *cancel, uint64_t peer_token,
    enum mesh_private_object_receiver_result *out)
{
    if (!out) return ZCL_ERR(-1, "private-object cancel requires output");
    *out = MESH_PRIVATE_OBJECT_RECEIVER_INVALID;
    if (!receiver || !cancel || cancel->cancel_id == 0 || peer_token == 0)
        return ZCL_ERR(-1, "private-object cancel context is invalid");
    struct mesh_private_object_receive_slot *slot =
        receiver_find(receiver, cancel->transfer_id);
    if (!slot) return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_NOT_FOUND);
    if (slot->peer_token != peer_token ||
        memcmp(slot->offer.request_id, cancel->offer_request_id, 32) != 0)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
    enum mesh_private_object_stage_error stored =
        mesh_private_object_stage_cancel_v1(slot->stage, cancel);
    if (stored == MESH_PRIVATE_OBJECT_STAGE_IDENTITY ||
        stored == MESH_PRIVATE_OBJECT_STAGE_OFFER)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
    if (stored == MESH_PRIVATE_OBJECT_STAGE_CANCELLED)
        return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_CANCELLED);
    if (stored != MESH_PRIVATE_OBJECT_STAGE_OK) {
        receiver_slot_clear(slot);
        return ZCL_ERR(-2, "private-object cancel persistence failed: %s",
                       mesh_private_object_stage_error_string(stored));
    }
    mesh_private_object_schedule_v1_cancel(&slot->schedule);
    receiver_slot_clear(slot);
    return receiver_reply(out, MESH_PRIVATE_OBJECT_RECEIVER_CANCELLED);
}

size_t mesh_private_object_receiver_active(
    const struct mesh_private_object_receiver *receiver)
{
    size_t count = 0;
    if (!receiver) return 0;
    for (size_t i = 0; i < MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS; i++)
        count += receiver->slots[i].used;
    return count;
}
