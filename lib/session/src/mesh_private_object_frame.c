/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Strict allocation-free private-object transfer framing. */

#include "session/mesh_private_object_frame.h"

#include "base/serialize_le.h"

#include <string.h>

static const uint8_t frame_magic[4] = {'Z', 'M', 'P', 'O'};

static_assert(MESH_PRIVATE_OBJECT_FRAME_MAX == 65624u);
static_assert(MESH_PRIVATE_OBJECT_FRAME_MAX < 2u * 1024u * 1024u);

const char *mesh_private_object_frame_error_string(
    enum mesh_private_object_frame_error error)
{
    switch (error) {
    case MESH_PRIVATE_OBJECT_FRAME_OK: return "ok";
    case MESH_PRIVATE_OBJECT_FRAME_NULL: return "null";
    case MESH_PRIVATE_OBJECT_FRAME_SIZE: return "size";
    case MESH_PRIVATE_OBJECT_FRAME_MAGIC: return "magic";
    case MESH_PRIVATE_OBJECT_FRAME_VERSION_INVALID: return "version";
    case MESH_PRIVATE_OBJECT_FRAME_FLAGS: return "flags";
    case MESH_PRIVATE_OBJECT_FRAME_KIND_INVALID: return "kind";
    case MESH_PRIVATE_OBJECT_FRAME_FIELD: return "field";
    case MESH_PRIVATE_OBJECT_FRAME_PAYLOAD: return "payload";
    }
    return "unknown";
}

static bool bytes_nonzero(const uint8_t *bytes, size_t count)
{
    uint8_t any = 0;
    if (!bytes)
        return false;
    for (size_t i = 0; i < count; i++)
        any |= bytes[i];
    return any != 0;
}

static bool ids_valid(const uint8_t transfer_id[32],
                      const uint8_t offer_request_id[32])
{
    return bytes_nonzero(transfer_id, 32) &&
           bytes_nonzero(offer_request_id, 32);
}

static enum mesh_private_object_frame_error frame_begin(
    enum mesh_private_object_frame_kind kind, uint8_t *out, size_t out_cap,
    size_t need, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!out || !out_len)
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    if (out_cap < need)
        return MESH_PRIVATE_OBJECT_FRAME_SIZE;
    memcpy(out, frame_magic, sizeof(frame_magic));
    zcl_write_u16_le(out + 4, MESH_PRIVATE_OBJECT_FRAME_VERSION);
    out[6] = (uint8_t)kind;
    out[7] = MESH_PRIVATE_OBJECT_FRAME_FLAGS_NONE;
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

enum mesh_private_object_frame_error mesh_private_object_frame_offer_v1_encode(
    const struct mesh_private_object_offer_v1 *offer, uint8_t *out,
    size_t out_cap, size_t *out_len)
{
    if (!offer) {
        if (out_len)
            *out_len = 0;
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    }
    enum mesh_private_object_frame_error error = frame_begin(
        MESH_PRIVATE_OBJECT_FRAME_OFFER, out, out_cap,
        MESH_PRIVATE_OBJECT_FRAME_OFFER_BYTES, out_len);
    if (error != MESH_PRIVATE_OBJECT_FRAME_OK)
        return error;
    if (mesh_private_object_offer_v1_encode(
            offer, out + MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return MESH_PRIVATE_OBJECT_FRAME_PAYLOAD;
    *out_len = MESH_PRIVATE_OBJECT_FRAME_OFFER_BYTES;
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

enum mesh_private_object_frame_error
mesh_private_object_frame_request_v1_encode(
    const struct mesh_private_object_chunk_request_v1 *request, uint8_t *out,
    size_t out_cap, size_t *out_len)
{
    if (!request) {
        if (out_len)
            *out_len = 0;
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    }
    enum mesh_private_object_frame_error error = frame_begin(
        MESH_PRIVATE_OBJECT_FRAME_REQUEST, out, out_cap,
        MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES, out_len);
    if (error != MESH_PRIVATE_OBJECT_FRAME_OK)
        return error;
    if (!ids_valid(request->transfer_id, request->offer_request_id) ||
        request->chunk_request_id == 0)
        return MESH_PRIVATE_OBJECT_FRAME_FIELD;
    memcpy(out + 8, request->transfer_id, 32);
    memcpy(out + 40, request->offer_request_id, 32);
    zcl_write_u64_le(out + 72, request->chunk_request_id);
    zcl_write_u32_le(out + 80, request->chunk_index);
    *out_len = MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES;
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

enum mesh_private_object_frame_error mesh_private_object_frame_chunk_v1_encode(
    const struct mesh_private_object_chunk_v1 *chunk, uint8_t *out,
    size_t out_cap, size_t *out_len)
{
    if (!chunk) {
        if (out_len)
            *out_len = 0;
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    }
    if (!ids_valid(chunk->transfer_id, chunk->offer_request_id) ||
        chunk->chunk_request_id == 0 || !chunk->sealed ||
        chunk->sealed_len <= MESH_PRIVATE_OBJECT_TAG_BYTES ||
        chunk->sealed_len > MESH_PRIVATE_OBJECT_CHUNK_BYTES) {
        if (out_len)
            *out_len = 0;
        return MESH_PRIVATE_OBJECT_FRAME_FIELD;
    }
    size_t need = MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES +
                  (size_t)chunk->sealed_len;
    enum mesh_private_object_frame_error error = frame_begin(
        MESH_PRIVATE_OBJECT_FRAME_CHUNK, out, out_cap, need, out_len);
    if (error != MESH_PRIVATE_OBJECT_FRAME_OK)
        return error;
    memcpy(out + 8, chunk->transfer_id, 32);
    memcpy(out + 40, chunk->offer_request_id, 32);
    zcl_write_u64_le(out + 72, chunk->chunk_request_id);
    zcl_write_u32_le(out + 80, chunk->chunk_index);
    zcl_write_u32_le(out + 84, chunk->sealed_len);
    memmove(out + MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES,
            chunk->sealed, chunk->sealed_len);
    *out_len = need;
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

enum mesh_private_object_frame_error mesh_private_object_frame_cancel_v1_encode(
    const struct mesh_private_object_cancel_v1 *cancel, uint8_t *out,
    size_t out_cap, size_t *out_len)
{
    if (!cancel) {
        if (out_len)
            *out_len = 0;
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    }
    enum mesh_private_object_frame_error error = frame_begin(
        MESH_PRIVATE_OBJECT_FRAME_CANCEL, out, out_cap,
        MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES, out_len);
    if (error != MESH_PRIVATE_OBJECT_FRAME_OK)
        return error;
    if (!ids_valid(cancel->transfer_id, cancel->offer_request_id) ||
        cancel->cancel_id == 0)
        return MESH_PRIVATE_OBJECT_FRAME_FIELD;
    memcpy(out + 8, cancel->transfer_id, 32);
    memcpy(out + 40, cancel->offer_request_id, 32);
    zcl_write_u64_le(out + 72, cancel->cancel_id);
    *out_len = MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES;
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

static enum mesh_private_object_frame_error decode_header(
    const uint8_t *wire, size_t wire_len,
    enum mesh_private_object_frame_kind *kind)
{
    if (wire_len < MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES)
        return MESH_PRIVATE_OBJECT_FRAME_SIZE;
    if (memcmp(wire, frame_magic, sizeof(frame_magic)) != 0)
        return MESH_PRIVATE_OBJECT_FRAME_MAGIC;
    if (zcl_read_u16_le(wire + 4) != MESH_PRIVATE_OBJECT_FRAME_VERSION)
        return MESH_PRIVATE_OBJECT_FRAME_VERSION_INVALID;
    if (wire[7] != MESH_PRIVATE_OBJECT_FRAME_FLAGS_NONE)
        return MESH_PRIVATE_OBJECT_FRAME_FLAGS;
    if (wire[6] < MESH_PRIVATE_OBJECT_FRAME_OFFER ||
        wire[6] > MESH_PRIVATE_OBJECT_FRAME_CANCEL)
        return MESH_PRIVATE_OBJECT_FRAME_KIND_INVALID;
    *kind = (enum mesh_private_object_frame_kind)wire[6];
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

static enum mesh_private_object_frame_error decode_request(
    struct mesh_private_object_chunk_request_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES)
        return MESH_PRIVATE_OBJECT_FRAME_SIZE;
    memcpy(out->transfer_id, wire + 8, 32);
    memcpy(out->offer_request_id, wire + 40, 32);
    out->chunk_request_id = zcl_read_u64_le(wire + 72);
    out->chunk_index = zcl_read_u32_le(wire + 80);
    return ids_valid(out->transfer_id, out->offer_request_id) &&
                   out->chunk_request_id != 0
               ? MESH_PRIVATE_OBJECT_FRAME_OK
               : MESH_PRIVATE_OBJECT_FRAME_FIELD;
}

static enum mesh_private_object_frame_error decode_chunk(
    struct mesh_private_object_chunk_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len < MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES)
        return MESH_PRIVATE_OBJECT_FRAME_SIZE;
    memcpy(out->transfer_id, wire + 8, 32);
    memcpy(out->offer_request_id, wire + 40, 32);
    out->chunk_request_id = zcl_read_u64_le(wire + 72);
    out->chunk_index = zcl_read_u32_le(wire + 80);
    out->sealed_len = zcl_read_u32_le(wire + 84);
    if (!ids_valid(out->transfer_id, out->offer_request_id) ||
        out->chunk_request_id == 0 ||
        out->sealed_len <= MESH_PRIVATE_OBJECT_TAG_BYTES ||
        out->sealed_len > MESH_PRIVATE_OBJECT_CHUNK_BYTES)
        return MESH_PRIVATE_OBJECT_FRAME_FIELD;
    if (wire_len != MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES +
                        (size_t)out->sealed_len)
        return MESH_PRIVATE_OBJECT_FRAME_SIZE;
    out->sealed = wire + MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES;
    return MESH_PRIVATE_OBJECT_FRAME_OK;
}

static enum mesh_private_object_frame_error decode_cancel(
    struct mesh_private_object_cancel_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES)
        return MESH_PRIVATE_OBJECT_FRAME_SIZE;
    memcpy(out->transfer_id, wire + 8, 32);
    memcpy(out->offer_request_id, wire + 40, 32);
    out->cancel_id = zcl_read_u64_le(wire + 72);
    return ids_valid(out->transfer_id, out->offer_request_id) &&
                   out->cancel_id != 0
               ? MESH_PRIVATE_OBJECT_FRAME_OK
               : MESH_PRIVATE_OBJECT_FRAME_FIELD;
}

enum mesh_private_object_frame_error mesh_private_object_frame_v1_decode(
    struct mesh_private_object_frame_view_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out)
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire)
        return MESH_PRIVATE_OBJECT_FRAME_NULL;
    enum mesh_private_object_frame_kind kind;
    enum mesh_private_object_frame_error error =
        decode_header(wire, wire_len, &kind);
    if (error != MESH_PRIVATE_OBJECT_FRAME_OK)
        return error;
    out->kind = kind;
    switch (kind) {
    case MESH_PRIVATE_OBJECT_FRAME_OFFER:
        if (wire_len != MESH_PRIVATE_OBJECT_FRAME_OFFER_BYTES)
            error = MESH_PRIVATE_OBJECT_FRAME_SIZE;
        else if (mesh_private_object_offer_v1_decode(
                     &out->body.offer,
                     wire + MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES,
                     MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES) !=
                 MESH_PRIVATE_OBJECT_PROTO_OK)
            error = MESH_PRIVATE_OBJECT_FRAME_PAYLOAD;
        break;
    case MESH_PRIVATE_OBJECT_FRAME_REQUEST:
        error = decode_request(&out->body.request, wire, wire_len);
        break;
    case MESH_PRIVATE_OBJECT_FRAME_CHUNK:
        error = decode_chunk(&out->body.chunk, wire, wire_len);
        break;
    case MESH_PRIVATE_OBJECT_FRAME_CANCEL:
        error = decode_cancel(&out->body.cancel, wire, wire_len);
        break;
    default:
        error = MESH_PRIVATE_OBJECT_FRAME_KIND_INVALID;
        break;
    }
    if (error != MESH_PRIVATE_OBJECT_FRAME_OK)
        memset(out, 0, sizeof(*out));
    return error;
}
