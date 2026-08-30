/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical and adversarial private-object frame acceptance. */

#include "test/test_core.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "session/mesh_private_object_frame.h"

#include <string.h>

static void frame_fill(uint8_t *out, size_t len, uint8_t first)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(first + i * 17u);
}

static bool frame_make_offer(struct mesh_private_object_offer_v1 *offer)
{
    uint8_t seed[32], grant_nonce[32], secret[32];
    frame_fill(seed, sizeof(seed), 0x55);
    frame_fill(grant_nonce, sizeof(grant_nonce), 0x15);
    memset(offer, 0, sizeof(*offer));
    offer->version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    frame_fill(offer->network_genesis, 32, 0x01);
    frame_fill(offer->pairing_id, 32, 0x21);
    frame_fill(offer->grant_id, 32, 0x41);
    frame_fill(offer->source_master_pubkey, 32, 0x61);
    frame_fill(offer->source_noise_static, 32, 0x81);
    ed25519_keypair(offer->source_online_pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
    frame_fill(offer->target_master_pubkey, 32, 0xa1);
    frame_fill(offer->target_noise_static, 32, 0xc1);
    frame_fill(offer->transcript_hash, 32, 0xe1);
    offer->connection_generation = UINT64_C(0x1020304050607080);
    offer->pairing_revocation_generation = 7;
    frame_fill(offer->plaintext_root, 32, 0x32);
    frame_fill(offer->ciphertext_root, 32, 0x52);
    offer->object_size_bytes =
        MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 17u;
    offer->ciphertext_size_bytes = offer->object_size_bytes +
                                   2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
    offer->chunk_size = MESH_PRIVATE_OBJECT_CHUNK_BYTES;
    offer->chunk_count = 2;
    frame_fill(offer->ephemeral_x25519_pubkey, 32, 0x72);
    offer->issued_unix = UINT64_C(1800000000);
    offer->expires_unix = offer->issued_unix + 60;
    offer->deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;
    if (mesh_private_object_offer_request_id_v1_derive(
            offer, grant_nonce, offer->request_id) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return false;
    return mesh_private_object_offer_v1_sign(offer, seed) ==
           MESH_PRIVATE_OBJECT_PROTO_OK;
}

static void frame_make_ids(uint8_t transfer_id[32],
                           uint8_t offer_request_id[32])
{
    frame_fill(transfer_id, 32, 0x11);
    frame_fill(offer_request_id, 32, 0x51);
}

static int frame_offer_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("private object offer frame preserves its signed offer") {
        struct mesh_private_object_offer_v1 offer;
        struct mesh_private_object_frame_view_v1 view;
        uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_OFFER_BYTES];
        size_t wire_len = 99;
        ASSERT(frame_make_offer(&offer));
        ASSERT_EQ(mesh_private_object_frame_offer_v1_encode(
                      &offer, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(wire_len, sizeof(wire));
        ASSERT(memcmp(wire, "ZMPO", 4) == 0);
        ASSERT_EQ(zcl_read_u16_le(wire + 4),
                  MESH_PRIVATE_OBJECT_FRAME_VERSION);
        ASSERT_EQ(wire[6], MESH_PRIVATE_OBJECT_FRAME_OFFER);
        ASSERT_EQ(wire[7], MESH_PRIVATE_OBJECT_FRAME_FLAGS_NONE);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(view.kind, MESH_PRIVATE_OBJECT_FRAME_OFFER);
        uint8_t decoded_wire[MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES];
        ASSERT_EQ(mesh_private_object_offer_v1_encode(
                      &view.body.offer, decoded_wire),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(decoded_wire,
                      wire + MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES,
                      sizeof(decoded_wire)) == 0);

        wire[MESH_PRIVATE_OBJECT_FRAME_HEADER_BYTES + 100] ^= 1;
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_PAYLOAD);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&view, sizeof(view)));
    } TEST_END
    return failures;
}

static int frame_request_cancel_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("private object request and cancel frames bind one transfer") {
        struct mesh_private_object_chunk_request_v1 request = {0};
        struct mesh_private_object_cancel_v1 cancel = {0};
        struct mesh_private_object_frame_view_v1 view;
        uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES];
        size_t wire_len = 0;
        frame_make_ids(request.transfer_id, request.offer_request_id);
        request.chunk_request_id = UINT64_C(0x1122334455667788);
        request.chunk_index = UINT32_C(0xa1b2c3d4);
        ASSERT_EQ(mesh_private_object_frame_request_v1_encode(
                      &request, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(wire_len, MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES);
        ASSERT_EQ(zcl_read_u64_le(wire + 72), request.chunk_request_id);
        ASSERT_EQ(zcl_read_u32_le(wire + 80), request.chunk_index);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(view.kind, MESH_PRIVATE_OBJECT_FRAME_REQUEST);
        ASSERT(memcmp(view.body.request.transfer_id,
                      request.transfer_id, 32) == 0);
        ASSERT(memcmp(view.body.request.offer_request_id,
                      request.offer_request_id, 32) == 0);
        ASSERT_EQ(view.body.request.chunk_request_id,
                  request.chunk_request_id);
        ASSERT_EQ(view.body.request.chunk_index, request.chunk_index);

        memcpy(cancel.transfer_id, request.transfer_id, 32);
        memcpy(cancel.offer_request_id, request.offer_request_id, 32);
        cancel.cancel_id = UINT64_C(0x8877665544332211);
        ASSERT_EQ(mesh_private_object_frame_cancel_v1_encode(
                      &cancel, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(wire_len, MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(view.kind, MESH_PRIVATE_OBJECT_FRAME_CANCEL);
        ASSERT(memcmp(view.body.cancel.transfer_id,
                      cancel.transfer_id, 32) == 0);
        ASSERT(memcmp(view.body.cancel.offer_request_id,
                      cancel.offer_request_id, 32) == 0);
        ASSERT_EQ(view.body.cancel.cancel_id, cancel.cancel_id);
    } TEST_END
    return failures;
}

static int frame_chunk_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("private object chunk frame carries one maximum sealed chunk") {
        struct mesh_private_object_chunk_v1 chunk = {0};
        struct mesh_private_object_frame_view_v1 view;
        uint8_t sealed[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
        uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_MAX];
        size_t wire_len = 0;
        frame_make_ids(chunk.transfer_id, chunk.offer_request_id);
        chunk.chunk_request_id = UINT64_C(0x0102030405060708);
        chunk.chunk_index = 1234;
        frame_fill(sealed, sizeof(sealed), 0x91);
        chunk.sealed = sealed;
        chunk.sealed_len = sizeof(sealed);
        ASSERT_EQ(mesh_private_object_frame_chunk_v1_encode(
                      &chunk, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(wire_len, MESH_PRIVATE_OBJECT_FRAME_MAX);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(view.kind, MESH_PRIVATE_OBJECT_FRAME_CHUNK);
        ASSERT_EQ(view.body.chunk.sealed_len, sizeof(sealed));
        ASSERT(view.body.chunk.sealed ==
               wire + MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES);
        ASSERT(memcmp(view.body.chunk.sealed, sealed, sizeof(sealed)) == 0);
        ASSERT_EQ(view.body.chunk.chunk_index, chunk.chunk_index);
        ASSERT_EQ(view.body.chunk.chunk_request_id, chunk.chunk_request_id);
    } TEST_END
    return failures;
}

static int frame_refusals(void)
{
    int failures = 0;
    TEST_CASE("private object frames fail closed on malformed envelopes") {
        struct mesh_private_object_chunk_request_v1 request = {0};
        struct mesh_private_object_frame_view_v1 view;
        uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES + 1];
        size_t wire_len = 77;
        frame_make_ids(request.transfer_id, request.offer_request_id);
        request.chunk_request_id = 9;
        request.chunk_index = 3;
        ASSERT_EQ(mesh_private_object_frame_request_v1_encode(
                      &request, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);

        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len - 1),
                  MESH_PRIVATE_OBJECT_FRAME_SIZE);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&view, sizeof(view)));
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len + 1),
                  MESH_PRIVATE_OBJECT_FRAME_SIZE);
        wire[0] ^= 1;
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_MAGIC);
        wire[0] ^= 1;
        wire[4] = 2;
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_VERSION_INVALID);
        wire[4] = 1;
        wire[7] = 1;
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_FLAGS);
        wire[7] = 0;
        wire[6] = 99;
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_KIND_INVALID);
        wire[6] = MESH_PRIVATE_OBJECT_FRAME_REQUEST;
        memset(wire + 8, 0, 32);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_FIELD);

        wire_len = 55;
        ASSERT_EQ(mesh_private_object_frame_request_v1_encode(
                      &request, wire,
                      MESH_PRIVATE_OBJECT_FRAME_REQUEST_BYTES - 1,
                      &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_SIZE);
        ASSERT_EQ(wire_len, 0);
        request.chunk_request_id = 0;
        ASSERT_EQ(mesh_private_object_frame_request_v1_encode(
                      &request, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_FIELD);
        ASSERT_EQ(wire_len, 0);
    } TEST_END
    return failures;
}

static int frame_chunk_refusals(void)
{
    int failures = 0;
    TEST_CASE("private object chunk frames reject impossible sealed lengths") {
        struct mesh_private_object_chunk_v1 chunk = {0};
        struct mesh_private_object_frame_view_v1 view;
        uint8_t sealed[MESH_PRIVATE_OBJECT_TAG_BYTES + 1u] = {0};
        uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES +
                     sizeof(sealed) + 1u];
        size_t wire_len = 0;
        frame_make_ids(chunk.transfer_id, chunk.offer_request_id);
        chunk.chunk_request_id = 1;
        chunk.sealed = sealed;
        chunk.sealed_len = sizeof(sealed);
        ASSERT_EQ(mesh_private_object_frame_chunk_v1_encode(
                      &chunk, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len - 1u),
                  MESH_PRIVATE_OBJECT_FRAME_SIZE);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len + 1u),
                  MESH_PRIVATE_OBJECT_FRAME_SIZE);
        zcl_write_u32_le(wire + 84, MESH_PRIVATE_OBJECT_TAG_BYTES);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_FIELD);
        zcl_write_u32_le(wire + 84, MESH_PRIVATE_OBJECT_CHUNK_BYTES + 1u);
        ASSERT_EQ(mesh_private_object_frame_v1_decode(
                      &view, wire, wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_FIELD);
        chunk.sealed_len = MESH_PRIVATE_OBJECT_TAG_BYTES;
        ASSERT_EQ(mesh_private_object_frame_chunk_v1_encode(
                      &chunk, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_FIELD);
        ASSERT_EQ(wire_len, 0);
    } TEST_END
    return failures;
}

int test_mesh_private_object_frame(void)
{
    int failures = 0;
    failures += frame_offer_roundtrip();
    failures += frame_request_cancel_roundtrip();
    failures += frame_chunk_roundtrip();
    failures += frame_refusals();
    failures += frame_chunk_refusals();
    return failures;
}
