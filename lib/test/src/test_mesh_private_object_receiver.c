/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Receiver composition acceptance for resume, pipeline, and cancel. */

#include "test/test_core.h"

#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "session/mesh_private_object_crypto.h"
#include "session/mesh_private_object_root.h"
#include "services/mesh_private_object_receiver.h"

#include <string.h>

struct receiver_fixture {
    struct mesh_private_object_offer_v1 offer;
    uint8_t target_secret[32];
    uint8_t sealed[2][MESH_PRIVATE_OBJECT_CHUNK_BYTES];
    size_t sealed_len[2];
};

static void receiver_fill(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(first + i);
}

static bool receiver_fixture_make(struct receiver_fixture *f, uint8_t tag)
{
    memset(f, 0, sizeof(*f));
    uint8_t source_secret[32], online_seed[32], ignored_secret[32];
    uint8_t grant_nonce[32];
    receiver_fill(source_secret, (uint8_t)(0x11u + tag));
    receiver_fill(f->target_secret, 0x31);
    receiver_fill(online_seed, (uint8_t)(0x51u + tag));
    receiver_fill(grant_nonce, (uint8_t)(0x71u + tag));
    if (!curve25519_scalarmult_base(
            f->offer.ephemeral_x25519_pubkey, source_secret) ||
        !curve25519_scalarmult_base(
            f->offer.target_noise_static, f->target_secret))
        return false;
    f->offer.version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    receiver_fill(f->offer.network_genesis, 0x01);
    receiver_fill(f->offer.pairing_id, 0x21);
    receiver_fill(f->offer.grant_id, (uint8_t)(0x41u + tag));
    receiver_fill(f->offer.source_master_pubkey, (uint8_t)(0x61u + tag));
    receiver_fill(f->offer.source_noise_static, (uint8_t)(0x81u + tag));
    ed25519_keypair(f->offer.source_online_pubkey, ignored_secret,
                    online_seed);
    memset(ignored_secret, 0, sizeof(ignored_secret));
    receiver_fill(f->offer.target_master_pubkey, 0xa1);
    receiver_fill(f->offer.transcript_hash, (uint8_t)(0xc1u + tag));
    f->offer.connection_generation = 9 + tag;
    f->offer.pairing_revocation_generation = 3;
    f->offer.object_size_bytes =
        MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 7u;
    f->offer.chunk_size = MESH_PRIVATE_OBJECT_CHUNK_BYTES;
    f->offer.chunk_count = 2;
    f->offer.ciphertext_size_bytes =
        f->offer.object_size_bytes + 2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
    f->offer.issued_unix = UINT64_C(1800000000);
    f->offer.expires_unix = f->offer.issued_unix + 60;
    f->offer.deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;

    uint8_t plain[2][MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES] = {{0}};
    for (size_t i = 0; i < sizeof(plain[0]); i++)
        plain[0][i] = (uint8_t)(i * 29u + 7u + tag);
    for (size_t i = 0; i < 7; i++)
        plain[1][i] = (uint8_t)(0xd0u + i + tag);
    struct mesh_private_object_root_v1 root;
    bool rooted = mesh_private_object_root_v1_init(
            &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
            f->offer.object_size_bytes, f->offer.ciphertext_size_bytes, 2) ==
            MESH_PRIVATE_OBJECT_ROOT_OK &&
        mesh_private_object_root_v1_update(
            &root, 0, plain[0], sizeof(plain[0])) ==
            MESH_PRIVATE_OBJECT_ROOT_OK &&
        mesh_private_object_root_v1_update(&root, 1, plain[1], 7) ==
            MESH_PRIVATE_OBJECT_ROOT_OK &&
        mesh_private_object_root_v1_finalize(
            &root, f->offer.plaintext_root) == MESH_PRIVATE_OBJECT_ROOT_OK;
    if (!rooted ||
        mesh_private_object_chunk_seal_v1(
            &f->offer, source_secret, 0, plain[0], sizeof(plain[0]),
            f->sealed[0], sizeof(f->sealed[0]), &f->sealed_len[0]) !=
            MESH_PRIVATE_OBJECT_CHUNK_OK ||
        mesh_private_object_chunk_seal_v1(
            &f->offer, source_secret, 1, plain[1], 7,
            f->sealed[1], sizeof(f->sealed[1]), &f->sealed_len[1]) !=
            MESH_PRIVATE_OBJECT_CHUNK_OK)
        return false;
    if (mesh_private_object_root_v1_init(
            &root, MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT,
            f->offer.object_size_bytes, f->offer.ciphertext_size_bytes, 2) !=
            MESH_PRIVATE_OBJECT_ROOT_OK ||
        mesh_private_object_root_v1_update(
            &root, 0, f->sealed[0], f->sealed_len[0]) !=
            MESH_PRIVATE_OBJECT_ROOT_OK ||
        mesh_private_object_root_v1_update(
            &root, 1, f->sealed[1], f->sealed_len[1]) !=
            MESH_PRIVATE_OBJECT_ROOT_OK ||
        mesh_private_object_root_v1_finalize(
            &root, f->offer.ciphertext_root) != MESH_PRIVATE_OBJECT_ROOT_OK)
        return false;
    return mesh_private_object_offer_request_id_v1_derive(
               &f->offer, grant_nonce, f->offer.request_id) ==
               MESH_PRIVATE_OBJECT_PROTO_OK &&
        mesh_private_object_offer_v1_sign(&f->offer, online_seed) ==
            MESH_PRIVATE_OBJECT_PROTO_OK;
}

static bool receiver_admission_make(
    const struct mesh_private_object_offer_v1 *offer,
    struct mesh_private_object_admission *admission)
{
    memset(admission, 0, sizeof(*admission));
    admission->reason = MESH_PRIVATE_OBJECT_ADMISSION_NEW;
    admission->pairing_revocation_generation =
        offer->pairing_revocation_generation;
    admission->grant_revocation_generation = 1;
    return mesh_private_object_offer_v1_root(
               offer, admission->offer_root) == MESH_PRIVATE_OBJECT_PROTO_OK &&
        mesh_private_object_offer_transfer_id_v1(
            offer, admission->transfer_id) == MESH_PRIVATE_OBJECT_PROTO_OK;
}

struct receiver_emissions {
    struct mesh_private_object_chunk_request_v1 requests[8];
    size_t count;
};

static bool receiver_emit(
    const struct mesh_private_object_chunk_request_v1 *request, void *opaque)
{
    struct receiver_emissions *emissions = opaque;
    if (!request || !emissions || emissions->count >= 8) return false;
    emissions->requests[emissions->count++] = *request;
    return true;
}

static bool receiver_emit_refuse(
    const struct mesh_private_object_chunk_request_v1 *request, void *opaque)
{
    (void)request;
    (void)opaque;
    return false;
}

static int receiver_resume(void)
{
    int failures = 0;
    TEST_CASE("private receiver pipelines, reopens, and completes exact chunks") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "mesh_private_receiver", "resume");
        struct receiver_fixture f;
        ASSERT(receiver_fixture_make(&f, 0));
        struct mesh_private_object_admission admission;
        ASSERT(receiver_admission_make(&f.offer, &admission));
        struct mesh_private_object_receiver *receiver = NULL;
        struct zcl_result result = mesh_private_object_receiver_create(
            dir, f.target_secret, &receiver);
        ASSERT(result.ok);
        enum mesh_private_object_receiver_result outcome;
        struct mesh_private_object_admission unbound = admission;
        unbound.offer_root[0] ^= 1u;
        result = mesh_private_object_receiver_admit(
            receiver, &f.offer, &unbound, 7, 100, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_AUTH);
        ASSERT_EQ(mesh_private_object_receiver_active(receiver), 0);
        result = mesh_private_object_receiver_admit(
            receiver, &f.offer, &admission, 7, 100, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_OK);
        struct receiver_emissions emitted = {0};
        size_t count = 0;
        result = mesh_private_object_receiver_drive(
            receiver, &admission, 7, 999, receiver_emit_refuse,
            NULL, &count, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_BACKPRESSURE);
        ASSERT_EQ(count, 0);
        result = mesh_private_object_receiver_drive(
            receiver, &admission, 7, 1000, receiver_emit,
            &emitted, &count, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_OK);
        ASSERT_EQ(count, 2);
        ASSERT_EQ(emitted.count, 2);
        ASSERT_EQ(emitted.requests[0].chunk_index, 0);
        ASSERT_EQ(emitted.requests[1].chunk_index, 1);

        struct mesh_private_object_chunk_v1 chunk = {
            .chunk_request_id = emitted.requests[1].chunk_request_id,
            .chunk_index = 1,
            .sealed = f.sealed[1],
            .sealed_len = (uint32_t)f.sealed_len[1],
        };
        memcpy(chunk.transfer_id, admission.transfer_id, 32);
        memcpy(chunk.offer_request_id, f.offer.request_id, 32);
        result = mesh_private_object_receiver_chunk(
            receiver, &chunk, &admission, 8, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
        chunk.chunk_request_id++;
        result = mesh_private_object_receiver_chunk(
            receiver, &chunk, &admission, 7, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_CORRELATION);
        chunk.chunk_request_id--;
        result = mesh_private_object_receiver_chunk(
            receiver, &chunk, &admission, 7, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_OK);
        mesh_private_object_receiver_free(receiver);

        receiver = NULL;
        result = mesh_private_object_receiver_create(
            dir, f.target_secret, &receiver);
        ASSERT(result.ok);
        admission.reason = MESH_PRIVATE_OBJECT_ADMISSION_RESUME;
        result = mesh_private_object_receiver_admit(
            receiver, &f.offer, &admission, 9, 200, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_RESUME);
        memset(&emitted, 0, sizeof(emitted));
        result = mesh_private_object_receiver_drive(
            receiver, &admission, 9, 2000, receiver_emit,
            &emitted, &count, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_OK);
        ASSERT_EQ(count, 1);
        ASSERT_EQ(emitted.requests[0].chunk_index, 0);
        chunk.chunk_request_id = emitted.requests[0].chunk_request_id;
        chunk.chunk_index = 0;
        chunk.sealed = f.sealed[0];
        chunk.sealed_len = (uint32_t)f.sealed_len[0];
        result = mesh_private_object_receiver_chunk(
            receiver, &chunk, &admission, 9, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_STAGED);
        ASSERT_EQ(mesh_private_object_receiver_active(receiver), 0);
        result = mesh_private_object_receiver_admit(
            receiver, &f.offer, &admission, 10, 300, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_STAGED);
        mesh_private_object_receiver_free(receiver);
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int receiver_capacity_and_cancel(void)
{
    int failures = 0;
    TEST_CASE("private receiver bounds active transfers and frees cancel slots") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "mesh_private_receiver", "cancel");
        struct receiver_fixture fixture;
        struct mesh_private_object_offer_v1 offers[5];
        struct mesh_private_object_admission admissions[5];
        for (uint8_t i = 0; i < 5; i++) {
            ASSERT(receiver_fixture_make(&fixture, (uint8_t)(i + 1u)));
            offers[i] = fixture.offer;
            ASSERT(receiver_admission_make(&offers[i], &admissions[i]));
        }
        struct mesh_private_object_receiver *receiver = NULL;
        struct zcl_result result = mesh_private_object_receiver_create(
            dir, fixture.target_secret, &receiver);
        ASSERT(result.ok);
        enum mesh_private_object_receiver_result outcome;
        for (uint8_t i = 0; i < MESH_PRIVATE_OBJECT_RECEIVER_MAX_TRANSFERS;
             i++) {
            result = mesh_private_object_receiver_admit(
                receiver, &offers[i], &admissions[i], i + 1u, 100 + i,
                &outcome);
            ASSERT(result.ok);
            ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_OK);
        }
        ASSERT_EQ(mesh_private_object_receiver_active(receiver), 4);
        result = mesh_private_object_receiver_admit(
            receiver, &offers[4], &admissions[4], 5, 105, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_BUSY);
        struct mesh_private_object_cancel_v1 cancel = {.cancel_id = 1};
        memcpy(cancel.transfer_id, admissions[0].transfer_id, 32);
        memcpy(cancel.offer_request_id, offers[0].request_id, 32);
        result = mesh_private_object_receiver_cancel(
            receiver, &cancel, 2, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_BINDING);
        result = mesh_private_object_receiver_cancel(
            receiver, &cancel, 1, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_CANCELLED);
        ASSERT_EQ(mesh_private_object_receiver_active(receiver), 3);
        result = mesh_private_object_receiver_admit(
            receiver, &offers[4], &admissions[4], 5, 105, &outcome);
        ASSERT(result.ok);
        ASSERT_EQ(outcome, MESH_PRIVATE_OBJECT_RECEIVER_OK);
        mesh_private_object_receiver_free(receiver);
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

int test_mesh_private_object_receiver(void)
{
    return receiver_resume() + receiver_capacity_and_cancel();
}
