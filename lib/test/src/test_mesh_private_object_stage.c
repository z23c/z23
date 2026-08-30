/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reopen, corruption, and root acceptance for private staging. */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "platform/directory_transaction.h"
#include "session/mesh_private_object_crypto.h"
#include "session/mesh_private_object_root.h"
#include "session/mesh_private_object_stage.h"

#include <string.h>

struct stage_fixture {
    struct mesh_private_object_offer_v1 offer;
    uint8_t source_secret[32];
    uint8_t target_secret[32];
    uint8_t online_seed[32];
    uint8_t sealed[2][MESH_PRIVATE_OBJECT_CHUNK_BYTES];
    size_t sealed_len[2];
};

static void stage_fill(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(first + i);
}

static bool stage_fixture_make(struct stage_fixture *f)
{
    memset(f, 0, sizeof(*f));
    stage_fill(f->source_secret, 0x11);
    stage_fill(f->target_secret, 0x31);
    stage_fill(f->online_seed, 0x51);
    uint8_t grant_nonce[32], ignored_secret[32];
    stage_fill(grant_nonce, 0x71);
    if (!curve25519_scalarmult_base(
            f->offer.ephemeral_x25519_pubkey, f->source_secret) ||
        !curve25519_scalarmult_base(
            f->offer.target_noise_static, f->target_secret))
        return false;
    f->offer.version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    stage_fill(f->offer.network_genesis, 0x01);
    stage_fill(f->offer.pairing_id, 0x21);
    stage_fill(f->offer.grant_id, 0x41);
    stage_fill(f->offer.source_master_pubkey, 0x61);
    stage_fill(f->offer.source_noise_static, 0x81);
    ed25519_keypair(f->offer.source_online_pubkey, ignored_secret,
                    f->online_seed);
    memset(ignored_secret, 0, sizeof(ignored_secret));
    stage_fill(f->offer.target_master_pubkey, 0xa1);
    stage_fill(f->offer.transcript_hash, 0xc1);
    f->offer.connection_generation = 9;
    f->offer.pairing_revocation_generation = 3;
    f->offer.object_size_bytes =
        MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 7u;
    f->offer.chunk_size = MESH_PRIVATE_OBJECT_CHUNK_BYTES;
    f->offer.chunk_count = 2;
    f->offer.ciphertext_size_bytes =
        f->offer.object_size_bytes +
        2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
    f->offer.issued_unix = UINT64_C(1800000000);
    f->offer.expires_unix = f->offer.issued_unix + 60;
    f->offer.deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;

    uint8_t plain[2][MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES] = {{0}};
    for (size_t i = 0; i < sizeof(plain[0]); i++)
        plain[0][i] = (uint8_t)(i * 29u + 7u);
    for (size_t i = 0; i < 7; i++) plain[1][i] = (uint8_t)(0xd0u + i);
    struct mesh_private_object_root_v1 root;
    if (mesh_private_object_root_v1_init(
            &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
            f->offer.object_size_bytes, f->offer.ciphertext_size_bytes, 2) !=
            MESH_PRIVATE_OBJECT_ROOT_OK ||
        mesh_private_object_root_v1_update(
            &root, 0, plain[0], sizeof(plain[0])) !=
            MESH_PRIVATE_OBJECT_ROOT_OK ||
        mesh_private_object_root_v1_update(&root, 1, plain[1], 7) !=
            MESH_PRIVATE_OBJECT_ROOT_OK ||
        mesh_private_object_root_v1_finalize(
            &root, f->offer.plaintext_root) != MESH_PRIVATE_OBJECT_ROOT_OK)
        return false;
    if (mesh_private_object_chunk_seal_v1(
            &f->offer, f->source_secret, 0, plain[0], sizeof(plain[0]),
            f->sealed[0], sizeof(f->sealed[0]), &f->sealed_len[0]) !=
            MESH_PRIVATE_OBJECT_CHUNK_OK ||
        mesh_private_object_chunk_seal_v1(
            &f->offer, f->source_secret, 1, plain[1], 7,
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
        mesh_private_object_offer_v1_sign(&f->offer, f->online_seed) ==
            MESH_PRIVATE_OBJECT_PROTO_OK;
}

static void stage_leaf(char out[80], const uint8_t id[32], const char *suffix)
{
    memcpy(out, "mpos-", 5);
    zcl_hex_encode(id, 32, out + 5);
    snprintf(out + 69, 11, ".%s", suffix);
}

static bool stage_append_journal(const char *dir, const uint8_t transfer_id[32],
                                 const uint8_t *bytes, size_t count)
{
    char leaf[80];
    stage_leaf(leaf, transfer_id, "journal");
    struct platform_directory_transaction directory;
    struct platform_directory_child journal;
    struct platform_directory_child_info info;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&journal);
    bool ok = platform_directory_transaction_open(&directory, dir) &&
        platform_directory_child_open(&directory, leaf, &journal) &&
        platform_directory_child_info(&journal, &info) &&
        platform_directory_child_write_exact(
            &journal, bytes, count, info.size) &&
        platform_directory_child_flush(&journal);
    platform_directory_child_close(&journal);
    platform_directory_transaction_close(&directory);
    return ok;
}

static int stage_resume_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("private staging resumes authenticated chunks and verifies root") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "mesh_private_stage", "resume");
        struct stage_fixture f;
        ASSERT(stage_fixture_make(&f));
        struct mesh_private_object_stage *stage = NULL;
        ASSERT_EQ(mesh_private_object_stage_open_v1(
                      &stage, dir, &f.offer, f.target_secret),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_put_v1(
                      stage, 1, f.sealed[1], f.sealed_len[1]),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT(mesh_private_object_stage_has_v1(stage, 1));
        ASSERT_EQ(mesh_private_object_stage_count_v1(stage), 1);
        ASSERT_EQ(mesh_private_object_stage_verify_v1(stage),
                  MESH_PRIVATE_OBJECT_STAGE_INCOMPLETE);
        mesh_private_object_stage_close(stage);
        stage = NULL;

        ASSERT_EQ(mesh_private_object_stage_open_v1(
                      &stage, dir, &f.offer, f.target_secret),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT(mesh_private_object_stage_has_v1(stage, 1));
        ASSERT_EQ(mesh_private_object_stage_put_v1(
                      stage, 0, f.sealed[0], f.sealed_len[0]),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_put_v1(
                      stage, 0, f.sealed[0], f.sealed_len[0]),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_count_v1(stage), 2);
        ASSERT_EQ(mesh_private_object_stage_verify_v1(stage),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        mesh_private_object_stage_close(stage);
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int stage_corruption_refusal(void)
{
    int failures = 0;
    TEST_CASE("private staging refuses a corrupted recorded chunk on reopen") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "mesh_private_stage", "corrupt");
        struct stage_fixture f;
        ASSERT(stage_fixture_make(&f));
        struct mesh_private_object_stage *stage = NULL;
        ASSERT_EQ(mesh_private_object_stage_open_v1(
                      &stage, dir, &f.offer, f.target_secret),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_put_v1(
                      stage, 0, f.sealed[0], f.sealed_len[0]),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        mesh_private_object_stage_close(stage);
        stage = NULL;

        uint8_t transfer_id[32];
        ASSERT_EQ(mesh_private_object_offer_transfer_id_v1(
                      &f.offer, transfer_id), MESH_PRIVATE_OBJECT_PROTO_OK);
        char leaf[80];
        stage_leaf(leaf, transfer_id, "data");
        struct platform_directory_transaction directory;
        struct platform_directory_child data;
        platform_directory_transaction_init(&directory);
        platform_directory_child_init(&data);
        ASSERT(platform_directory_transaction_open(&directory, dir));
        ASSERT(platform_directory_child_open(&directory, leaf, &data));
        uint8_t changed = (uint8_t)(f.sealed[0][0] ^ 1u);
        ASSERT(platform_directory_child_write_exact(&data, &changed, 1, 0));
        ASSERT(platform_directory_child_flush(&data));
        platform_directory_child_close(&data);
        platform_directory_transaction_close(&directory);

        ASSERT_EQ(mesh_private_object_stage_open_v1(
                      &stage, dir, &f.offer, f.target_secret),
                  MESH_PRIVATE_OBJECT_STAGE_CORRUPT);
        ASSERT(stage == NULL);
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int stage_cancellation(void)
{
    int failures = 0;
    TEST_CASE("private staging persists one terminal canonical cancellation") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "mesh_private_stage", "cancel");
        struct stage_fixture f;
        ASSERT(stage_fixture_make(&f));
        uint8_t transfer_id[32];
        ASSERT_EQ(mesh_private_object_offer_transfer_id_v1(
                      &f.offer, transfer_id), MESH_PRIVATE_OBJECT_PROTO_OK);
        struct mesh_private_object_cancel_v1 cancel = {.cancel_id = 17};
        memcpy(cancel.transfer_id, transfer_id, 32);
        memcpy(cancel.offer_request_id, f.offer.request_id, 32);
        struct mesh_private_object_stage *stage = NULL;
        ASSERT_EQ(mesh_private_object_stage_open_v1(
                      &stage, dir, &f.offer, f.target_secret),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_put_v1(
                      stage, 0, f.sealed[0], f.sealed_len[0]),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_cancel_v1(stage, &cancel),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        ASSERT_EQ(mesh_private_object_stage_cancel_v1(stage, &cancel),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        struct mesh_private_object_cancel_v1 recorded = {0};
        ASSERT(mesh_private_object_stage_cancelled_v1(stage, &recorded));
        ASSERT_EQ(recorded.cancel_id, cancel.cancel_id);
        ASSERT(memcmp(&recorded, &cancel, sizeof(cancel)) == 0);
        ASSERT_EQ(mesh_private_object_stage_put_v1(
                      stage, 1, f.sealed[1], f.sealed_len[1]),
                  MESH_PRIVATE_OBJECT_STAGE_CANCELLED);
        ASSERT_EQ(mesh_private_object_stage_verify_v1(stage),
                  MESH_PRIVATE_OBJECT_STAGE_CANCELLED);
        mesh_private_object_stage_close(stage);
        stage = NULL;
        ASSERT_EQ(mesh_private_object_stage_open_v1(
                      &stage, dir, &f.offer, f.target_secret),
                  MESH_PRIVATE_OBJECT_STAGE_OK);
        memset(&recorded, 0, sizeof(recorded));
        ASSERT(mesh_private_object_stage_cancelled_v1(stage, &recorded));
        ASSERT(memcmp(&recorded, &cancel, sizeof(cancel)) == 0);
        mesh_private_object_stage_close(stage);
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static bool stage_cancel_tail_refused(
    const struct stage_fixture *f, const uint8_t transfer_id[32],
    const char *tag, const uint8_t *tail, size_t tail_len)
{
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "mesh_private_stage", tag);
    struct mesh_private_object_stage *stage = NULL;
    bool created = mesh_private_object_stage_open_v1(
                       &stage, dir, &f->offer, f->target_secret) ==
                   MESH_PRIVATE_OBJECT_STAGE_OK;
    mesh_private_object_stage_close(stage);
    stage = NULL;
    bool appended = created &&
        stage_append_journal(dir, transfer_id, tail, tail_len);
    bool refused = appended && mesh_private_object_stage_open_v1(
        &stage, dir, &f->offer, f->target_secret) ==
        MESH_PRIVATE_OBJECT_STAGE_CORRUPT && stage == NULL;
    mesh_private_object_stage_close(stage);
    test_rm_rf_recursive(dir);
    return refused;
}

static int stage_cancel_corruption(void)
{
    int failures = 0;
    TEST_CASE("private staging fails closed on torn or forged cancellation") {
        struct stage_fixture f;
        ASSERT(stage_fixture_make(&f));
        uint8_t transfer_id[32];
        ASSERT_EQ(mesh_private_object_offer_transfer_id_v1(
                      &f.offer, transfer_id), MESH_PRIVATE_OBJECT_PROTO_OK);
        struct mesh_private_object_cancel_v1 cancel = {.cancel_id = 29};
        memcpy(cancel.transfer_id, transfer_id, 32);
        memcpy(cancel.offer_request_id, f.offer.request_id, 32);
        uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(mesh_private_object_frame_cancel_v1_encode(
                      &cancel, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);

        ASSERT(stage_cancel_tail_refused(
            &f, transfer_id, "cancel-torn", wire, wire_len - 1u));
        uint8_t oversized[MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES + 1u];
        memcpy(oversized, wire, wire_len);
        oversized[wire_len] = 0;
        ASSERT(stage_cancel_tail_refused(
            &f, transfer_id, "cancel-oversized",
            oversized, sizeof(oversized)));
        wire[0] ^= 1u;
        ASSERT(stage_cancel_tail_refused(
            &f, transfer_id, "cancel-malformed", wire, wire_len));
        wire[0] ^= 1u;
        wire[6] = MESH_PRIVATE_OBJECT_FRAME_REQUEST;
        ASSERT(stage_cancel_tail_refused(
            &f, transfer_id, "cancel-wrong-kind", wire, wire_len));
        wire[6] = MESH_PRIVATE_OBJECT_FRAME_CANCEL;
        memset(wire + 72, 0, 8);
        ASSERT(stage_cancel_tail_refused(
            &f, transfer_id, "cancel-zero-id", wire, wire_len));
        cancel.transfer_id[0] ^= 1u;
        ASSERT_EQ(mesh_private_object_frame_cancel_v1_encode(
                      &cancel, wire, sizeof(wire), &wire_len),
                  MESH_PRIVATE_OBJECT_FRAME_OK);
        ASSERT(stage_cancel_tail_refused(
            &f, transfer_id, "cancel-wrong-transfer", wire, wire_len));
    } TEST_END
    return failures;
}

int test_mesh_private_object_stage(void)
{
    return stage_resume_roundtrip() + stage_corruption_refusal() +
           stage_cancellation() + stage_cancel_corruption();
}
