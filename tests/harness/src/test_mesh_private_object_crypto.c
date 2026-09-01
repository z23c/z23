/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Adversarial acceptance for private-object chunk encryption. */

#include "test/test_core.h"

#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "session/mesh_private_object_crypto.h"

#include <string.h>

static void chunk_test_fill(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static bool chunk_test_offer(
    struct mesh_private_object_offer_v1 *offer, uint8_t source_secret[32],
    uint8_t target_secret[32], uint8_t online_seed[32],
    uint8_t grant_nonce[32])
{
    memset(offer, 0, sizeof(*offer));
    chunk_test_fill(source_secret, 0x11);
    chunk_test_fill(target_secret, 0x31);
    chunk_test_fill(online_seed, 0x51);
    chunk_test_fill(grant_nonce, 0x71);
    uint8_t ignored_secret[32];
    if (!curve25519_scalarmult_base(
            offer->ephemeral_x25519_pubkey, source_secret) ||
        !curve25519_scalarmult_base(
            offer->target_noise_static, target_secret))
        return false;
    offer->version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    chunk_test_fill(offer->network_genesis, 0x01);
    chunk_test_fill(offer->pairing_id, 0x21);
    chunk_test_fill(offer->grant_id, 0x41);
    chunk_test_fill(offer->source_master_pubkey, 0x61);
    chunk_test_fill(offer->source_noise_static, 0x81);
    ed25519_keypair(offer->source_online_pubkey, ignored_secret, online_seed);
    memset(ignored_secret, 0, sizeof(ignored_secret));
    chunk_test_fill(offer->target_master_pubkey, 0xa1);
    chunk_test_fill(offer->transcript_hash, 0xc1);
    offer->connection_generation = 9;
    offer->pairing_revocation_generation = 3;
    chunk_test_fill(offer->plaintext_root, 0xe1);
    offer->object_size_bytes =
        2u * MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES;
    offer->chunk_size = MESH_PRIVATE_OBJECT_CHUNK_BYTES;
    offer->chunk_count = 2;
    offer->ciphertext_size_bytes =
        offer->object_size_bytes +
        offer->chunk_count * MESH_PRIVATE_OBJECT_TAG_BYTES;
    offer->issued_unix = UINT64_C(1800000000);
    offer->expires_unix = offer->issued_unix + 60;
    offer->deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;
    return true;
}

static int chunk_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("private object chunks round-trip with independent AEAD") {
        struct mesh_private_object_offer_v1 offer;
        uint8_t source_secret[32], target_secret[32], online_seed[32];
        uint8_t grant_nonce[32], context_before[32], context_after[32];
        ASSERT(chunk_test_offer(&offer, source_secret, target_secret,
                                online_seed, grant_nonce));
        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &offer, context_before),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        uint8_t plain[MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES];
        uint8_t opened[sizeof(plain)];
        uint8_t sealed[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
        for (size_t i = 0; i < sizeof(plain); i++)
            plain[i] = (uint8_t)(i * 29u + 7u);
        size_t sealed_len = 0, opened_len = 0;
        ASSERT_EQ(mesh_private_object_chunk_seal_v1(
                      &offer, source_secret, 0, plain, sizeof(plain),
                      sealed, sizeof(sealed), &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
        ASSERT_EQ(sealed_len, MESH_PRIVATE_OBJECT_CHUNK_BYTES);
        ASSERT(memcmp(sealed, plain, sizeof(plain)) != 0);
        ASSERT_EQ(mesh_private_object_chunk_open_v1(
                      &offer, target_secret, 0, sealed, sealed_len,
                      opened, sizeof(opened), &opened_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
        ASSERT_EQ(opened_len, sizeof(plain));
        ASSERT(memcmp(opened, plain, sizeof(plain)) == 0);

        sha3_256(sealed, sealed_len, offer.ciphertext_root);
        ASSERT_EQ(mesh_private_object_offer_request_id_v1_derive(
                      &offer, grant_nonce, offer.request_id),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&offer, online_seed),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &offer, context_after),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(context_before, context_after, 32) == 0);
        ASSERT_EQ(mesh_private_object_chunk_open_v1(
                      &offer, target_secret, 0, sealed, sealed_len,
                      opened, sizeof(opened), &opened_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
    } TEST_END
    return failures;
}

static int chunk_refusals(void)
{
    int failures = 0;
    TEST_CASE("private object chunks reject wrong key, index, size, and tag") {
        struct mesh_private_object_offer_v1 offer;
        uint8_t source_secret[32], target_secret[32], online_seed[32];
        uint8_t grant_nonce[32], wrong_secret[32];
        ASSERT(chunk_test_offer(&offer, source_secret, target_secret,
                                online_seed, grant_nonce));
        uint8_t plain[MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES] = {0};
        uint8_t opened[sizeof(plain)], sealed[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
        size_t sealed_len = 0, opened_len = 0;
        ASSERT_EQ(mesh_private_object_chunk_seal_v1(
                      &offer, source_secret, 0, plain, sizeof(plain), sealed,
                      sizeof(sealed), &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
        chunk_test_fill(wrong_secret, 0x91);
        ASSERT_EQ(mesh_private_object_chunk_seal_v1(
                      &offer, wrong_secret, 0, plain, sizeof(plain), sealed,
                      sizeof(sealed), &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH);
        ASSERT_EQ(mesh_private_object_chunk_open_v1(
                      &offer, wrong_secret, 0, sealed, sizeof(sealed), opened,
                      sizeof(opened), &opened_len),
                  MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH);
        ASSERT_EQ(mesh_private_object_chunk_open_v1(
                      &offer, target_secret, 2, sealed, sizeof(sealed), opened,
                      sizeof(opened), &opened_len),
                  MESH_PRIVATE_OBJECT_CHUNK_INDEX);
        ASSERT_EQ(mesh_private_object_chunk_open_v1(
                      &offer, target_secret, 0, sealed, sizeof(sealed) - 1,
                      opened, sizeof(opened), &opened_len),
                  MESH_PRIVATE_OBJECT_CHUNK_SIZE);

        ASSERT_EQ(mesh_private_object_chunk_seal_v1(
                      &offer, source_secret, 0, plain, sizeof(plain), sealed,
                      sizeof(sealed), &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
        sealed[sealed_len - 1] ^= 1;
        memset(opened, 0xa5, sizeof(opened));
        ASSERT_EQ(mesh_private_object_chunk_open_v1(
                      &offer, target_secret, 0, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len),
                  MESH_PRIVATE_OBJECT_CHUNK_AUTH);
        ASSERT_EQ(opened_len, 0);
        for (size_t i = 0; i < sizeof(opened); i++)
            ASSERT_EQ(opened[i], 0);
    } TEST_END
    return failures;
}

static int chunk_geometry(void)
{
    int failures = 0;
    TEST_CASE("private object last-chunk geometry is canonical") {
        struct mesh_private_object_offer_v1 offer;
        uint8_t source_secret[32], target_secret[32], online_seed[32];
        uint8_t grant_nonce[32];
        ASSERT(chunk_test_offer(&offer, source_secret, target_secret,
                                online_seed, grant_nonce));
        offer.object_size_bytes =
            MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 7u;
        offer.chunk_count = 2;
        offer.ciphertext_size_bytes =
            offer.object_size_bytes + 2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
        uint32_t plain_len = 0, sealed_len = 0;
        ASSERT_EQ(mesh_private_object_chunk_shape_v1(
                      &offer, 0, &plain_len, &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
        ASSERT_EQ(plain_len, MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES);
        ASSERT_EQ(sealed_len, MESH_PRIVATE_OBJECT_CHUNK_BYTES);
        ASSERT_EQ(mesh_private_object_chunk_shape_v1(
                      &offer, 1, &plain_len, &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OK);
        ASSERT_EQ(plain_len, 7);
        ASSERT_EQ(sealed_len, 7 + MESH_PRIVATE_OBJECT_TAG_BYTES);
        offer.ciphertext_size_bytes--;
        ASSERT_EQ(mesh_private_object_chunk_shape_v1(
                      &offer, 0, &plain_len, &sealed_len),
                  MESH_PRIVATE_OBJECT_CHUNK_OFFER);
    } TEST_END
    return failures;
}

int test_mesh_private_object_crypto(void)
{
    int failures = 0;
    failures += chunk_roundtrip();
    failures += chunk_refusals();
    failures += chunk_geometry();
    return failures;
}
