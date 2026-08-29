/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical and adversarial private-object root acceptance. */

#include "test/test_core.h"

#include "session/mesh_private_object_proto.h"
#include "session/mesh_private_object_root.h"

#include <string.h>

static void root_fill(uint8_t *out, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(seed + i * 29u);
}

static int root_canonical(void)
{
    int failures = 0;
    TEST_CASE("private object plaintext and ciphertext roots are canonical") {
        constexpr uint32_t last_plain = 19;
        constexpr uint64_t object_size =
            MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + last_plain;
        constexpr uint64_t ciphertext_size =
            object_size + 2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
        uint8_t plain0[MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES];
        uint8_t plain1[last_plain];
        uint8_t cipher0[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
        uint8_t cipher1[last_plain + MESH_PRIVATE_OBJECT_TAG_BYTES];
        root_fill(plain0, sizeof(plain0), 1);
        root_fill(plain1, sizeof(plain1), 2);
        root_fill(cipher0, sizeof(cipher0), 3);
        root_fill(cipher1, sizeof(cipher1), 4);

        struct mesh_private_object_root_v1 plain, cipher, repeat;
        uint8_t plain_root[32], cipher_root[32], repeated_root[32];
        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &plain, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &plain, 0, plain0, sizeof(plain0)),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &plain, 1, plain1, sizeof(plain1)),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_finalize(&plain, plain_root),
                  MESH_PRIVATE_OBJECT_ROOT_OK);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &cipher, MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &cipher, 0, cipher0, sizeof(cipher0)),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &cipher, 1, cipher1, sizeof(cipher1)),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_finalize(&cipher, cipher_root),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT(memcmp(plain_root, cipher_root, 32) != 0);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &repeat, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &repeat, 0, plain0, sizeof(plain0)),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &repeat, 1, plain1, sizeof(plain1)),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_finalize(
                      &repeat, repeated_root),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT(memcmp(plain_root, repeated_root, 32) == 0);
    } TEST_END
    return failures;
}

static int root_refusals(void)
{
    int failures = 0;
    TEST_CASE("private object roots fail closed on malformed streams") {
        constexpr uint32_t last_plain = 7;
        constexpr uint64_t object_size =
            MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + last_plain;
        constexpr uint64_t ciphertext_size =
            object_size + 2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
        uint8_t chunk[MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES] = {0};
        uint8_t out[32];
        struct mesh_private_object_root_v1 root;

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &root, 1, chunk, last_plain),
                  MESH_PRIVATE_OBJECT_ROOT_INDEX);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &root, 0, chunk, sizeof(chunk)),
                  MESH_PRIVATE_OBJECT_ROOT_STATE);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &root, 0, chunk, sizeof(chunk) - 1u),
                  MESH_PRIVATE_OBJECT_ROOT_LENGTH);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        memset(out, 0xa5, sizeof(out));
        ASSERT_EQ(mesh_private_object_root_v1_finalize(&root, out),
                  MESH_PRIVATE_OBJECT_ROOT_INCOMPLETE);
        for (size_t i = 0; i < sizeof(out); i++) ASSERT_EQ(out[i], 0);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 2),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        root.bytes_seen = UINT64_MAX;
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &root, 0, chunk, sizeof(chunk)),
                  MESH_PRIVATE_OBJECT_ROOT_OVERFLOW);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      last_plain, last_plain + MESH_PRIVATE_OBJECT_TAG_BYTES,
                      1), MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_update(
                      &root, 0, chunk, last_plain),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        ASSERT_EQ(mesh_private_object_root_v1_finalize(&root, out),
                  MESH_PRIVATE_OBJECT_ROOT_OK);
        memset(out, 0xa5, sizeof(out));
        ASSERT_EQ(mesh_private_object_root_v1_finalize(&root, out),
                  MESH_PRIVATE_OBJECT_ROOT_STATE);
        for (size_t i = 0; i < sizeof(out); i++) ASSERT_EQ(out[i], 0);

        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size - 1u, 2),
                  MESH_PRIVATE_OBJECT_ROOT_PARAMETER);
        ASSERT_EQ(mesh_private_object_root_v1_init(
                      &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
                      object_size, ciphertext_size, 1),
                  MESH_PRIVATE_OBJECT_ROOT_PARAMETER);
    } TEST_END
    return failures;
}

int test_mesh_private_object_root(void)
{
    int failures = 0;
    failures += root_canonical();
    failures += root_refusals();
    return failures;
}
