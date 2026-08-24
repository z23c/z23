/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Known-answer tests for HMAC-SHA3-256 (NIST HMAC_SHA3-256.pdf examples)
 * and structural tests for HKDF-SHA3-256 (RFC 5869 over that HMAC). Overlay
 * KDF only — consensus SHA-256d and Noise HKDF-SHA256 are not these tests. */

#include "test/test_core.h"
#include "crypto/hkdf_sha256.h"
#include "crypto/hkdf_sha3.h"
#include "crypto/hmac_sha3.h"

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (const char *p = hex; p[0] && p[1] && n < cap; p += 2) {
        unsigned v;
        sscanf(p, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static bool bytes_are(const uint8_t *buf, size_t n, const char *expected)
{
    char hex[512];
    for (size_t i = 0; i < n && i * 2 + 2 < sizeof(hex); i++)
        snprintf(hex + i * 2, 3, "%02x", buf[i]);
    return strcmp(hex, expected) == 0;
}

static void hmac_oneshot(const unsigned char *key, size_t keylen,
                         const unsigned char *msg, size_t msglen,
                         unsigned char out[HMAC_SHA3_256_OUTPUT_SIZE])
{
    struct hmac_sha3_256_ctx ctx;
    hmac_sha3_256_init(&ctx, key, keylen);
    hmac_sha3_256_write(&ctx, msg, msglen);
    hmac_sha3_256_finalize(&ctx, out);
}

int test_hkdf_sha3_256(void)
{
    int failures = 0;

    TEST_CASE("hmac-sha3-256 NIST examples + HKDF-SHA3-256 structure") {
        unsigned char mac[HMAC_SHA3_256_OUTPUT_SIZE];
        uint8_t key[256];

        /* NIST HMAC_SHA3-256.pdf — keylen < blocklen (32-byte key). */
        {
            const unsigned char msg[] = "Sample message for keylen<blocklen";
            size_t klen = unhex(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f",
                key, sizeof(key));
            hmac_oneshot(key, klen, msg, sizeof(msg) - 1, mac);
            ASSERT(bytes_are(mac, 32,
                "4fe8e202c4f058e8dddc23d8c34e4673"
                "43e23555e24fc2f025d598f558f67205"));
        }

        /* NIST — keylen = blocklen (136-byte key, the SHA3-256 rate). */
        {
            const unsigned char msg[] = "Sample message for keylen=blocklen";
            for (int i = 0; i < HMAC_SHA3_256_BLOCK_SIZE; i++)
                key[i] = (uint8_t)i;
            hmac_oneshot(key, HMAC_SHA3_256_BLOCK_SIZE, msg,
                         sizeof(msg) - 1, mac);
            ASSERT(bytes_are(mac, 32,
                "68b94e2e538a9be4103bebb5aa016d47"
                "961d4d1aa906061313b557f8af2c3faa"));
        }

        /* NIST — keylen > blocklen (168-byte key is pre-hashed). */
        {
            const unsigned char msg[] = "Sample message for keylen>blocklen";
            for (int i = 0; i < 168; i++)
                key[i] = (uint8_t)i;
            hmac_oneshot(key, 168, msg, sizeof(msg) - 1, mac);
            ASSERT(bytes_are(mac, 32,
                "9bcf2c238e235c3ce88404e813bd2f3a"
                "97185ac6f238c63d6229a00b07974258"));
        }

        /* Multi-write equals one-shot (stateful HMAC). */
        {
            const unsigned char msg[] = "Sample message for keylen<blocklen";
            size_t klen = unhex(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f",
                key, sizeof(key));
            unsigned char split[HMAC_SHA3_256_OUTPUT_SIZE];
            struct hmac_sha3_256_ctx ctx;
            hmac_sha3_256_init(&ctx, key, klen);
            hmac_sha3_256_write(&ctx, msg, 6);
            hmac_sha3_256_write(&ctx, msg + 6, sizeof(msg) - 1 - 6);
            hmac_sha3_256_finalize(&ctx, split);
            hmac_oneshot(key, klen, msg, sizeof(msg) - 1, mac);
            ASSERT(memcmp(split, mac, 32) == 0);
        }

        /* HKDF: one-shot equals extract-then-expand; empty salt is defined. */
        {
            uint8_t ikm[22], salt[13], info[10], prk[32], okm[42], oneshot[42];
            size_t il = unhex(
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                ikm, sizeof(ikm));
            size_t sl = unhex("000102030405060708090a0b0c", salt, sizeof(salt));
            size_t fl = unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
            hkdf_sha3_256_extract(salt, sl, ikm, il, prk);
            ASSERT(hkdf_sha3_256_expand(prk, info, fl, okm, 42));
            ASSERT(hkdf_sha3_256(salt, sl, ikm, il, info, fl, oneshot, 42));
            ASSERT(memcmp(okm, oneshot, 42) == 0);

            uint8_t sha256_okm[42];
            ASSERT(hkdf_sha256(salt, sl, ikm, il, info, fl, sha256_okm, 42));
            ASSERT(memcmp(okm, sha256_okm, 42) != 0);

            uint8_t empty_prk[32], empty_okm[32];
            hkdf_sha3_256_extract(NULL, 0, ikm, il, empty_prk);
            ASSERT(hkdf_sha3_256_expand(empty_prk, NULL, 0, empty_okm, 32));
            ASSERT(memcmp(empty_prk, prk, 32) != 0);
        }

        /* RFC ceiling: 255 * HashLen is the max; one more byte fails. */
        {
            uint8_t prk[32];
            memset(prk, 0x11, sizeof(prk));
            uint8_t byte = 0;
            ASSERT(!hkdf_sha3_256_expand(prk, NULL, 0, &byte,
                                         (size_t)255 * 32 + 1));
            ASSERT(hkdf_sha3_256_expand(prk, NULL, 0, &byte, 0));
        }
    } TEST_END

    return failures;
}
