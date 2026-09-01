/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Known-answer regression seal for the Sprout/Sapling note-encryption key
 * derivation functions in core/modules/sapling/src/note_encryption.c:
 *
 *   sapling_kdf(key, dhsecret, epk)
 *       BLAKE2b-256 personal "Zcash_SaplingKDF", block = dhsecret || epk (64B)
 *   sapling_prf_ock(key, ovk, cv, cm, epk)
 *       BLAKE2b-256 personal "Zcash_Derive_ock", block = ovk||cv||cm||epk (128B)
 *   sprout_kdf(key, hsig, dhsecret, epk, pk_enc, nonce)
 *       BLAKE2b-256 personal "ZcashKDF\0..\0<nonce>",
 *       block = hsig || dhsecret || epk || pk_enc (128B)
 *
 * These three functions are consensus-adjacent: they produce the symmetric
 * keys that gate ChaCha20-Poly1305 over shielded note plaintexts. A silent
 * change in BLAKE2b personalization, block layout, or byte ordering would
 * make this node unable to decrypt notes produced by every other Zcash/
 * ZClassic implementation. The expected vectors below were captured from the
 * real functions over fixed inputs and are pinned byte-for-byte: any drift in
 * the KDF construction breaks the seal.
 *
 * sapling/note_encryption.h is included directly by this file.
 */

#include "test/test_core.h"
#include "sapling/note_encryption.h"

/* Fill `buf[32]` with bytes (base + i) & 0xff for a deterministic, distinct
 * 32-byte input. Distinct `base` values produce distinct blocks. */
static void kdf_fill(uint8_t buf[32], uint8_t base)
{
    for (int i = 0; i < 32; i++)
        buf[i] = (uint8_t)(base + (uint8_t)i);
}

static bool kdf_all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0)
            return false;
    return true;
}

/* ── 1. sapling_kdf fixed-vector seal + 32-byte / non-zero contract ──── */
int test_note_encryption_sapling_kdf_known_answer(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sapling_kdf known-answer seal") {
        /* dhsecret = 0x00..0x1f, epk = 0x80..0x9f */
        uint8_t dhsecret[32], epk[32];
        kdf_fill(dhsecret, 0x00);
        kdf_fill(epk, 0x80);

        /* Captured from the real sapling_kdf over the inputs above:
         * BLAKE2b-256("Zcash_SaplingKDF", dhsecret || epk). */
        static const uint8_t expected[32] = {
            0xb1,0x3a,0xcd,0x7c,0xe4,0x08,0xed,0xc6,
            0x8b,0x21,0x00,0x12,0xb8,0xb6,0x3e,0x1d,
            0x48,0xd5,0x25,0x5b,0xd6,0x1b,0x28,0xe1,
            0x2b,0x7c,0x39,0xfa,0x43,0x83,0xf4,0x27,
        };

        /* Poison the output buffer so a no-op KDF cannot accidentally pass. */
        uint8_t key[32];
        memset(key, 0xCD, sizeof(key));
        ASSERT(sapling_kdf(key, dhsecret, epk));

        /* 32-byte, non-zero, and byte-exact to the pinned vector. */
        ASSERT(!kdf_all_zero(key, 32));
        ASSERT(memcmp(key, expected, 32) == 0);

        /* Determinism: recomputing yields the identical key. */
        uint8_t key2[32];
        memset(key2, 0xAB, sizeof(key2));
        ASSERT(sapling_kdf(key2, dhsecret, epk));
        ASSERT(memcmp(key, key2, 32) == 0);
    } TEST_END
    return failures;
}

/* ── 2. sapling_kdf: swapping dhsecret and epk yields a different key ─── */
int test_note_encryption_sapling_kdf_arg_order_distinct(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sapling_kdf arg-order distinct") {
        uint8_t a[32], b[32];
        kdf_fill(a, 0x00); /* "dhsecret" role */
        kdf_fill(b, 0x80); /* "epk" role */

        uint8_t key_ab[32], key_ba[32];
        ASSERT(sapling_kdf(key_ab, a, b));
        ASSERT(sapling_kdf(key_ba, b, a)); /* args swapped */

        /* The block is dhsecret||epk, so swapping must change the digest. */
        ASSERT(memcmp(key_ab, key_ba, 32) != 0);

        /* Pin the swapped output too, so neither branch can silently mutate
         * into the other (which would also pass a bare "!=" check). */
        static const uint8_t expected_ba[32] = {
            0x45,0x21,0xea,0xb2,0xb9,0x85,0x98,0xaa,
            0x70,0x65,0x9e,0xe9,0x7f,0x30,0xf3,0x87,
            0x53,0x66,0x17,0x95,0xcf,0xdf,0x5a,0xcf,
            0x01,0x2e,0x30,0xe6,0x7a,0xd4,0x26,0x09,
        };
        ASSERT(memcmp(key_ba, expected_ba, 32) == 0);
    } TEST_END
    return failures;
}

/* ── 3. sapling_kdf: flipping any single input byte changes the key ──── */
int test_note_encryption_sapling_kdf_avalanche(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sapling_kdf single-byte avalanche") {
        uint8_t dhsecret[32], epk[32];
        kdf_fill(dhsecret, 0x40);
        kdf_fill(epk, 0xC0);

        uint8_t base[32];
        ASSERT(sapling_kdf(base, dhsecret, epk));

        /* Flip each byte of dhsecret in turn — output must change. */
        for (int i = 0; i < 32; i++) {
            uint8_t mod[32];
            memcpy(mod, dhsecret, 32);
            mod[i] ^= 0xFF;
            uint8_t k[32];
            ASSERT(sapling_kdf(k, mod, epk));
            ASSERT(memcmp(k, base, 32) != 0);
        }

        /* Flip each byte of epk in turn — output must change. */
        for (int i = 0; i < 32; i++) {
            uint8_t mod[32];
            memcpy(mod, epk, 32);
            mod[i] ^= 0xFF;
            uint8_t k[32];
            ASSERT(sapling_kdf(k, dhsecret, mod));
            ASSERT(memcmp(k, base, 32) != 0);
        }
    } TEST_END
    return failures;
}

/* ── 4. sprout_kdf fixed-vector seal at nonce 0 and nonce 7 ──────────── */
int test_note_encryption_sprout_kdf_known_answer(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sprout_kdf known-answer seal") {
        uint8_t hsig[32], dhsecret[32], epk[32], pk_enc[32];
        kdf_fill(hsig, 0x11);
        kdf_fill(dhsecret, 0x22);
        kdf_fill(epk, 0x33);
        kdf_fill(pk_enc, 0x44);

        /* nonce = 0 vector. */
        static const uint8_t expected_n0[32] = {
            0xa0,0x43,0x26,0x8e,0xc8,0x28,0xd9,0x42,
            0x4f,0x2b,0x56,0x43,0x05,0x55,0x62,0xbd,
            0x7d,0x58,0x27,0xf9,0x3d,0x7a,0xc0,0x73,
            0xe2,0xe2,0x22,0x24,0x3e,0xb8,0xe6,0x8c,
        };
        uint8_t k0[32];
        memset(k0, 0x5A, sizeof(k0));
        ASSERT(sprout_kdf(k0, hsig, dhsecret, epk, pk_enc, 0));
        ASSERT(!kdf_all_zero(k0, 32));
        ASSERT(memcmp(k0, expected_n0, 32) == 0);

        /* nonce = 7 vector (same block, different personalization byte). */
        static const uint8_t expected_n7[32] = {
            0xa2,0xd8,0x8c,0x2c,0xf0,0x0c,0x51,0x5c,
            0x35,0x68,0x7f,0x67,0x79,0xa1,0x8a,0xbf,
            0xfb,0xc8,0x06,0xfd,0x74,0xc1,0xe0,0x15,
            0xb9,0xff,0x81,0x05,0x82,0x45,0x81,0x00,
        };
        uint8_t k7[32];
        memset(k7, 0x5A, sizeof(k7));
        ASSERT(sprout_kdf(k7, hsig, dhsecret, epk, pk_enc, 7));
        ASSERT(!kdf_all_zero(k7, 32));
        ASSERT(memcmp(k7, expected_n7, 32) == 0);

        /* Nonce is part of the personalization, so n0 != n7. */
        ASSERT(memcmp(k0, k7, 32) != 0);
    } TEST_END
    return failures;
}

/* ── 5. sprout_kdf: every nonce 0..254 yields a distinct, valid key ──── */
int test_note_encryption_sprout_kdf_nonce_sweep(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sprout_kdf nonce 0..254 distinct") {
        uint8_t hsig[32], dhsecret[32], epk[32], pk_enc[32];
        kdf_fill(hsig, 0x01);
        kdf_fill(dhsecret, 0x02);
        kdf_fill(epk, 0x03);
        kdf_fill(pk_enc, 0x04);

        /* 255 valid nonces (the encrypt path caps at 254). Store every
         * derived key, then assert pairwise distinctness across the sweep.
         * 255*32 = 8160 bytes on the stack — well within limits. */
        static uint8_t keys[255][32];
        for (int n = 0; n <= 254; n++) {
            uint8_t k[32];
            memset(k, 0x00, sizeof(k));
            ASSERT(sprout_kdf(k, hsig, dhsecret, epk, pk_enc, (uint8_t)n));
            ASSERT(!kdf_all_zero(k, 32)); /* every nonce gives a real key */
            memcpy(keys[n], k, 32);
        }

        /* No two distinct nonces collide — the nonce truly differentiates
         * the BLAKE2b personalization. O(n^2) over 255 entries is cheap. */
        for (int i = 0; i <= 254; i++)
            for (int j = i + 1; j <= 254; j++)
                ASSERT(memcmp(keys[i], keys[j], 32) != 0);
    } TEST_END
    return failures;
}

/* ── 6. sprout_kdf: flipping any byte of any block input changes key ──── */
int test_note_encryption_sprout_kdf_avalanche(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sprout_kdf single-byte avalanche") {
        uint8_t hsig[32], dhsecret[32], epk[32], pk_enc[32];
        kdf_fill(hsig, 0x10);
        kdf_fill(dhsecret, 0x30);
        kdf_fill(epk, 0x50);
        kdf_fill(pk_enc, 0x70);

        uint8_t base[32];
        ASSERT(sprout_kdf(base, hsig, dhsecret, epk, pk_enc, 0));

        /* Treat the four 32-byte inputs as one logical block and flip every
         * byte; each flip must change the output. */
        uint8_t *fields[4] = { hsig, dhsecret, epk, pk_enc };
        for (int f = 0; f < 4; f++) {
            for (int i = 0; i < 32; i++) {
                uint8_t saved = fields[f][i];
                fields[f][i] ^= 0xFF;
                uint8_t k[32];
                ASSERT(sprout_kdf(k, hsig, dhsecret, epk, pk_enc, 0));
                ASSERT(memcmp(k, base, 32) != 0);
                fields[f][i] = saved; /* restore for the next iteration */
            }
        }

        /* And the nonce input also avalanches (already covered in the sweep,
         * but pin it directly against `base`). */
        for (int n = 1; n <= 254; n++) {
            uint8_t k[32];
            ASSERT(sprout_kdf(k, hsig, dhsecret, epk, pk_enc, (uint8_t)n));
            ASSERT(memcmp(k, base, 32) != 0);
        }
    } TEST_END
    return failures;
}

/* ── 7. sapling_prf_ock fixed-vector seal + per-field avalanche ──────── */
int test_note_encryption_prf_ock_known_answer(void)
{
    int failures = 0;
    TEST_CASE("note_encryption sapling_prf_ock known-answer + avalanche") {
        uint8_t ovk[32], cv[32], cm[32], epk[32];
        kdf_fill(ovk, 0x55);
        kdf_fill(cv, 0x66);
        kdf_fill(cm, 0x77);
        kdf_fill(epk, 0x88);

        /* Captured from the real sapling_prf_ock:
         * BLAKE2b-256("Zcash_Derive_ock", ovk || cv || cm || epk). */
        static const uint8_t expected[32] = {
            0x85,0x1a,0x51,0xbe,0x1d,0xcd,0xa1,0x8d,
            0x6a,0xde,0x20,0x34,0xcf,0x13,0x64,0xe1,
            0xf1,0xaa,0x19,0x4f,0x56,0x05,0xc2,0x78,
            0xaf,0xc6,0xf6,0xc8,0x78,0x99,0xa9,0x24,
        };
        uint8_t key[32];
        memset(key, 0x33, sizeof(key));
        ASSERT(sapling_prf_ock(key, ovk, cv, cm, epk));
        ASSERT(!kdf_all_zero(key, 32));
        ASSERT(memcmp(key, expected, 32) == 0);

        /* Each of the four 32-byte fields must affect the output: flip every
         * byte of each in turn and require a change vs. the sealed key. */
        uint8_t *fields[4] = { ovk, cv, cm, epk };
        for (int f = 0; f < 4; f++) {
            for (int i = 0; i < 32; i++) {
                uint8_t saved = fields[f][i];
                fields[f][i] ^= 0xFF;
                uint8_t k[32];
                ASSERT(sapling_prf_ock(k, ovk, cv, cm, epk));
                ASSERT(memcmp(k, expected, 32) != 0);
                fields[f][i] = saved;
            }
        }
    } TEST_END
    return failures;
}

/* ── 8. Cross-domain separation: the three KDFs over the same bytes
 *       must not collide (distinct BLAKE2b personalizations). ────────── */
int test_note_encryption_kdf_domain_separation(void)
{
    int failures = 0;
    TEST_CASE("note_encryption KDF domain separation") {
        /* Feed identical 32-byte chunks into all three KDFs and require the
         * personalization strings keep their outputs apart. */
        uint8_t a[32], b[32], c[32], d[32];
        kdf_fill(a, 0xA0);
        kdf_fill(b, 0xB0);
        kdf_fill(c, 0xC0);
        kdf_fill(d, 0xD0);

        uint8_t sap[32], ock[32], spr[32];
        ASSERT(sapling_kdf(sap, a, b));
        ASSERT(sapling_prf_ock(ock, a, b, c, d));
        ASSERT(sprout_kdf(spr, a, b, c, d, 0));

        ASSERT(!kdf_all_zero(sap, 32));
        ASSERT(!kdf_all_zero(ock, 32));
        ASSERT(!kdf_all_zero(spr, 32));

        /* Different personalization / block length ⇒ all three differ. */
        ASSERT(memcmp(sap, ock, 32) != 0);
        ASSERT(memcmp(sap, spr, 32) != 0);
        ASSERT(memcmp(ock, spr, 32) != 0);
    } TEST_END
    return failures;
}
