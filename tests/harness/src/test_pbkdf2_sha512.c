/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for PBKDF2-HMAC-SHA512 (RFC 8018 §5.2).
 *
 * Module under test: core/modules/crypto/src/pbkdf2_sha512.c
 *   void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
 *                            const uint8_t *salt, size_t salt_len,
 *                            uint32_t iterations,
 *                            uint8_t *out, size_t out_len);
 *
 * Expected outputs below were derived from the reference C implementation
 * itself and independently corroborate the canonical RFC PBKDF2-HMAC-SHA512
 * test vector for (P="password", S="salt", c=1, dkLen=64):
 *   867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252
 *   c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce
 *
 * One TEST_CASE per test_*() entrypoint (TEST_END defines a label, so two
 * per function would not compile).
 */

#include "test/test_core.h"
#include "crypto/pbkdf2_sha512.h"

/* ── Shared expected vectors (lowercase hex) ─────────────────────────────
 *
 * BLOCK1 is T_1 for (P="password", S="salt", c=1): the full 64-byte output
 * for dkLen=64, and also the first 64 bytes of any dkLen >= 64 derivation
 * with the same inputs (PBKDF2 derives each output block independently). */
static const char *const BLOCK1_HEX =
    "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
    "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce";

/* BLOCK2 is T_2 for the same inputs (salt || INT(2) as the HMAC message),
 * i.e. bytes [64,128) of the dkLen=128 derivation. A correct big-endian
 * block counter is the only thing that makes this block come out right. */
static const char *const BLOCK2_HEX =
    "7b532e206c2967d4c7d2ffa460539fc4d4e5eec70125d74c6c7cf86d25284f29"
    "7907fcea1ad214effdbea23e1312084eabb180ab72edbac45ea2a53f5f5b9fe1";

/* c=4096, dkLen=64 for (P="password", S="salt"): pins the U_j chaining /
 * XOR-accumulation loop across a high iteration count. */
static const char *const C4096_HEX =
    "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
    "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5";

/* Empty password AND empty salt, c=1, dkLen=64. */
static const char *const EMPTY_HEX =
    "6d2ecbbbfb2e6dcd7056faf9af6aa06eae594391db983279a6bf27e0eb228614"
    "3ab0c996f33ca4b667e945829ea693340f2831797324e5f31df18ed171d18c97";

/* Convert a 2*n char lowercase-hex string into n bytes. */
static void from_hex(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* ── Test 1: RFC vector, c=1, dkLen=64 (full deterministic output) ─────── */
int test_pbkdf2_sha512_rfc_vector(void)
{
    int failures = 0;

    TEST_CASE("pbkdf2_sha512: RFC vector P=password S=salt c=1 dkLen=64") {
        uint8_t expect[64];
        from_hex(BLOCK1_HEX, expect, 64);

        /* Pre-fill the buffer with a sentinel so a no-op implementation that
         * silently returns (e.g. mis-evaluated guard) would leave 0xCC and
         * fail the byte comparison rather than passing vacuously. */
        uint8_t out[64];
        memset(out, 0xCC, sizeof(out));

        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           1, out, sizeof(out));

        /* Every one of the 64 output bytes must match the known vector. */
        ASSERT(memcmp(out, expect, 64) == 0);

        /* Spot-pin endpoints so a partial/off-by-one copy is caught loudly. */
        ASSERT(out[0] == 0x86);
        ASSERT(out[63] == 0xce);
    } TEST_END

    return failures;
}

/* ── Test 2: multi-block (dkLen=128) — block counter + XOR accumulation ── */
int test_pbkdf2_sha512_multiblock(void)
{
    int failures = 0;

    TEST_CASE("pbkdf2_sha512: dkLen=128 spans two blocks, INT(i) big-endian") {
        uint8_t expect1[64], expect2[64];
        from_hex(BLOCK1_HEX, expect1, 64);
        from_hex(BLOCK2_HEX, expect2, 64);

        uint8_t out[128];
        memset(out, 0x55, sizeof(out));

        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           1, out, sizeof(out));

        /* Block 1 ([0,64)) is independent of dkLen and must equal the
         * dkLen=64 result — confirms per-block derivation, not a stream. */
        ASSERT(memcmp(out, expect1, 64) == 0);

        /* Block 2 ([64,128)) is computed with INT(2) appended to the salt.
         * It only matches if the 32-bit block counter is encoded big-endian
         * ({00 00 00 02}); a little-endian counter would produce garbage. */
        ASSERT(memcmp(out + 64, expect2, 64) == 0);

        /* The two blocks must differ — proves the counter actually advanced
         * rather than re-deriving block 1 twice. */
        ASSERT(memcmp(out, out + 64, 64) != 0);

        /* Cross-pin: a fresh dkLen=64 call yields exactly the first block. */
        uint8_t half[64];
        memset(half, 0x00, sizeof(half));
        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           1, half, sizeof(half));
        ASSERT(memcmp(half, out, 64) == 0);
    } TEST_END

    return failures;
}

/* ── Test 3: high iteration count (c=4096) ─────────────────────────────── */
int test_pbkdf2_sha512_high_iterations(void)
{
    int failures = 0;

    TEST_CASE("pbkdf2_sha512: c=4096 U_j chaining + XOR accumulation") {
        uint8_t expect[64];
        from_hex(C4096_HEX, expect, 64);

        uint8_t out[64];
        memset(out, 0x00, sizeof(out));
        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           4096, out, sizeof(out));
        ASSERT(memcmp(out, expect, 64) == 0);

        /* 4096 iterations must differ from 1 iteration — proves the inner
         * U_j loop ran and accumulated, not short-circuited. */
        uint8_t one[64];
        memset(one, 0x00, sizeof(one));
        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           1, one, sizeof(one));
        ASSERT(memcmp(out, one, 64) != 0);

        /* iterations==0 is normalized to 1 by the implementation, so it must
         * equal the c=1 result exactly (pins that defensive clamp). */
        uint8_t zero[64];
        memset(zero, 0x11, sizeof(zero));
        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           0, zero, sizeof(zero));
        ASSERT(memcmp(zero, one, 64) == 0);
    } TEST_END

    return failures;
}

/* ── Test 4: empty password AND empty salt boundary ────────────────────── */
int test_pbkdf2_sha512_empty_inputs(void)
{
    int failures = 0;

    TEST_CASE("pbkdf2_sha512: empty password and empty salt, c=1, dkLen=64") {
        uint8_t expect[64];
        from_hex(EMPTY_HEX, expect, 64);

        uint8_t out[64];
        memset(out, 0xEE, sizeof(out));

        /* Zero-length P and S with non-NULL pointers must derive normally
         * (HMAC of an empty key / empty salt is well-defined). */
        pbkdf2_hmac_sha512((const uint8_t *)"", 0,
                           (const uint8_t *)"", 0,
                           1, out, sizeof(out));
        ASSERT(memcmp(out, expect, 64) == 0);

        /* The sentinel must have been fully overwritten (no byte left 0xEE
         * by accident); also distinct from the non-empty-input vector. */
        uint8_t pw_vector[64];
        from_hex(BLOCK1_HEX, pw_vector, 64);
        ASSERT(memcmp(out, pw_vector, 64) != 0);
    } TEST_END

    return failures;
}

/* ── Test 5: out_len == 1 — final-block memcpy take/clamp boundary ─────── */
int test_pbkdf2_sha512_one_byte_output(void)
{
    int failures = 0;

    TEST_CASE("pbkdf2_sha512: out_len=1 copies exactly one byte, no overrun") {
        /* Surround the 1-byte output with guard bytes so a too-large
         * memcpy (take not clamped to out_len) would clobber a guard and
         * fail; the implementation computes take=min(HLEN, out_len)=1. */
        uint8_t buf[5];
        memset(buf, 0xAB, sizeof(buf));

        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           1, &buf[1], 1);

        /* The single derived byte equals byte 0 of the full c=1 vector. */
        ASSERT(buf[1] == 0x86);

        /* Guards on both sides untouched — confirms exactly one byte written
         * and no underflow/overflow past the requested length. */
        ASSERT(buf[0] == 0xAB);
        ASSERT(buf[2] == 0xAB);
        ASSERT(buf[3] == 0xAB);
        ASSERT(buf[4] == 0xAB);

        /* out_len==0 with a non-NULL buffer must be a no-op (early return):
         * the byte stays at its sentinel value. */
        uint8_t noop = 0x7F;
        pbkdf2_hmac_sha512((const uint8_t *)"password", 8,
                           (const uint8_t *)"salt", 4,
                           1, &noop, 0);
        ASSERT(noop == 0x7F);
    } TEST_END

    return failures;
}
