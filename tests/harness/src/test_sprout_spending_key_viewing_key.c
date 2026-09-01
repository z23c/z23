/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pin test for sprout_spending_key_to_viewing_key() in
 * core/modules/sapling/src/address.c.
 *
 * Pins:
 *   - a_pk is passed through from PRF_addr(a_sk, t=0) unchanged.
 *   - sk_enc is PRF_addr(a_sk, t=1) followed by Curve25519 clamping:
 *       data[0]  &= 0xF8  (clear low 3 bits)
 *       data[31] &= 0x7F  (clear high bit)
 *       data[31] |= 0x40  (set second-highest bit)
 *   - the transformation is deterministic (same seed -> same vk).
 *   - distinct spending keys yield distinct viewing keys.
 *
 * The expected PRF outputs are recomputed here from the same public
 * building blocks the production function uses (prf_addr_a_pk /
 * prf_addr_sk_enc from sapling/prf.h) rather than hardcoding SHA256
 * digests. This keeps the test honest about WHAT the function does
 * (passthrough + clamp + which t-index) without duplicating the hash
 * implementation: it fails if the passthrough breaks, the clamp rule
 * changes, or the a_pk/sk_enc t-indices are swapped. */

#include "test/test_core.h"
#include "sapling/prf.h"
#include "sapling/address.h"

int test_sprout_spending_key_viewing_key(void)
{
    int failures = 0;

    TEST_CASE("sprout_spending_key_to_viewing_key: passthrough + clamp + determinism") {
        /* A fixed, known seed (a_sk). Deliberately includes bytes whose
         * clamp targets (byte 0 and byte 31) start out "dirty" so the
         * clamp is forced to actually change them. */
        struct sprout_spending_key sk;
        for (int i = 0; i < 32; i++)
            sk.data[i] = (unsigned char)(i * 7 + 3);   /* 0x03, 0x0A, 0x11, ... */

        struct sprout_viewing_key vk;
        memset(&vk, 0xCC, sizeof(vk));   /* poison: detect untouched fields */
        sprout_spending_key_to_viewing_key(&sk, &vk);

        /* ---- a_pk is the raw PRF_addr(a_sk, 0), copied through verbatim ---- */
        struct uint256 expect_a_pk;
        prf_addr_a_pk(sk.data, &expect_a_pk);
        ASSERT(memcmp(vk.a_pk.data, expect_a_pk.data, 32) == 0);

        /* a_pk must not be the poison pattern (function actually wrote it). */
        bool a_pk_written = false;
        for (int i = 0; i < 32; i++)
            if (vk.a_pk.data[i] != 0xCC) { a_pk_written = true; break; }
        ASSERT(a_pk_written);

        /* ---- sk_enc is PRF_addr(a_sk, 1) with the three clamp ops ---- */
        struct uint256 expect_sk_enc;
        prf_addr_sk_enc(sk.data, &expect_sk_enc);

        /* Capture the pre-clamp values at the two clamp positions so we can
         * prove each clamp op is exactly the documented bit operation. */
        unsigned char raw0  = expect_sk_enc.data[0];
        unsigned char raw31 = expect_sk_enc.data[31];

        /* Apply the same clamp the production code applies, independently. */
        expect_sk_enc.data[0]  &= 0xF8;   /* 248 */
        expect_sk_enc.data[31] &= 0x7F;   /* 127 */
        expect_sk_enc.data[31] |= 0x40;   /* 64  */
        ASSERT(memcmp(vk.sk_enc.data, expect_sk_enc.data, 32) == 0);

        /* sk_enc and a_pk derive from different PRF t-indices, so they must
         * differ (guards against an accidental t-swap that would make both
         * equal). */
        ASSERT(memcmp(vk.sk_enc.data, vk.a_pk.data, 32) != 0);

        /* ---- Pin each clamp rule as an absolute bit invariant ---- */
        /* Low 3 bits of byte 0 cleared. */
        ASSERT((vk.sk_enc.data[0] & 0x07) == 0);
        /* The remaining high bits of byte 0 are preserved (input & 0xF8). */
        ASSERT(vk.sk_enc.data[0] == (unsigned char)(raw0 & 0xF8));
        /* High bit of byte 31 cleared. */
        ASSERT((vk.sk_enc.data[31] & 0x80) == 0);
        /* Second-highest bit of byte 31 set. */
        ASSERT((vk.sk_enc.data[31] & 0x40) == 0x40);
        /* Full byte-31 rule: (input & 0x7F) | 0x40. */
        ASSERT(vk.sk_enc.data[31] ==
               (unsigned char)((raw31 & 0x7F) | 0x40));

        /* The clamp must have genuinely modified our chosen dirty seed:
         * (i*7+3) at byte 0 is 0x03 (low bits set -> changes), and the PRF
         * outputs above are non-trivial, so at minimum bit-6 of byte 31 is
         * forced on. Assert the function did not leave poison in sk_enc. */
        bool sk_enc_written = false;
        for (int i = 0; i < 32; i++)
            if (vk.sk_enc.data[i] != 0xCC) { sk_enc_written = true; break; }
        ASSERT(sk_enc_written);

        /* ---- Determinism: a second derivation from the same seed is bit
         * identical (no hidden RNG / global state). ---- */
        struct sprout_viewing_key vk2;
        memset(&vk2, 0x00, sizeof(vk2));
        sprout_spending_key_to_viewing_key(&sk, &vk2);
        ASSERT(memcmp(vk2.a_pk.data,  vk.a_pk.data,  32) == 0);
        ASSERT(memcmp(vk2.sk_enc.data, vk.sk_enc.data, 32) == 0);

        /* ---- Distinct spending keys -> distinct viewing keys ---- */
        struct sprout_spending_key sk_other;
        memcpy(sk_other.data, sk.data, 32);
        sk_other.data[0] ^= 0x01;   /* flip a single bit of the seed */

        struct sprout_viewing_key vk_other;
        sprout_spending_key_to_viewing_key(&sk_other, &vk_other);

        /* Both components are PRF outputs of the (now different) seed, so
         * each must change; a one-bit seed change must not leave the whole
         * viewing key identical. */
        bool a_pk_differs  = memcmp(vk_other.a_pk.data,  vk.a_pk.data,  32) != 0;
        bool sk_enc_differs = memcmp(vk_other.sk_enc.data, vk.sk_enc.data, 32) != 0;
        ASSERT(a_pk_differs);
        ASSERT(sk_enc_differs);

        /* Even though sk_other yields a different sk_enc, the clamp
         * invariants must still hold for it (rule is seed-independent). */
        ASSERT((vk_other.sk_enc.data[0]  & 0x07) == 0x00);
        ASSERT((vk_other.sk_enc.data[31] & 0x80) == 0x00);
        ASSERT((vk_other.sk_enc.data[31] & 0x40) == 0x40);
    } TEST_END

    return failures;
}
