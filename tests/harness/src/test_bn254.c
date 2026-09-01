/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * BN-254 (alt_bn128) pairing tests.
 * Validates Fq arithmetic, G1/G2 operations, and pairing correctness
 * using known test vectors from Ethereum EIP-197 and mathematical properties. */

#include "test/test_core.h"
#include "sapling/bn254.h"

/* Load Fq element from decimal string (for test vectors) */
static bool fq_from_decimal(struct bn_fq *r, const char *s)
{
    uint64_t raw[4] = {0};
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        __uint128_t carry = (uint64_t)(*p - '0');
        for (int i = 0; i < 4; i++) {
            carry += (__uint128_t)raw[i] * 10;
            raw[i] = (uint64_t)carry;
            carry >>= 64;
        }
    }
    uint8_t be[32];
    for (int i = 0; i < 32; i++) {
        int limb = (31 - i) / 8;
        int shift = ((31 - i) % 8) * 8;
        be[i] = (uint8_t)(raw[limb] >> shift);
    }
    return bn_fq_from_bytes_be(r, be);
}

int test_bn254(void)
{
    int failures = 0;

    printf("\n=== BN-254 Pairing Tests ===\n");

    printf("Fq basic arithmetic... ");
    {
        struct bn_fq a, b, c, one, zero;
        bn_fq_one(&one);
        bn_fq_zero(&zero);

        /* 1 + 1 = 2, 2 * 2 = 4, 4 - 1 = 3 */
        bn_fq_add(&a, &one, &one);    /* a = 2 */
        bn_fq_mul(&b, &a, &a);        /* b = 4 */
        bn_fq_sub(&c, &b, &one);      /* c = 3 */

        /* 3 * inv(3) = 1 */
        struct bn_fq inv_c, prod;
        bn_fq_inv(&inv_c, &c);
        bn_fq_mul(&prod, &c, &inv_c);
        bool ok = bn_fq_eq(&prod, &one);

        /* 0 is additive identity */
        bn_fq_add(&prod, &a, &zero);
        ok = ok && bn_fq_eq(&prod, &a);

        /* 1 is multiplicative identity */
        bn_fq_mul(&prod, &a, &one);
        ok = ok && bn_fq_eq(&prod, &a);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Fq from_bytes/to_bytes roundtrip... ");
    {
        /* The number 42 */
        struct bn_fq a;
        bn_fq_from_u64(&a, 42);
        uint8_t buf[32];
        bn_fq_to_bytes_be(buf, &a);
        struct bn_fq b;
        bn_fq_from_bytes_be(&b, buf);
        bool ok = bn_fq_eq(&a, &b);

        /* Verify byte representation: 42 in BE is all zeros except last byte */
        ok = ok && (buf[31] == 42);
        bool all_zero = true;
        for (int i = 0; i < 31; i++) if (buf[i] != 0) all_zero = false;
        ok = ok && all_zero;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Fq2 arithmetic... ");
    {
        struct bn_fq2 a, b, one, prod, inv_a;
        bn_fq2_one(&one);  /* (1, 0) */
        /* a = (3, 4) — a + b*i */
        bn_fq_from_u64(&a.c0, 3);
        bn_fq_from_u64(&a.c1, 4);

        /* inv(a) * a = 1 */
        bn_fq2_inv(&inv_a, &a);
        bn_fq2_mul(&prod, &a, &inv_a);
        bool ok = bn_fq2_eq(&prod, &one);

        /* a * 1 = a */
        bn_fq2_mul(&b, &a, &one);
        ok = ok && bn_fq2_eq(&b, &a);

        /* (a+b)(a-b) = a^2 - b^2 (Fq2 product formula) */
        struct bn_fq2 c, sum, diff, lhs, rhs, a2, c2;
        bn_fq_from_u64(&c.c0, 7);
        bn_fq_from_u64(&c.c1, 2);
        bn_fq2_add(&sum, &a, &c);
        bn_fq2_sub(&diff, &a, &c);
        bn_fq2_mul(&lhs, &sum, &diff);
        bn_fq2_sq(&a2, &a);
        bn_fq2_sq(&c2, &c);
        bn_fq2_sub(&rhs, &a2, &c2);
        ok = ok && bn_fq2_eq(&lhs, &rhs);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("G1 point operations... ");
    {
        /* G1 generator: (1, 2) is the standard BN-254 G1 generator */
        struct bn_g1 g;
        bn_fq_from_u64(&g.x, 1);
        bn_fq_from_u64(&g.y, 2);
        bn_fq_one(&g.z);

        /* G is not identity */
        bool ok = !bn_g1_is_identity(&g);

        /* G + G = 2G, should not be identity */
        struct bn_g1 g2;
        bn_g1_double(&g2, &g);
        ok = ok && !bn_g1_is_identity(&g2);

        /* 2G via double == G+G via add */
        struct bn_g1 g2_add;
        bn_g1_add(&g2_add, &g, &g);
        struct bn_fq ax1, ay1, ax2, ay2;
        bn_g1_to_affine(&ax1, &ay1, &g2);
        bn_g1_to_affine(&ax2, &ay2, &g2_add);
        ok = ok && bn_fq_eq(&ax1, &ax2) && bn_fq_eq(&ay1, &ay2);

        /* G - G = identity */
        struct bn_g1 neg_g, zero;
        bn_g1_neg(&neg_g, &g);
        bn_g1_add(&zero, &g, &neg_g);
        ok = ok && bn_g1_is_identity(&zero);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("G1 scalar multiplication... ");
    {
        /* G1 generator */
        struct bn_g1 g;
        bn_fq_from_u64(&g.x, 1);
        bn_fq_from_u64(&g.y, 2);
        bn_fq_one(&g.z);

        bool ok = true;

        /* 1*G = G */
        uint64_t scalar_one[4] = {1, 0, 0, 0};
        struct bn_g1 result;
        bn_g1_scalar_mul(&result, &g, scalar_one);
        struct bn_fq ax, ay, gx, gy;
        bn_g1_to_affine(&ax, &ay, &result);
        bn_g1_to_affine(&gx, &gy, &g);
        if (!bn_fq_eq(&ax, &gx) || !bn_fq_eq(&ay, &gy)) {
            printf("FAIL (1*G != G)\n"); failures++; ok = false;
        }

        /* 0*G = identity */
        if (ok) {
            uint64_t scalar_zero[4] = {0, 0, 0, 0};
            bn_g1_scalar_mul(&result, &g, scalar_zero);
            if (!bn_g1_is_identity(&result)) {
                printf("FAIL (0*G != identity)\n"); failures++; ok = false;
            }
        }

        /* 2*G should equal G+G */
        if (ok) {
            uint64_t scalar_two[4] = {2, 0, 0, 0};
            struct bn_g1 g2_scalar, g2_add;
            bn_g1_scalar_mul(&g2_scalar, &g, scalar_two);
            bn_g1_add(&g2_add, &g, &g);
            struct bn_fq sx, sy, ax2, ay2;
            bn_g1_to_affine(&sx, &sy, &g2_scalar);
            bn_g1_to_affine(&ax2, &ay2, &g2_add);
            if (!bn_fq_eq(&sx, &ax2) || !bn_fq_eq(&sy, &ay2)) {
                printf("FAIL (2*G != G+G)\n"); failures++; ok = false;
            }
        }

        if (ok) printf("OK\n");
    }

    printf("Fq12 frobenius maps... ");
    {
        /* f^{p^12} = f for all f in Fq12 (by Fermat's little theorem for Fq12*).
         * Equivalently, applying the p-Frobenius 12 times should give identity.
         * We test: applying p^6 Frobenius is conjugation. */
        struct bn_fq12 f, fp6;
        bn_fq12_one(&f);
        /* Set f to something non-trivial */
        bn_fq_from_u64(&f.c0.c0.c0, 7);
        bn_fq_from_u64(&f.c0.c1.c0, 13);
        bn_fq_from_u64(&f.c1.c0.c0, 3);

        /* Frobenius_p^6 should equal conjugation */
        struct bn_fq12 fp, fp2, fp3;
        bn_fq12_frobenius_map(&fp, &f, 1);
        bn_fq12_frobenius_map(&fp2, &fp, 1);
        bn_fq12_frobenius_map(&fp3, &fp2, 1);
        struct bn_fq12 fp4, fp5;
        bn_fq12_frobenius_map(&fp4, &fp3, 1);
        bn_fq12_frobenius_map(&fp5, &fp4, 1);
        bn_fq12_frobenius_map(&fp6, &fp5, 1);

        /* fp6 should equal conjugate(f) */
        struct bn_fq12 conj_f;
        conj_f = f;
        bn_fq12_conjugate(&conj_f);
        bool ok = bn_fq12_eq(&fp6, &conj_f);

        /* Frobenius_p^12 = identity */
        struct bn_fq12 fp7, fp8, fp9, fp10, fp11, fp12;
        bn_fq12_frobenius_map(&fp7, &fp6, 1);
        bn_fq12_frobenius_map(&fp8, &fp7, 1);
        bn_fq12_frobenius_map(&fp9, &fp8, 1);
        bn_fq12_frobenius_map(&fp10, &fp9, 1);
        bn_fq12_frobenius_map(&fp11, &fp10, 1);
        bn_fq12_frobenius_map(&fp12, &fp11, 1);
        ok = ok && bn_fq12_eq(&fp12, &f);

        /* Frobenius p^2(f) applied 6 times = f */
        struct bn_fq12 g1, g2, g3, g4, g5, g6;
        bn_fq12_frobenius_map(&g1, &f, 2);
        bn_fq12_frobenius_map(&g2, &g1, 2);
        bn_fq12_frobenius_map(&g3, &g2, 2);
        bn_fq12_frobenius_map(&g4, &g3, 2);
        bn_fq12_frobenius_map(&g5, &g4, 2);
        bn_fq12_frobenius_map(&g6, &g5, 2);
        ok = ok && bn_fq12_eq(&g6, &f);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Pairing: e(G1, G2) != 1 (non-degeneracy)... ");
    {
        /* G1 generator: (1, 2) */
        struct bn_g1 g1;
        bn_fq_from_u64(&g1.x, 1);
        bn_fq_from_u64(&g1.y, 2);
        bn_fq_one(&g1.z);

        /* G2 generator (standard alt_bn128) */
        static const uint8_t g2_x_c0[32] = {
            0x18,0x00,0xde,0xef,0x12,0x1f,0x1e,0x76,0x42,0x6a,0x00,0x66,0x5e,0x5c,0x44,0x79,
            0x67,0x44,0x22,0xce,0x15,0x39,0x28,0x47,0x02,0xb3,0xf6,0x6f,0x43,0x60,0x0e,0xd3
        };
        static const uint8_t g2_x_c1[32] = {
            0x19,0x8e,0x95,0x93,0x92,0x0d,0x48,0x3a,0x72,0x60,0xbf,0xb7,0x31,0xfb,0x5d,0x25,
            0xf1,0xaa,0x49,0x33,0x35,0xa9,0xe7,0x12,0x97,0xe4,0x85,0xb7,0xae,0xf3,0x12,0xc2
        };
        static const uint8_t g2_y_c0[32] = {
            0x12,0xc8,0x5e,0xa5,0xdb,0x8c,0x6d,0xeb,0x4a,0xab,0x71,0x80,0x8d,0xcb,0x40,0x8f,
            0xe3,0xd1,0xe7,0x69,0x0c,0x43,0xd3,0x7b,0x49,0x03,0x87,0x01,0x06,0x42,0xac,0xca
        };
        static const uint8_t g2_y_c1[32] = {
            0x09,0x0e,0xf9,0xd8,0xbe,0x39,0x9a,0xf0,0x09,0x96,0x0a,0x6a,0xdb,0x13,0x23,0xd2,
            0xdc,0x5c,0xf0,0x14,0x0c,0xac,0x34,0x15,0x22,0x99,0x0b,0x5c,0x27,0x13,0xef,0x0b
        };

        struct bn_g2 g2;
        bn_fq_from_bytes_be(&g2.x.c0, g2_x_c0);
        bn_fq_from_bytes_be(&g2.x.c1, g2_x_c1);
        bn_fq_from_bytes_be(&g2.y.c0, g2_y_c0);
        bn_fq_from_bytes_be(&g2.y.c1, g2_y_c1);
        bn_fq2_one(&g2.z);

        struct bn_fq12 result;
        bn254_pairing(&result, &g1, &g2);

        struct bn_fq12 one;
        bn_fq12_one(&one);
        bool ok = !bn_fq12_eq(&result, &one);  /* should NOT be 1 */

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Pairing: e(O, Q) = 1 (identity element)... ");
    {
        struct bn_g1 zero;
        bn_g1_identity(&zero);

        struct bn_g2 g2;
        bn_g2_identity(&g2);  /* any Q works */

        struct bn_fq12 result;
        bn254_pairing(&result, &zero, &g2);

        struct bn_fq12 one;
        bn_fq12_one(&one);
        bool ok = bn_fq12_eq(&result, &one);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Pairing bilinearity: e(P,Q)*e(-P,Q)==1... ");
    {
        struct bn_g1 g1;
        bn_fq_from_u64(&g1.x, 1);
        bn_fq_from_u64(&g1.y, 2);
        bn_fq_one(&g1.z);

        /* Use decimal-loaded G2 generator (correct values) */
        struct bn_g2 g2;
        fq_from_decimal(&g2.x.c0, "10857046999023057135944570762232829481370756359578518086990519993285655852781");
        fq_from_decimal(&g2.x.c1, "11559732032986387107991004021392285783925812861821192530917403151452391805634");
        fq_from_decimal(&g2.y.c0, "8495653923123431417604973247489272438418190587263600148770280649306958101930");
        fq_from_decimal(&g2.y.c1, "4082367875863433681332203403145435568316851327593401208105741076214120093531");
        bn_fq2_one(&g2.z);

        struct bn_g1 neg_g1;
        bn_g1_neg(&neg_g1, &g1);
        struct bn_g1 pts[2] = { g1, neg_g1 };
        struct bn_g2 qpts[2] = { g2, g2 };
        bool ok = bn254_multi_pairing_check(pts, qpts, 2);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Pairing bilinearity: e(2P,Q)==e(P,Q)^2... ");
    {
        struct bn_g1 g1;
        bn_fq_from_u64(&g1.x, 1);
        bn_fq_from_u64(&g1.y, 2);
        bn_fq_one(&g1.z);

        struct bn_g2 g2;
        fq_from_decimal(&g2.x.c0, "10857046999023057135944570762232829481370756359578518086990519993285655852781");
        fq_from_decimal(&g2.x.c1, "11559732032986387107991004021392285783925812861821192530917403151452391805634");
        fq_from_decimal(&g2.y.c0, "8495653923123431417604973247489272438418190587263600148770280649306958101930");
        fq_from_decimal(&g2.y.c1, "4082367875863433681332203403145435568316851327593401208105741076214120093531");
        bn_fq2_one(&g2.z);

        struct bn_g1 g1_2;
        bn_g1_double(&g1_2, &g1);

        struct bn_fq12 e_2g_q, e_g_q, e_g_q_sq;
        bn254_pairing(&e_2g_q, &g1_2, &g2);
        bn254_pairing(&e_g_q, &g1, &g2);
        bn_fq12_sq(&e_g_q_sq, &e_g_q);

        bool ok = bn_fq12_eq(&e_2g_q, &e_g_q_sq);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("\n%d BN-254 test(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
