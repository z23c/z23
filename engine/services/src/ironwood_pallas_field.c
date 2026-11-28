/* purpose: Fixed-width Pallas base-field arithmetic for isolated research. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "ironwood_pallas_field.h"
#include <stddef.h>
/* Fp from pasta_curves 0.6.0 fields/fp.rs, canonical little-endian limbs. */
static const uint64_t modulus[4] = {
    UINT64_C(0x992d30ed00000001), UINT64_C(0x224698fc094cf91b),
    UINT64_C(0), UINT64_C(0x4000000000000000)
};
__extension__ typedef unsigned __int128 wide;
static uint64_t subtract(uint64_t out[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t borrow = 0;
    for (size_t i = 0; i < 4; ++i) {
        wide d = (wide)a[i] - b[i] - borrow;
        out[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 127);
    }
    return borrow;
}
static void select_limbs(uint64_t out[4], const uint64_t a[4], const uint64_t b[4], uint64_t pick_b)
{
    uint64_t mask = UINT64_C(0) - pick_b;
    for (size_t i = 0; i < 4; ++i) out[i] = (a[i] & ~mask) | (b[i] & mask);
}
struct zcl_result pallas_fp_read(struct pallas_fp *out, const uint8_t bytes[32])
{
    if (!out || !bytes) return ZCL_ERR(-1, "Invalid Pallas field input");
    struct pallas_fp x = {{0}}; uint64_t ignored[4];
    for (size_t i = 0; i < 32; ++i) x.limb[i / 8] |= (uint64_t)bytes[i] << (8 * (i % 8));
    if (!subtract(ignored, x.limb, modulus)) return ZCL_ERR(-1, "Noncanonical Pallas field element");
    *out = x;
    return ZCL_OK;
}
void pallas_fp_write(uint8_t out[32], const struct pallas_fp *a)
{
    const struct pallas_fp snapshot = *a;
    for (size_t i = 0; i < 32; ++i) out[i] = (uint8_t)(snapshot.limb[i / 8] >> (8 * (i % 8)));
}
void pallas_fp_add(struct pallas_fp *out, const struct pallas_fp *a, const struct pallas_fp *b)
{
    uint64_t sum[4], reduced[4], carry = 0;
    for (size_t i = 0; i < 4; ++i) {
        wide t = (wide)a->limb[i] + b->limb[i] + carry;
        sum[i] = (uint64_t)t; carry = (uint64_t)(t >> 64);
    }
    /* Canonical inputs have sum < 2p < 2^256, so carry is zero. */
    uint64_t borrow = subtract(reduced, sum, modulus);
    select_limbs(out->limb, sum, reduced, borrow ^ UINT64_C(1));
}
void pallas_fp_sub(struct pallas_fp *out, const struct pallas_fp *a, const struct pallas_fp *b)
{
    uint64_t difference[4], carry = 0;
    uint64_t mask = UINT64_C(0) - subtract(difference, a->limb, b->limb);
    for (size_t i = 0; i < 4; ++i) {
        wide t = (wide)difference[i] + (modulus[i] & mask) + carry;
        out->limb[i] = (uint64_t)t; carry = (uint64_t)(t >> 64);
    }
}
void pallas_fp_mul(struct pallas_fp *out, const struct pallas_fp *a, const struct pallas_fp *b)
{
    /* Binary modular multiplication: 256 fixed rounds; each maintains
     * acc + 2^i * a * (b >> i) = a*b (mod p). */
    struct pallas_fp acc = {{0}}, base = *a, rhs = *b;
    for (size_t i = 0; i < 256; ++i) {
        struct pallas_fp sum;
        pallas_fp_add(&sum, &acc, &base);
        select_limbs(acc.limb, acc.limb, sum.limb, (rhs.limb[i / 64] >> (i % 64)) & 1);
        pallas_fp_add(&base, &base, &base);
    }
    *out = acc;
}
struct zcl_result pallas_fp_invert(struct pallas_fp *out, const struct pallas_fp *a)
{
    /* Fermat: a^(p-2). The exponent is a public constant;
     * every input takes the same 256 squares and public-exponent multiplies. */
    static const uint64_t exp[4] = {
        UINT64_C(0x992d30ecffffffff), UINT64_C(0x224698fc094cf91b),
        UINT64_C(0), UINT64_C(0x4000000000000000)
    };
    if (!out || !a) return ZCL_ERR(-1, "Invalid Pallas inversion input");
    struct pallas_fp acc = {{1, 0, 0, 0}}, base = *a;
    for (size_t i = 256; i-- > 0;) {
        struct pallas_fp squared;
        pallas_fp_mul(&squared, &acc, &acc);
        acc = squared;
        if ((exp[i / 64] >> (i % 64)) & 1) pallas_fp_mul(&acc, &acc, &base);
    }
    if ((base.limb[0] | base.limb[1] | base.limb[2] | base.limb[3]) == 0)
        return ZCL_ERR(-1, "Pallas zero has no inverse");
    *out = acc;
    return ZCL_OK;
}
