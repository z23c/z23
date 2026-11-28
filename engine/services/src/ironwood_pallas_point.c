/* purpose: Isolated Jacobian Pallas operations for public research vectors. */
// one-result-type-ok:total-arithmetic-on-validated-points
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "ironwood_pallas_point.h"
#include <stddef.h>
/* Equality and selection have fixed source-level work. Compiler and platform
 * qualification is still required before handling secret values. */
static uint64_t fp_equal(const struct pallas_fp *a, const struct pallas_fp *b)
{
    uint64_t d = 0;
    for (size_t i = 0; i < 4; ++i) d |= a->limb[i] ^ b->limb[i];
    return ((d | (UINT64_C(0) - d)) >> 63) ^ 1;
}
static void point_select(struct pallas_point *out, const struct pallas_point *a,
                         const struct pallas_point *b, uint64_t choose_b)
{
    uint64_t mask = UINT64_C(0) - choose_b;
    for (size_t i = 0; i < 4; ++i) {
        out->x.limb[i] = (a->x.limb[i] & ~mask) | (b->x.limb[i] & mask);
        out->y.limb[i] = (a->y.limb[i] & ~mask) | (b->y.limb[i] & mask);
        out->z.limb[i] = (a->z.limb[i] & ~mask) | (b->z.limb[i] & mask);
    }
}
static const struct pallas_point identity = { .y = {{1,0,0,0}} };
/* dbl-2009-l, EFD short-Weierstrass Jacobian a=0; exceptional infinity
 * is selected by mask. Pallas has prime order and no point of order two. */
void pallas_point_double(struct pallas_point *out, const struct pallas_point *input)
{
    const struct pallas_point p = *input;
    struct pallas_fp a,b,c,d,e,f,t;
    struct pallas_point r;
    pallas_fp_mul(&a,&p.x,&p.x); pallas_fp_mul(&b,&p.y,&p.y);
    pallas_fp_mul(&c,&b,&b); pallas_fp_add(&d,&p.x,&b); pallas_fp_mul(&d,&d,&d);
    pallas_fp_sub(&d,&d,&a); pallas_fp_sub(&d,&d,&c); pallas_fp_add(&d,&d,&d);
    pallas_fp_add(&e,&a,&a); pallas_fp_add(&e,&e,&a); pallas_fp_mul(&f,&e,&e);
    pallas_fp_mul(&r.z,&p.z,&p.y); pallas_fp_add(&r.z,&r.z,&r.z);
    pallas_fp_add(&t,&d,&d); pallas_fp_sub(&r.x,&f,&t);
    pallas_fp_add(&c,&c,&c); pallas_fp_add(&c,&c,&c); pallas_fp_add(&c,&c,&c);
    pallas_fp_sub(&t,&d,&r.x); pallas_fp_mul(&t,&e,&t); pallas_fp_sub(&r.y,&t,&c);
    point_select(out,&r,&identity,fp_equal(&p.z,&identity.z));
}
/* add-2007-bl, EFD short-Weierstrass Jacobian. Compute generic, doubling,
 * inverse and infinity cases, then select without branches on coordinates. */
void pallas_point_add(struct pallas_point *out, const struct pallas_point *left,
                      const struct pallas_point *right)
{
    const struct pallas_point a = *left, b = *right;
    struct pallas_fp z1,z2,u1,u2,s1,s2,h,i,j,r,v,t;
    struct pallas_point result, doubled;
    pallas_fp_mul(&z1,&a.z,&a.z); pallas_fp_mul(&z2,&b.z,&b.z);
    pallas_fp_mul(&u1,&a.x,&z2); pallas_fp_mul(&u2,&b.x,&z1);
    pallas_fp_mul(&s1,&a.y,&z2); pallas_fp_mul(&s1,&s1,&b.z);
    pallas_fp_mul(&s2,&b.y,&z1); pallas_fp_mul(&s2,&s2,&a.z);
    pallas_fp_sub(&h,&u2,&u1); pallas_fp_add(&i,&h,&h); pallas_fp_mul(&i,&i,&i);
    pallas_fp_mul(&j,&h,&i); pallas_fp_sub(&r,&s2,&s1); pallas_fp_add(&r,&r,&r);
    pallas_fp_mul(&v,&u1,&i); pallas_fp_mul(&result.x,&r,&r);
    pallas_fp_sub(&result.x,&result.x,&j); pallas_fp_sub(&result.x,&result.x,&v);
    pallas_fp_sub(&result.x,&result.x,&v); pallas_fp_sub(&t,&v,&result.x);
    pallas_fp_mul(&result.y,&r,&t); pallas_fp_mul(&t,&s1,&j); pallas_fp_add(&t,&t,&t);
    pallas_fp_sub(&result.y,&result.y,&t); pallas_fp_add(&t,&a.z,&b.z);
    pallas_fp_mul(&t,&t,&t); pallas_fp_sub(&t,&t,&z1); pallas_fp_sub(&t,&t,&z2);
    pallas_fp_mul(&result.z,&t,&h);
    pallas_point_double(&doubled,&a);
    uint64_t same_x = fp_equal(&u1,&u2), same_y = fp_equal(&s1,&s2);
    point_select(&result,&result,&identity,same_x & (same_y ^ 1));
    point_select(&result,&result,&doubled,same_x & same_y);
    point_select(&result,&result,&b,fp_equal(&a.z,&identity.z));
    point_select(out,&result,&a,fp_equal(&b.z,&identity.z));
}
/* Fixed 255-bit double-and-add/select schedule. This is research arithmetic:
 * neither compiler-level timing nor secret-memory handling is qualified. */
void pallas_point_multiply(struct pallas_point *out, const struct pallas_point *point,
                           const uint8_t scalar[32])
{
    struct pallas_point base = *point, acc = identity;
    uint8_t bits[32];
    for (size_t i = 0; i < 32; ++i) bits[i] = scalar[i];
    for (size_t i = 255; i-- > 0;) {
        struct pallas_point doubled, sum;
        pallas_point_double(&doubled, &acc);
        pallas_point_add(&sum, &doubled, &base);
        point_select(&acc, &doubled, &sum, (bits[i / 8] >> (i % 8)) & 1);
    }
    *out = acc;
}
