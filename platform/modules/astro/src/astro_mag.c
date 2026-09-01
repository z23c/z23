/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_mag — unsigned big-magnitude integer arithmetic in 64-bit limbs. The
 * whole exact numeric type rests on this file, so every routine is total:
 * defined for every input, no assert, no abort, and capacity exhaustion
 * reported as false rather than wrapped or truncated. See astro_priv.h for
 * what was adapted from astro-calc's core/rational/rat.c and which three
 * defects in that original are corrected here.
 */

#include "astro_priv.h"

#include <string.h>

/* EXACT PATH — see astro_priv.h. Any floating-point type below this line is a
 * compile error, which is how the module's exact/cosmetic boundary is
 * enforced rather than merely documented. */
#pragma GCC poison double float

void astro_mag_zero(struct astro_mag *m)
{
    memset(m->limb, 0, sizeof(m->limb));
    m->used = 0;
}

void astro_mag_from_u64(struct astro_mag *m, uint64_t v)
{
    astro_mag_zero(m);
    if (v != 0) {
        m->limb[0] = v;
        m->used = 1;
    }
}

void astro_mag_norm(struct astro_mag *m)
{
    unsigned n = m->used > ASTRO_MAG_LIMBS ? ASTRO_MAG_LIMBS : m->used;
    while (n > 0 && m->limb[n - 1] == 0)
        n--;
    m->used = n;
}

bool astro_mag_is_zero(const struct astro_mag *m) { return m->used == 0; }

size_t astro_mag_bitlen(const struct astro_mag *m)
{
    if (m->used == 0)
        return 0;
    uint64_t top = m->limb[m->used - 1];
    size_t bits = 0;
    while (top != 0) {
        bits++;
        top >>= 1;
    }
    return (size_t)(m->used - 1) * 64u + bits;
}

int astro_mag_cmp(const struct astro_mag *a, const struct astro_mag *b)
{
    if (a->used != b->used)
        return a->used < b->used ? -1 : 1;
    for (unsigned i = a->used; i > 0; i--) {
        if (a->limb[i - 1] != b->limb[i - 1])
            return a->limb[i - 1] < b->limb[i - 1] ? -1 : 1;
    }
    return 0;
}

/* Two checked steps, not one. `sum = carry + a + b` in a single wrapping
 * accumulation cannot be tested for overflow against a alone: a == 0,
 * b == UINT64_MAX, carry == 1 wraps to zero with no comparison firing. This
 * is the carry bug named in astro_priv.h. */
bool astro_mag_add(struct astro_mag *r, const struct astro_mag *a,
                   const struct astro_mag *b)
{
    struct astro_mag out;
    astro_mag_zero(&out);

    unsigned n = a->used > b->used ? a->used : b->used;
    uint64_t carry = 0;
    for (unsigned i = 0; i < n; i++) {
        uint64_t av = i < a->used ? a->limb[i] : 0;
        uint64_t bv = i < b->used ? b->limb[i] : 0;
        uint64_t s = av + bv;
        uint64_t c = s < av ? 1u : 0u;
        uint64_t s2 = s + carry;
        if (s2 < s)
            c++;
        out.limb[i] = s2;
        carry = c;
    }
    if (carry != 0) {
        if (n >= ASTRO_MAG_LIMBS) {
            astro_mag_zero(r);
            return false;
        }
        out.limb[n] = carry;
        n++;
    }
    out.used = n;
    astro_mag_norm(&out);
    *r = out;
    return true;
}

bool astro_mag_sub(struct astro_mag *r, const struct astro_mag *a,
                   const struct astro_mag *b)
{
    if (astro_mag_cmp(a, b) < 0) {
        astro_mag_zero(r);
        return false;
    }

    struct astro_mag out;
    astro_mag_zero(&out);

    uint64_t borrow = 0;
    for (unsigned i = 0; i < a->used; i++) {
        uint64_t av = a->limb[i];
        uint64_t bv = i < b->used ? b->limb[i] : 0;
        uint64_t d = av - bv;
        uint64_t nb = av < bv ? 1u : 0u;
        uint64_t d2 = d - borrow;
        if (d < borrow)
            nb++;
        out.limb[i] = d2;
        borrow = nb;
    }
    out.used = a->used;
    astro_mag_norm(&out);
    *r = out;
    return true;
}

bool astro_mag_mul(struct astro_mag *r, const struct astro_mag *a,
                   const struct astro_mag *b)
{
    struct astro_mag out;
    astro_mag_zero(&out);

    if (a->used == 0 || b->used == 0) {
        *r = out;
        return true;
    }
    if ((size_t)a->used + (size_t)b->used > ASTRO_MAG_LIMBS + 1u) {
        astro_mag_zero(r);
        return false;
    }

    for (unsigned i = 0; i < a->used; i++) {
        uint64_t carry = 0;
        for (unsigned j = 0; j < b->used; j++) {
            unsigned k = i + j;
            if (k >= ASTRO_MAG_LIMBS) {
                astro_mag_zero(r);
                return false;
            }
            __uint128_t p = (__uint128_t)a->limb[i] * (__uint128_t)b->limb[j] +
                            (__uint128_t)out.limb[k] + (__uint128_t)carry;
            out.limb[k] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        unsigned k = i + b->used;
        while (carry != 0) {
            if (k >= ASTRO_MAG_LIMBS) {
                astro_mag_zero(r);
                return false;
            }
            __uint128_t p = (__uint128_t)out.limb[k] + (__uint128_t)carry;
            out.limb[k] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
            k++;
        }
    }
    out.used = ASTRO_MAG_LIMBS;
    astro_mag_norm(&out);
    *r = out;
    return true;
}

bool astro_mag_shl(struct astro_mag *r, const struct astro_mag *a, size_t bits)
{
    if (a->used == 0 || bits == 0) {
        struct astro_mag out = *a;
        astro_mag_norm(&out);
        *r = out;
        return true;
    }
    if (astro_mag_bitlen(a) + bits > ASTRO_MAG_BITS) {
        astro_mag_zero(r);
        return false;
    }

    struct astro_mag out;
    astro_mag_zero(&out);

    size_t limbs = bits / 64u;
    unsigned rem = (unsigned)(bits % 64u);
    for (unsigned i = a->used; i > 0; i--) {
        size_t dst = (size_t)(i - 1) + limbs;
        uint64_t v = a->limb[i - 1];
        if (rem == 0) {
            out.limb[dst] |= v;
        } else {
            out.limb[dst] |= v << rem;
            if (dst + 1 < ASTRO_MAG_LIMBS)
                out.limb[dst + 1] |= v >> (64u - rem);
        }
    }
    out.used = ASTRO_MAG_LIMBS;
    astro_mag_norm(&out);
    *r = out;
    return true;
}

void astro_mag_shr(struct astro_mag *r, const struct astro_mag *a, size_t bits)
{
    struct astro_mag out;
    astro_mag_zero(&out);

    if (bits == 0) {
        out = *a;
        astro_mag_norm(&out);
        *r = out;
        return;
    }
    size_t limbs = bits / 64u;
    unsigned rem = (unsigned)(bits % 64u);
    if (limbs >= a->used) {
        *r = out;
        return;
    }
    for (size_t i = 0; i + limbs < a->used; i++) {
        uint64_t v = a->limb[i + limbs];
        if (rem == 0) {
            out.limb[i] |= v;
        } else {
            out.limb[i] |= v >> rem;
            if (i > 0)
                out.limb[i - 1] |= v << (64u - rem);
        }
    }
    out.used = (unsigned)(a->used - limbs);
    astro_mag_norm(&out);
    *r = out;
}

/* Restoring binary long division, bounded by the dividend's bit length. The
 * original this file is adapted from counted repeated subtractions one at a
 * time, which does not terminate for the operand sizes here. */
bool astro_mag_divmod(struct astro_mag *q, struct astro_mag *r,
                      const struct astro_mag *a, const struct astro_mag *b)
{
    if (astro_mag_is_zero(b)) {
        if (q) astro_mag_zero(q);
        if (r) astro_mag_zero(r);
        return false;
    }

    struct astro_mag quo, rem;
    astro_mag_zero(&quo);
    astro_mag_zero(&rem);

    size_t nbits = astro_mag_bitlen(a);
    for (size_t i = nbits; i > 0; i--) {
        size_t bit = i - 1;

        /* rem = rem*2 + bit(a, bit). rem stays below b, so for any operands
         * that fit the array the shift cannot fail — but a silently zeroed
         * remainder would be a wrong quotient, so refuse instead of assuming. */
        struct astro_mag shifted;
        if (!astro_mag_shl(&shifted, &rem, 1)) {
            if (q) astro_mag_zero(q);
            if (r) astro_mag_zero(r);
            return false;
        }
        rem = shifted;
        if ((a->limb[bit / 64u] >> (bit % 64u)) & 1u) {
            if (rem.used == 0)
                rem.used = 1;
            rem.limb[0] |= 1u;
        }

        if (astro_mag_cmp(&rem, b) >= 0) {
            struct astro_mag diff;
            (void)astro_mag_sub(&diff, &rem, b);
            rem = diff;
            quo.limb[bit / 64u] |= (uint64_t)1u << (bit % 64u);
            if (quo.used < bit / 64u + 1u)
                quo.used = (unsigned)(bit / 64u + 1u);
        }
    }
    astro_mag_norm(&quo);
    astro_mag_norm(&rem);
    if (q) *q = quo;
    if (r) *r = rem;
    return true;
}

/* Single-limb divisor fast path. The series that build the trig tables divide
 * by small odd integers thousands of times; routing those through the bitwise
 * loop above would make table setup the slowest thing in the module. */
bool astro_mag_div_u64(struct astro_mag *q, uint64_t *rem,
                       const struct astro_mag *a, uint64_t b)
{
    if (b == 0) {
        if (q) astro_mag_zero(q);
        if (rem) *rem = 0;
        return false;
    }

    struct astro_mag out;
    astro_mag_zero(&out);

    __uint128_t carry = 0;
    for (unsigned i = a->used; i > 0; i--) {
        __uint128_t cur = (carry << 64) | (__uint128_t)a->limb[i - 1];
        out.limb[i - 1] = (uint64_t)(cur / b);
        carry = cur % b;
    }
    out.used = a->used;
    astro_mag_norm(&out);
    if (q) *q = out;
    if (rem) *rem = (uint64_t)carry;
    return true;
}

/* floor(sqrt(a)) by the classic bit-by-bit method: one iteration per two bits
 * of the operand, only shifts, compares and subtractions. Terminating and
 * exact, so it is safe on the verifiable path in a way that a
 * convergence-tolerance Newton loop is not. */
void astro_mag_isqrt(struct astro_mag *r, const struct astro_mag *a)
{
    struct astro_mag res, rem, bit;
    astro_mag_zero(&res);
    rem = *a;
    astro_mag_norm(&rem);

    size_t nbits = astro_mag_bitlen(&rem);
    if (nbits == 0) {
        *r = res;
        return;
    }

    /* Highest even power of two not exceeding the operand's bit length. */
    size_t start = (nbits - 1u) & ~(size_t)1u;
    astro_mag_from_u64(&bit, 1);
    struct astro_mag shifted;
    if (!astro_mag_shl(&shifted, &bit, start)) {
        /* Unreachable for any operand that fits the array, but the shift is
         * fallible in general and a silent wrong root is worse than zero. */
        astro_mag_zero(r);
        return;
    }
    bit = shifted;

    while (!astro_mag_is_zero(&bit)) {
        struct astro_mag sum;
        if (astro_mag_add(&sum, &res, &bit) && astro_mag_cmp(&rem, &sum) >= 0) {
            struct astro_mag diff;
            (void)astro_mag_sub(&diff, &rem, &sum);
            rem = diff;
            astro_mag_shr(&res, &res, 1);
            struct astro_mag next;
            (void)astro_mag_add(&next, &res, &bit);
            res = next;
        } else {
            astro_mag_shr(&res, &res, 1);
        }
        astro_mag_shr(&bit, &bit, 2);
    }
    *r = res;
}

/* ── bridge to struct astro_exact ─────────────────────────────────────── */

void astro_exact_unpack(struct astro_mag *m, const struct astro_exact *a)
{
    astro_mag_zero(m);
    unsigned n = a->used > ASTRO_EXACT_LIMBS ? ASTRO_EXACT_LIMBS : a->used;
    for (unsigned i = 0; i < n; i++)
        m->limb[i] = a->limb[i];
    m->used = n;
    astro_mag_norm(m);
}

bool astro_exact_pack(struct astro_exact *out, const struct astro_mag *m,
                      bool negative)
{
    struct astro_mag src = *m;
    astro_mag_norm(&src);
    if (src.used > ASTRO_EXACT_LIMBS) {
        *out = astro_exact_invalid();
        return false;
    }
    memset(out, 0, sizeof(*out));
    for (unsigned i = 0; i < src.used; i++)
        out->limb[i] = src.limb[i];
    out->used = (uint8_t)src.used;
    out->negative = src.used != 0 && negative;
    out->valid = true;
    return true;
}
