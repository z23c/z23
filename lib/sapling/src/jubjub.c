/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Jubjub scalar field arithmetic for Sapling.
 * Implements 512-bit reduction modulo the Jubjub scalar field order.
 *
 * (constant-time): `jubjub_to_scalar` is on the Sapling
 * nullifier-derivation path (via `prf_nsk`) where `nsk` is a
 * long-lived secret reused across all spends from the same key.
 * Any per-bit timing or cache leak here correlates across many
 * spends, so the reduction loop and its helpers must be
 * branchless. See lib/test/src/test_sapling_crypto.c for the
 * diff and Hamming-weight timing regressions. */

#include "sapling/jubjub.h"
#include <string.h>

/* Jubjub scalar field order r (little-endian bytes):
 * r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7 */
static const unsigned char JUBJUB_R[32] = {
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0,
    0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06,
    0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e
};

/* 288-bit big integer (9 x 32-bit limbs, little-endian).
 * r is 256 bits, so an accumulator < 2r always fits without a carry-out. */
#define NL 9

struct bigint {
    uint32_t d[NL];
};

static void bi_zero(struct bigint *a)
{
    memset(a->d, 0, sizeof(a->d));
}

static void bi_from_bytes(struct bigint *a, const unsigned char *b, size_t n)
{
    bi_zero(a);
    for (size_t i = 0; i < n && i < NL * 4; i++)
        a->d[i / 4] |= (uint32_t)b[i] << (8 * (i % 4));
}

static void bi_to_bytes(const struct bigint *a, unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (unsigned char)(a->d[i / 4] >> (8 * (i % 4)));
}

/* acc <<= 1.  Branchless, carry is thrown away.  Safe because callers
 * keep acc < r so 2*acc < 2r fits in 257 bits (<< our 288-bit struct). */
static void bi_shl1(struct bigint *a)
{
    uint32_t carry = 0;
    for (int i = 0; i < NL; i++) {
        uint32_t new_carry = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = new_carry;
    }
    (void)carry;
}

/* If (a >= r): a := a - r.
 * Implementation is constant-time: always computes the full
 * 9-limb subtraction `sub = a - r`, then selects limb-wise between
 * `sub` (when no borrow propagated out of the top limb, i.e. a>=r)
 * and the original `a` (when a<r).  No data-dependent branches,
 * no data-dependent memory accesses. */
static void bi_cond_sub(struct bigint *a, const struct bigint *r)
{
    struct bigint sub;
    uint64_t borrow = 0;
    for (int i = 0; i < NL; i++) {
        uint64_t diff = (uint64_t)a->d[i] - (uint64_t)r->d[i] - borrow;
        sub.d[i] = (uint32_t)diff;
        borrow = (diff >> 32) & 1u;
    }
    /* mask = 0xFFFFFFFF iff no final borrow (i.e., a >= r); else 0. */
    uint32_t mask = (uint32_t)borrow - 1u;
    for (int i = 0; i < NL; i++)
        a->d[i] = (sub.d[i] & mask) | (a->d[i] & ~mask);
}

/* result = a mod r, where a is 512-bit LE and r is 256-bit.
 *
 * Schoolbook shift-and-subtract, one bit per iteration from MSB down.
 * All 512 iterations always execute; inside each iteration every
 * operation runs unconditionally, and the would-be "if bit set" and
 * "if acc >= r" branches are replaced by bitmask selects.  Total
 * work is identical regardless of the secret input's Hamming weight
 * or the exact reduction schedule.
 *
 * Threat: callers include `prf_nsk` (Sapling nullifier key) where the
 * input is derived from a long-lived spending secret; any timing leak
 * here correlates across every spend.  See AGENT-3.md ("prf.c
 * nullifier-path constant-time audit"). */
void jubjub_to_scalar(const unsigned char *input, unsigned char *result)
{
    struct bigint r;
    bi_from_bytes(&r, JUBJUB_R, 32);

    struct bigint acc;
    bi_zero(&acc);

    /* Process 512 bits from MSB (bit 511) to LSB (bit 0). */
    for (int bit = 511; bit >= 0; bit--) {
        /* acc = acc << 1.  Low bit of acc.d[0] is now 0. */
        bi_shl1(&acc);

        /* OR in the next input bit — branchless.  byte_idx / bit_idx
         * are derived from the public loop counter only, not from the
         * secret. */
        int byte_idx = bit >> 3;
        int bit_idx = bit & 7;
        acc.d[0] |= (uint32_t)((input[byte_idx] >> bit_idx) & 1u);

        /* Reduce: if acc >= r, subtract r.  Always executes the
         * subtraction and chooses the result via a mask. */
        bi_cond_sub(&acc, &r);
    }

    bi_to_bytes(&acc, result, 32);
}
