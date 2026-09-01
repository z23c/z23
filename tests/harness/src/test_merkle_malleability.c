/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial coverage of the Merkle-root primitive and its
 * CVE-2012-2459 duplicate-transaction malleability defense.
 *
 * This group pins the behavior of the PRIMITIVE layer
 * (core/modules/bloom/src/merkle.c: compute_merkle_root /
 * compute_merkle_root_mutated / merkle_hash_pair) — the math the
 * domain block-check (domain_consensus_check_block_merkle_root, which
 * feeds REJECT_CORRUPT_IF "bad-txns-duplicate") is built on. The
 * domain wrapper over struct block is already pinned by
 * test_check_block_edge / test_domain_consensus_check_block; here we
 * cover the malleability MATH they don't: that two DIFFERENT txid lists
 * collide to the SAME root, and that the `mutated` flag — the exact
 * predicate this codebase rejects on — distinguishes them.
 *
 * Teeth: every merkle root asserted here is checked against an
 * INDEPENDENT hand reference computed with hash256() directly (not via
 * merkle_hash_pair), so the tree-walk (odd-leaf padding, per-level
 * reduction) is validated by construction rather than by trusting the
 * function under test. The CVE cases assert BOTH the collision (the
 * vulnerability exists — same root for [A,B,C] and [A,B,C,C]) AND
 * mutated==true on the padded list (the defense fires): delete the
 * `*mutated = true` line in compute_merkle_root_mutated and the
 * "mutated flag set" assertions here go RED while the roots stay equal.
 *
 * Deterministic: no RNG, no clock, no globals, no node process.
 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "core/hash.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

#define MMAL_CHECK(name, expr) do {                                   \
    printf("merkle_malleability: %s... ", (name));                    \
    if ((expr)) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

/* A distinct, deterministic leaf hash. Distinct seeds => distinct leaves. */
static struct uint256 mk_leaf(uint8_t seed)
{
    struct uint256 h;
    memset(h.data, seed, 32);
    /* Vary the tail so leaves aren't a palindrome of a single byte —
     * keeps them clearly distinct even after a one-byte edit elsewhere. */
    h.data[31] = (uint8_t)(0xA0 ^ seed);
    return h;
}

/* Independent reference pairing: SHA256d over left||right, computed with
 * hash256() directly so it does not route through merkle_hash_pair. */
static struct uint256 ref_pair(const struct uint256 *l, const struct uint256 *r)
{
    unsigned char buf[64];
    memcpy(buf, l->data, 32);
    memcpy(buf + 32, r->data, 32);
    struct uint256 o;
    hash256(buf, 64, o.data);
    return o;
}

int test_merkle_malleability(void)
{
    int failures = 0;

    /* ================================================================
     * 1. Degenerate trees: 0-tx and single-tx.
     * ================================================================ */
    {
        /* count==0 -> null hash, mutated stays false (early return). */
        bool mutated = true;
        struct uint256 root = compute_merkle_root_mutated(NULL, 0, &mutated);
        struct uint256 zero;
        uint256_set_null(&zero);
        MMAL_CHECK("0-tx: root is null, mutated=false",
                   uint256_eq(&root, &zero) && !mutated);
    }
    {
        /* Single-tx block: root == the coinbase txid (degenerate tree,
         * no pairing at all), and no mutation is possible with one leaf. */
        struct uint256 cb = mk_leaf(0x11);
        bool mutated = true;
        struct uint256 root = compute_merkle_root_mutated(&cb, 1, &mutated);
        MMAL_CHECK("1-tx: root == sole txid, mutated=false",
                   uint256_eq(&root, &cb) && !mutated);
        /* The non-mutated wrapper agrees. */
        struct uint256 root_w = compute_merkle_root(&cb, 1);
        MMAL_CHECK("1-tx: compute_merkle_root wrapper == txid",
                   uint256_eq(&root_w, &cb));
    }

    /* ================================================================
     * 2. Hand-computed reference roots for small trees N=2,3,4,5.
     *    Odd N duplicates the last hash at each level (Bitcoin rule).
     * ================================================================ */
    {
        struct uint256 L[5];
        for (int i = 0; i < 5; i++) L[i] = mk_leaf((uint8_t)(0x40 + i));

        /* N=2: pair(L0,L1). */
        {
            struct uint256 ref = ref_pair(&L[0], &L[1]);
            bool m = true;
            struct uint256 root = compute_merkle_root_mutated(L, 2, &m);
            MMAL_CHECK("N=2: root == ref, mutated=false",
                       uint256_eq(&root, &ref) && !m);
        }
        /* N=3 (odd): pair( pair(L0,L1), pair(L2,L2) ). */
        {
            struct uint256 p01 = ref_pair(&L[0], &L[1]);
            struct uint256 p22 = ref_pair(&L[2], &L[2]);
            struct uint256 ref = ref_pair(&p01, &p22);
            bool m = true;
            struct uint256 root = compute_merkle_root_mutated(L, 3, &m);
            MMAL_CHECK("N=3 odd: root == ref (last hash self-paired), mutated=false",
                       uint256_eq(&root, &ref) && !m);
        }
        /* N=4: pair( pair(L0,L1), pair(L2,L3) ). */
        {
            struct uint256 p01 = ref_pair(&L[0], &L[1]);
            struct uint256 p23 = ref_pair(&L[2], &L[3]);
            struct uint256 ref = ref_pair(&p01, &p23);
            bool m = true;
            struct uint256 root = compute_merkle_root_mutated(L, 4, &m);
            MMAL_CHECK("N=4: root == ref, mutated=false",
                       uint256_eq(&root, &ref) && !m);
        }
        /* N=5 (odd): level0 -> [p01,p23,p44]; level1 -> [q0,q1];
         * root = pair(q0,q1), where p44=pair(L4,L4), q1=pair(p44,p44). */
        {
            struct uint256 p01 = ref_pair(&L[0], &L[1]);
            struct uint256 p23 = ref_pair(&L[2], &L[3]);
            struct uint256 p44 = ref_pair(&L[4], &L[4]);
            struct uint256 q0  = ref_pair(&p01, &p23);
            struct uint256 q1  = ref_pair(&p44, &p44);
            struct uint256 ref = ref_pair(&q0, &q1);
            bool m = true;
            struct uint256 root = compute_merkle_root_mutated(L, 5, &m);
            MMAL_CHECK("N=5 odd: root == ref (two padding levels), mutated=false",
                       uint256_eq(&root, &ref) && !m);
        }
    }

    /* ================================================================
     * 3. CVE-2012-2459 — the classic collision + defense.
     *
     *    An honest 3-tx block [A,B,C] and a forged 4-tx block [A,B,C,C]
     *    yield the IDENTICAL merkle root: the odd-leaf padding in the
     *    honest block self-pairs C (pair(C,C)), which is byte-identical
     *    to the forged block's explicit trailing duplicate. Two
     *    different tx lists, one root — that is the malleability. The
     *    defense: the forged (even, explicitly-duplicated) list sets
     *    mutated=true; the honest (odd, padded) list does not.
     * ================================================================ */
    {
        struct uint256 A = mk_leaf(0x01);
        struct uint256 B = mk_leaf(0x02);
        struct uint256 C = mk_leaf(0x03);

        struct uint256 honest[3] = { A, B, C };
        struct uint256 forged[4] = { A, B, C, C };

        bool m_honest = true, m_forged = false;
        struct uint256 root_honest =
            compute_merkle_root_mutated(honest, 3, &m_honest);
        struct uint256 root_forged =
            compute_merkle_root_mutated(forged, 4, &m_forged);

        /* The vulnerability: the two distinct lists collide to one root. */
        MMAL_CHECK("CVE: [A,B,C] and [A,B,C,C] have the SAME root (collision)",
                   uint256_eq(&root_honest, &root_forged));

        /* The independent reference confirms that shared root. */
        struct uint256 p01 = ref_pair(&A, &B);
        struct uint256 pcc = ref_pair(&C, &C);
        struct uint256 ref = ref_pair(&p01, &pcc);
        MMAL_CHECK("CVE: shared root matches hand reference",
                   uint256_eq(&root_honest, &ref));

        /* The defense: honest odd-padded list is NOT flagged... */
        MMAL_CHECK("CVE: honest [A,B,C] mutated=false (legit odd padding)",
                   !m_honest);
        /* ...but the forged explicit-duplicate list IS flagged. This is
         * the exact predicate the domain check rejects on
         * (bad-txns-duplicate, dos=100). Removing `*mutated=true` from
         * compute_merkle_root_mutated fails THIS assertion while the
         * collision above still holds — i.e. the block would validate. */
        MMAL_CHECK("CVE: forged [A,B,C,C] mutated=true (defense fires)",
                   m_forged);
    }

    /* ================================================================
     * 4. Mutation detection runs at EVERY level, not only the leaves.
     *
     *    [A,B,A,B] has NO adjacent identical leaf pair (A!=B), so the
     *    leaf level is clean, but the two computed subtree hashes
     *    pair(A,B) are identical and occupy the final (non-padded) pair
     *    at level 1 -> mutated=true. Guards against a forgery that
     *    duplicates a whole subtree rather than a single trailing tx.
     * ================================================================ */
    {
        struct uint256 A = mk_leaf(0x21);
        struct uint256 B = mk_leaf(0x22);
        struct uint256 leaves[4] = { A, B, A, B };

        bool m = false;
        struct uint256 root = compute_merkle_root_mutated(leaves, 4, &m);

        struct uint256 p = ref_pair(&A, &B);
        struct uint256 ref = ref_pair(&p, &p);
        MMAL_CHECK("interior-dup [A,B,A,B]: root == pair(pair(A,B),pair(A,B))",
                   uint256_eq(&root, &ref));
        MMAL_CHECK("interior-dup [A,B,A,B]: mutated=true (flagged at level 1)",
                   m);
    }

    /* ================================================================
     * 5. Binding: a one-bit flip in any leaf changes the root.
     * ================================================================ */
    {
        struct uint256 L[4];
        for (int i = 0; i < 4; i++) L[i] = mk_leaf((uint8_t)(0x50 + i));
        bool m = true;
        struct uint256 root = compute_merkle_root_mutated(L, 4, &m);
        MMAL_CHECK("binding: baseline [A,B,C,D] mutated=false",
                   !m);

        /* Flip a single bit in leaf C. */
        struct uint256 L2[4] = { L[0], L[1], L[2], L[3] };
        L2[2].data[7] ^= 0x01;
        bool m2 = true;
        struct uint256 root2 = compute_merkle_root_mutated(L2, 4, &m2);
        MMAL_CHECK("binding: one-bit flip in a leaf changes the root",
                   !uint256_eq(&root, &root2));

        /* Flip a bit in a DIFFERENT leaf position -> yet another root. */
        struct uint256 L3[4] = { L[0], L[1], L[2], L[3] };
        L3[0].data[0] ^= 0x80;
        struct uint256 root3 = compute_merkle_root(L3, 4);
        MMAL_CHECK("binding: distinct leaf edit yields a distinct root",
                   !uint256_eq(&root, &root3) &&
                   !uint256_eq(&root2, &root3));
    }

    /* ================================================================
     * 6. merkle_hash_pair == SHA256d(left||right) and is order-sensitive.
     *    (The pairing primitive the whole tree is built on.)
     * ================================================================ */
    {
        struct uint256 a = mk_leaf(0x71);
        struct uint256 b = mk_leaf(0x72);
        struct uint256 got;
        merkle_hash_pair(&a, &b, &got);
        struct uint256 ref = ref_pair(&a, &b);
        MMAL_CHECK("merkle_hash_pair == SHA256d(l||r)",
                   uint256_eq(&got, &ref));

        struct uint256 swapped;
        merkle_hash_pair(&b, &a, &swapped);
        MMAL_CHECK("merkle_hash_pair is order-sensitive (l||r != r||l)",
                   !uint256_eq(&got, &swapped));
    }

    return failures;
}
