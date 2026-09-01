/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling Groth16 DIFFERENTIAL PARITY ORACLE
 * ==========================================
 * The safety net that makes optimizing the consensus zk-SNARK verifier safe.
 *
 * WHAT THIS IS
 * ------------
 * A frozen corpus of Sapling Groth16 verification inputs, each paired with the
 * accept/reject VERDICT of the CURRENT (frozen) in-tree verifier
 * (core/modules/sapling/src/bls12_381.c). Any future optimization of that verifier
 * ("make the same checks run faster") is replayed against this corpus: if a
 * single verdict flips, the change altered WHICH proofs are accepted/rejected —
 * a consensus break — and the harness exits non-zero.
 *
 * This tool ONLY reads the verifier and records/checks verdicts. It never
 * modifies consensus code. The corpus is the golden; the golden is defined by
 * OUR current consensus behavior (parity is defined against ourselves), which
 * includes the DELIBERATE quirks that differ from librustzcash — e.g. the
 * BLS12-381 non-canonical-infinity ACCEPTANCE (owner-gated; PRESERVE exactly).
 *
 * TWO MODES
 * ---------
 *   record : regenerate every vector deterministically, run the current
 *            verifier, and WRITE two artifacts:
 *              - groth16_parity_golden.bin  : ordered verdict byte per vector
 *                                             (in-tree differential replay set,
 *                                              covers ALL families incl. the
 *                                              algebraically-crafted verify /
 *                                              batch vectors)
 *              - groth16_decode_corpus.bin  : self-describing bytes->verdict
 *                                             records for the pure byte-decode
 *                                             families (externally replayable,
 *                                             e.g. against librustzcash point
 *                                             decode / Groth16)
 *   check  : regenerate every vector deterministically, run the (possibly
 *            optimized) verifier, and ASSERT each verdict == the frozen golden.
 *            Also reloads groth16_decode_corpus.bin and re-verifies every stored
 *            bytes->verdict record. ANY mismatch => exit 1 (consensus-affecting).
 *
 * DETERMINISM
 * -----------
 * Every vector is generated from fixed constants (canonical BLS12-381
 * generators + integer scalars) with NO RNG, so the vector set is byte-identical
 * across hosts and runs. The golden is therefore host-invariant and can be
 * committed and replayed anywhere. (An optional params-gated real-prover
 * extension is described at the bottom but is NOT part of the frozen core.)
 *
 * EDGE / ADVERSARIAL COVERAGE (see build_corpus())
 * ------------------------------------------------
 *   - canonical point-at-infinity (G1/G2, compressed + uncompressed)  -> ACCEPT
 *   - NON-CANONICAL infinity (infinity flag + dirty trailing bytes)    -> ACCEPT
 *     (the owner-gated quirk; librustzcash REJECTS — pinned here as ACCEPT)
 *   - x >= field modulus (non-canonical field element)                 -> REJECT
 *   - all-zero / all-0xFF / bad compression-flag combinations
 *   - on-curve-but-NOT-prime-order-subgroup point in a proof           -> REJECT
 *     (small-subgroup forgery guard)
 *   - full valid Groth16 proof                                          -> ACCEPT
 *   - valid proof with ONE public-input bit flipped                     -> REJECT
 *   - valid proof with the C point corrupted                            -> REJECT
 *   - batch: all-valid set ACCEPT; one-bad-proof set REJECT; crafted
 *     error-cancelling invalid pair REJECT (RLC soundness)
 *
 * VALUE PARITY, NOT ONLY VERDICT PARITY
 * -------------------------------------
 * Everything above pins a BIT per vector. That is the right bar for decode and
 * for accept/reject behaviour, but it is too weak to gate a restructure of the
 * pairing arithmetic: two pairing implementations can agree on every verdict
 * in a finite corpus and still compute different GT elements, and the first
 * block where they disagree forks this node off the network permanently.
 *
 * So `record`/`check` also freeze groth16_pairing_values.bin — the canonically
 * serialized Fp12 output of the pairing on a fixed corpus (pairing_corpus.h),
 * 576 bytes per vector, out of Montgomery form and fully reduced so the
 * comparison is immune to representation changes. `check` asserts byte
 * equality against the frozen file AND, when
 * bls12_381_pairing_candidate is linked in, against the candidate too.
 *
 * The frozen file catches a change that moves BOTH in-process implementations
 * together; the in-process comparison catches a change that moves only one.
 * Neither subsumes the other.
 *
 * IF FP12 BIT EQUALITY CANNOT BE MADE TO HOLD FOR AN OPTIMIZATION, ABANDON THE
 * OPTIMIZATION. Re-recording the golden is legitimate ONLY for a deliberate,
 * replay-approved consensus change — never to make a diff go green.
 */

#include "pairing_corpus.h"

#include "sapling/bls12_381.h"
#include "util/log_level.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Canonical BLS12-381 generators (compressed, big-endian, with flags) ── */
static const uint8_t G1_GEN_COMPRESSED[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,
    0x4f,0xa9,0xac,0x0f,0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,0x6c,0x55,0xe8,0x3f,
    0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};
static const uint8_t G2_GEN_COMPRESSED[96] = {
    0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,0x7d,0xac,0xd3,0xa0,
    0x88,0x27,0x4f,0x65,0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,0x33,0x4c,0xf1,0x12,
    0x13,0x94,0x5d,0x57,0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,0x26,0x08,0x05,0x27,
    0x2d,0xc5,0x10,0x51,0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,0x0b,0xac,0x03,0x26,
    0xa8,0x05,0xbb,0xef,0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};

/* ── Corpus record families ── */
enum vec_family {
    FAM_G1_COMPRESSED   = 1, /* input[48]  -> g1_from_compressed         */
    FAM_G1_UNCOMPRESSED = 2, /* input[96]  -> g1_from_uncompressed       */
    FAM_G2_COMPRESSED   = 3, /* input[96]  -> g2_from_compressed         */
    FAM_G2_UNCOMPRESSED = 4, /* input[192] -> g2_from_uncompressed       */
    FAM_PROOF_READ      = 5, /* input[192] -> groth16_proof_read (subgroup gate) */
    FAM_VERIFY          = 6, /* algebraic  -> groth16_verify (single)    */
    FAM_BATCH           = 7, /* algebraic  -> groth16_batch_verify       */
};

#define MAX_VECS  512
#define MAX_INPUT 256

struct vec {
    enum vec_family fam;
    char   label[96];
    /* Byte-decode families store raw input bytes here. */
    uint8_t input[MAX_INPUT];
    size_t  input_len;
    uint8_t verdict;   /* filled by run_vector() */
};

static struct vec g_vecs[MAX_VECS];
static size_t     g_nvecs;

/* Verify/batch families need constructed inputs that are not raw byte strings;
 * we keep a small parallel table indexed by the vector's position. */
#define MAX_PROOFS  8
#define MAX_PI      4    /* public inputs per proof (== vk.ic_len - 1)      */

struct verify_payload {
    struct groth16_vk vk;            /* synthetic, params-free */
    struct groth16_proof proof[MAX_PROOFS];
    /* Flat, proof-major: inputs[j * n_inputs + i] is proof j's input i, the
     * layout groth16_batch_verify consumes. */
    uint64_t inputs[MAX_PROOFS * MAX_PI][4];
    size_t   n_proofs;               /* 1 for FAM_VERIFY */
    size_t   n_inputs;               /* public inputs per proof */
};
static struct verify_payload g_vpayload[MAX_VECS];

static struct vec *push_vec(enum vec_family fam, const char *label)
{
    if (g_nvecs >= MAX_VECS) { fprintf(stderr, "vec overflow\n"); exit(2); }
    struct vec *v = &g_vecs[g_nvecs++];
    v->fam = fam;
    snprintf(v->label, sizeof(v->label), "%s", label);
    return v;
}

static struct vec *push_bytes(enum vec_family fam, const char *label,
                              const uint8_t *bytes, size_t len)
{
    struct vec *v = push_vec(fam, label);
    if (len > MAX_INPUT) { fprintf(stderr, "input overflow\n"); exit(2); }
    memcpy(v->input, bytes, len);
    v->input_len = len;
    return v;
}

/* On-curve-but-NOT-prime-order-subgroup G1 point (cofactor ~76-bit => a curve
 * point chosen this way is in the r-subgroup with prob ~2^-76 => never). */
static bool make_g1_offcurve_torsion(struct g1_point *out)
{
    struct fp four, one, x;
    fp_one(&one);
    fp_add(&four, &one, &one);
    fp_add(&four, &four, &one);
    fp_add(&four, &four, &one);
    for (unsigned k = 2; k < 64; k++) {
        struct fp acc; fp_zero(&acc);
        for (unsigned j = 0; j < k; j++) fp_add(&acc, &acc, &one);
        x = acc;
        struct fp x3b, y;
        fp_sq(&x3b, &x);
        fp_mul(&x3b, &x3b, &x);
        fp_add(&x3b, &x3b, &four);
        if (!fp_sqrt(&y, &x3b)) continue;
        out->x = x; out->y = y; fp_one(&out->z);
        return true;
    }
    return false;
}

/* Serialize an affine G1 point to the 48-byte compressed encoding. */
static void g1_affine_to_compressed(uint8_t out[48], const struct g1_point *p)
{
    fp_to_bytes(out, &p->x);
    out[0] |= 0x80;
    if (fp_lexicographically_largest(&p->y)) out[0] |= 0x20;
}

/* ============================================================
 * Corpus construction — deterministic, params-free
 * ============================================================ */
static void build_corpus(void)
{
    uint8_t buf[MAX_INPUT];

    /* ---- FAM_G1_COMPRESSED (48 bytes) ---- */
    push_bytes(FAM_G1_COMPRESSED, "g1c: canonical generator",
               G1_GEN_COMPRESSED, 48);
    memset(buf, 0, 48);
    push_bytes(FAM_G1_COMPRESSED, "g1c: all-zero (compression flag unset)", buf, 48);
    memset(buf, 0, 48); buf[0] = 0xc0;
    push_bytes(FAM_G1_COMPRESSED, "g1c: canonical infinity", buf, 48);
    memset(buf, 0xff, 48); buf[0] = 0xe0;
    push_bytes(FAM_G1_COMPRESSED, "g1c: NON-CANONICAL infinity (quirk: ACCEPT)", buf, 48);
    memset(buf, 0xff, 48); buf[0] = 0xbf;
    push_bytes(FAM_G1_COMPRESSED, "g1c: x >= q (non-canonical field elem)", buf, 48);
    memset(buf, 0xff, 48);
    push_bytes(FAM_G1_COMPRESSED, "g1c: all-0xFF (infinity flag dominates)", buf, 48);
    /* boundary: valid generator with sort bit forced opposite */
    memcpy(buf, G1_GEN_COMPRESSED, 48); buf[0] ^= 0x20;
    push_bytes(FAM_G1_COMPRESSED, "g1c: generator with sign bit flipped", buf, 48);
    /* one-bit flip deep in x */
    memcpy(buf, G1_GEN_COMPRESSED, 48); buf[40] ^= 0x01;
    push_bytes(FAM_G1_COMPRESSED, "g1c: generator x one-bit flipped", buf, 48);

    /* ---- FAM_G1_UNCOMPRESSED (96 bytes) ---- */
    memset(buf, 0, 96);
    push_bytes(FAM_G1_UNCOMPRESSED, "g1u: all-zero (0 not on curve)", buf, 96);
    memset(buf, 0, 96); buf[0] = 0x40;
    push_bytes(FAM_G1_UNCOMPRESSED, "g1u: canonical infinity", buf, 96);
    memset(buf, 0, 96); buf[0] = 0x80;
    push_bytes(FAM_G1_UNCOMPRESSED, "g1u: compression flag set (invalid)", buf, 96);
    memset(buf, 0xff, 96); buf[0] = 0x1f;
    push_bytes(FAM_G1_UNCOMPRESSED, "g1u: x >= q", buf, 96);
    memset(buf, 0xff, 96); buf[0] = 0x40;
    push_bytes(FAM_G1_UNCOMPRESSED, "g1u: infinity flag + dirty bytes (quirk)", buf, 96);

    /* ---- FAM_G2_COMPRESSED (96 bytes) ---- */
    push_bytes(FAM_G2_COMPRESSED, "g2c: canonical generator", G2_GEN_COMPRESSED, 96);
    memset(buf, 0, 96);
    push_bytes(FAM_G2_COMPRESSED, "g2c: all-zero (compression flag unset)", buf, 96);
    memset(buf, 0, 96); buf[0] = 0xc0;
    push_bytes(FAM_G2_COMPRESSED, "g2c: canonical infinity", buf, 96);
    memset(buf, 0xff, 96); buf[0] = 0xe0;
    push_bytes(FAM_G2_COMPRESSED, "g2c: NON-CANONICAL infinity (quirk: ACCEPT)", buf, 96);
    memset(buf, 0xff, 96); buf[0] = 0xbf;
    push_bytes(FAM_G2_COMPRESSED, "g2c: x >= q", buf, 96);
    memcpy(buf, G2_GEN_COMPRESSED, 96); buf[80] ^= 0x01;
    push_bytes(FAM_G2_COMPRESSED, "g2c: generator x one-bit flipped", buf, 96);

    /* ---- FAM_G2_UNCOMPRESSED (192 bytes) ---- */
    memset(buf, 0, 192);
    push_bytes(FAM_G2_UNCOMPRESSED, "g2u: all-zero (0 not on curve)", buf, 192);
    memset(buf, 0, 192); buf[0] = 0x40;
    push_bytes(FAM_G2_UNCOMPRESSED, "g2u: canonical infinity", buf, 192);
    memset(buf, 0xff, 192); buf[0] = 0x1f;
    push_bytes(FAM_G2_UNCOMPRESSED, "g2u: x >= q", buf, 192);

    /* ---- FAM_PROOF_READ (192 bytes, compressed A|B|C) ---- */
    {
        uint8_t good[192];
        memcpy(good, G1_GEN_COMPRESSED, 48);
        memcpy(good + 48, G2_GEN_COMPRESSED, 96);
        memcpy(good + 144, G1_GEN_COMPRESSED, 48);
        push_bytes(FAM_PROOF_READ, "proof: all-in-subgroup generators (ACCEPT)",
                   good, 192);

        /* subgroup-invalid A: on-curve non-subgroup point */
        struct g1_point torsion;
        if (make_g1_offcurve_torsion(&torsion)) {
            uint8_t p[192];
            memset(p, 0, 192);
            g1_affine_to_compressed(p, &torsion);
            memcpy(p + 48, G2_GEN_COMPRESSED, 96);
            memcpy(p + 144, G1_GEN_COMPRESSED, 48);
            push_bytes(FAM_PROOF_READ,
                       "proof: A = on-curve NON-subgroup point (REJECT: forgery guard)",
                       p, 192);
        }
        /* truncated / malformed: all-zero */
        uint8_t zeros[192]; memset(zeros, 0, 192);
        push_bytes(FAM_PROOF_READ, "proof: all-zero bytes (malformed)", zeros, 192);
        /* garbage with out-of-field A */
        uint8_t junk[192]; memset(junk, 0xff, 192); junk[0] = 0xbf;
        push_bytes(FAM_PROOF_READ, "proof: A x >= q (malformed)", junk, 192);
        /* valid A, corrupted B (out-of-field) */
        uint8_t badB[192];
        memcpy(badB, good, 192);
        memset(badB + 48, 0xff, 96); badB[48] = 0xbf;
        push_bytes(FAM_PROOF_READ, "proof: B out-of-field (REJECT)", badB, 192);
    }

    /* ---- FAM_VERIFY (synthetic params-free VK) ----
     * alpha=G1, beta=gamma=delta=G2, IC=[O, G1], n_inputs=1.
     * proof j: A=G1, B=G2, C=-t*G1, input t  => valid. */
    {
        struct g1_point G1, O1;
        struct g2_point G2;
        (void)g1_from_compressed(&G1, G1_GEN_COMPRESSED);
        (void)g2_from_compressed(&G2, G2_GEN_COMPRESSED);
        g1_identity(&O1);

        static struct g1_point ic_storage[2];
        ic_storage[0] = O1;
        ic_storage[1] = G1;

        for (int variant = 0; variant < 6; variant++) {
            struct vec *v = push_vec(FAM_VERIFY, "");
            struct verify_payload *vp = &g_vpayload[g_nvecs - 1];
            vp->vk.alpha_g1 = G1;
            vp->vk.beta_g2  = G2;
            vp->vk.gamma_g2 = G2;
            vp->vk.delta_g2 = G2;
            vp->vk.ic       = ic_storage;
            vp->vk.ic_len   = 2;
            vp->n_proofs    = 1;
            vp->n_inputs    = 1;

            uint64_t t = (uint64_t)(variant + 3);
            uint64_t ts[4] = { t, 0, 0, 0 };
            struct g1_point vkx;
            g1_scalar_mul(&vkx, &G1, ts);
            vp->proof[0].a = G1;
            vp->proof[0].b = G2;
            g1_neg(&vp->proof[0].c, &vkx);   /* C = -t*G1 */
            vp->inputs[0][0] = t;
            vp->inputs[0][1] = 0; vp->inputs[0][2] = 0; vp->inputs[0][3] = 0;

            switch (variant) {
            case 0:
                snprintf(v->label, sizeof(v->label),
                         "verify: valid synthetic proof t=%llu (ACCEPT)",
                         (unsigned long long)t);
                break;
            case 1:
                /* flip one bit of the public input */
                vp->inputs[0][0] ^= 0x1;
                snprintf(v->label, sizeof(v->label),
                         "verify: public input bit-flipped (REJECT)");
                break;
            case 2:
                /* corrupt C by +G1 */
                g1_add(&vp->proof[0].c, &vp->proof[0].c, &G1);
                snprintf(v->label, sizeof(v->label),
                         "verify: C point corrupted (REJECT)");
                break;
            case 3:
                /* corrupt A by +G1 */
                g1_add(&vp->proof[0].a, &vp->proof[0].a, &G1);
                snprintf(v->label, sizeof(v->label),
                         "verify: A point corrupted (REJECT)");
                break;
            case 4:
                snprintf(v->label, sizeof(v->label),
                         "verify: valid synthetic proof t=%llu (ACCEPT)",
                         (unsigned long long)t);
                break;
            case 5:
                snprintf(v->label, sizeof(v->label),
                         "verify: valid synthetic proof t=%llu (ACCEPT)",
                         (unsigned long long)t);
                break;
            }
        }
    }

    /* ---- FAM_BATCH ---- */
    {
        struct g1_point G1, O1;
        struct g2_point G2;
        (void)g1_from_compressed(&G1, G1_GEN_COMPRESSED);
        (void)g2_from_compressed(&G2, G2_GEN_COMPRESSED);
        g1_identity(&O1);
        static struct g1_point bic[2];
        bic[0] = O1; bic[1] = G1;

        /* (a) all-valid set of 4 => ACCEPT */
        {
            push_vec(FAM_BATCH, "batch: 4 valid proofs (ACCEPT)");
            struct verify_payload *vp = &g_vpayload[g_nvecs - 1];
            vp->vk.alpha_g1 = G1; vp->vk.beta_g2 = G2;
            vp->vk.gamma_g2 = G2; vp->vk.delta_g2 = G2;
            vp->vk.ic = bic; vp->vk.ic_len = 2; vp->n_proofs = 4; vp->n_inputs = 1;
            for (int j = 0; j < 4; j++) {
                uint64_t t = (uint64_t)(j + 3);
                uint64_t ts[4] = { t, 0, 0, 0 };
                struct g1_point vkx;
                g1_scalar_mul(&vkx, &G1, ts);
                vp->proof[j].a = G1; vp->proof[j].b = G2;
                g1_neg(&vp->proof[j].c, &vkx);
                vp->inputs[j][0] = t;
                vp->inputs[j][1] = 0; vp->inputs[j][2] = 0; vp->inputs[j][3] = 0;
            }
        }
        /* (b) one bad proof in the set => REJECT */
        {
            push_vec(FAM_BATCH, "batch: 4 proofs, one corrupted (REJECT)");
            struct verify_payload *vp = &g_vpayload[g_nvecs - 1];
            vp->vk.alpha_g1 = G1; vp->vk.beta_g2 = G2;
            vp->vk.gamma_g2 = G2; vp->vk.delta_g2 = G2;
            vp->vk.ic = bic; vp->vk.ic_len = 2; vp->n_proofs = 4; vp->n_inputs = 1;
            for (int j = 0; j < 4; j++) {
                uint64_t t = (uint64_t)(j + 3);
                uint64_t ts[4] = { t, 0, 0, 0 };
                struct g1_point vkx;
                g1_scalar_mul(&vkx, &G1, ts);
                vp->proof[j].a = G1; vp->proof[j].b = G2;
                g1_neg(&vp->proof[j].c, &vkx);
                vp->inputs[j][0] = t;
                vp->inputs[j][1] = 0; vp->inputs[j][2] = 0; vp->inputs[j][3] = 0;
            }
            g1_add(&vp->proof[2].c, &vp->proof[2].c, &G1); /* corrupt #2 */
        }
        /* (c) crafted error-cancelling INVALID pair (RLC soundness) => REJECT.
         * C_0 = -vkx_0 + D, C_1 = -vkx_1 - D: each individually invalid; a
         * naive equal-weight batch would cancel to accept, RLC must reject. */
        {
            push_vec(FAM_BATCH, "batch: error-cancelling invalid pair (RLC soundness REJECT)");
            struct verify_payload *vp = &g_vpayload[g_nvecs - 1];
            vp->vk.alpha_g1 = G1; vp->vk.beta_g2 = G2;
            vp->vk.gamma_g2 = G2; vp->vk.delta_g2 = G2;
            vp->vk.ic = bic; vp->vk.ic_len = 2; vp->n_proofs = 2; vp->n_inputs = 1;
            struct g1_point D;
            uint64_t two[4] = {2,0,0,0};
            g1_scalar_mul(&D, &G1, two);
            for (int j = 0; j < 2; j++) {
                uint64_t t = (uint64_t)(j + 3);
                uint64_t ts[4] = { t, 0, 0, 0 };
                struct g1_point vkx, negvkx;
                g1_scalar_mul(&vkx, &G1, ts);
                g1_neg(&negvkx, &vkx);
                vp->proof[j].a = G1; vp->proof[j].b = G2;
                vp->inputs[j][0] = t;
                vp->inputs[j][1] = 0; vp->inputs[j][2] = 0; vp->inputs[j][3] = 0;
                if (j == 0) {
                    g1_add(&vp->proof[j].c, &negvkx, &D);
                } else {
                    struct g1_point negD; g1_neg(&negD, &D);
                    g1_add(&vp->proof[j].c, &negvkx, &negD);
                }
            }
        }
    }

    /* ---- WIDE family: MAX_PI distinct IC bases + full-width scalars ----
     * The single-input vectors above only ever multiply IC[1] by a small
     * scalar, which leaves the high limbs of the multiplier — and every IC
     * base but the first — untested. Any fixed-base / windowed rewrite of the
     * public-input scalar-mul has to reproduce the SAME group element for a
     * full 256-bit multiplier on EVERY base, so these vectors sweep:
     *   zero, 1, 2^64-1, all-256-bits-set, r-1, and mixed limb patterns,
     * across MAX_PI independent bases, with a bit-flip reject control on each.
     * A window that straddles a limb boundary, drops the top window, or
     * mis-indexes a base flips one of these from ACCEPT to REJECT. */
    {
        struct g1_point G1, O1;
        struct g2_point G2;
        (void)g1_from_compressed(&G1, G1_GEN_COMPRESSED);
        (void)g2_from_compressed(&G2, G2_GEN_COMPRESSED);
        g1_identity(&O1);

        /* Distinct fixed bases: IC[0] = O, IC[i] = (7i+1)*G1. */
        static struct g1_point wic[MAX_PI + 1];
        wic[0] = O1;
        for (int i = 1; i <= MAX_PI; i++) {
            uint64_t m[4] = { (uint64_t)(7 * i + 1), 0, 0, 0 };
            g1_scalar_mul(&wic[i], &G1, m);
        }

        /* Set 4 leads with r-1 (0x73eda753...ffffffff00000000), the largest
         * valid Fr scalar, on two bases. */
        static const uint64_t SCALARS[][MAX_PI][4] = {
            {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}},
            {{1,0,0,0},{2,0,0,0},{3,0,0,0},{4,0,0,0}},
            {{0xFFFFFFFFFFFFFFFFULL,0,0,0},{0,0,1,0},{0,1,0,0},{0,0,0,1}},
            {{0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
              0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL},
             {0xF0F0F0F0F0F0F0F0ULL,0x0F0F0F0F0F0F0F0FULL,
              0xAAAAAAAAAAAAAAAAULL,0x5555555555555555ULL},
             {1,0,0,0},{0,0,0,0}},
            {{0xffffffff00000000ULL,0x53bda402fffe5bfeULL,
              0x3339d80809a1d805ULL,0x73eda753299d7d48ULL},
             {0xffffffff00000000ULL,0x53bda402fffe5bfeULL,
              0x3339d80809a1d805ULL,0x73eda753299d7d48ULL},
             {0x8000000000000000ULL,0,0,0x0000000000000001ULL},
             {0x0000000000000010ULL,0x0000000000000000ULL,
              0x1000000000000000ULL,0x0000000000000000ULL}},
        };
        const size_t n_sets = sizeof(SCALARS) / sizeof(SCALARS[0]);

        for (size_t s = 0; s < n_sets; s++) {
            for (int flip = 0; flip < 2; flip++) {
                char lbl[96];
                snprintf(lbl, sizeof(lbl),
                         "verify-wide: %zu bases, scalar set %zu%s",
                         (size_t)MAX_PI, s, flip ? " + input bit-flip (REJECT)"
                                                 : " (ACCEPT)");
                push_vec(FAM_VERIFY, lbl);
                struct verify_payload *vp = &g_vpayload[g_nvecs - 1];
                vp->vk.alpha_g1 = G1; vp->vk.beta_g2 = G2;
                vp->vk.gamma_g2 = G2; vp->vk.delta_g2 = G2;
                vp->vk.ic = wic; vp->vk.ic_len = MAX_PI + 1;
                vp->n_proofs = 1; vp->n_inputs = MAX_PI;

                /* vk_x = IC[0] + sum(input[i] * IC[i+1]); C = -vk_x accepts. */
                struct g1_point vkx = wic[0];
                for (int i = 0; i < MAX_PI; i++) {
                    memcpy(vp->inputs[i], SCALARS[s][i], sizeof(vp->inputs[i]));
                    if (SCALARS[s][i][0] == 0 && SCALARS[s][i][1] == 0 &&
                        SCALARS[s][i][2] == 0 && SCALARS[s][i][3] == 0)
                        continue;
                    struct g1_point term;
                    g1_scalar_mul(&term, &wic[i + 1], SCALARS[s][i]);
                    g1_add(&vkx, &vkx, &term);
                }
                vp->proof[0].a = G1;
                vp->proof[0].b = G2;
                g1_neg(&vp->proof[0].c, &vkx);
                if (flip)
                    vp->inputs[MAX_PI - 1][3] ^= 0x8000000000000000ULL;
            }
        }

        /* Batch over the same wide VK: all-valid ACCEPT, one-corrupted REJECT. */
        for (int corrupt = 0; corrupt < 2; corrupt++) {
            push_vec(FAM_BATCH, corrupt
                     ? "batch-wide: 4 proofs over 4 bases, one corrupted (REJECT)"
                     : "batch-wide: 4 proofs over 4 bases (ACCEPT)");
            struct verify_payload *vp = &g_vpayload[g_nvecs - 1];
            vp->vk.alpha_g1 = G1; vp->vk.beta_g2 = G2;
            vp->vk.gamma_g2 = G2; vp->vk.delta_g2 = G2;
            vp->vk.ic = wic; vp->vk.ic_len = MAX_PI + 1;
            vp->n_proofs = 4; vp->n_inputs = MAX_PI;
            for (size_t j = 0; j < 4; j++) {
                struct g1_point vkx = wic[0];
                for (int i = 0; i < MAX_PI; i++) {
                    uint64_t *dst = vp->inputs[j * MAX_PI + i];
                    memcpy(dst, SCALARS[j + 1][i], sizeof(SCALARS[j + 1][i]));
                    if (dst[0] == 0 && dst[1] == 0 && dst[2] == 0 && dst[3] == 0)
                        continue;
                    struct g1_point term;
                    g1_scalar_mul(&term, &wic[i + 1], dst);
                    g1_add(&vkx, &vkx, &term);
                }
                vp->proof[j].a = G1;
                vp->proof[j].b = G2;
                g1_neg(&vp->proof[j].c, &vkx);
            }
            if (corrupt)
                g1_add(&vp->proof[3].c, &vp->proof[3].c, &G1);
        }
    }
}

/* ============================================================
 * Verdict computation — the current (frozen) verifier
 * ============================================================ */

/* Verdict byte that can never equal a recorded ACCEPT(1)/REJECT(0), so an
 * internal divergence always fails `check` even if the golden were stale. */
#define VERDICT_DIVERGED 0xFF
static int g_path_divergences;

/* Run a verify/batch vector down BOTH public-input paths — the naive
 * double-and-add and the precomputed fixed-base tables — and require the same
 * verdict. The frozen golden only pins one number per vector, so without this
 * the corpus would silently exercise whichever path the VK happened to carry;
 * running both is what makes the gate bite on the optimization itself. */
static uint8_t run_verify_both_paths(size_t idx)
{
    struct verify_payload *vp = &g_vpayload[idx];
    bool batch = (g_vecs[idx].fam == FAM_BATCH);

    vp->vk.ic_combs = NULL;
    uint8_t naive = batch
        ? (groth16_batch_verify(&vp->vk, vp->proof,
                                (const uint64_t (*)[4])vp->inputs,
                                vp->n_inputs, vp->n_proofs) ? 1 : 0)
        : (groth16_verify(&vp->vk, &vp->proof[0],
                          (const uint64_t (*)[4])vp->inputs,
                          vp->n_inputs) ? 1 : 0);

    if (!groth16_vk_build_combs(&vp->vk)) {
        fprintf(stderr, "PARITY FAIL @%zu [%s]: build_combs failed\n",
                idx, g_vecs[idx].label);
        g_path_divergences++;
        return VERDICT_DIVERGED;
    }
    uint8_t comb = batch
        ? (groth16_batch_verify(&vp->vk, vp->proof,
                                (const uint64_t (*)[4])vp->inputs,
                                vp->n_inputs, vp->n_proofs) ? 1 : 0)
        : (groth16_verify(&vp->vk, &vp->proof[0],
                          (const uint64_t (*)[4])vp->inputs,
                          vp->n_inputs) ? 1 : 0);
    groth16_vk_free_combs(&vp->vk);

    if (naive != comb) {
        fprintf(stderr,
                "PATH DIVERGENCE @%zu [%s]: naive=%u fixed-base=%u — the "
                "optimized public-input path accepts a DIFFERENT set of "
                "proofs = CONSENSUS BREAK\n",
                idx, g_vecs[idx].label, naive, comb);
        g_path_divergences++;
        return VERDICT_DIVERGED;
    }
    return naive;
}

static uint8_t run_vector(size_t idx)
{
    struct vec *v = &g_vecs[idx];
    switch (v->fam) {
    case FAM_G1_COMPRESSED: {
        struct g1_point p;
        return g1_from_compressed(&p, v->input) ? 1 : 0;
    }
    case FAM_G1_UNCOMPRESSED: {
        struct g1_point p;
        return g1_from_uncompressed(&p, v->input) ? 1 : 0;
    }
    case FAM_G2_COMPRESSED: {
        struct g2_point p;
        return g2_from_compressed(&p, v->input) ? 1 : 0;
    }
    case FAM_G2_UNCOMPRESSED: {
        struct g2_point p;
        return g2_from_uncompressed(&p, v->input) ? 1 : 0;
    }
    case FAM_PROOF_READ: {
        struct groth16_proof gp;
        return groth16_proof_read(&gp, v->input) ? 1 : 0;
    }
    case FAM_VERIFY:
    case FAM_BATCH:
        return run_verify_both_paths(idx);
    }
    return 0;
}

static void run_all(void)
{
    for (size_t i = 0; i < g_nvecs; i++)
        g_vecs[i].verdict = run_vector(i);
}

/* ============================================================
 * Corpus serialization
 * ============================================================ */
#define GOLDEN_MAGIC "G16PARITY-GOLD-01\n"
#define DECODE_MAGIC "G16PARITY-DECODE-01\n"
#define PAIRVAL_MAGIC "G16PARITY-PAIRVAL-01\n"

/* ── frozen pairing VALUES ───────────────────────────────────────────
 *
 * One record per pairing_corpus.h vector: the canonically serialized Fp12
 * (576 bytes) the current verifier computes. Verdict parity pins one bit per
 * vector; this pins all 4608. See the "VALUE PARITY" section at the top of
 * this file for why the weaker assertion is not acceptable for the pairing.
 */
static int write_pairing_values(const char *path)
{
    struct pc_vec v[PC_MAX_VECS];
    size_t n = pc_build(v);
    if (n == 0) { fprintf(stderr, "pairing corpus build failed\n"); return -1; }
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    fwrite(PAIRVAL_MAGIC, 1, strlen(PAIRVAL_MAGIC), f);
    uint32_t cnt = (uint32_t)n;
    fwrite(&cnt, sizeof(cnt), 1, f);
    for (size_t i = 0; i < n; i++) {
        struct fp12 e;
        uint8_t bytes[PC_FP12_BYTES];
        bls12_381_pairing(&e, &v[i].p, &v[i].q);
        pc_fp12_to_bytes(bytes, &e);
        uint16_t llen = (uint16_t)strlen(v[i].label);
        fwrite(&llen, sizeof(llen), 1, f);
        fwrite(v[i].label, 1, llen, f);
        fwrite(bytes, 1, PC_FP12_BYTES, f);
    }
    fclose(f);
    return 0;
}

/* Returns 0 iff every vector's Fp12 is byte-identical to the frozen file AND
 * (when linked) to bls12_381_pairing_candidate. */
static int check_pairing_values(const char *path)
{
    struct pc_vec v[PC_MAX_VECS];
    size_t n = pc_build(v);
    if (n == 0) { fprintf(stderr, "pairing corpus build failed\n"); return -1; }
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    char magic[64] = {0};
    if (fread(magic, 1, strlen(PAIRVAL_MAGIC), f) != strlen(PAIRVAL_MAGIC) ||
        memcmp(magic, PAIRVAL_MAGIC, strlen(PAIRVAL_MAGIC)) != 0) {
        fprintf(stderr, "pairing values: bad magic\n"); fclose(f); return -1;
    }
    uint32_t cnt = 0;
    if (fread(&cnt, sizeof(cnt), 1, f) != 1) { fclose(f); return -1; }
    if (cnt != (uint32_t)n) {
        fprintf(stderr,
                "PAIRING VALUE FAIL: frozen vector count %u != current %zu "
                "(the corpus changed — regenerate + re-freeze)\n", cnt, n);
        fclose(f);
        return -1;
    }
    const bool have_cand = pc_have_candidate();
    int bad = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint16_t llen = 0;
        char label[128] = {0};
        uint8_t frozen[PC_FP12_BYTES];
        if (fread(&llen, sizeof(llen), 1, f) != 1) break;
        if (llen >= sizeof(label)) { fclose(f); return -1; }
        if (fread(label, 1, llen, f) != llen) break;
        if (fread(frozen, 1, PC_FP12_BYTES, f) != PC_FP12_BYTES) break;

        struct fp12 e;
        uint8_t now[PC_FP12_BYTES];
        bls12_381_pairing(&e, &v[i].p, &v[i].q);
        pc_fp12_to_bytes(now, &e);
        if (memcmp(now, frozen, PC_FP12_BYTES) != 0) {
            int d = 0;
            while (d < PC_FP12_BYTES && now[d] == frozen[d]) d++;
            fprintf(stderr,
                    "PAIRING VALUE MISMATCH [%s]: Fp12 coefficient %s, "
                    "byte %d: frozen %02x current %02x\n"
                    "  -> the pairing computes a DIFFERENT field element than "
                    "the frozen consensus one. ABANDON the change.\n",
                    label, pc_fp12_coeff_name(d), d, frozen[d], now[d]);
            bad++;
            continue;
        }
        if (have_cand) {
            struct fp12 ec;
            uint8_t cand[PC_FP12_BYTES];
            bls12_381_pairing_candidate(&ec, &v[i].p, &v[i].q);
            pc_fp12_to_bytes(cand, &ec);
            if (memcmp(cand, frozen, PC_FP12_BYTES) != 0) {
                int d = 0;
                while (d < PC_FP12_BYTES && cand[d] == frozen[d]) d++;
                fprintf(stderr,
                        "PAIRING CANDIDATE MISMATCH [%s]: Fp12 coefficient %s, "
                        "byte %d: frozen %02x candidate %02x\n"
                        "  -> ABANDON the optimization. Do NOT fall back to "
                        "verdict equality.\n",
                        label, pc_fp12_coeff_name(d), d, frozen[d], cand[d]);
                bad++;
            }
        }
    }
    fclose(f);
    if (bad) return -1;
    printf("PAIRING VALUES OK: %u vectors, all %d Fp12 bytes match the frozen "
           "consensus values%s\n", cnt, PC_FP12_BYTES,
           have_cand ? " (candidate checked too)"
                     : " (no candidate linked — baseline only)");
    return 0;
}

static int write_golden(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    fwrite(GOLDEN_MAGIC, 1, strlen(GOLDEN_MAGIC), f);
    uint32_t n = (uint32_t)g_nvecs;
    fwrite(&n, sizeof(n), 1, f);
    for (size_t i = 0; i < g_nvecs; i++) {
        uint8_t fam = (uint8_t)g_vecs[i].fam;
        fwrite(&fam, 1, 1, f);
        fwrite(&g_vecs[i].verdict, 1, 1, f);
    }
    fclose(f);
    return 0;
}

static int read_golden_and_check(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    char magic[64] = {0};
    if (fread(magic, 1, strlen(GOLDEN_MAGIC), f) != strlen(GOLDEN_MAGIC) ||
        memcmp(magic, GOLDEN_MAGIC, strlen(GOLDEN_MAGIC)) != 0) {
        fprintf(stderr, "golden: bad magic\n"); fclose(f); return -1;
    }
    uint32_t n = 0;
    if (fread(&n, sizeof(n), 1, f) != 1) { fclose(f); return -1; }
    if (n != g_nvecs) {
        fprintf(stderr,
                "PARITY FAIL: golden vector count %u != current %zu "
                "(the vector generator changed — regenerate + re-freeze)\n",
                n, g_nvecs);
        fclose(f); return -1;
    }
    int mismatches = 0;
    for (size_t i = 0; i < g_nvecs; i++) {
        uint8_t fam = 0, verdict = 0;
        if (fread(&fam, 1, 1, f) != 1 || fread(&verdict, 1, 1, f) != 1) {
            fclose(f); return -1;
        }
        if (fam != (uint8_t)g_vecs[i].fam || verdict != g_vecs[i].verdict) {
            fprintf(stderr,
                    "PARITY MISMATCH @%zu [%s]: golden verdict=%u current=%u\n",
                    i, g_vecs[i].label, verdict, g_vecs[i].verdict);
            mismatches++;
        }
    }
    fclose(f);
    if (mismatches) {
        fprintf(stderr,
                "PARITY FAIL: %d verdict mismatch(es) => the verifier now "
                "accepts/rejects a DIFFERENT set of proofs = CONSENSUS BREAK\n",
                mismatches);
        return -1;
    }
    return 0;
}

/* Self-describing bytes->verdict corpus for the pure byte-decode families
 * (1-5). Externally replayable (e.g. against librustzcash point decode). */
static int write_decode_corpus(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    fwrite(DECODE_MAGIC, 1, strlen(DECODE_MAGIC), f);
    uint32_t n = 0;
    for (size_t i = 0; i < g_nvecs; i++)
        if (g_vecs[i].fam <= FAM_PROOF_READ) n++;
    fwrite(&n, sizeof(n), 1, f);
    for (size_t i = 0; i < g_nvecs; i++) {
        struct vec *v = &g_vecs[i];
        if (v->fam > FAM_PROOF_READ) continue;
        uint8_t fam = (uint8_t)v->fam;
        uint8_t verdict = v->verdict;
        uint16_t ilen = (uint16_t)v->input_len;
        uint16_t llen = (uint16_t)strlen(v->label);
        fwrite(&fam, 1, 1, f);
        fwrite(&verdict, 1, 1, f);
        fwrite(&ilen, sizeof(ilen), 1, f);
        fwrite(v->input, 1, ilen, f);
        fwrite(&llen, sizeof(llen), 1, f);
        fwrite(v->label, 1, llen, f);
    }
    fclose(f);
    return 0;
}

/* Reload the decode corpus and re-run each record's bytes through the current
 * decoder, asserting the stored verdict still holds (independent of the
 * in-memory generator — proves the on-disk corpus and the code agree). */
static int check_decode_corpus(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    char magic[64] = {0};
    if (fread(magic, 1, strlen(DECODE_MAGIC), f) != strlen(DECODE_MAGIC) ||
        memcmp(magic, DECODE_MAGIC, strlen(DECODE_MAGIC)) != 0) {
        fprintf(stderr, "decode corpus: bad magic\n"); fclose(f); return -1;
    }
    uint32_t n = 0;
    if (fread(&n, sizeof(n), 1, f) != 1) { fclose(f); return -1; }
    int mismatches = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t fam = 0, verdict = 0;
        uint16_t ilen = 0, llen = 0;
        uint8_t input[MAX_INPUT];
        char label[128] = {0};
        if (fread(&fam, 1, 1, f) != 1) break;
        if (fread(&verdict, 1, 1, f) != 1) break;
        if (fread(&ilen, sizeof(ilen), 1, f) != 1) break;
        if (ilen > MAX_INPUT) { fclose(f); return -1; }
        if (fread(input, 1, ilen, f) != ilen) break;
        if (fread(&llen, sizeof(llen), 1, f) != 1) break;
        if (llen >= sizeof(label)) llen = sizeof(label) - 1;
        if (fread(label, 1, llen, f) != llen) break;

        uint8_t got = 0;
        switch (fam) {
        case FAM_G1_COMPRESSED:   { struct g1_point p; got = g1_from_compressed(&p, input) ? 1 : 0; break; }
        case FAM_G1_UNCOMPRESSED: { struct g1_point p; got = g1_from_uncompressed(&p, input) ? 1 : 0; break; }
        case FAM_G2_COMPRESSED:   { struct g2_point p; got = g2_from_compressed(&p, input) ? 1 : 0; break; }
        case FAM_G2_UNCOMPRESSED: { struct g2_point p; got = g2_from_uncompressed(&p, input) ? 1 : 0; break; }
        case FAM_PROOF_READ:      { struct groth16_proof gp; got = groth16_proof_read(&gp, input) ? 1 : 0; break; }
        default: fprintf(stderr, "decode corpus: bad family %u\n", fam); fclose(f); return -1;
        }
        if (got != verdict) {
            fprintf(stderr, "DECODE CORPUS MISMATCH [%s]: stored=%u current=%u\n",
                    label, verdict, got);
            mismatches++;
        }
    }
    fclose(f);
    return mismatches ? -1 : 0;
}

/* ============================================================ */
int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "check";
    const char *dir  = (argc > 2) ? argv[2] : ".";
    char golden[1024], corpus[1024], pairval[1024];
    snprintf(golden, sizeof(golden), "%s/groth16_parity_golden.bin", dir);
    snprintf(corpus, sizeof(corpus), "%s/groth16_decode_corpus.bin", dir);
    snprintf(pairval, sizeof(pairval), "%s/groth16_pairing_values.bin", dir);

    /* Most vectors are SUPPOSED to be rejected, and every reject path logs.
     * Silence the verifier's own logging so stderr carries only this harness's
     * mismatch and divergence lines — which callers must be able to see. */
    zcl_log_level_set(ZCL_LOG_OFF);

    build_corpus();
    run_all();

    /* A divergence poisons every affected verdict, so refuse to freeze it. */
    if (g_path_divergences && strcmp(mode, "list") != 0) {
        fprintf(stderr,
                "PARITY FAILED: %d naive-vs-fixed-base path divergence(s)\n",
                g_path_divergences);
        return 1;
    }

    if (strcmp(mode, "record") == 0) {
        if (write_golden(golden) != 0) return 2;
        if (write_decode_corpus(corpus) != 0) return 2;
        if (write_pairing_values(pairval) != 0) return 2;
        printf("recorded %zu golden verdicts -> %s\n", g_nvecs, golden);
        printf("recorded decode corpus -> %s\n", corpus);
        printf("recorded pairing Fp12 values -> %s\n", pairval);
        /* Print a human-readable manifest to stdout. */
        for (size_t i = 0; i < g_nvecs; i++)
            printf("  [%3zu] fam=%d verdict=%s  %s\n",
                   i, g_vecs[i].fam, g_vecs[i].verdict ? "ACCEPT" : "REJECT",
                   g_vecs[i].label);
        return 0;
    }
    if (strcmp(mode, "check") == 0) {
        int rc = 0;
        if (read_golden_and_check(golden) != 0) rc = 1;
        if (check_decode_corpus(corpus) != 0) rc = 1;
        if (check_pairing_values(pairval) != 0) rc = 1;
        if (rc == 0)
            printf("PARITY OK: %zu vectors, verdicts match frozen golden "
                   "(verify/batch vectors agree on both public-input paths)\n",
                   g_nvecs);
        else
            fprintf(stderr, "PARITY FAILED (see mismatches above)\n");
        return rc;
    }
    if (strcmp(mode, "list") == 0) {
        for (size_t i = 0; i < g_nvecs; i++)
            printf("  [%3zu] fam=%d verdict=%s  %s\n",
                   i, g_vecs[i].fam, g_vecs[i].verdict ? "ACCEPT" : "REJECT",
                   g_vecs[i].label);
        return 0;
    }
    fprintf(stderr, "usage: %s {record|check|list} [dir]\n", argv[0]);
    return 2;
}
