/* Canonical R1CS TRANSCRIPT parity oracle for the Sapling SPEND circuit
 * (test-only, QAP lane).
 *
 * Portions interoperate with librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. No reference code
 * is linked into the production node; the golden values below were derived by
 * running a throwaway recording ConstraintSystem against that pinned commit.
 *
 * WHY THIS EXISTS
 * ---------------
 * `cs_is_satisfied()` proves the honest witness satisfies A*B==C for every
 * emitted constraint. That is NECESSARY but NOT SUFFICIENT for parity with the
 * real Sapling trusted-setup proving key: the key is built per-variable from
 * WHICH MATRIX (A, B or C) each coefficient sits in, not from the reduced
 * algebraic identity. Two circuits can agree on every A*B==C check and still be
 * different QAPs — for example
 *
 *     (y - 1) * cond = y' - 1          and          y * cond = y' - (1 - cond)
 *
 * are the same identity, are satisfied by exactly the same witness, and are
 * DIFFERENT R1CS matrices. Only a matrix-level transcript diff can tell them
 * apart, and the second form is the one bellman emits. Both of the mismatches
 * this oracle first caught were of exactly that shape.
 *
 * WHAT IS COMPARED
 * ----------------
 * For every constraint, the A/B/C linear combinations under a STABLE variable
 * identity that is reproducible on both sides:
 *
 *     kind 0 -> the constant ONE          (bellman Index::Input(0);  native var 0)
 *     kind 1 -> public INPUT n            (bellman Index::Input(n);  native var n)
 *     kind 2 -> AUX/witness variable n    (bellman Index::Aux(n);    native var n - 8)
 *
 * Those are ALLOCATION-ORDER positions, not raw internal indices. bellman keeps
 * inputs and aux in two separate index spaces; the native constraint system has
 * one shared counter and reserves slots 1..7 for the seven public inputs, so
 * native aux index = var - (num_inputs + 1).
 *
 * Canonicalization, identical on both sides:
 *   * duplicate terms on the same variable are SUMMED
 *   * zero-coefficient terms are DROPPED (after summing)
 *   * terms are sorted by (kind, index)
 *   * coefficients are canonical NON-Montgomery 32-byte little-endian
 *
 * Row hash  = SHA3-256( enc(A) || enc(B) || enc(C) )
 *   where enc(LC) = u32le n_terms, then n_terms * { u8 kind, u64le idx, [32]coeff }
 * Section hash    = SHA3-256( row_hash[first..last] )
 * Transcript hash = SHA3-256( row_hash[0..76893] )
 *
 * Summing duplicates is the right normalization rather than a convenience: the
 * QAP coefficient for (constraint, variable) IS the sum of that variable's
 * terms in the linear combination, so two term lists that differ only by
 * splitting or reordering describe the SAME matrix and must hash the same.
 *
 * HOW THE GOLDENS WERE PRODUCED, AND HOW TO RE-DERIVE THEM
 * --------------------------------------------------------
 * A throwaway Rust tool (a recording `ConstraintSystem<Bls12>` over the pinned
 * bellman) dumps the reference transcript for the same 76893-constraint prefix
 * into a binary file in the canonical encoding above. Point this test at it:
 *
 *     ZCL_R1CS_REF=/path/to/ref_spend_1_21.bin build/bin/test_zcl ...
 *
 * and it does a full row-by-row diff, printing the first differing row with
 * both sides decoded. With the variable unset (the CI path) it compares the
 * native transcript against the baked golden hashes below, which ARE the
 * reference's hashes. The reference recorder was itself validated by checking
 * that all 98777 recorded matrices are satisfied by the recorded assignment.
 *
 * ANTI-VACUOUS GATE
 * -----------------
 * A comparison that cannot fail proves nothing, so this test also injects five
 * synthetic breakages and asserts the oracle flags every one: A/C swapped on
 * one constraint, the historical wrong select-Y split, one flipped low bit in
 * one Fr coefficient, two constraints reordered, and one input variable
 * relabelled as aux. The select-Y case additionally asserts that BOTH forms are
 * satisfied by the same witness — that is the proof that A*B==C alone could
 * never have caught it.
 */

#include "test/test_core.h"

#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/groth16_prover.h"
#include "sapling/pedersen_hash.h"
#include "sapling/fr.h"
#include "crypto/sha3.h"
#include "test/groth16_spend_oracle_kat.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define R1CS_CHECK(name, expr) do {            \
    printf("  %s... ", (name));                \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

/* Sections 1..21 are the prefix the Rust recording ConstraintSystem was run
 * against, so their goldens below ARE the reference's own hashes. Sections
 * 22..28 were ported afterwards, from the pinned reference SOURCE rather than a
 * recorded transcript, so their goldens are NATIVE-derived regression pins —
 * they prove the matrices do not drift, they do not by themselves prove
 * reference parity. What does prove reference parity for the whole circuit is
 * further down: the constraint total, the auxiliary-variable total taken from
 * the OFFICIAL trusted-setup proving key, and (in the params-gated groups) a
 * proof that verifies under the official verifying key. Do not paper over a
 * 22..28 mismatch by re-baking a golden without understanding it. */
#define R1CS_REF_SECTIONS 21u
#define R1CS_SECTIONS 28u
#define R1CS_PREFIX_CONSTRAINTS 76893u
#define R1CS_PUBLIC_INPUTS 7u

/* The complete circuit. 98777 is bellman's published Spend constraint count
 * (also pinned as SPEND_CIRCUIT_TOTAL_CONSTRAINTS in sapling_circuit.h).
 *
 * 98638 is not a native number either: it is the `l` query length of the
 * OFFICIAL sapling-spend.params trusted-setup file, which bellman emits with
 * exactly one entry per AUXILIARY variable. So it is the reference circuit's aux
 * count, read out of the trusted setup itself. A port that allocated one wire
 * too many or too few anywhere in 28 sections cannot hit it, which makes it the
 * strongest reference check available without a Rust recorder. Re-derived from
 * the file (not restated) by the params-gated leg in
 * tests/harness/src/test_groth16_selfverify.c. */
#define R1CS_TOTAL_CONSTRAINTS 98777u
#define R1CS_TOTAL_AUX         98638u

/* ── Canonical term ────────────────────────────────────────────────────── */

struct ct {
    uint8_t  kind;      /* 0 = ONE, 1 = INPUT, 2 = AUX */
    uint64_t idx;
    uint8_t  coeff[32]; /* canonical non-Montgomery little-endian */
};

struct ctbuf {
    struct ct *t;
    size_t n, cap;
};

/* Intermediate form: field element not yet serialized, so duplicate terms can
 * be summed in the field before canonical encoding. */
struct ftmp {
    uint8_t   kind;
    uint64_t  idx;
    struct fr c;
};

static void ctbuf_free(struct ctbuf *b)
{
    free(b->t);
    b->t = NULL;
    b->n = b->cap = 0;
}

static bool ctbuf_reserve(struct ctbuf *b, size_t want)
{
    if (want <= b->cap)
        return true;
    size_t cap = b->cap ? b->cap : 8;
    while (cap < want)
        cap *= 2;
    struct ct *p = zcl_realloc(b->t, cap * sizeof(*p), "r1cs_ctbuf");
    if (!p)
        LOG_FAIL("groth16_r1cs_oracle",
                 "ctbuf_reserve: out of memory for %zu canonical terms", cap);
    b->t = p;
    b->cap = cap;
    return true;
}

static int ftmp_cmp(const void *pa, const void *pb)
{
    const struct ftmp *a = pa, *b = pb;
    if (a->kind != b->kind)
        return a->kind < b->kind ? -1 : 1;
    if (a->idx != b->idx)
        return a->idx < b->idx ? -1 : 1;
    return 0;
}

/* native variable index -> (kind, idx). Inputs occupy 1..num_inputs; aux start
 * immediately after, so aux index is var - (num_inputs + 1). */
static void map_var(const struct constraint_system *cs, size_t var,
                    uint8_t *kind, uint64_t *idx)
{
    if (var == 0) {
        *kind = 0;
        *idx = 0;
    } else if (var <= cs->num_inputs) {
        *kind = 1;
        *idx = (uint64_t)var;
    } else {
        *kind = 2;
        *idx = (uint64_t)(var - cs->num_inputs - 1);
    }
}

/* Canonicalize one native linear combination into `out`. */
static bool canon_lc(const struct constraint_system *cs,
                     const struct linear_combination *lc,
                     struct ctbuf *out, struct ftmp **scratch,
                     size_t *scratch_cap)
{
    out->n = 0;
    if (lc->num_terms == 0)
        return true;

    if (lc->num_terms > *scratch_cap) {
        size_t cap = *scratch_cap ? *scratch_cap : 8;
        while (cap < lc->num_terms)
            cap *= 2;
        struct ftmp *p = zcl_realloc(*scratch, cap * sizeof(*p),
                                     "r1cs_canon_scratch");
        if (!p)
            LOG_FAIL("groth16_r1cs_oracle",
                     "canon_lc: out of memory for %zu terms", cap);
        *scratch = p;
        *scratch_cap = cap;
    }
    struct ftmp *tmp = *scratch;

    for (size_t i = 0; i < lc->num_terms; i++) {
        map_var(cs, lc->terms[i].var, &tmp[i].kind, &tmp[i].idx);
        tmp[i].c = lc->terms[i].coeff;
    }
    qsort(tmp, lc->num_terms, sizeof(*tmp), ftmp_cmp);

    /* Merge equal keys by field addition, drop the zeros that fall out. */
    if (!ctbuf_reserve(out, lc->num_terms))
        return false;
    size_t i = 0;
    while (i < lc->num_terms) {
        struct fr acc = tmp[i].c;
        size_t j = i + 1;
        while (j < lc->num_terms && ftmp_cmp(&tmp[i], &tmp[j]) == 0) {
            fr_add(&acc, &acc, &tmp[j].c);
            j++;
        }
        if (!fr_is_zero(&acc)) {
            struct ct *slot = &out->t[out->n++];
            slot->kind = tmp[i].kind;
            slot->idx = tmp[i].idx;
            fr_to_bytes(slot->coeff, &acc);
        }
        i = j;
    }
    return true;
}

/* ── Hashing ───────────────────────────────────────────────────────────── */

static void hash_lc(struct sha3_256_ctx *h, const struct ct *t, size_t n)
{
    uint8_t hdr[4];
    for (int j = 0; j < 4; j++)
        hdr[j] = (uint8_t)(((uint32_t)n) >> (j * 8));
    sha3_256_write(h, hdr, 4);
    for (size_t i = 0; i < n; i++) {
        uint8_t rec[41];
        rec[0] = t[i].kind;
        for (int j = 0; j < 8; j++)
            rec[1 + j] = (uint8_t)(t[i].idx >> (j * 8));
        memcpy(rec + 9, t[i].coeff, 32);
        sha3_256_write(h, rec, sizeof rec);
    }
}

static void row_hash(uint8_t out[32],
                     const struct ctbuf *a, const struct ctbuf *b,
                     const struct ctbuf *c)
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    hash_lc(&h, a->t, a->n);
    hash_lc(&h, b->t, b->n);
    hash_lc(&h, c->t, c->n);
    sha3_256_finalize(&h, out);
}

static void hex_of(char out[65], const uint8_t h[32])
{
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = d[h[i] >> 4];
        out[i * 2 + 1] = d[h[i] & 0xf];
    }
    out[64] = '\0';
}

/* ── Decoding for human-readable diff output ───────────────────────────── */

static void print_lc(const char *label, const struct ct *t, size_t n)
{
    printf("      %s[%zu]:", label, n);
    if (n == 0) {
        printf(" 0");
    }
    for (size_t i = 0; i < n; i++) {
        const char *k = t[i].kind == 0 ? "ONE"
                      : t[i].kind == 1 ? "INPUT" : "AUX";
        printf(" %s", k);
        if (t[i].kind != 0)
            printf(":%" PRIu64, t[i].idx);
        printf("*");
        /* Print short forms for the two overwhelmingly common coefficients so
         * a diff is readable at a glance; otherwise full little-endian hex. */
        static const uint8_t one_le[32] = { 1 };
        static const uint8_t neg_one_le[32] = {
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
            0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
            0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
        };
        if (memcmp(t[i].coeff, one_le, 32) == 0) {
            printf("1");
        } else if (memcmp(t[i].coeff, neg_one_le, 32) == 0) {
            printf("(-1)");
        } else {
            char hx[65];
            hex_of(hx, t[i].coeff);
            printf("0x%s", hx);
        }
    }
    printf("\n");
}

static bool ct_equal(const struct ctbuf *x, const struct ctbuf *y)
{
    if (x->n != y->n)
        return false;
    for (size_t i = 0; i < x->n; i++) {
        if (x->t[i].kind != y->t[i].kind || x->t[i].idx != y->t[i].idx)
            return false;
        if (memcmp(x->t[i].coeff, y->t[i].coeff, 32) != 0)
            return false;
    }
    return true;
}

/* ── Reference-file reader (canonical encoding, produced by the Rust dump) ── */

static bool rd_u32(FILE *f, uint32_t *v)
{
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4)
        return false;
    *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8)
       | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return true;
}

static bool ref_read_lc(FILE *f, struct ctbuf *out)
{
    uint32_t n;
    if (!rd_u32(f, &n))
        return false;
    out->n = 0;
    if (!ctbuf_reserve(out, n ? n : 1))
        return false;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t rec[41];
        if (fread(rec, 1, sizeof rec, f) != sizeof rec)
            return false;
        struct ct *slot = &out->t[out->n++];
        slot->kind = rec[0];
        slot->idx = 0;
        for (int j = 0; j < 8; j++)
            slot->idx |= ((uint64_t)rec[1 + j]) << (j * 8);
        memcpy(slot->coeff, rec + 9, 32);
    }
    return true;
}

/* ── Golden hashes (the REFERENCE transcript's, from the pinned commit) ──
 *
 * Per-section hashes, so a failure names the section rather than just the
 * whole circuit. Section i covers rows [cum[i-1], cum[i]).
 */
static const char *GOLDEN_SECTION[R1CS_REF_SECTIONS] = {
    "e7b2379615feac81aacb2c0f4e1eb23ce0c520c7994b292911853796ceaa60a5", /* S1  ak witness/on-curve/not-small-order */
    "ab0af592b36c8d8e72296ba5b2c31183efbd0be532a96afa4f035a68c18c3651", /* S2  ar bits */
    "0d083bb22826bd28d162b45acbaf63e3501112155962529255b1165998df460a", /* S3  randomization of signing key */
    "42e986011831e1dfaf204402c32b38fbf62a10bf6d9653a9e226cd9b1ae656cc", /* S4  rk = ak + [ar]G */
    "50f765f3b45d959aaeda85efe1d8ea69a8b528320e3d73cff85051130cb45590", /* S5  rk inputize */
    "160ac3775a9e3ba311f5968ebcd7bb75c70f78d19fb86f7c8171a260586675eb", /* S6  nsk bits */
    "11372a6cbba069d7cbeb89eda8aa77c92e18a758469b5fa1a0c9250296d353c4", /* S7  nk = [nsk] ProofGenerationKey */
    "7ad337175b2ca2046b325961b39c27703c9267f190e958f8a38f348038245299", /* S8  representation of ak */
    "48057ca393839df772ed904889b8c8da5d4121dccb7274f1307d5c2acdb56c1a", /* S9  representation of nk */
    "6e145eaf2e70b5299c9adcdc1e7ab43d58e93c24dc29bb3f8193dc0e3f84ce7d", /* S10 computation of ivk (blake2s) */
    "6ed97f8f4ef54b301acd6eaf1446da80b1b700511b7693627d2893e7b0c4a68b", /* S11 witness g_d */
    "0fc6e6db517193bfe0e6b2ed98c4a5ee742974540baabb7875e69e9fefb131eb", /* S12 g_d not small order */
    "26c325aace7234a8731b53f774e07284f9984d349d36a3fe49f11946ae02c709", /* S13 compute pk_d */
    "88f3969de56abeb0eb2b9b4ada23bcf5a267c391dc33ff842410624bc485190e", /* S14 value commitment */
    "890927eb4912421c54f6a811272d38983464a7793fea3e14e9c7efe3b2295ae5", /* S15 representation of g_d */
    "762caa93739897fe1336854e32f7b59b83958f491c642427fcb04323807250e2", /* S16 representation of pk_d */
    "57e3bcf54edbe52caafb51593f3ca757ee26ace020b885f71e7df4bc194eb9fe", /* S17 note content hash */
    "14905a8bf0e97f20d5ffe4f8b4de1a63096c878230fead6fbe91f3a9885c82ef", /* S18 rcm bits */
    "6fe72df6f94dd19421efdf88254419fa6c424bcbdb3a86c58874438b49ac33f3", /* S19 commitment randomness */
    "7a6f395fcd311d56d6c2e6f9ce03e03463595d15b6f1378cc640d62a473ddc03", /* S20 randomization of note commitment */
    "7847822d7f99894a1bb475fb48463991d33c35efc633021f1c2f698aa1dff0ed", /* S21 32-level Merkle authentication path */
};
static const char *GOLDEN_TRANSCRIPT =
    "6f528ff699b0cf7e0e707dfd5d51359c2a62cddaf1129206be0cb899c5ce8039";

/* Sections 22..28. NATIVE-derived pins — see the R1CS_REF_SECTIONS note. */
static const char *PIN_SECTION[R1CS_SECTIONS - R1CS_REF_SECTIONS] = {
    "5ffca837ab49079daec2630f91710a57398ec33ffc32d87426835a3e8f85d653",
        /* S22 conditionally enforce correct root */
    "f34177286c5a36d31b46d71d026e5e1315c3a9bed86a1a9cdbf7756f4fbbeba3",
        /* S23 anchor inputize */
    "1fdc1212b3f08496b0867af06c6560194d5fecaf8e6ce7d94b60d18e460359ae",
        /* S24 g^position */
    "079379626eaa0cd724aaa45f12b4d62fe0114d95bbb63f599fe5cdba3e81bea5",
        /* S25 faerie gold prevention */
    "dd5f9fea97330a24c5108b1ff63fe51e205bfa7c03154de546c29789f52982ca",
        /* S26 representation of rho */
    "0063739f07c39c75903d1eeb3f7f0e67f9c4d1f73907691adcc673c4623dd346",
        /* S27 nf computation (blake2s) */
    "79a81ec96d361677ee372cb9bb021a3a5d456e5fca067ed301be7d92bafdfbb0",
        /* S28 pack nullifier */
};
static const char *PIN_TRANSCRIPT =
    "7b3da862d7bc79861ed28585d600438aba586228ef17e6da4f5e44b76d86e7c7";

/* Cumulative constraint counts per section — the boundaries of bellman's
 * top-level namespace runs in Spend::synthesize.
 *
 * 1..21 were independently reproduced by the recording ConstraintSystem.
 * 22..28 are derived from the reference source's own gadget costs and are
 * NOT free parameters: they have to sum to bellman's published 98777, and the
 * only split that does is
 *   S22 +1     the single (cur - rt) * value = 0 row
 *   S23 +1     rt.inputize()
 *   S24 +92    g^position: 32 position bits -> 11 windows, of which the last
 *              has a constant-false third bit, so 10*3 + 2 lookups + 10*6
 *              Edwards additions. (The naive 11*3 + 60 = 93 is what a padded
 *              window costs when you allocate a dummy wire for the pad — the
 *              reference folds Boolean::and away instead, and that ONE
 *              constraint is the whole 98777-vs-98778 discrepancy.)
 *   S25 +6     one Edwards addition, rho = cm + [position] G_pos
 *   S26 +776   EdwardsPoint::repr(rho), same body as sections 8/9/15/16
 *   S27 +21006 blake2s over a 512-bit all-allocated preimage, same body and
 *              same cost as section 10
 *   S28 +2     multipack::pack_into_inputs, 256 bits at Fr::CAPACITY = 254 */
static const size_t REF_CUM[R1CS_SECTIONS] = {
    20, 272, 1022, 1028, 1030, 1282, 2032, 2808, 3584, 24590,
    24594, 24610, 27862, 29127, 29903, 30679, 31661, 31913, 32663, 32669,
    76893,
    76894, 76895, 76987, 76993, 77769, 98775, 98777,
};

/* ── Witness fixture (identical to the H3 shape gate's) ────────────────── */

static bool find_diversifier(uint8_t d[11])
{
    memset(d, 0, 11);
    for (unsigned int i = 0; i < 256; i++) {
        d[0] = (uint8_t)i;
        if (sapling_check_diversifier(d))
            return true;
    }
    return false;
}

static bool build_fixture(struct sapling_spend_witness *wit,
                          struct sapling_spend_inputs *pub)
{
    uint8_t ak[32];
    sapling_ask_to_ak(SPEND_ORACLE_KAT_ASK, ak);

    memset(wit, 0, sizeof *wit);
    memcpy(wit->ak, ak, 32);
    memcpy(wit->nsk, SPEND_ORACLE_KAT_NSK, 32);
    wit->ar[0] = 0x03;
    memcpy(wit->pk_d, ak, 32);
    wit->value = UINT64_C(54321);
    wit->rcv[0] = 0x71;
    wit->rcv[1] = 0x0d;
    wit->rcm[0] = 0x5c;
    wit->rcm[1] = 0x23;
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t pa[32] = {0}, pb[32] = {0};
        pa[0] = (uint8_t)(0x10u + d);
        pa[1] = 0x5b;
        pb[0] = (uint8_t)(d * 7u);
        pb[3] = 0x11;
        pedersen_merkle_hash(0, pa, pb, wit->auth_path[d]);
        wit->auth_path_bits[d] = (((d * 5u) + (d / 3u)) & 1u) != 0u;
    }
    if (!find_diversifier(wit->diversifier))
        return false;

    /* rk, cv, the anchor the path folds to, and the nullifier. Sections 5, 14,
     * 22 and 28 bind all four, so they are part of the fixture, not decoration:
     * with a placeholder anchor the R1CS is unsatisfiable by construction. */
    memset(pub, 0, sizeof *pub);
    return sapling_spend_derive_public(wit, pub);
}

/* ── The anti-vacuous gate ─────────────────────────────────────────────── */

/* Build the two algebraically-identical select-Y forms as canonical rows over
 * the same variables, and prove (a) both are satisfied by the same witness and
 * (b) the oracle's row hash separates them. This is the whole thesis of the
 * test in six lines of algebra. */
static int antivacuous_select_y(void)
{
    int failures = 0;
    printf("\n--- anti-vacuous 2/5: the two select-Y matrix splits ---\n");

    /* Wires: y (AUX 0), cond (AUX 1), y' (AUX 2). Take cond = 0, y = 9,
     * so y' must be 1. Both forms must hold. */
    struct constraint_system cs;
    cs_init(&cs);
    struct fr nine, zero, one;
    fr_zero(&zero);
    fr_one(&one);
    fr_from_bytes(&nine, (const uint8_t[32]){ 9 });

    size_t y = cs_alloc_aux(&cs, &nine);
    size_t cond = cs_alloc_aux(&cs, &zero);
    size_t yp = cs_alloc_aux(&cs, &one);

    struct fr neg_one;
    fr_neg(&neg_one, &one);

    /* Form W (what the native circuit used to emit): (y - 1) * cond = y' - 1 */
    struct linear_combination wa, wb, wc;
    lc_init(&wa); lc_add_term(&wa, y, &one); lc_add_term(&wa, 0, &neg_one);
    lc_init(&wb); lc_add_term(&wb, cond, &one);
    lc_init(&wc); lc_add_term(&wc, yp, &one); lc_add_term(&wc, 0, &neg_one);

    /* Form R (what bellman emits): y * cond = y' - (1 - cond) */
    struct linear_combination ra, rb, rc;
    lc_init(&ra); lc_add_term(&ra, y, &one);
    lc_init(&rb); lc_add_term(&rb, cond, &one);
    lc_init(&rc);
    lc_add_term(&rc, yp, &one);
    lc_add_term(&rc, 0, &neg_one);
    lc_add_term(&rc, cond, &one);

    /* (a) Both are satisfied by the SAME witness — so A*B==C is blind here. */
    struct fr av, bv, cv, ab;
    lc_evaluate(&av, &wa, cs.witness);
    lc_evaluate(&bv, &wb, cs.witness);
    lc_evaluate(&cv, &wc, cs.witness);
    fr_mul(&ab, &av, &bv);
    bool w_sat = fr_eq(&ab, &cv);
    lc_evaluate(&av, &ra, cs.witness);
    lc_evaluate(&bv, &rb, cs.witness);
    lc_evaluate(&cv, &rc, cs.witness);
    fr_mul(&ab, &av, &bv);
    bool r_sat = fr_eq(&ab, &cv);
    R1CS_CHECK("both select-Y forms satisfy A*B==C on the same witness",
               w_sat && r_sat);

    /* (b) The oracle separates them. */
    struct ctbuf ca = {0}, cb = {0}, cc = {0};
    struct ftmp *scratch = NULL;
    size_t scratch_cap = 0;
    uint8_t hw[32], hr[32];
    canon_lc(&cs, &wa, &ca, &scratch, &scratch_cap);
    canon_lc(&cs, &wb, &cb, &scratch, &scratch_cap);
    canon_lc(&cs, &wc, &cc, &scratch, &scratch_cap);
    row_hash(hw, &ca, &cb, &cc);
    printf("      wrong form  (y-1)*cond = y'-1:\n");
    print_lc("A", ca.t, ca.n);
    print_lc("C", cc.t, cc.n);
    canon_lc(&cs, &ra, &ca, &scratch, &scratch_cap);
    canon_lc(&cs, &rb, &cb, &scratch, &scratch_cap);
    canon_lc(&cs, &rc, &cc, &scratch, &scratch_cap);
    row_hash(hr, &ca, &cb, &cc);
    printf("      reference   y*cond = y'-(1-cond):\n");
    print_lc("A", ca.t, ca.n);
    print_lc("C", cc.t, cc.n);
    R1CS_CHECK("oracle row hash SEPARATES the two select-Y splits",
               memcmp(hw, hr, 32) != 0);

    ctbuf_free(&ca); ctbuf_free(&cb); ctbuf_free(&cc);
    free(scratch);
    lc_free(&wa); lc_free(&wb); lc_free(&wc);
    lc_free(&ra); lc_free(&rb); lc_free(&rc);
    cs_free(&cs);
    return failures;
}

/* The other four injections operate on the REAL transcript's row hashes, so
 * they prove detection at full scale (76893 rows), not just on a toy. Each
 * returns the recomputed transcript hash after the mutation. */
static void transcript_hash_of(uint8_t out[32], const uint8_t *rows, size_t n)
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, rows, n * 32);
    sha3_256_finalize(&h, out);
}

int test_groth16_r1cs_oracle(void)
{
    int failures = 0;
    printf("\n=== groth16_r1cs_oracle: canonical R1CS transcript parity "
           "(SPEND sections 1-28) ===\n");

    struct sapling_spend_witness wit;
    struct sapling_spend_inputs pub;
    R1CS_CHECK("built the deterministic spend witness fixture",
               build_fixture(&wit, &pub));

    struct spend_section_shape sections[R1CS_SECTIONS + 1];
    size_t nsec = 0;
    struct constraint_system cs;
    cs_init(&cs);
    bool synth_ok = sapling_spend_synthesize_traced(
        &cs, &wit, &pub, sections, R1CS_SECTIONS + 1, &nsec, NULL);
    R1CS_CHECK("traced spend synthesis succeeded", synth_ok);
    if (!synth_ok) {
        cs_free(&cs);
        return failures + 1;
    }

    size_t num_aux = (cs.num_vars > cs.num_inputs + 1)
                   ? cs.num_vars - cs.num_inputs - 1 : 0;
    printf("  native: %zu constraints, %zu inputs, %zu vars, %zu aux "
           "(%zu sections)\n",
           cs.num_constraints, cs.num_inputs, cs.num_vars, num_aux, nsec);
    R1CS_CHECK("native recorded exactly 28 sections", nsec == R1CS_SECTIONS);
    R1CS_CHECK("native constraint count == reference total (98777)",
               cs.num_constraints == R1CS_TOTAL_CONSTRAINTS);
    R1CS_CHECK("native aux count == official trusted-setup l_len (98638)",
               num_aux == R1CS_TOTAL_AUX);
    R1CS_CHECK("native public input count == 7",
               cs.num_inputs == R1CS_PUBLIC_INPUTS);
    R1CS_CHECK("the honest witness satisfies every emitted constraint",
               cs_is_satisfied(&cs, NULL));

    /* Per-section cumulative boundaries. A section that lands on the wrong
     * count cannot be parity-correct whatever its hash says, and naming the
     * section is what makes a regression diagnosable. */
    for (size_t s = 0; s < nsec && s < R1CS_SECTIONS; s++) {
        if (sections[s].num_constraints == REF_CUM[s])
            continue;
        printf("  S%-2zu (%s) cumulative constraints %zu != reference %zu\n",
               s + 1, sections[s].name ? sections[s].name : "?",
               sections[s].num_constraints, REF_CUM[s]);
        failures++;
    }

    /* ── Canonical transcript ─────────────────────────────────────────── */
    size_t n_rows = cs.num_constraints;
    uint8_t *rows = zcl_malloc(n_rows * 32, "r1cs_row_hashes");
    if (!rows) {
        printf("  FAIL: out of memory for %zu row hashes\n", n_rows);
        cs_free(&cs);
        return failures + 1;
    }

    struct ctbuf na = {0}, nb = {0}, nc = {0};
    struct ctbuf ra = {0}, rb = {0}, rc = {0};
    struct ftmp *scratch = NULL;
    size_t scratch_cap = 0;

    /* Optional full row-by-row diff against the reference dump. */
    const char *ref_path = getenv("ZCL_R1CS_REF");
    FILE *ref = NULL;
    size_t ref_rows = 0;
    if (ref_path && *ref_path) {
        ref = fopen(ref_path, "rb");
        if (!ref) {
            printf("  NOTE: ZCL_R1CS_REF=%s could not be opened; "
                   "falling back to golden-hash comparison\n", ref_path);
        } else {
            uint8_t magic[8];
            uint32_t r_rows = 0, r_inputs = 0, r_aux = 0;
            bool hdr_ok = fread(magic, 1, 8, ref) == 8
                       && memcmp(magic, "ZR1CS\x00\x00\x01", 8) == 0
                       && rd_u32(ref, &r_rows) && rd_u32(ref, &r_inputs)
                       && rd_u32(ref, &r_aux);
            R1CS_CHECK("reference dump header parsed", hdr_ok);
            if (!hdr_ok) {
                fclose(ref);
                ref = NULL;
            } else {
                ref_rows = r_rows;
                printf("  reference: %u rows, %u inputs, %u aux (from %s)\n",
                       r_rows, r_inputs, r_aux, ref_path);
                R1CS_CHECK("reference row count == the 1..21 prefix (76893)",
                           (size_t)r_rows == R1CS_PREFIX_CONSTRAINTS);
                R1CS_CHECK("reference input count == native input count",
                           (size_t)r_inputs == cs.num_inputs);
            }
        }
    }

    /* When diffing against the reference, hash the REFERENCE rows with the
     * very same encoder. That is what makes the baked goldens below the
     * reference's hashes rather than a restatement of the native side. */
    uint8_t *ref_rowh = NULL;
    if (ref) {
        ref_rowh = zcl_malloc(n_rows * 32, "r1cs_ref_row_hashes");
        if (!ref_rowh)
            printf("  NOTE: no memory for reference row hashes; "
                   "diff only\n");
    }

    size_t diffs = 0, first_diff = 0;
    bool have_first_diff = false;
    for (size_t i = 0; i < n_rows; i++) {
        const struct r1cs_constraint *k = &cs.constraints[i];
        canon_lc(&cs, &k->a, &na, &scratch, &scratch_cap);
        canon_lc(&cs, &k->b, &nb, &scratch, &scratch_cap);
        canon_lc(&cs, &k->c, &nc, &scratch, &scratch_cap);
        row_hash(rows + i * 32, &na, &nb, &nc);

        if (ref && i < ref_rows) {
            if (!ref_read_lc(ref, &ra) || !ref_read_lc(ref, &rb)
                || !ref_read_lc(ref, &rc)) {
                printf("  FAIL: reference dump truncated at row %zu\n", i);
                failures++;
                fclose(ref);
                ref = NULL;
            } else {
                if (ref_rowh)
                    row_hash(ref_rowh + i * 32, &ra, &rb, &rc);
                if (!ct_equal(&na, &ra) || !ct_equal(&nb, &rb)
                    || !ct_equal(&nc, &rc)) {
                diffs++;
                if (!have_first_diff) {
                    have_first_diff = true;
                    first_diff = i;
                }
                if (diffs <= 12) {
                    /* Name the section the row falls in, so the report points
                     * at a gadget rather than a bare row number. */
                    size_t sec = 0;
                    while (sec < R1CS_SECTIONS && i >= REF_CUM[sec])
                        sec++;
                    printf("  DIFF row %zu (section %zu, %s):\n", i, sec + 1,
                           sec < nsec && sections[sec].name
                               ? sections[sec].name : "?");
                    printf("    native:\n");
                    print_lc("A", na.t, na.n);
                    print_lc("B", nb.t, nb.n);
                    print_lc("C", nc.t, nc.n);
                    printf("    reference:\n");
                    print_lc("A", ra.t, ra.n);
                    print_lc("B", rb.t, rb.n);
                    print_lc("C", rc.t, rc.n);
                }
                }
            }
        }
    }

    if (ref) {
        printf("  row-by-row diff vs reference: %zu differing rows of %zu\n",
               diffs, n_rows);
        if (diffs)
            printf("  first differing row: %zu\n", first_diff);
        R1CS_CHECK("ZERO matrix differences vs the reference transcript",
                   diffs == 0);
        fclose(ref);
        ref = NULL;
    }

    /* The reference's own section + transcript hashes, computed by this same
     * encoder. These are the values to bake into GOLDEN_SECTION /
     * GOLDEN_TRANSCRIPT — printed in a paste-ready form on purpose. */
    if (ref_rowh) {
        printf("  --- REFERENCE section hashes (bake these as goldens) ---\n");
        size_t rprev = 0;
        for (size_t s = 0; s < R1CS_REF_SECTIONS; s++) {
            size_t end = REF_CUM[s];
            uint8_t h[32];
            struct sha3_256_ctx ctx;
            sha3_256_init(&ctx);
            sha3_256_write(&ctx, ref_rowh + rprev * 32, (end - rprev) * 32);
            sha3_256_finalize(&ctx, h);
            char hx[65];
            hex_of(hx, h);
            printf("    \"%s\",\n", hx);
            rprev = end;
        }
        uint8_t rall[32];
        char rallhx[65];
        transcript_hash_of(rall, ref_rowh, R1CS_PREFIX_CONSTRAINTS);
        hex_of(rallhx, rall);
        printf("  REFERENCE transcript SHA3-256 = \"%s\"\n", rallhx);
        free(ref_rowh);
        ref_rowh = NULL;
    }

    /* ── Section + transcript hashes ──────────────────────────────────── */
    printf("  --- canonical section hashes ---\n");
    size_t prev = 0;
    for (size_t s = 0; s < R1CS_SECTIONS; s++) {
        size_t end = REF_CUM[s];
        if (end > n_rows)
            break;
        uint8_t h[32];
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        sha3_256_write(&ctx, rows + prev * 32, (end - prev) * 32);
        sha3_256_finalize(&ctx, h);
        char hx[65];
        hex_of(hx, h);
        const bool is_ref = s < R1CS_REF_SECTIONS;
        const char *want = is_ref ? GOLDEN_SECTION[s]
                                  : PIN_SECTION[s - R1CS_REF_SECTIONS];
        bool match = *want && strcmp(hx, want) == 0;
        printf("  S%-2zu rows[%6zu,%6zu)  %s  %s\n", s + 1, prev, end, hx,
               match ? (is_ref ? "== golden (reference)" : "== pin (native)")
                     : (*want ? "!! MISMATCH" : "!! NO GOLDEN BAKED"));
        if (!match)
            failures++;
        prev = end;
    }

    /* The 1..21 prefix hash is the REFERENCE transcript's, unchanged by the
     * later sections — keep checking exactly those rows. */
    if (n_rows >= R1CS_PREFIX_CONSTRAINTS) {
        uint8_t pre[32];
        char prehx[65];
        transcript_hash_of(pre, rows, R1CS_PREFIX_CONSTRAINTS);
        hex_of(prehx, pre);
        printf("  prefix   SHA3-256 over %u rows: %s\n",
               R1CS_PREFIX_CONSTRAINTS, prehx);
        R1CS_CHECK("prefix hash == golden (reference) transcript hash",
                   strcmp(prehx, GOLDEN_TRANSCRIPT) == 0);
    } else {
        printf("  FAIL: only %zu rows — the 1..21 reference prefix is "
               "incomplete\n", n_rows);
        failures++;
    }

    uint8_t all[32];
    transcript_hash_of(all, rows, n_rows);
    char allhx[65];
    hex_of(allhx, all);
    printf("  full     SHA3-256 over %zu rows: %s\n", n_rows, allhx);
    R1CS_CHECK("full transcript hash == native pin",
               *PIN_TRANSCRIPT && strcmp(allhx, PIN_TRANSCRIPT) == 0);

    /* ── Anti-vacuous injections ──────────────────────────────────────── */
    printf("\n--- anti-vacuous gate: the oracle must catch all 5 ---\n");

    /* 1/5: swap A and C on one constraint. */
    {
        size_t victim = n_rows / 2;
        const struct r1cs_constraint *k = &cs.constraints[victim];
        canon_lc(&cs, &k->a, &na, &scratch, &scratch_cap);
        canon_lc(&cs, &k->b, &nb, &scratch, &scratch_cap);
        canon_lc(&cs, &k->c, &nc, &scratch, &scratch_cap);
        uint8_t swapped[32];
        row_hash(swapped, &nc, &nb, &na);   /* A and C exchanged */
        bool caught = memcmp(swapped, rows + victim * 32, 32) != 0;
        R1CS_CHECK("1/5 swapped A and C on one constraint is CAUGHT", caught);
        /* And it must move the transcript hash, not just the row hash. */
        uint8_t *mut = zcl_malloc(n_rows * 32, "r1cs_mut");
        if (mut) {
            memcpy(mut, rows, n_rows * 32);
            memcpy(mut + victim * 32, swapped, 32);
            uint8_t h2[32];
            transcript_hash_of(h2, mut, n_rows);
            R1CS_CHECK("    ... and moves the whole-transcript hash",
                       memcmp(h2, all, 32) != 0);
            free(mut);
        }
    }

    /* 2/5: the historical wrong select-Y split. */
    failures += antivacuous_select_y();

    /* 3/5: flip one low bit in one Fr coefficient. */
    {
        printf("\n--- anti-vacuous 3/5 .. 5/5 (on the real 76893-row "
               "transcript) ---\n");
        size_t victim = 3;
        const struct r1cs_constraint *k = &cs.constraints[victim];
        canon_lc(&cs, &k->a, &na, &scratch, &scratch_cap);
        canon_lc(&cs, &k->b, &nb, &scratch, &scratch_cap);
        canon_lc(&cs, &k->c, &nc, &scratch, &scratch_cap);
        bool caught = false;
        if (na.n > 0) {
            na.t[0].coeff[0] ^= 0x01;      /* one flipped low bit */
            uint8_t h[32];
            row_hash(h, &na, &nb, &nc);
            caught = memcmp(h, rows + victim * 32, 32) != 0;
            na.t[0].coeff[0] ^= 0x01;
        }
        R1CS_CHECK("3/5 one flipped low bit in one Fr coefficient is CAUGHT",
                   caught);
    }

    /* 4/5: reorder two constraints. */
    {
        uint8_t *mut = zcl_malloc(n_rows * 32, "r1cs_mut_reorder");
        bool caught = false;
        size_t located = SIZE_MAX;
        if (mut) {
            memcpy(mut, rows, n_rows * 32);
            /* Two rows that genuinely differ, so the swap is observable. */
            size_t i = 0, j = 1;
            while (j < n_rows
                   && memcmp(rows + i * 32, rows + j * 32, 32) == 0)
                j++;
            uint8_t tmp[32];
            memcpy(tmp, mut + i * 32, 32);
            memcpy(mut + i * 32, mut + j * 32, 32);
            memcpy(mut + j * 32, tmp, 32);
            uint8_t h[32];
            transcript_hash_of(h, mut, n_rows);
            caught = memcmp(h, all, 32) != 0;
            for (size_t r = 0; r < n_rows; r++)
                if (memcmp(mut + r * 32, rows + r * 32, 32) != 0) {
                    located = r;
                    break;
                }
            free(mut);
        }
        R1CS_CHECK("4/5 two reordered constraints is CAUGHT", caught);
        R1CS_CHECK("    ... and the first differing row is located",
                   located != SIZE_MAX);
    }

    /* 5/5: relabel one input variable as an aux variable. */
    {
        /* Find a row that references a public INPUT — the rk/cv binding rows
         * do. Relabel that term's kind to AUX and confirm the hash moves.
         * The scan covers A, B and C: which matrix the input term lands in is
         * exactly what this oracle exists to pin down, so an injection that
         * only looked in A would silently find nothing whenever the circuit
         * put its inputs elsewhere (that is how this check first failed). */
        bool caught = false, found_input = false;
        struct ctbuf *lcs[3] = { &na, &nb, &nc };
        static const char *lcname[3] = { "A", "B", "C" };
        for (size_t i = 0; i < n_rows && !found_input; i++) {
            const struct r1cs_constraint *k = &cs.constraints[i];
            canon_lc(&cs, &k->a, &na, &scratch, &scratch_cap);
            canon_lc(&cs, &k->b, &nb, &scratch, &scratch_cap);
            canon_lc(&cs, &k->c, &nc, &scratch, &scratch_cap);
            for (size_t w = 0; w < 3 && !found_input; w++) {
                for (size_t t = 0; t < lcs[w]->n; t++) {
                    if (lcs[w]->t[t].kind != 1)
                        continue;
                    found_input = true;
                    lcs[w]->t[t].kind = 2;     /* INPUT:n -> AUX:n */
                    uint8_t h[32];
                    row_hash(h, &na, &nb, &nc);
                    caught = memcmp(h, rows + i * 32, 32) != 0;
                    printf("      relabelled INPUT:%" PRIu64 " as AUX in %s "
                           "at row %zu\n", lcs[w]->t[t].idx, lcname[w], i);
                    break;
                }
            }
        }
        R1CS_CHECK("5/5 an input variable relabelled as aux is CAUGHT",
                   found_input && caught);
    }

    free(rows);
    ctbuf_free(&na); ctbuf_free(&nb); ctbuf_free(&nc);
    ctbuf_free(&ra); ctbuf_free(&rb); ctbuf_free(&rc);
    free(scratch);
    cs_free(&cs);

    if (failures == 0)
        printf("groth16_r1cs_oracle: ALL PASS\n");
    else
        printf("groth16_r1cs_oracle: %d FAILURE(S)\n", failures);
    return failures;
}
