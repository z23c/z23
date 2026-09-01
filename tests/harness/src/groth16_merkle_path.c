/* Section-21 gate: the Sapling spend circuit's 32-level Merkle authentication
 * path (test-only).
 *
 * Portions interoperate with librustzcash / bellman / sapling-crypto (The Zcash
 * developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. No reference code
 * is linked here: every reference value below is produced by this repository's
 * own out-of-circuit implementations.
 *
 * WHAT THIS GATES
 * ---------------
 * Section 21 is 44224 of the spend circuit's 98777 constraints — the largest
 * single section, 45% of the whole circuit. A section that lands on the right
 * constraint count with the wrong arithmetic is the exact failure the spend
 * parity oracle exists to catch, so this gate never accepts a count on its own.
 * Four independent things are asserted:
 *
 *   (A) EXACT COST, top down and bottom up. The whole fold is 44224 and each of
 *       the 32 levels is 1382, and each of the level's four pieces is measured
 *       on its own (1 position bit + 2 conditional swap + 512 decomposition +
 *       867 Pedersen). A compensating pair of errors cancels in the total but
 *       not in the breakdown.
 *
 *   (B) THE ROOT IS RIGHT. The anchor wire the circuit computes is compared,
 *       byte for byte, against a root folded out of circuit with
 *       pedersen_merkle_hash() — a separate implementation (precomputed
 *       chunk-multiple tables on the Jubjub generators) that shares no code with
 *       the in-circuit Montgomery-window gadget. The in-circuit Pedersen hash is
 *       additionally diffed against pedersen_hash_bits() on the same 516 bits.
 *
 *   (C) THE SWAP IS REAL. Re-synthesizing with every position bit inverted must
 *       produce the DIFFERENT root the out-of-circuit fold produces for those
 *       inverted bits. A conditional reversal that quietly ignored its
 *       condition would pass (A) and pass (B) for one witness; it cannot pass
 *       this.
 *
 *   (D) THE WIRES ARE BOUND. Counts and values both read only the honest
 *       witness, so neither can see an UNDER-constrained gadget. Flipping the
 *       anchor wire, or any one of the 32 position bits, must make the R1CS
 *       unsatisfiable. A free position bit would let a prover choose the note's
 *       position, which is what the nullifier binds.
 *
 * The gate is params-free and hermetic (pure Jubjub/Pedersen + R1CS synthesis),
 * so it runs unconditionally with no proving key and no ~/.zcash-params.
 */

#include "test/test_core.h"

#include "sapling/circuit_merkle.h"
#include "sapling/circuit_gadgets.h"
#include "sapling/sapling_circuit.h"
#include "sapling/pedersen_hash.h"
#include "sapling/groth16_prover.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MERKLE_CHECK(name, expr) do {                  \
    printf("  %s... ", (name));                        \
    if ((expr)) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

/* Reference section boundaries for the four sections that surround this one, from
 * the pinned reference trace (the same table tests/harness/src/groth16_spend_parity.c
 * diffs against — restated here as read-only context for the scoreboard, never
 * as something this gate may adjust). */
#define REF_CUM_SECTION_16   30679u   /* end of the prefix ported before this */
#define REF_CUM_SECTION_20   32669u   /* sections 17..20 — a sibling lane */
#define REF_CUM_SECTION_21   76893u
#define REF_DELTA_SECTION_21 (REF_CUM_SECTION_21 - REF_CUM_SECTION_20)

/* ── Deterministic witness ──────────────────────────────────────────────── */

/* Every 32-byte value fed to the circuit as a field element has to be a
 * CANONICAL Fr encoding, or the in-circuit 255-bit decomposition and the
 * out-of-circuit reference read different numbers. Taking each one from a
 * Pedersen hash guarantees it: the output is a Jubjub point's x-coordinate, so
 * it is an Fr element by construction. */
static void derive_field_element(uint8_t out[32], uint8_t tag_a, uint8_t tag_b)
{
    uint8_t a[32] = {0}, b[32] = {0};
    a[0] = tag_a;
    a[1] = 0x5b;
    b[0] = tag_b;
    b[3] = 0x11;
    pedersen_merkle_hash(0, a, b, out);
}

struct merkle_fixture {
    uint8_t leaf[32];
    uint8_t path[SAPLING_MERKLE_DEPTH][32];
    bool bits[SAPLING_MERKLE_DEPTH];
};

static void build_fixture(struct merkle_fixture *f)
{
    memset(f, 0, sizeof(*f));
    derive_field_element(f->leaf, 0x01, 0x02);
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        derive_field_element(f->path[d], (uint8_t)(0x10 + d), (uint8_t)(d * 7u));
        /* A mixed pattern: both branches of the conditional swap have to be
         * exercised, and the bit must not be a function of the depth's parity
         * alone (that would make a swapped-every-level bug look identical). */
        f->bits[d] = (((d * 5u) + (d / 3u)) & 1u) != 0u;
    }
}

/* Fold the authentication path out of circuit. `bits[d]` true means the running
 * value is the RIGHT child at that depth, matching the circuit's conditional
 * reversal. */
static void reference_root(const struct merkle_fixture *f, bool invert_bits,
                           uint8_t out[32])
{
    uint8_t cur[32];
    memcpy(cur, f->leaf, 32);
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        const bool right = invert_bits ? !f->bits[d] : f->bits[d];
        uint8_t next[32];
        if (right)
            pedersen_merkle_hash(d, f->path[d], cur, next);
        else
            pedersen_merkle_hash(d, cur, f->path[d], next);
        memcpy(cur, next, 32);
    }
    memcpy(out, cur, 32);
}

/* Read a wire's assignment back as a 32-byte canonical Fr encoding. */
static bool wire_bytes(const struct constraint_system *cs, size_t var,
                       uint8_t out[32])
{
    if (var >= cs->num_vars)
        return false;
    fr_to_bytes(out, &cs->witness[var]);
    return true;
}

/* Synthesize the whole 32-level fold over `f` into a fresh constraint system.
 * Returns the constraint delta the section cost, or SIZE_MAX on failure. */
static size_t synthesize_path(struct constraint_system *cs,
                              const struct merkle_fixture *f, bool invert_bits,
                              size_t *root_out,
                              size_t position_bits[SAPLING_MERKLE_DEPTH])
{
    cs_init(cs);
    struct fr leaf_fr;
    if (!fr_from_bytes(&leaf_fr, f->leaf))
        return SIZE_MAX;
    /* The leaf enters as a bare wire, exactly as section 20 hands over the
     * randomized note commitment's x-coordinate. Allocating it costs no
     * constraint, so the measured delta below is section 21 alone. */
    const size_t leaf_var = cs_alloc_aux(cs, &leaf_fr);
    const size_t before = cs->num_constraints;

    bool bits[SAPLING_MERKLE_DEPTH];
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++)
        bits[d] = invert_bits ? !f->bits[d] : f->bits[d];

    if (!gadget_merkle_auth_path(cs, leaf_var, f->path, bits, root_out,
                                 position_bits))
        return SIZE_MAX;
    return cs->num_constraints - before;
}

/* ── Per-piece cost + value checks for ONE level ────────────────────────── */

/* Measures the four pieces of a single level in isolation and diffs the
 * in-circuit Pedersen hash against the out-of-circuit one. Returns the failure
 * count. */
static int level_breakdown_gate(const struct merkle_fixture *f)
{
    int failures = 0;
    const size_t depth = 7;              /* a depth with a non-trivial 6-bit
                                          * MerkleTree personalization */

    struct constraint_system cs;
    cs_init(&cs);

    struct fr cur_fr, path_fr;
    bool decoded = fr_from_bytes(&cur_fr, f->leaf)
                && fr_from_bytes(&path_fr, f->path[depth]);
    MERKLE_CHECK("fixture leaf and path element are canonical Fr encodings",
                 decoded);
    if (!decoded) { cs_free(&cs); return failures; }

    const size_t cur_var = cs_alloc_aux(&cs, &cur_fr);
    const size_t path_var = cs_alloc_aux(&cs, &path_fr);

    /* (i) position bit — AllocatedBit::alloc, 1 constraint. */
    size_t mark = cs.num_constraints;
    const size_t pos = gadget_alloc_boolean(&cs, true);
    MERKLE_CHECK("piece 1/4: position bit costs 1 constraint (booleanity)",
                 cs.num_constraints - mark == 1);

    /* (ii) conditional reversal — 2 constraints, and it really swaps. */
    mark = cs.num_constraints;
    size_t xl, xr;
    gadget_conditionally_reverse(&cs, cur_var, path_var, pos, &xl, &xr);
    MERKLE_CHECK("piece 2/4: conditionally_reverse costs 2 constraints",
                 cs.num_constraints - mark == 2);
    MERKLE_CHECK("conditionally_reverse with cond=1 puts the running value on "
                 "the right",
                 xl < cs.num_vars && xr < cs.num_vars
                 && fr_eq(&cs.witness[xl], &path_fr)
                 && fr_eq(&cs.witness[xr], &cur_fr));

    /* The cond=0 branch, on its own wires. */
    {
        const size_t pos0 = gadget_alloc_boolean(&cs, false);
        size_t l0, r0;
        gadget_conditionally_reverse(&cs, cur_var, path_var, pos0, &l0, &r0);
        MERKLE_CHECK("conditionally_reverse with cond=0 keeps the running value "
                     "on the left",
                     l0 < cs.num_vars && r0 < cs.num_vars
                     && fr_eq(&cs.witness[l0], &cur_fr)
                     && fr_eq(&cs.witness[r0], &path_fr));
    }

    /* (iii) two non-strict 255-bit decompositions — 256 constraints each. */
    size_t preimage[2 * MERKLE_FIELD_BITS];
    mark = cs.num_constraints;
    gadget_into_bits_le(&cs, xl, &preimage[0]);
    MERKLE_CHECK("piece 3/4: into_bits_le costs 256 constraints "
                 "(255 booleanity + 1 unpacking)",
                 cs.num_constraints - mark == 256);
    gadget_into_bits_le(&cs, xr, &preimage[MERKLE_FIELD_BITS]);
    MERKLE_CHECK("piece 3/4: both halves decompose for 512 constraints",
                 cs.num_constraints - mark == 512);

    /* The decomposition's bits must be the value's little-endian bits — a
     * reversed or big-endian order hashes a different preimage while costing
     * exactly the same. */
    {
        struct fr one_fr;
        fr_one(&one_fr);
        uint8_t xl_bytes[32], xr_bytes[32];
        bool ok = wire_bytes(&cs, xl, xl_bytes) && wire_bytes(&cs, xr, xr_bytes);
        for (size_t b = 0; b < MERKLE_FIELD_BITS && ok; b++) {
            const bool want_l = ((xl_bytes[b / 8] >> (b % 8)) & 1u) != 0u;
            const bool want_r = ((xr_bytes[b / 8] >> (b % 8)) & 1u) != 0u;
            const size_t vl = preimage[b];
            const size_t vr = preimage[MERKLE_FIELD_BITS + b];
            ok = vl < cs.num_vars && vr < cs.num_vars
              && fr_eq(&cs.witness[vl], &one_fr) == want_l
              && fr_eq(&cs.witness[vr], &one_fr) == want_r;
        }
        MERKLE_CHECK("510 preimage bits are xl||xr, little-endian", ok);
    }

    /* (iv) the Pedersen hash under MerkleTree(depth) — 867 constraints, and its
     *      x-coordinate equals the out-of-circuit hash of the same 516 bits. */
    bool pers[6];
    MERKLE_CHECK("MerkleTree(7) personalization derived",
                 gadget_pedersen_personalization_merkle_tree(depth, pers));
    mark = cs.num_constraints;
    size_t hash_x = SIZE_MAX, hash_y = SIZE_MAX;
    gadget_pedersen_hash_pers(&cs, pers, preimage, 2 * MERKLE_FIELD_BITS,
                              &hash_x, &hash_y);
    MERKLE_CHECK("piece 4/4: Pedersen hash over 510 bits costs 867 constraints",
                 cs.num_constraints - mark == 867);
    MERKLE_CHECK("Pedersen hash produced a point", hash_x != SIZE_MAX
                                                && hash_y != SIZE_MAX);

    /* Independent oracle: pedersen_hash_bits() over the SAME 516 bits. It is a
     * different implementation (precomputed chunk-multiple tables, plain Jubjub
     * arithmetic) — this is a differential, not a restatement. */
    {
        uint8_t bits[6 + 2 * MERKLE_FIELD_BITS];
        size_t n = 0;
        for (size_t i = 0; i < 6; i++)
            bits[n++] = pers[i] ? 1u : 0u;
        struct fr one_fr;
        fr_one(&one_fr);
        bool ok = true;
        for (size_t i = 0; i < 2 * MERKLE_FIELD_BITS && ok; i++) {
            const size_t v = preimage[i];
            ok = v < cs.num_vars;
            if (ok)
                bits[n++] = fr_eq(&cs.witness[v], &one_fr) ? 1u : 0u;
        }
        if (ok) {
            struct jub_point ref_pt;
            pedersen_hash_bits(bits, (int)n, &ref_pt);
            struct fr ref_x, ref_y;
            jub_get_x(&ref_x, &ref_pt);
            jub_get_y(&ref_y, &ref_pt);
            ok = hash_x < cs.num_vars && hash_y < cs.num_vars
              && fr_eq(&cs.witness[hash_x], &ref_x)
              && fr_eq(&cs.witness[hash_y], &ref_y);
        }
        MERKLE_CHECK("in-circuit Pedersen point == out-of-circuit "
                     "pedersen_hash_bits over the same 516 bits", ok);
    }

    /* Everything emitted so far must be satisfied by its own witness — the
     * coefficient-level check the counts and values cannot make. */
    {
        size_t bad = SIZE_MAX;
        MERKLE_CHECK("every constraint of the isolated level pieces is "
                     "satisfied (A*B==C)", cs_is_satisfied(&cs, &bad));
    }

    /* And one whole level through the level gadget: exactly 1382. */
    {
        struct constraint_system lcs;
        cs_init(&lcs);
        struct fr leaf_fr;
        bool ok = fr_from_bytes(&leaf_fr, f->leaf);
        const size_t lvar = ok ? cs_alloc_aux(&lcs, &leaf_fr) : 0;
        const size_t before = lcs.num_constraints;
        size_t next = SIZE_MAX, posbit = SIZE_MAX;
        ok = ok && gadget_merkle_level(&lcs, depth, lvar, f->path[depth],
                                       f->bits[depth], &next, &posbit);
        MERKLE_CHECK("one level synthesizes", ok);
        MERKLE_CHECK("one level costs exactly 1382 constraints "
                     "(1 + 2 + 512 + 867)",
                     ok && lcs.num_constraints - before
                             == MERKLE_LEVEL_CONSTRAINTS);
        /* The level's own root, against the out-of-circuit hash for that depth
         * in the order the position bit dictates. */
        uint8_t want[32], got[32];
        if (f->bits[depth])
            pedersen_merkle_hash(depth, f->path[depth], f->leaf, want);
        else
            pedersen_merkle_hash(depth, f->leaf, f->path[depth], want);
        MERKLE_CHECK("one level's output wire == pedersen_merkle_hash(depth, "
                     "left, right)",
                     ok && wire_bytes(&lcs, next, got)
                        && memcmp(got, want, 32) == 0);
        cs_free(&lcs);
    }

    cs_free(&cs);
    return failures;
}

/* ── The section-21 gate ────────────────────────────────────────────────── */

int groth16_merkle_path_gate(void);
int groth16_merkle_path_gate(void)
{
    printf("\n--- H3/S21: Sapling SPEND circuit section 21 — 32-level Merkle "
           "authentication path ---\n");
    int failures = 0;

    /* The Montgomery-form constants. Both are literal coefficients inside the
     * Pedersen gadget's constraints, and the `scale` that shipped before this
     * section landed was NOT a square root of -40964: only scale^2 reaches the
     * Montgomery addition, so single-window hashes round-tripped and every real
     * multi-window Pedersen hash was wrong. Production now DERIVES scale with
     * fr_sqrt instead of carrying a blob, so a value that is not a square root
     * can no longer ship at all — but that is only half of what has to hold, and
     * this gate covers the other half. */
    {
        struct fr mont_a, scale, want_a, sq, want_sq;
        gadget_jubjub_montgomery_params(&mont_a, &scale);
        uint8_t a_bytes[32] = {0};
        a_bytes[0] = 0x02;              /* 40962 = 0xA002, little-endian */
        a_bytes[1] = 0xA0;
        MERKLE_CHECK("Jubjub Montgomery A == 40962 == 2(a+d)/(a-d)",
                     fr_from_bytes(&want_a, a_bytes)
                     && fr_eq(&mont_a, &want_a));
        /* scale^2 == -40964 == 4/(a-d) */
        uint8_t b_bytes[32] = {0};
        b_bytes[0] = 0x04;              /* 40964 = 0xA004, little-endian */
        b_bytes[1] = 0xA0;
        fr_mul(&sq, &scale, &scale);
        bool b_ok = fr_from_bytes(&want_sq, b_bytes);
        fr_neg(&want_sq, &want_sq);
        MERKLE_CHECK("Jubjub Montgomery scale^2 == -40964 == 4/(a-d)",
                     b_ok && fr_eq(&sq, &want_sq));

        /* WHICH of the two square roots, pinned against sapling-crypto's
         * published `JubjubBls12::scale`:
         *   17814886934372412843466061268024708274627479829237077604635722030778476050649
         * little-endian below.
         *
         * The defining equation above CANNOT catch a wrong choice here, and
         * neither can anything else this suite runs. Negating scale negates every
         * Montgomery y — the window tables, every lambda, every y3 — and the
         * conversion back to Edwards divides scale*x by y, so the negation
         * cancels and both roots compute the IDENTICAL hash. Same output, same
         * constraint count, same satisfied witness. What differs is that scale
         * appears as a literal COEFFICIENT in those constraints, so the two roots
         * are two different A/B/C matrices — a different QAP, and a proof that
         * the Sapling trusted setup's verifying key rejects. fr_sqrt returns this
         * root today; a Tonelli-Shanks change that returned the other one would
         * be invisible without this line. */
        static const uint8_t REF_SCALE_LE[32] = {
            0xD9,0xB8,0x82,0xCF,0xF7,0x35,0x45,0x8F,
            0xBD,0x8A,0xA8,0x3D,0x70,0x69,0x40,0xCE,
            0xE5,0x64,0xD7,0x77,0x1E,0x34,0xDE,0x31,
            0x5E,0x64,0x62,0xE8,0x61,0xDE,0x62,0x27
        };
        struct fr want_scale;
        MERKLE_CHECK("Jubjub Montgomery scale == sapling-crypto's published "
                     "root (not the other one — same hash, different QAP)",
                     fr_from_bytes(&want_scale, REF_SCALE_LE)
                     && fr_eq(&scale, &want_scale));
    }

    struct merkle_fixture f;
    build_fixture(&f);

    /* The fixture must actually exercise both sides of the swap. */
    {
        size_t rights = 0;
        for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++)
            rights += f.bits[d] ? 1u : 0u;
        MERKLE_CHECK("fixture position bits exercise both branches",
                     rights > 0 && rights < SAPLING_MERKLE_DEPTH);
    }

    failures += level_breakdown_gate(&f);

    /* (A) The whole section, top down. */
    struct constraint_system cs;
    size_t root_var = SIZE_MAX;
    size_t position_bits[SAPLING_MERKLE_DEPTH];
    const size_t delta = synthesize_path(&cs, &f, false, &root_var,
                                         position_bits);
    MERKLE_CHECK("32-level authentication path synthesizes",
                 delta != SIZE_MAX && root_var != SIZE_MAX);
    if (delta == SIZE_MAX) {
        printf("  >> BLOCKER: section 21 synthesis failed; nothing below can "
               "be trusted\n");
        cs_free(&cs);
        printf("--- end H3/S21 gate (%d failure[s]) ---\n", failures);
        return failures + 1;
    }

    if (delta != REF_DELTA_SECTION_21)
        printf("  >> DIVERGENCE: section 21 emitted %zu constraints, reference "
               "trace delta is %u (cum %u - cum %u)\n",
               delta, REF_DELTA_SECTION_21, REF_CUM_SECTION_21,
               REF_CUM_SECTION_20);
    MERKLE_CHECK("section 21 delta == 44224 (reference trace, 32 * 1382)",
                 delta == REF_DELTA_SECTION_21);
    MERKLE_CHECK("section 21 delta == MERKLE_PATH_CONSTRAINTS "
                 "(the documented cost)",
                 delta == (size_t)MERKLE_PATH_CONSTRAINTS);

    /* (B) THE ROOT IS RIGHT — the assertion a constraint count cannot make. */
    uint8_t want_root[32], got_root[32];
    reference_root(&f, false, want_root);
    const bool root_read = wire_bytes(&cs, root_var, got_root);
    if (root_read && memcmp(got_root, want_root, 32) != 0)
        printf("  >> DIVERGENCE: in-circuit anchor != out-of-circuit fold "
               "(first differing byte %d)\n",
               (int)(memcmp(got_root, want_root, 1) != 0 ? 0 : 1));
    MERKLE_CHECK("in-circuit anchor wire == out-of-circuit "
                 "pedersen_merkle_hash fold over the same path",
                 root_read && memcmp(got_root, want_root, 32) == 0);

    /* Position bits carry the witnessed pattern, in depth order. */
    {
        struct fr one_fr;
        fr_one(&one_fr);
        bool ok = true;
        for (size_t d = 0; d < SAPLING_MERKLE_DEPTH && ok; d++)
            ok = position_bits[d] < cs.num_vars
              && fr_eq(&cs.witness[position_bits[d]], &one_fr) == f.bits[d];
        MERKLE_CHECK("32 position-bit wires == the witnessed path bits, "
                     "deepest first", ok);
    }

    /* Coefficient-level check over the whole section. */
    {
        size_t bad = SIZE_MAX;
        const bool sat = cs_is_satisfied(&cs, &bad);
        if (!sat)
            printf("  >> DIVERGENCE: R1CS UNSATISFIED at constraint %zu of "
                   "%zu\n", bad, cs.num_constraints);
        char label[128];
        snprintf(label, sizeof(label),
                 "all %zu emitted constraints satisfied by the honest witness "
                 "(A*B==C)", cs.num_constraints);
        MERKLE_CHECK(label, sat);
    }

    /* (C) THE SWAP IS REAL. Invert every position bit; the circuit must land on
     *     the different root the out-of-circuit fold gives for those bits. A
     *     conditional reversal that ignored its condition passes (A) and (B). */
    {
        uint8_t want_inv[32], got_inv[32];
        reference_root(&f, true, want_inv);
        MERKLE_CHECK("inverting the position bits changes the reference root "
                     "(the fixture is swap-sensitive)",
                     memcmp(want_inv, want_root, 32) != 0);

        struct constraint_system cs_inv;
        size_t root_inv = SIZE_MAX;
        size_t pos_inv[SAPLING_MERKLE_DEPTH];
        const size_t d_inv = synthesize_path(&cs_inv, &f, true, &root_inv,
                                             pos_inv);
        MERKLE_CHECK("inverted-bit synthesis costs the same 44224 constraints "
                     "(shape is witness-invariant)",
                     d_inv == REF_DELTA_SECTION_21);
        MERKLE_CHECK("inverted-bit anchor == out-of-circuit fold with the "
                     "swaps reversed",
                     d_inv != SIZE_MAX && wire_bytes(&cs_inv, root_inv, got_inv)
                     && memcmp(got_inv, want_inv, 32) == 0);
        cs_free(&cs_inv);
    }

    /* (D) THE WIRES ARE BOUND. */
    {
        struct fr one_fr, zero_fr;
        fr_one(&one_fr);
        fr_zero(&zero_fr);
        size_t ignored = SIZE_MAX;

        /* Sanity first, or "flip detected" would be vacuous. */
        MERKLE_CHECK("honest witness satisfies the section before any mutation",
                     cs_is_satisfied(&cs, &ignored));

        /* The anchor. Perturbing it must break the Pedersen constraint that
         * produced it — otherwise a prover could pick the anchor, which is the
         * public input the whole section exists to justify. */
        {
            struct fr saved = cs.witness[root_var];
            struct fr bumped;
            fr_add(&bumped, &saved, &one_fr);
            cs.witness[root_var] = bumped;
            const bool detected = !cs_is_satisfied(&cs, &ignored);
            cs.witness[root_var] = saved;
            MERKLE_CHECK("the anchor wire is bound (perturbing it breaks the "
                         "R1CS)", detected);
        }

        /* Every position bit. Flipping 0<->1 keeps booleanity satisfied, so a
         * detection here is the swap constraints doing their job. */
        size_t tried = 0, detected = 0;
        for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
            const size_t v = position_bits[d];
            if (v >= cs.num_vars)
                continue;
            struct fr saved = cs.witness[v];
            cs.witness[v] = fr_eq(&saved, &one_fr) ? zero_fr : one_fr;
            tried++;
            if (!cs_is_satisfied(&cs, &ignored))
                detected++;
            cs.witness[v] = saved;
        }
        printf("  position-bit flips detected: %zu/%zu\n", detected, tried);
        MERKLE_CHECK("every position bit is bound (a flipped bit breaks the "
                     "R1CS)",
                     tried == SAPLING_MERKLE_DEPTH
                     && detected == SAPLING_MERKLE_DEPTH);
        MERKLE_CHECK("witness restored after the mutation probe",
                     cs_is_satisfied(&cs, &ignored));
    }

    /* Determinism — identical inputs, byte-identical witness. */
    {
        struct constraint_system cs2;
        size_t root2 = SIZE_MAX;
        size_t pos2[SAPLING_MERKLE_DEPTH];
        const size_t d2 = synthesize_path(&cs2, &f, false, &root2, pos2);
        const bool det = d2 == delta && cs2.num_vars == cs.num_vars
            && cs2.num_constraints == cs.num_constraints
            && root2 == root_var
            && memcmp(cs.witness, cs2.witness,
                      cs.num_vars * sizeof(struct fr)) == 0;
        MERKLE_CHECK("section 21 synthesis is deterministic (byte-identical "
                     "witness)", det);
        cs_free(&cs2);
    }

    /* Honest scoreboard. Section 21 sits AFTER sections 17..20, which are a
     * different lane's work; until they land the spend circuit's cumulative
     * count cannot reach the reference's 76893 no matter how correct this
     * section is, and this gate says so rather than implying the gap away. */
    struct spend_prover_native_status st;
    sapling_spend_prover_native_status(&st);
    printf("  section 21 measured delta: %zu constraints "
           "(reference %u = cum %u - cum %u)\n",
           delta, REF_DELTA_SECTION_21, REF_CUM_SECTION_21,
           REF_CUM_SECTION_20);
    printf("  spend circuit today: %zu/%zu sections, %zu/%zu constraints "
           "synthesized in Spend::synthesize order; next blocker '%s'\n",
           st.sections_ported, st.sections_total, st.constraints_ported,
           st.constraints_total, st.next_blocker);
    if (st.constraints_ported + delta < REF_CUM_SECTION_21)
        printf("  section 21 is NOT yet counted in that prefix: the spend "
               "circuit's cumulative can only reach %u once sections 17..20 "
               "(+%u constraints) land — %zu + %u + %zu = %zu. Section 21's "
               "own cost is proven here, out of line, against the same "
               "reference delta.\n",
               REF_CUM_SECTION_21, REF_CUM_SECTION_20 - REF_CUM_SECTION_16,
               st.constraints_ported, REF_CUM_SECTION_20 - REF_CUM_SECTION_16,
               delta,
               st.constraints_ported
                   + (size_t)(REF_CUM_SECTION_20 - REF_CUM_SECTION_16) + delta);

    cs_free(&cs);
    printf("--- end H3/S21 gate (%d failure[s]) ---\n", failures);
    return failures;
}
