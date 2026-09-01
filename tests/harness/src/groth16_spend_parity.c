/* Sapling SPEND-circuit standing differential parity oracle (test-only, H4 lane).
 *
 * Portions interoperate with librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Fixed
 * externally-derived reference bytes are checked in; no Rust code is fetched,
 * built or linked.
 *
 * WHAT THIS IS
 * ------------
 * The C-must-beat-Rust ratchet requires a differential parity oracle before any
 * native-crypto claim. The H2 oracle (groth16_spend_oracle.c) proves the native
 * key-derivation / commitment / nullifier building blocks match librustzcash for
 * ONE fixed KAT witness. The H3 shape gate (test_groth16_selfverify.c) pins the
 * ported prefix's per-section constraint boundaries for that SAME single witness.
 *
 * This oracle is the STANDING safety net that generalizes both: over a CORPUS of
 * deterministic spend witnesses, it re-runs the native C23 spend synthesis and
 * asserts, for every witness:
 *
 *   (A) SECTION-BOUNDARY PARITY (auto-tightening). Each recorded section's
 *       cumulative constraint count equals the pinned REFERENCE trace boundary
 *       (the full 28-section table from commit 06da3b9..., cross-checked 3x in
 *       the salvage plan). The oracle drives its assertions off the reference
 *       table and compares only the sections the native circuit ACTUALLY
 *       recorded (n_sections). So when the H3 port advances from 7 sections to
 *       8, 9, ... this oracle automatically validates the new section's boundary
 *       against REF_SECTIONS[i] with NO edit here — it tightens itself.
 *
 *   (B) STRUCTURAL INVARIANCE. An R1CS circuit's shape must not depend on the
 *       witness values — a witness-dependent constraint/var/input count is an
 *       unsound circuit. Every corpus witness must produce a byte-identical
 *       section shape (constraints/vars/inputs per section) to witness 0. This
 *       is a class of divergence the single-witness H2/H3 gates cannot see.
 *
 *   (C) PER-WIRE VALUE PARITY vs the fixed external KAT where available. The
 *       in-circuit nk wire ([nsk] ProofGenerationKeyGenerator, section 7) is
 *       checked against ground truth for the pinned witness. The in-circuit ak
 *       (section 1) and rk (section 4) wires are cross-checked against native
 *       scalar derivations for self-consistency.
 *
 *   (D) DETERMINISM. Re-synthesizing an identical witness yields a byte-identical
 *       witness vector.
 *
 *   (E) R1CS SATISFACTION — the coefficient-level check. (A) reads constraint
 *       COUNTS and (C) reads three wire VALUES; neither can see a wrong
 *       coefficient inside an otherwise correctly-shaped constraint. So every
 *       emitted constraint is evaluated against the honest witness and asserted
 *       to satisfy A*B==C (bellman's TestConstraintSystem::which_is_unsatisfied).
 *       Without this, "proven at parity" would mean only that the right NUMBER
 *       of constraints exist — a circuit whose own witness does not satisfy it
 *       yields proofs the network rejects, and counts alone cannot detect that.
 *
 * On the FIRST divergence in any category the oracle prints the offending
 * (witness index, section name, expected vs actual) — it flags, never hides.
 *
 * The oracle is params-free and hermetic (pure Jubjub/blake2s/Pedersen crypto +
 * R1CS synthesis); it needs no ~/.zcash-params and no proving key, so it gates
 * unconditionally. It proves parity ONLY over the sections currently ported; the
 * honest scoreboard (ported prefix vs the 98777-constraint target) is printed and
 * documented in docs/work/GROTH16-SPEND-PARITY.md.
 */

#include "test/test_core.h"
#include "test/groth16_spend_oracle_kat.h"

#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/pedersen_hash.h"
#include "sapling/fr.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Reference nk for one corpus witness.
 *
 * The checked-in KAT supplies the reference nk for the one witness whose nsk
 * is pinned. Remaining corpus entries report no external reference rather than
 * comparing native code against itself, which would be circular. */
static bool parity_reference_nk(const uint8_t *nsk, uint8_t out[32])
{
#if SPEND_ORACLE_KAT_BAKED
    if (memcmp(nsk, SPEND_ORACLE_KAT_NSK, 32) == 0) {
        memcpy(out, SPEND_ORACLE_KAT_NK, 32);
        return true;
    }
#endif
    (void)nsk; (void)out;
    return false;
}

/* ── Pinned reference section-boundary table ────────────────────────────────
 * Cumulative num_constraints after each of bellman's 28 Spend::synthesize
 * sections, from the reference trace at commit 06da3b9ac8f278e5d4ae13088cf0a4c
 * 03d2c13f5 (num_constraints=98777, num_aux=98638, num_inputs=8 = 7 public +
 * ONE). Boundaries verified 3x against reference/groth16-traces/spend_circuit.
 * trace in the salvage plan. This table is the AUTHORITY the oracle diffs
 * against; the native port is correct for a prefix iff its recorded per-section
 * cumulative counts equal this table entry-for-entry over that prefix. */
static const struct ref_section {
    const char *name;
    size_t cum_constraints;
} REF_SECTIONS[28] = {
    { "1:ak witness+on-curve+not-small-order",   20 },
    { "2:ar bits",                              272 },
    { "3:randomization of signing key",        1022 },
    { "4:computation of rk",                   1028 },
    { "5:rk inputize",                         1030 },
    { "6:nsk bits",                            1282 },
    { "7:computation of nk",                   2032 },
    { "8:representation of ak",                2808 },
    { "9:representation of nk",                3584 },
    { "10:computation of ivk",               24590 },
    { "11:witness g_d",                      24594 },
    { "12:g_d not small order",              24610 },
    { "13:compute pk_d",                     27862 },
    { "14:value commitment",                 29127 },
    { "15:representation of g_d",            29903 },
    { "16:representation of pk_d",           30679 },
    { "17:note content hash",               31661 },
    { "18:rcm bits",                        31913 },
    { "19:commitment randomness",           32663 },
    { "20:randomization of note commitment", 32669 },
    { "21:merkle tree hash 0..31",          76893 },
    { "22:conditionally enforce correct root", 76894 },
    { "23:anchor inputize",                 76895 },
    { "24:g^position",                      76987 },
    { "25:faerie gold prevention",          76993 },
    { "26:representation of rho",            77769 },
    { "27:nf computation",                  98775 },
    { "28:pack nullifier",                  98777 },
};
#define REF_TOTAL_CONSTRAINTS 98777
#define REF_TOTAL_AUX         98638
#define REF_TOTAL_INPUTS          8 /* 7 public + ONE */
#define REF_NUM_SECTIONS         28

/* Deterministic corpus. Index 0 is the pinned H2 KAT witness (ties the nk wire
 * to the checked-in librustzcash reference vector); 1..N-1 are distinct
 * canonical witnesses (small Fs scalars, guaranteed < 2^252 so the in-circuit
 * 252-bit decomposition and the reference full reduction agree). */
#define CORPUS_N 6

struct parity_witness {
    struct sapling_spend_witness wit;
    struct sapling_spend_inputs  pub;
    bool ok;
};

static void build_corpus_witness(struct parity_witness *pw, unsigned idx)
{
    memset(pw, 0, sizeof(*pw));
    struct sapling_spend_witness *w = &pw->wit;

    uint8_t ask[32];
    memset(ask, 0, sizeof(ask));
    if (idx == 0) {
        memcpy(ask, SPEND_ORACLE_KAT_ASK, 32);
        memcpy(w->nsk, SPEND_ORACLE_KAT_NSK, 32);
        w->ar[0] = 0x03;
        w->rcv[0] = 0x71;
        w->rcv[1] = 0x0d;
    } else {
        /* Distinct, canonical, small scalars — deterministic per index. */
        ask[0] = (uint8_t)(0x11 + idx);
        ask[1] = 0x22;
        ask[2] = (uint8_t)(idx * 5u);
        w->nsk[0] = (uint8_t)(idx * 7u + 1u);
        w->nsk[1] = (uint8_t)idx;
        w->nsk[2] = 0x5A;
        w->ar[0]  = (uint8_t)(idx + 1u);
        w->ar[1]  = (uint8_t)(idx * 3u);
        w->rcv[0] = (uint8_t)(idx * 11u + 3u);
        w->rcv[1] = (uint8_t)(idx * 2u);
    }
    /* Note commitment randomness (sections 18/19/20). Kept small so it is a
     * canonical Fs scalar: the in-circuit decomposition keeps 252 bits and the
     * out-of-circuit jub_scalar_mul reads all 256, so a scalar with a bit above
     * 252 set would make the two disagree for a reason that is not a bug. A
     * zero rcm would synthesize but select the identity slot in every window,
     * exercising none of section 19's arithmetic. */
    w->rcm[0] = (uint8_t)(idx * 13u + 0x5cu);
    w->rcm[1] = (uint8_t)(idx * 3u + 0x23u);

    /* The authentication path section 21 folds cm.x up (32 siblings + 32
     * position bits). Each sibling is taken from a Pedersen Merkle hash so it is
     * a canonical Fr encoding by construction — the in-circuit 255-bit
     * decomposition and the out-of-circuit reference must read the same number.
     * The position bits deliberately are NOT a function of depth parity alone;
     * a swapped-every-level bug would be invisible against that pattern. */
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t a[32] = {0}, b[32] = {0};
        a[0] = (uint8_t)(0x10u + d);
        a[1] = (uint8_t)(0x5bu + idx);
        b[0] = (uint8_t)(d * 7u);
        b[3] = 0x11;
        pedersen_merkle_hash(0, a, b, w->auth_path[d]);
        w->auth_path_bits[d] = ((((d * 5u) + (d / 3u)) ^ idx) & 1u) != 0u;
    }

    /* Section 11 witnesses g_d = GH("Zcash_gd", d) and section 12 asserts it is
     * not small order, so the diversifier has to be one that actually hashes to
     * a point — group_hash misses on roughly half of them. Deterministic scan
     * from d = 0, per witness. */
    bool have_d = false;
    for (unsigned i = 0; i < 256 && !have_d; i++) {
        memset(w->diversifier, 0, sizeof(w->diversifier));
        w->diversifier[0] = (uint8_t)((i + idx) & 0xFF);
        have_d = sapling_check_diversifier(w->diversifier);
    }
    if (!have_d)
        return;                         /* pw->ok stays false */

    uint8_t ak[32];
    sapling_ask_to_ak(ask, ak);
    memcpy(w->ak, ak, 32);
    memcpy(w->pk_d, ak, 32);           /* unused by Spend: pk_d is DERIVED in 13 */
    w->value = UINT64_C(54321) + idx;

    uint8_t rk[32];
    if (!sapling_compute_rk(ak, w->ar, rk))
        return;                         /* pw->ok stays false */
    memcpy(pw->pub.rk, rk, 32);
    /* cv is bound to public inputs 3/4 by section 14, so the real value
     * commitment is the only cv an honest witness can carry. */
    if (!sapling_value_commit(w->value, w->rcv, pw->pub.cv))
        return;                         /* pw->ok stays false */
    /* Sections 22 and 28 bind the anchor and the packed nullifier too, so the
     * whole public-input vector has to be the honest one or the system is
     * unsatisfiable by construction. */
    if (!sapling_spend_derive_public(w, &pw->pub))
        return;                         /* pw->ok stays false */
    pw->ok = true;
}

/* Decode a compressed Jubjub point to (x,y) Fr coords. */
static bool decode_xy(const uint8_t comp[32], struct fr *x, struct fr *y)
{
    struct jub_point p;
    if (!jub_from_bytes(&p, comp))
        return false;
    jub_get_x(x, &p);
    jub_get_y(y, &p);
    return true;
}

/* Reference section-17 note-content hash: the table-driven Pedersen hash
 * (core/modules/sapling/src/pedersen_hash.c — Edwards coordinates, precomputed chunk
 * multiples) over the 6 NoteCommitment personalization bits plus
 * value(64) || repr(g_d) || repr(pk_d). The circuit synthesizes the same point
 * through 194 Montgomery-coordinate window lookups, four Montgomery->Edwards
 * conversions and three Edwards additions, so agreement is a differential
 * between two genuinely different algorithms, not a restatement.
 * Section 20's reference is the PRODUCTION sapling_note_commitment_point(). */
static void reference_note_content_hash(uint64_t value,
                                        const uint8_t gd[32],
                                        const uint8_t pkd[32],
                                        struct jub_point *hash_out)
{
    uint8_t contents[72];
    for (size_t i = 0; i < 8; i++)
        contents[i] = (uint8_t)(value >> (i * 8));
    memcpy(contents + 8, gd, 32);
    memcpy(contents + 40, pkd, 32);

    uint8_t bits[6 + 576];
    size_t n = 0;
    for (size_t i = 0; i < 6; i++)
        bits[n++] = 1;              /* Personalization::NoteCommitment == 63 */
    for (size_t i = 0; i < 576; i++)
        bits[n++] = (uint8_t)((contents[i / 8] >> (i % 8)) & 1u);

    pedersen_hash_bits(bits, (int)n, hash_out);
}

/* Reference section-21 anchor: fold the SAME witnessed authentication path over
 * the SAME leaf with the out-of-circuit pedersen_merkle_hash. `leaf` is the note
 * commitment's x-coordinate — sections 17..20's own output, which is the point
 * of doing this in one pass: it checks the value the circuit committed to is the
 * value that entered the tree, not merely that each half is internally right. */
static void reference_anchor(const uint8_t leaf[32],
                             const uint8_t path[SAPLING_MERKLE_DEPTH][32],
                             const bool bits[SAPLING_MERKLE_DEPTH],
                             uint8_t out[32])
{
    uint8_t cur[32];
    memcpy(cur, leaf, 32);
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t next[32];
        if (bits[d])
            pedersen_merkle_hash(d, path[d], cur, next);
        else
            pedersen_merkle_hash(d, cur, path[d], next);
        memcpy(cur, next, 32);
    }
    memcpy(out, cur, 32);
}

#define PARITY_CHECK(name, expr) do {                 \
    printf("  %s... ", (name));                        \
    if ((expr)) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

/* Public entry point: standing differential parity oracle for the Sapling spend
 * circuit. Returns the number of failures (0 == green). Non-skippable and
 * params-free. */
int groth16_spend_parity_oracle(void);
int groth16_spend_parity_oracle(void)
{
    printf("\n--- H4: Sapling SPEND standing differential parity oracle ---\n");
    int failures = 0;

    /* Reference table self-consistency (guards a typo in the pinned boundaries;
     * they must be strictly increasing and terminate at the trace total). */
    bool ref_monotone = true;
    for (size_t i = 1; i < REF_NUM_SECTIONS; i++)
        if (REF_SECTIONS[i].cum_constraints <= REF_SECTIONS[i - 1].cum_constraints)
            ref_monotone = false;
    PARITY_CHECK("reference section table is strictly increasing", ref_monotone);
    PARITY_CHECK("reference table terminates at trace total (98777)",
                 REF_SECTIONS[REF_NUM_SECTIONS - 1].cum_constraints
                     == REF_TOTAL_CONSTRAINTS);

    /* Canonical shape recorded from witness 0, used for the invariance check. */
    struct spend_section_shape shape0[REF_NUM_SECTIONS];
    size_t nsec0 = 0;
    bool have_shape0 = false;

    /* Track the first divergence for a single, precise flag line. */
    bool flagged = false;
    size_t max_ported = 0;

    for (unsigned c = 0; c < CORPUS_N; c++) {
        struct parity_witness pw;
        build_corpus_witness(&pw, c);
        char label[160];

        snprintf(label, sizeof(label),
                 "corpus[%u]: witness constructed (valid rk/ak points)", c);
        PARITY_CHECK(label, pw.ok);
        if (!pw.ok)
            continue;

        struct spend_section_shape sections[REF_NUM_SECTIONS];
        size_t nsec = 0;
        struct spend_wire_probe probe;
        struct constraint_system cs;
        cs_init(&cs);
        bool synth = sapling_spend_synthesize_traced(
            &cs, &pw.wit, &pw.pub, sections, REF_NUM_SECTIONS, &nsec, &probe);

        snprintf(label, sizeof(label),
                 "corpus[%u]: traced synthesis succeeded", c);
        PARITY_CHECK(label, synth);
        if (!synth) { cs_free(&cs); continue; }

        if (nsec > max_ported)
            max_ported = nsec;

        /* (A) Section-boundary parity vs the reference — auto-tightening: only
         *     the `nsec` sections actually recorded are diffed, so the coverage
         *     grows automatically as the port advances. */
        bool boundaries_ok = (nsec <= REF_NUM_SECTIONS);
        for (size_t i = 0; i < nsec && i < REF_NUM_SECTIONS; i++) {
            if (sections[i].num_constraints != REF_SECTIONS[i].cum_constraints) {
                boundaries_ok = false;
                if (!flagged) {
                    flagged = true;
                    printf("  >> FIRST DIVERGENCE: corpus[%u] section '%s': "
                           "native cum_constraints=%zu, reference=%zu\n",
                           c, REF_SECTIONS[i].name,
                           sections[i].num_constraints,
                           REF_SECTIONS[i].cum_constraints);
                }
            }
        }
        snprintf(label, sizeof(label),
                 "corpus[%u]: %zu section boundaries == reference trace",
                 c, nsec);
        PARITY_CHECK(label, boundaries_ok);

        /* (B) Structural invariance across the corpus. */
        if (!have_shape0) {
            memcpy(shape0, sections, nsec * sizeof(sections[0]));
            nsec0 = nsec;
            have_shape0 = true;
        } else {
            bool shape_same = (nsec == nsec0);
            for (size_t i = 0; i < nsec && i < nsec0 && shape_same; i++)
                shape_same = sections[i].num_constraints == shape0[i].num_constraints
                          && sections[i].num_vars       == shape0[i].num_vars
                          && sections[i].num_inputs     == shape0[i].num_inputs;
            if (!shape_same && !flagged) {
                flagged = true;
                printf("  >> FIRST DIVERGENCE: corpus[%u] R1CS shape differs "
                       "from corpus[0] (witness-dependent circuit)\n", c);
            }
            snprintf(label, sizeof(label),
                     "corpus[%u]: R1CS shape witness-invariant vs corpus[0]", c);
            PARITY_CHECK(label, shape_same);
        }

        /* (C) Per-wire value parity. */
        /* nk wire vs the librustzcash reference (the differential). */
        uint8_t nk_ref[32];
        const bool have_nk_ref = parity_reference_nk(pw.wit.nsk, nk_ref);
        uint8_t nk_native[32];
        sapling_nsk_to_nk(pw.wit.nsk, nk_native);
        if (!have_nk_ref) {
            printf("  corpus[%u]: external nk reference unavailable for this "
                   "non-KAT witness; native circuit/value/satisfaction gates "
                   "still run\n", c);
        } else {
            snprintf(label, sizeof(label),
                     "corpus[%u]: native nsk_to_nk == librustzcash reference", c);
            PARITY_CHECK(label, memcmp(nk_native, nk_ref, 32) == 0);

            struct fr nkx, nky;
            bool nk_dec = decode_xy(nk_ref, &nkx, &nky);
            bool nk_wire_ok = nk_dec
                && probe.nk_x < cs.num_vars && probe.nk_y < cs.num_vars
                && fr_eq(&cs.witness[probe.nk_x], &nkx)
                && fr_eq(&cs.witness[probe.nk_y], &nky);
            if (!nk_wire_ok && !flagged) {
                flagged = true;
                printf("  >> FIRST DIVERGENCE: corpus[%u] in-circuit nk wire != "
                       "librustzcash [nsk] ProofGenerationKeyGenerator\n", c);
            }
            snprintf(label, sizeof(label),
                     "corpus[%u]: in-circuit nk wire == reference nk (section 7)",
                     c);
            PARITY_CHECK(label, nk_wire_ok);
        }

        /* ak wire vs the decoded witness ak (self-consistent, section 1). */
        struct fr akx, aky;
        bool ak_dec = decode_xy(pw.wit.ak, &akx, &aky);
        bool ak_wire_ok = ak_dec
            && probe.ak_x < cs.num_vars && probe.ak_y < cs.num_vars
            && fr_eq(&cs.witness[probe.ak_x], &akx)
            && fr_eq(&cs.witness[probe.ak_y], &aky);
        snprintf(label, sizeof(label),
                 "corpus[%u]: in-circuit ak wire == witness ak (section 1)", c);
        PARITY_CHECK(label, ak_wire_ok);

        /* rk wire vs the native scalar rk (self-consistent, section 4). */
        struct fr rkx, rky;
        bool rk_dec = decode_xy(pw.pub.rk, &rkx, &rky);
        bool rk_wire_ok = rk_dec
            && probe.rk_x < cs.num_vars && probe.rk_y < cs.num_vars
            && fr_eq(&cs.witness[probe.rk_x], &rkx)
            && fr_eq(&cs.witness[probe.rk_y], &rky);
        snprintf(label, sizeof(label),
                 "corpus[%u]: in-circuit rk wire == ak + [ar]G (section 4)", c);
        PARITY_CHECK(label, rk_wire_ok);

        /* Sections 11/13/14/17/20: the note-content points, per witness. pk_d is the
         * output of the circuit's only VARIABLE-base multiplication, so it is
         * the one section whose gadget the fixed-base checks above cannot
         * exercise; cv is additionally the first public input past rk that the
         * circuit constrains. Reference values come from the independent scalar
         * implementations (group_hash / ivk_to_pkd / value_commit), not from the
         * circuit — so this is a differential, not a restatement. */
        uint8_t nk_for_ivk[32], ivk_ref[32];
        sapling_nsk_to_nk(pw.wit.nsk, nk_for_ivk);
        sapling_crh_ivk(pw.wit.ak, nk_for_ivk, ivk_ref);

        struct jub_point gd_ref_pt;
        uint8_t gd_ref[32], pkd_ref[32], cv_ref[32];
        bool refs_ok = sapling_diversifier_to_gd(&gd_ref_pt, pw.wit.diversifier);
        if (refs_ok) {
            jub_to_bytes(gd_ref, &gd_ref_pt);
            refs_ok = sapling_ivk_to_pkd(ivk_ref, pw.wit.diversifier, pkd_ref)
                   && sapling_value_commit(pw.wit.value, pw.wit.rcv, cv_ref);
        }

        /* Sections 17/20: the note-content Pedersen hash and the randomized
         * note commitment, from the out-of-circuit table-driven Pedersen hash +
         * plain Jubjub scalar mul. Compressed here so they join the same
         * table-driven comparison as the points above. */
        uint8_t note_hash_ref[32] = {0}, cm_ref[32] = {0};
        struct jub_point cm_ref_pt;
        if (refs_ok) {
            struct jub_point hash_pt;
            reference_note_content_hash(pw.wit.value, gd_ref, pkd_ref,
                                        &hash_pt);
            jub_to_bytes(note_hash_ref, &hash_pt);
            refs_ok = sapling_note_commitment_point(pw.wit.diversifier, pkd_ref,
                                                    pw.wit.value, pw.wit.rcm,
                                                    &cm_ref_pt);
            if (refs_ok)
                jub_to_bytes(cm_ref, &cm_ref_pt);
        }

        const struct { const char *what; const uint8_t *want;
                       size_t x_var, y_var; } note_points[5] = {
            { "g_d wire == GH(\"Zcash_gd\", d) (section 11)",
              gd_ref,  probe.gd_x,  probe.gd_y },
            { "pk_d wire == reference [ivk] g_d (section 13)",
              pkd_ref, probe.pkd_x, probe.pkd_y },
            { "cv wire == [value]G_v + [rcv]G_rcv (section 14)",
              cv_ref,  probe.cv_x,  probe.cv_y },
            { "note hash wire == PedersenHash(NoteCommitment, note) (section 17)",
              note_hash_ref, probe.note_hash_x, probe.note_hash_y },
            { "cm wire == note hash + [rcm] G_rcm (section 20)",
              cm_ref,  probe.cm_x,  probe.cm_y },
        };
        for (size_t np = 0; np < 5; np++) {
            struct fr wx, wy;
            bool ok = refs_ok && decode_xy(note_points[np].want, &wx, &wy)
                   && note_points[np].x_var < cs.num_vars
                   && note_points[np].y_var < cs.num_vars
                   && fr_eq(&cs.witness[note_points[np].x_var], &wx)
                   && fr_eq(&cs.witness[note_points[np].y_var], &wy);
            if (!ok && !flagged) {
                flagged = true;
                printf("  >> FIRST DIVERGENCE: corpus[%u] %s\n",
                       c, note_points[np].what);
            }
            snprintf(label, sizeof(label), "corpus[%u]: in-circuit %s",
                     c, note_points[np].what);
            PARITY_CHECK(label, ok);
        }

        /* Section 20, tied to the PRODUCTION note-commitment API rather than to
         * a reference this file assembled: sapling_compute_cm() is what the
         * wallet and the output-proof path commit with, and the protocol's `cmu`
         * is exactly this x-coordinate. If the circuit's cm.x wire and
         * sapling_compute_cm() ever disagree, a spend proof would be over a note
         * the tree does not contain. */
        uint8_t cm_api[32];
        bool cm_api_ok = refs_ok
               && sapling_compute_cm(pw.wit.diversifier, pkd_ref,
                                     pw.wit.value, pw.wit.rcm, cm_api);
        {
            struct fr cm_api_fr;
            bool ok = cm_api_ok
                   && fr_from_bytes(&cm_api_fr, cm_api)
                   && probe.cm_x < cs.num_vars
                   && fr_eq(&cs.witness[probe.cm_x], &cm_api_fr);
            if (!ok && !flagged) {
                flagged = true;
                printf("  >> FIRST DIVERGENCE: corpus[%u] in-circuit cm.x wire "
                       "!= sapling_compute_cm() (section 20)\n", c);
            }
            snprintf(label, sizeof(label),
                     "corpus[%u]: in-circuit cm.x == sapling_compute_cm() "
                     "(section 20)", c);
            PARITY_CHECK(label, ok);
        }

        /* Sections 17..21 END TO END, the assertion neither half can make alone:
         * fold the witnessed authentication path out of circuit starting from
         * sapling_compute_cm()'s OWN leaf, and require the circuit's anchor wire
         * to match. Section 20 proven correct and section 21 proven correct do
         * not between them prove the commitment section 20 computed is what
         * section 21 folded — an off-by-one in the handover would leave both
         * halves green. This is what opening that seam has to buy. */
        {
            uint8_t anchor_ref[32];
            struct fr anchor_ref_fr;
            bool ok = cm_api_ok;
            if (ok) {
                reference_anchor(cm_api, pw.wit.auth_path,
                                 pw.wit.auth_path_bits, anchor_ref);
                ok = fr_from_bytes(&anchor_ref_fr, anchor_ref)
                  && probe.anchor < cs.num_vars
                  && fr_eq(&cs.witness[probe.anchor], &anchor_ref_fr);
            }
            if (!ok && !flagged) {
                flagged = true;
                printf("  >> FIRST DIVERGENCE: corpus[%u] in-circuit anchor "
                       "!= out-of-circuit fold over sapling_compute_cm()'s cm.x "
                       "(sections 17..21 handover)\n", c);
            }
            snprintf(label, sizeof(label),
                     "corpus[%u]: in-circuit anchor == out-of-circuit fold over "
                     "the circuit's own cm.x (sections 17..21)", c);
            PARITY_CHECK(label, ok);
        }

        /* Sections 8/9: the EdwardsPoint::repr bit wires. Jubjub's compressed
         * encoding is y with x's low bit in the top bit, so repr's 256 bits
         * (y[0..255] then x[0]) are exactly the bits of the point's 32-byte
         * compressed encoding, LSB first. For nk that encoding is
         * librustzcash's own output — so this is a genuine per-witness
         * differential on the newly-ported sections, not a count. */
        bool ak_repr_ok = true, nk_repr_ok = true;
        for (size_t b = 0; b < 256; b++) {
            bool want_ak = (pw.wit.ak[b / 8] >> (b % 8)) & 1;
            bool want_nk = (nk_ref[b / 8] >> (b % 8)) & 1;
            size_t vak = probe.ak_repr[b], vnk = probe.nk_repr[b];
            struct fr one_fr;
            fr_one(&one_fr);
            if (vak >= cs.num_vars
                || fr_eq(&cs.witness[vak], &one_fr) != want_ak)
                ak_repr_ok = false;
            if (vnk >= cs.num_vars
                || fr_eq(&cs.witness[vnk], &one_fr) != want_nk)
                nk_repr_ok = false;
        }
        if (have_nk_ref && !nk_repr_ok && !flagged) {
            flagged = true;
            printf("  >> FIRST DIVERGENCE: corpus[%u] in-circuit repr(nk) bits "
                   "!= librustzcash compressed nk encoding\n", c);
        }
        snprintf(label, sizeof(label),
                 "corpus[%u]: repr(ak) 256 bits == compressed ak (section 8)", c);
        PARITY_CHECK(label, ak_repr_ok);
        /* repr(nk) is a differential against the reference encoding, so it
         * can only run where the reference exists: linked librustzcash, or
         * the baked KAT witness. Asserting it without one compares against
         * zeroed bytes and fails for a reason that has nothing to do with
         * the circuit. Section 8's repr(ak) needs no reference — ak comes
         * from the witness — so it stays unconditional. */
        if (!have_nk_ref) {
            printf("  corpus[%u]: external repr(nk) reference unavailable for "
                   "this non-KAT witness; native representation gates still "
                   "run\n", c);
        } else {
            snprintf(label, sizeof(label),
                     "corpus[%u]: repr(nk) 256 bits == librustzcash compressed "
                     "nk (section 9)", c);
            PARITY_CHECK(label, nk_repr_ok);
        }

        /* (E) R1CS SATISFACTION — the coefficient-level check. (A) compares
         *     constraint COUNTS and (C) probes three wire VALUES; neither can
         *     see a wrong coefficient inside an otherwise correctly-shaped
         *     constraint. A one-bit error in a constraint's A/B/C linear
         *     combination leaves counts and probed wires untouched but makes
         *     the honest witness fail to satisfy the circuit — i.e. a proof
         *     the network rejects. Assert A*B==C over the real witness for
         *     every emitted constraint, per corpus witness. */
        size_t bad_constraint = SIZE_MAX;
        bool sat_ok = cs_is_satisfied(&cs, &bad_constraint);
        if (!sat_ok && !flagged) {
            flagged = true;
            printf("  >> FIRST DIVERGENCE: corpus[%u] R1CS UNSATISFIED at "
                   "constraint index %zu of %zu (A*B != C under the honest "
                   "witness)\n", c, bad_constraint, cs.num_constraints);
        }
        snprintf(label, sizeof(label),
                 "corpus[%u]: all %zu constraints satisfied by the witness "
                 "(A*B==C)", c, cs.num_constraints);
        PARITY_CHECK(label, sat_ok);

        /* (D) Determinism: re-synthesize, expect a byte-identical witness. */
        struct constraint_system cs2;
        cs_init(&cs2);
        bool synth2 = sapling_spend_synthesize_traced(
            &cs2, &pw.wit, &pw.pub, NULL, 0, NULL, NULL);
        bool det_ok = synth2
            && cs.num_vars == cs2.num_vars
            && cs.num_constraints == cs2.num_constraints
            && memcmp(cs.witness, cs2.witness,
                      cs.num_vars * sizeof(struct fr)) == 0;
        snprintf(label, sizeof(label),
                 "corpus[%u]: synthesis deterministic (byte-identical witness)",
                 c);
        PARITY_CHECK(label, det_ok);

        cs_free(&cs2);
        cs_free(&cs);
    }

    /* Index-0 tie to the pinned checked-in KAT vector (belt-and-suspenders:
     * the corpus witness 0 nk MUST equal the baked SPEND_ORACLE_KAT_NK). */
    uint8_t nk_kat[32];
    sapling_nsk_to_nk(SPEND_ORACLE_KAT_NSK, nk_kat);
    PARITY_CHECK("corpus[0] nk == pinned SPEND_ORACLE_KAT_NK",
                 memcmp(nk_kat, SPEND_ORACLE_KAT_NK, 32) == 0);

    /* Honest scoreboard. */
    size_t cum = (max_ported > 0 && max_ported <= REF_NUM_SECTIONS)
                 ? REF_SECTIONS[max_ported - 1].cum_constraints : 0;
    printf("  parity coverage: %zu/%d reference sections ported, "
           "%zu/%d constraints proven at parity (%.1f%%)\n",
           max_ported, REF_NUM_SECTIONS, cum, REF_TOTAL_CONSTRAINTS,
           100.0 * (double)cum / (double)REF_TOTAL_CONSTRAINTS);
    if (max_ported < (size_t)REF_NUM_SECTIONS)
        printf("  reference target (full circuit): %d constraints, %d aux, "
               "%d inputs — remaining sections %zu..%d pending H3 port\n",
               REF_TOTAL_CONSTRAINTS, REF_TOTAL_AUX, REF_TOTAL_INPUTS,
               max_ported + 1, REF_NUM_SECTIONS);
    else
        printf("  reference target (full circuit): %d constraints, %d aux, "
               "%d inputs — every section ported\n",
               REF_TOTAL_CONSTRAINTS, REF_TOTAL_AUX, REF_TOTAL_INPUTS);
    if (max_ported < (size_t)REF_NUM_SECTIONS)
        printf("  next unimplemented section (typed blocker): '%s' "
               "(+%zu constraints to cum %zu) — native spend prover cannot "
               "round-trip until sections %zu..%d land\n",
               REF_SECTIONS[max_ported].name,
               REF_SECTIONS[max_ported].cum_constraints - cum,
               REF_SECTIONS[max_ported].cum_constraints,
               max_ported + 1, REF_NUM_SECTIONS);

    printf("--- end H4 parity oracle (%d failure[s]) ---\n", failures);
    return failures;
}
