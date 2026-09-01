/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Positive Sapling prover capability gate.
 *
 * This test used to print FALSE for the native prover's self-verification and
 * deliberately return success. That made a broken prover indistinguishable
 * from a healthy one. The production parameter loader now runs a complete
 * Spend + Output + binding-signature bundle through the independent C23
 * consensus verifier before enabling proving. This test makes that result a
 * hard assertion and independently exercises the public Output API.
 */

#include "test/test_core.h"

#include "sapling/params_init.h"
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/sapling_prover.h"
#include "sapling/groth16_prover.h"
#include "sapling/pedersen_hash.h"
#include "sapling/fr.h"
#include "crypto/blake2s.h"
#include "test/groth16_spend_oracle_kat.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROVER_CHECK(name, expr) do {          \
    printf("  %s... ", (name));                \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

/* First diversifier whose group_hash lands on a Jubjub point. group_hash is
 * probabilistic (~50% of tags miss), so a hard-coded diversifier is a coin
 * flip; spend section 11 witnesses g_d and section 12 asserts it is not small
 * order, both of which need a real point. */
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

/* ── Native C23 Groth16 prover baseline (H1 harness) ──────────────────
 *
 * NON-GATING diagnostic. The production/gated prover is native C23. This
 * section measures its circuits (sapling_output_synthesize /
 * sapling_spend_synthesize) against the
 * trusted-setup proving keys, so the spend-prover campaign can track exact
 * var/constraint counts vs target without re-deriving them each lane.
 *
 * A native circuit only round-trips when its auxiliary assignment matches the
 * pk L query and its query densities match the key. `a_len` is a compact query
 * density, not the total variable count, so comparing it to num_vars is
 * meaningless; groth16_prove() validates those densities while proving. This
 * table remains informational because the exact circuit gates below carry the
 * assertions. */
static void native_circuit_baseline(void)
{
    printf("\n--- H1 baseline: native C23 circuit counts (NON-GATING) ---\n");

    /* OUTPUT circuit vs sapling-output proving key ------------------- */
    size_t out_pk_len = 0;
    const uint8_t *out_pk_data = sapling_get_output_pk(&out_pk_len);
    if (out_pk_data && out_pk_len > 0) {
        struct groth16_pk opk;
        if (groth16_pk_read(&opk, out_pk_data, out_pk_len)) {
            printf("  OUTPUT pk: num_inputs=%zu a_len=%zu b_len=%zu "
                   "l_len=%zu h_len=%zu\n",
                   opk.num_inputs, opk.a_len, opk.b_len, opk.l_len, opk.h_len);

            /* Build a valid output witness (pk_d must be a real Jubjub point). */
            uint8_t d[11], ivk[32], pk_d[32];
            memset(ivk, 0x44, 32);
            bool have = false;
            for (unsigned i = 0; i < 256 && !have; i++) {
                memset(d, 0, 11);
                d[0] = (uint8_t)i;
                if (sapling_ivk_to_pkd(ivk, d, pk_d))
                    have = true;
            }
            if (have) {
                struct sapling_output_witness wit;
                memset(&wit, 0, sizeof wit);
                wit.value = UINT64_C(54321);
                memcpy(wit.diversifier, d, 11);
                memcpy(wit.pk_d, pk_d, 32);
                sapling_generate_r(wit.rcm);
                sapling_generate_r(wit.esk);
                sapling_generate_r(wit.rcv);
                struct sapling_output_inputs pub;
                sapling_value_commit(wit.value, wit.rcv, pub.cv);
                sapling_ka_derivepublic(wit.diversifier, wit.esk, pub.epk);
                sapling_compute_cm(wit.diversifier, wit.pk_d, wit.value,
                                   wit.rcm, pub.cm);

                struct constraint_system cs;
                cs_init(&cs);
                if (sapling_output_synthesize(&cs, &wit, &pub)) {
                    size_t num_aux = (cs.num_vars > cs.num_inputs + 1)
                        ? cs.num_vars - cs.num_inputs - 1 : 0;
                    printf("  OUTPUT circuit: num_inputs=%zu num_vars=%zu "
                           "num_aux=%zu num_constraints=%zu\n",
                           cs.num_inputs, cs.num_vars, num_aux,
                           cs.num_constraints);
                    printf("  OUTPUT match: num_aux==pk.l_len? %s  "
                           "query densities checked while proving\n",
                           (num_aux == opk.l_len) ? "YES" : "NO");
                }
                cs_free(&cs);
            }
            groth16_pk_free(&opk);
        } else {
            printf("  OUTPUT pk: groth16_pk_read failed\n");
        }
    } else {
        printf("  OUTPUT pk: not loaded\n");
    }

    /* SPEND circuit vs sapling-spend proving key --------------------- */
    size_t sp_pk_len = 0;
    const uint8_t *sp_pk_data = sapling_get_spend_pk(&sp_pk_len);
    if (sp_pk_data && sp_pk_len > 0) {
        struct groth16_pk spk;
        if (groth16_pk_read(&spk, sp_pk_data, sp_pk_len)) {
            printf("  SPEND  pk: num_inputs=%zu a_len=%zu b_len=%zu "
                   "l_len=%zu h_len=%zu\n",
                   spk.num_inputs, spk.a_len, spk.b_len, spk.l_len, spk.h_len);

            /* Build a valid spend witness. ak/pk_d must be real Jubjub points;
             * rk/cv public inputs likewise (point_to_xy decodes them). */
            uint8_t ask[32] = {0};
            ask[0] = 0x07; ask[1] = 0xCC;
            uint8_t ak[32];
            sapling_ask_to_ak(ask, ak);

            struct sapling_spend_witness wit;
            memset(&wit, 0, sizeof wit);
            memcpy(wit.ak, ak, 32);
            wit.nsk[0] = 0x0B; wit.nsk[1] = 0x5A; wit.nsk[7] = 0x11;
            memcpy(wit.pk_d, ak, 32);
            memcpy(wit.diversifier, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", 11);
            wit.value = UINT64_C(54321);

            struct sapling_spend_inputs pub;
            memset(&pub, 0, sizeof pub);
            memcpy(pub.rk, ak, 32);
            memcpy(pub.cv, ak, 32);

            struct constraint_system cs;
            cs_init(&cs);
            if (sapling_spend_synthesize(&cs, &wit, &pub)) {
                size_t num_aux = (cs.num_vars > cs.num_inputs + 1)
                    ? cs.num_vars - cs.num_inputs - 1 : 0;
                printf("  SPEND  circuit: num_inputs=%zu num_vars=%zu "
                       "num_aux=%zu num_constraints=%zu (target ~98777)\n",
                       cs.num_inputs, cs.num_vars, num_aux, cs.num_constraints);
                printf("  SPEND  match: num_aux==pk.l_len? %s  "
                       "query densities checked while proving\n",
                       (num_aux == spk.l_len) ? "YES" : "NO");
            }
            cs_free(&cs);
            groth16_pk_free(&spk);
        } else {
            printf("  SPEND  pk: groth16_pk_read failed\n");
        }
    } else {
        printf("  SPEND  pk: not loaded\n");
    }
    printf("--- end H1 baseline (informational) ---\n");
}

/* Output is small enough to gate as one exact production circuit. This is
 * params-free: it proves the C23 synthesis has the trusted-setup shape and an
 * honest, fully-derived public witness before any multi-minute proof runs. */
static int output_circuit_shape_gate(void)
{
    printf("\n--- H1: Sapling OUTPUT native C23 circuit gate ---\n");
    int failures = 0;
    struct sapling_output_witness wit;
    memset(&wit, 0, sizeof(wit));
    wit.value = UINT64_C(54321);
    wit.rcv[0] = 0x31;
    wit.esk[0] = 0x29;
    wit.rcm[0] = 0x47;

    uint8_t ivk[32] = {0};
    ivk[0] = 0x19;
    bool recipient_ok = find_diversifier(wit.diversifier) &&
        sapling_ivk_to_pkd(ivk, wit.diversifier, wit.pk_d);
    PROVER_CHECK("constructed deterministic output recipient", recipient_ok);

    struct sapling_output_inputs pub;
    memset(&pub, 0, sizeof(pub));
    bool public_ok = recipient_ok &&
        sapling_value_commit(wit.value, wit.rcv, pub.cv) &&
        sapling_ka_derivepublic(wit.diversifier, wit.esk, pub.epk) &&
        sapling_compute_cm(wit.diversifier, wit.pk_d, wit.value, wit.rcm,
                           pub.cm);
    PROVER_CHECK("derived cv, epk, and cm from the output witness", public_ok);

    struct constraint_system cs;
    cs_init(&cs);
    bool synth_ok = public_ok && sapling_output_synthesize(&cs, &wit, &pub);
    PROVER_CHECK("native output synthesis succeeded", synth_ok);
    PROVER_CHECK("output public input count == 5", cs.num_inputs == 5);
    PROVER_CHECK("output auxiliary count == production pk l_len (7821)",
                 cs.num_vars == cs.num_inputs + 1 + 7821);
    PROVER_CHECK("output constraint count == reference (7827)",
                 cs.num_constraints == 7827);
    size_t bad = SIZE_MAX;
    PROVER_CHECK("honest output witness satisfies every constraint",
                 synth_ok && cs_is_satisfied(&cs, &bad));

    struct constraint_system cs2;
    cs_init(&cs2);
    bool synth2 = public_ok && sapling_output_synthesize(&cs2, &wit, &pub);
    PROVER_CHECK("output synthesis is deterministic",
                 synth2 && cs.num_vars == cs2.num_vars &&
                 cs.num_constraints == cs2.num_constraints &&
                 memcmp(cs.witness, cs2.witness,
                        cs.num_vars * sizeof(struct fr)) == 0);
    cs_free(&cs2);
    cs_free(&cs);
    memset(&wit, 0, sizeof(wit));
    printf("--- end H1 output gate (%d failure[s]) ---\n", failures);
    return failures;
}

/* H3 lane: Sapling SPEND circuit port — shape + value + determinism gate.
 *
 * The spend circuit is ported gadget-by-gadget in bellman's Spend::synthesize
 * order. This gate is params-free (pure R1CS synthesis, no proving key) and
 * pins the ported prefix (sections 1..21) against ground truth:
 *   (1) cumulative constraint counts per section == the reference trace's
 *       cumulative boundaries (exact, verified by the salvage-plan legs);
 *   (2) the in-circuit nk / rk wires carry the reference-correct Jubjub points,
 *       with nk additionally pinned to the librustzcash reference vector (the
 *       H2 KAT) — validating the in-circuit fixed-base multiplication against
 *       ground truth end to end;
 *  (2b) section 10's 256 in-circuit blake2s digest bits == the out-of-circuit
 *       CRH^ivk over the same preimage, and its 251 truncated bits == the
 *       pinned librustzcash ivk. A matching constraint COUNT cannot see a wrong
 *       rotation constant or SIGMA row: mutation-testing confirms a wrong
 *       BLAKE2s rotation leaves the count at 24590 and the whole system
 *       satisfied, with only this check going red;
 *  (2c) every section-10 wire is BOUND — flipping any one of them (0<->1, which
 *       keeps booleanity intact) must make the R1CS unsatisfiable. Counts and
 *       values both read only the honest witness, so neither can see an
 *       UNDER-constrained gadget, which is the soundness-relevant failure: a
 *       free digest wire would let a prover choose its own ivk. Mutation-tested
 *       by making the XOR constraint vacuous — count, digest value and
 *       satisfaction all stay green and only this check fires;
 *  (2d) sections 11..16 — the note-content half. g_d is the witnessed
 *       GH("Zcash_gd", d) point; pk_d is the reference [ivk] g_d, which is the
 *       FIRST variable-base multiplication in the circuit, so its 3252-constraint
 *       count means nothing without the value check next to it;
 *       repr(g_d)/repr(pk_d) reproduce those points' compressed encodings; and
 *       cv is BOUND to public input 3/4, so the honest witness must carry the
 *       real [value]G_v + [rcv]G_rcv or the R1CS-satisfaction check below fails;
 *  (2e) sections 17..20 — the note commitment. The 982-constraint windowed
 *       Pedersen hash is the largest single gadget after blake2s, and a window
 *       lookup with the wrong table or the wrong personalization hits the same
 *       count while committing to a different note. So both the section-17 hash
 *       point and the section-20 commitment point are diffed, x AND y, against
 *       the out-of-circuit table-driven Pedersen hash + Jubjub scalar mul, and
 *       cm.x is additionally tied to the production sapling_compute_cm() — the
 *       protocol's `cmu`, i.e. the leaf the note-commitment tree stores;
 *  (2f) sections 17..21 END TO END. Section 21 folds the note commitment 32
 *       levels up to the anchor, and it now takes its leaf straight off section
 *       20's cm.x wire. Checking each half on its own would not establish that
 *       the commitment the circuit computed is the value that entered the fold,
 *       so the anchor wire is diffed against an out-of-circuit fold seeded from
 *       sapling_compute_cm()'s OWN output over the same witnessed path;
 *   (3) synthesis is deterministic (identical inputs => byte-identical witness).
 * Sections 22..28 are not yet ported, so this is a PARTIAL-prefix gate, not a
 * spend round-trip. Returns the number of failures (0 == green). */
static int spend_circuit_shape_gate(void)
{
    printf("\n--- H3: Sapling SPEND circuit port shape gate (sections 1-28) ---\n");
    int failures = 0;

    /* Fixed witness — reuses the H2 KAT scalars so the nk wire ties to the
     * pinned librustzcash reference vector. */
    uint8_t ak[32];
    sapling_ask_to_ak(SPEND_ORACLE_KAT_ASK, ak);

    struct sapling_spend_witness wit;
    memset(&wit, 0, sizeof wit);
    memcpy(wit.ak, ak, 32);
    memcpy(wit.nsk, SPEND_ORACLE_KAT_NSK, 32);
    wit.ar[0] = 0x03;               /* small fixed re-randomization scalar */
    memcpy(wit.pk_d, ak, 32);
    wit.value = UINT64_C(54321);
    wit.rcv[0] = 0x71;              /* small canonical Fs scalar (< 2^252) */
    wit.rcv[1] = 0x0d;
    wit.rcm[0] = 0x5c;              /* note commitment randomness (sections 18-20) */
    wit.rcm[1] = 0x23;
    /* The 32 authentication-path siblings section 21 folds cm.x through. Each
     * comes from a Pedersen Merkle hash so it is a canonical Fr encoding by
     * construction, and the position bits are not a function of depth parity
     * alone — a swapped-every-level bug has to be visible. */
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t pa[32] = {0}, pb[32] = {0};
        pa[0] = (uint8_t)(0x10u + d);
        pa[1] = 0x5b;
        pb[0] = (uint8_t)(d * 7u);
        pb[3] = 0x11;
        pedersen_merkle_hash(0, pa, pb, wit.auth_path[d]);
        wit.auth_path_bits[d] = (((d * 5u) + (d / 3u)) & 1u) != 0u;
    }
    PROVER_CHECK("found a diversifier whose group_hash is a Jubjub point",
                 find_diversifier(wit.diversifier));

    uint8_t rk_bytes[32];
    bool rk_ok = sapling_compute_rk(ak, wit.ar, rk_bytes);
    PROVER_CHECK("compute_rk produced rk for the fixed witness", rk_ok);

    /* cv is a PUBLIC INPUT the circuit now binds (section 14), so it has to be
     * the real value commitment. A placeholder point makes the R1CS
     * unsatisfiable — that is the intended behaviour, not a fixture quirk. */
    uint8_t cv_bytes[32];
    bool cv_ok = sapling_value_commit(wit.value, wit.rcv, cv_bytes);
    PROVER_CHECK("value_commit produced cv for the fixed witness", cv_ok);

    struct sapling_spend_inputs pub;
    memset(&pub, 0, sizeof pub);
    /* Sections 5, 14, 22 and 28 bind rk, cv, the anchor and the nullifier, so
     * all four are part of the fixture: a placeholder anchor or nf makes the
     * R1CS unsatisfiable by construction, not by a fixture quirk. */
    PROVER_CHECK("derived every public input from the witness",
                 sapling_spend_derive_public(&wit, &pub));

    struct spend_section_shape sections[29];
    size_t nsec = 0;
    struct spend_wire_probe probe;
    struct constraint_system cs;
    cs_init(&cs);
    bool synth_ok = sapling_spend_synthesize_traced(
        &cs, &wit, &pub, sections, 29, &nsec, &probe);
    PROVER_CHECK("traced spend synthesis succeeded", synth_ok);

    /* (1) Per-section cumulative constraint counts vs the reference trace. */
    static const size_t REF_CUM[28] =
        {20, 272, 1022, 1028, 1030, 1282, 2032, 2808, 3584, 24590,
         24594, 24610, 27862, 29127, 29903, 30679, 31661, 31913, 32663, 32669,
         76893, 76894, 76895, 76987, 76993, 77769, 98775, 98777};
    static const char *REF_NAME[28] = {
        "S1 ak witness/on-curve/not-small-order (cum 20)",
        "S2 ar bits (cum 272)",
        "S3 randomization of signing key (cum 1022)",
        "S4 rk = ak + [ar]G (cum 1028)",
        "S5 rk inputize (cum 1030)",
        "S6 nsk bits (cum 1282)",
        "S7 nk = [nsk] ProofGenerationKey (cum 2032)",
        "S8 representation of ak (cum 2808)",
        "S9 representation of nk (cum 3584)",
        "S10 computation of ivk — in-circuit blake2s (cum 24590)",
        "S11 witness g_d (cum 24594)",
        "S12 g_d not small order (cum 24610)",
        "S13 pk_d = [ivk] g_d — variable-base mul (cum 27862)",
        "S14 value commitment + cv inputize (cum 29127)",
        "S15 representation of g_d (cum 29903)",
        "S16 representation of pk_d (cum 30679)",
        "S17 note content hash — windowed Pedersen hash (cum 31661)",
        "S18 rcm bits (cum 31913)",
        "S19 [rcm] NoteCommitmentRandomness (cum 32663)",
        "S20 randomization of note commitment (cum 32669)",
        "S21 merkle tree hash 0..31 (cum 76893)",
        "S22 conditionally enforce correct root (cum 76894)",
        "S23 anchor inputize (cum 76895)",
        "S24 g^position (cum 76987)",
        "S25 faerie gold prevention (cum 76993)",
        "S26 representation of rho (cum 77769)",
        "S27 nf computation — in-circuit blake2s (cum 98775)",
        "S28 pack nullifier (cum 98777)",
    };
    PROVER_CHECK("synthesized all 28 sections", nsec == 28);
    for (size_t i = 0; i < 28 && i < nsec; i++)
        PROVER_CHECK(REF_NAME[i], sections[i].num_constraints == REF_CUM[i]);
    PROVER_CHECK("7 public inputs allocated (bellman-faithful low indices)",
                 cs.num_inputs == 7);
    PROVER_CHECK("full spend constraint count == 98777",
                 cs.num_constraints == 98777);
    /* Per-section DELTAS, not only cumulative totals — a compensating pair of
     * errors in adjacent sections cancels in the running total but not here.
     * 3252 = 13*251 - 11 is double-and-add over the 251 truncated ivk bits;
     * 1265 = 64 + 191 + 252 + 750 + 6 + 2 is expose_value_commitment;
     * 44224 = 32 * 1382 is the whole Merkle fold. */
    if (nsec >= 21) {
        static const size_t REF_DELTA[11] =
            {4, 16, 3252, 1265, 776, 776, 982, 252, 750, 6, 44224};
        static const char *REF_DELTA_NAME[11] = {
            "S11 delta == 4 (EdwardsPoint::witness on-curve check)",
            "S12 delta == 16 (assert_not_small_order)",
            "S13 delta == 3252 (13*251 - 11, variable-base mul)",
            "S14 delta == 1265 (expose_value_commitment)",
            "S15 delta == 776 (EdwardsPoint::repr)",
            "S16 delta == 776 (EdwardsPoint::repr)",
            ("S17 delta == 982 (386 windows + 570 montgomery add + 8 "
             "into_edwards + 18 edwards add)"),
            "S18 delta == 252 (field_into_boolean_vec_le, Fs::NUM_BITS)",
            "S19 delta == 750 (84*3 + 83*6, fixed-base mul over 252 bits)",
            "S20 delta == 6 (one Edwards addition)",
            "S21 delta == 44224 (32 levels * 1382)",
        };
        for (size_t i = 0; i < 11; i++)
            PROVER_CHECK(REF_DELTA_NAME[i],
                         sections[10 + i].num_constraints
                             - sections[9 + i].num_constraints
                                 == REF_DELTA[i]);
    }
    /* Section 10 alone must cost exactly what the reference's blake2s costs for
     * a 512-bit all-allocated input. bellman's own blake2s test asserts 21518
     * constraints for that shape, of which 512 are the input AllocatedBit::alloc
     * constraints the caller pays — leaving 21006 for the hash itself, which is
     * exactly the reference spend trace's section-10 delta. */
    PROVER_CHECK("S10 delta == 21006 (bellman blake2s, 512-bit input)",
                 nsec >= 10 && sections[9].num_constraints
                             - sections[8].num_constraints == 21006);

    /* (2) Value gate: in-circuit wires carry reference-correct points; nk is
     *     pinned to the librustzcash reference (H2 KAT). */
    uint8_t nk_bytes[32];
    sapling_nsk_to_nk(wit.nsk, nk_bytes);
    PROVER_CHECK("out-of-circuit nk == pinned librustzcash reference (H2 KAT)",
                 memcmp(nk_bytes, SPEND_ORACLE_KAT_NK, 32) == 0);

    struct jub_point nk_pt, rk_pt;
    struct fr nk_x, nk_y, rk_x, rk_y;
    bool nk_dec = jub_from_bytes(&nk_pt, nk_bytes);
    bool rk_dec = rk_ok && jub_from_bytes(&rk_pt, rk_bytes);
    if (nk_dec) { jub_get_x(&nk_x, &nk_pt); jub_get_y(&nk_y, &nk_pt); }
    if (rk_dec) { jub_get_x(&rk_x, &rk_pt); jub_get_y(&rk_y, &rk_pt); }

    bool nk_wire_ok = synth_ok && nk_dec
        && probe.nk_x < cs.num_vars && probe.nk_y < cs.num_vars
        && fr_eq(&cs.witness[probe.nk_x], &nk_x)
        && fr_eq(&cs.witness[probe.nk_y], &nk_y);
    PROVER_CHECK("in-circuit nk wire == [nsk] ProofGenerationKeyGenerator",
                 nk_wire_ok);

    bool rk_wire_ok = synth_ok && rk_dec
        && probe.rk_x < cs.num_vars && probe.rk_y < cs.num_vars
        && fr_eq(&cs.witness[probe.rk_x], &rk_x)
        && fr_eq(&cs.witness[probe.rk_y], &rk_y);
    PROVER_CHECK("in-circuit rk wire == ak + [ar] SpendAuthGenerator",
                 rk_wire_ok);

    /* (2b) Section 10 VALUE gate. A matching constraint COUNT says nothing
     *      about what the gadget computes, so read the digest back off the
     *      circuit's own wires and diff it against ground truth twice:
     *
     *        - all 256 bits vs the out-of-circuit C23 BLAKE2s over the same
     *          preimage (the scalar implementation, KAT-pinned elsewhere), and
     *        - the 251 bits bellman keeps after `truncate(Fs::CAPACITY)` vs the
     *          checked-in librustzcash `SPEND_ORACLE_KAT_IVK` vector.
     *
     *      bellman's blake2s returns Booleans that may be NEGATED views of a
     *      wire, so the probe's negation flag has to be applied — reading the
     *      raw wire would invert bits and fail for the wrong reason. */
    uint8_t ivk_full[32];
    {
        struct blake2s_ctx bctx;
        blake2s_init_personal(&bctx, 32, (const uint8_t *)"Zcashivk");
        blake2s_update(&bctx, ak, 32);
        blake2s_update(&bctx, nk_bytes, 32);
        blake2s_final(&bctx, ivk_full, 32);
    }
    uint8_t ivk_truncated[32];
    sapling_crh_ivk(ak, nk_bytes, ivk_truncated);
    PROVER_CHECK("out-of-circuit CRH^ivk == pinned librustzcash ivk (H2 KAT)",
                 memcmp(ivk_truncated, SPEND_ORACLE_KAT_IVK, 32) == 0);

    struct fr one_fr;
    fr_one(&one_fr);
    bool ivk_bits_ok = synth_ok;
    bool ivk_trunc_ok = synth_ok;
    size_t first_bad_ivk_bit = SIZE_MAX;
    for (size_t b = 0; b < 256; b++) {
        const size_t v = probe.ivk_bit[b];
        if (v >= cs.num_vars) { ivk_bits_ok = false; ivk_trunc_ok = false;
                                if (first_bad_ivk_bit == SIZE_MAX)
                                    first_bad_ivk_bit = b;
                                continue; }
        bool wire = fr_eq(&cs.witness[v], &one_fr);
        bool got = probe.ivk_bit_negated[b] ? !wire : wire;
        bool want_full = ((ivk_full[b / 8] >> (b % 8)) & 1) == 1;
        if (got != want_full) {
            ivk_bits_ok = false;
            if (first_bad_ivk_bit == SIZE_MAX)
                first_bad_ivk_bit = b;
        }
        if (b < SPEND_IVK_TRUNCATED_BITS) {
            bool want_trunc =
                ((SPEND_ORACLE_KAT_IVK[b / 8] >> (b % 8)) & 1) == 1;
            if (got != want_trunc)
                ivk_trunc_ok = false;
        }
    }
    if (!ivk_bits_ok && first_bad_ivk_bit != SIZE_MAX)
        printf("  >> section 10 digest bit %zu diverges from "
               "BLAKE2s(\"Zcashivk\", repr(ak)||repr(nk))\n", first_bad_ivk_bit);
    PROVER_CHECK("in-circuit blake2s digest (256 bits) == out-of-circuit "
                 "CRH^ivk preimage hash", ivk_bits_ok);
    PROVER_CHECK("in-circuit ivk truncated to 251 bits == pinned "
                 "librustzcash ivk", ivk_trunc_ok);

    /* (2c) ADVERSARIAL: are section 10's wires actually BOUND, or merely
     *      present? A count gate and a value gate both pass for an
     *      UNDER-constrained gadget — the dangerous failure here — because both
     *      only ever look at the honest witness. So mutate the witness: flip one
     *      section-10 wire at a time from 0 to 1 (or back), which keeps every
     *      booleanity constraint satisfied, and require the system to become
     *      UNSATISFIED. A wire that can be flipped freely is a soundness hole:
     *      it would let a prover choose a digest bit, and CRH^ivk is what binds
     *      the spend to its viewing key.
     *
     *      Two populations are probed: the 256 digest wires (the gadget's
     *      output, where a free bit is directly exploitable) and a deterministic
     *      stride across every wire section 10 allocated (its internal
     *      round state, carries and XOR results). */
    size_t sec10_first_var = (nsec >= 10) ? sections[8].num_vars : 0;
    size_t sec10_last_var  = (nsec >= 10) ? sections[9].num_vars : 0;
    size_t flips_tried = 0, flips_detected = 0;
    size_t digest_tried = 0, digest_detected = 0;
    if (synth_ok && nsec >= 10 && sec10_last_var > sec10_first_var) {
        struct fr zero_fr;
        fr_zero(&zero_fr);
        size_t ignored = SIZE_MAX;

        /* Sanity: the honest witness satisfies the system before any mutation,
         * otherwise "flip detected" would be vacuous. This is also what proves
         * the cv public input is the real value commitment — section 14 binds
         * it, so a placeholder cv shows up here as an unsatisfiable system. */
        PROVER_CHECK("honest witness satisfies the full 98777-constraint system",
                     cs_is_satisfied(&cs, &ignored));

        for (size_t b = 0; b < 256; b++) {
            const size_t v = probe.ivk_bit[b];
            if (v >= cs.num_vars)
                continue;
            struct fr saved = cs.witness[v];
            cs.witness[v] = fr_eq(&saved, &one_fr) ? zero_fr : one_fr;
            digest_tried++;
            if (!cs_is_satisfied(&cs, &ignored))
                digest_detected++;
            cs.witness[v] = saved;
        }

        const size_t span = sec10_last_var - sec10_first_var;
        const size_t stride = (span / 96) ? (span / 96) : 1;
        for (size_t v = sec10_first_var; v < sec10_last_var; v += stride) {
            struct fr saved = cs.witness[v];
            cs.witness[v] = fr_eq(&saved, &one_fr) ? zero_fr : one_fr;
            flips_tried++;
            if (!cs_is_satisfied(&cs, &ignored))
                flips_detected++;
            cs.witness[v] = saved;
        }

        /* Restoring must return the system to satisfied — proves the probe
         * itself did not corrupt the witness it was measuring. */
        PROVER_CHECK("witness restored after mutation probe",
                     cs_is_satisfied(&cs, &ignored));
    }
    printf("  section 10 wires %zu..%zu; single-bit flips detected: "
           "%zu/%zu digest, %zu/%zu strided internal\n",
           sec10_first_var, sec10_last_var,
           digest_detected, digest_tried, flips_detected, flips_tried);
    PROVER_CHECK("every section-10 digest wire is bound (a flipped digest bit "
                 "breaks the R1CS)",
                 digest_tried == 256 && digest_detected == 256);
    PROVER_CHECK("every probed section-10 internal wire is bound (no free "
                 "wire = no under-constrained gadget)",
                 flips_tried > 0 && flips_detected == flips_tried);

    /* (2d) Sections 11..16 VALUE gate. Every one of these is a point or a bit
     *      string with an out-of-circuit ground truth, so none of them is
     *      accepted on its constraint count alone:
     *
     *        11  g_d          == GH("Zcash_gd", d)
     *        13  pk_d         == sapling_ivk_to_pkd(ivk, d)  (the reference
     *                            variable-base multiplication — this is the one
     *                            new GADGET the six sections introduce)
     *        14  cv           == sapling_value_commit(value, rcv), and the 64
     *                            value bits are the note's value little-endian
     *        15  repr(g_d)    == compressed g_d, bit for bit
     *        16  repr(pk_d)   == compressed pk_d, bit for bit
     *
     *      Sections 12 and 16's cv/pk_d bindings are additionally covered by the
     *      satisfaction check above: assert_not_small_order and the cv copy
     *      constraint can only be satisfied by a witness that really holds. */
    uint8_t gd_bytes[32], pkd_bytes[32];
    struct jub_point gd_pt;
    bool gd_derived = sapling_diversifier_to_gd(&gd_pt, wit.diversifier);
    if (gd_derived)
        jub_to_bytes(gd_bytes, &gd_pt);
    else
        memset(gd_bytes, 0, sizeof gd_bytes);
    bool pkd_derived = gd_derived
        && sapling_ivk_to_pkd(ivk_truncated, wit.diversifier, pkd_bytes);
    if (!pkd_derived)
        memset(pkd_bytes, 0, sizeof pkd_bytes);
    PROVER_CHECK("reference g_d and pk_d = [ivk] g_d derived out of circuit",
                 gd_derived && pkd_derived);

    /* One helper for all three point-wire diffs (g_d, pk_d, cv): decode the
     * reference encoding and compare both coordinate wires. */
    struct point_wire_case {
        const char *label;
        const uint8_t *want;
        size_t x_var, y_var;
    };
    const struct point_wire_case point_cases[3] = {
        { "in-circuit g_d wire == GH(\"Zcash_gd\", d) (section 11)",
          gd_bytes,  probe.gd_x,  probe.gd_y },
        { "in-circuit pk_d wire == reference [ivk] g_d (section 13)",
          pkd_bytes, probe.pkd_x, probe.pkd_y },
        { "in-circuit cv wire == [value]G_v + [rcv]G_rcv (section 14)",
          cv_bytes,  probe.cv_x,  probe.cv_y },
    };
    for (size_t i = 0; i < 3; i++) {
        struct jub_point p;
        struct fr px, py;
        bool ok = synth_ok && jub_from_bytes(&p, point_cases[i].want);
        if (ok) {
            jub_get_x(&px, &p);
            jub_get_y(&py, &p);
            ok = point_cases[i].x_var < cs.num_vars
              && point_cases[i].y_var < cs.num_vars
              && fr_eq(&cs.witness[point_cases[i].x_var], &px)
              && fr_eq(&cs.witness[point_cases[i].y_var], &py);
        }
        PROVER_CHECK(point_cases[i].label, ok);
    }

    /* repr(g_d) / repr(pk_d): Jubjub's compressed encoding is y with x's low
     * bit in the top bit, so repr's 256 little-endian bits ARE the bits of the
     * 32-byte encoding. Same shape as the section 8/9 checks — they share the
     * gadget, so they share the ground truth too. */
    const struct { const char *label; const uint8_t *want; const size_t *bits; }
    repr_cases[2] = {
        { "repr(g_d) 256 bits == compressed g_d (section 15)",
          gd_bytes,  probe.gd_repr },
        { "repr(pk_d) 256 bits == compressed pk_d (section 16)",
          pkd_bytes, probe.pkd_repr },
    };
    for (size_t i = 0; i < 2; i++) {
        bool ok = synth_ok;
        for (size_t b = 0; b < 256 && ok; b++) {
            const size_t v = repr_cases[i].bits[b];
            bool want = ((repr_cases[i].want[b / 8] >> (b % 8)) & 1) == 1;
            ok = v < cs.num_vars
              && fr_eq(&cs.witness[v], &one_fr) == want;
        }
        PROVER_CHECK(repr_cases[i].label, ok);
    }

    /* Section 14's 64 value bits, little-endian — the order section 17 hashes
     * them in, so a reversed decomposition would be silent until then. */
    {
        bool ok = synth_ok;
        for (size_t b = 0; b < 64 && ok; b++) {
            const size_t v = probe.value_bit[b];
            bool want = ((wit.value >> b) & 1) == 1;
            ok = v < cs.num_vars && fr_eq(&cs.witness[v], &one_fr) == want;
        }
        PROVER_CHECK("64 value bits == note value little-endian (section 14)",
                     ok);
    }

    /* (2e) Sections 17 and 20 — the note commitment. The 982-constraint window
     *      lookups can land on the reference count while hashing the wrong
     *      table, the wrong personalization or the wrong bit order, so read the
     *      two points back off the circuit's own wires:
     *
     *        section 17  note_hash == PedersenHash(NoteCommitment,
     *                                 value(64) || repr(g_d) || repr(pk_d))
     *        section 20  cm        == note_hash + [rcm] G_rcm
     *
     *      Both references come from sapling_note_commitment_point() — the same
     *      body the wallet's sapling_compute_cm() and sapling_compute_nf() use
     *      out of circuit, over Edwards coordinates and a precomputed chunk
     *      table, which is a different algorithm from the in-circuit Montgomery
     *      windows. x AND y are compared: a matching x with a mismatched y is a
     *      point that is not the commitment. */
    uint8_t cm_api[32];
    bool cm_api_ok = synth_ok && pkd_derived
        && sapling_compute_cm(wit.diversifier, pkd_bytes, wit.value, wit.rcm,
                              cm_api);
    {
        struct jub_point cm_ref_pt;
        bool cm_ref_ok = pkd_derived
            && sapling_note_commitment_point(wit.diversifier, pkd_bytes,
                                             wit.value, wit.rcm, &cm_ref_pt);
        PROVER_CHECK("reference note commitment derived out of circuit",
                     cm_ref_ok);

        struct fr cm_x, cm_y;
        bool cm_wire_ok = synth_ok && cm_ref_ok;
        if (cm_wire_ok) {
            jub_get_x(&cm_x, &cm_ref_pt);
            jub_get_y(&cm_y, &cm_ref_pt);
            cm_wire_ok = probe.cm_x < cs.num_vars && probe.cm_y < cs.num_vars
                      && fr_eq(&cs.witness[probe.cm_x], &cm_x)
                      && fr_eq(&cs.witness[probe.cm_y], &cm_y);
        }
        PROVER_CHECK("in-circuit cm wire == note hash + [rcm] G_rcm "
                     "(section 20)", cm_wire_ok);

        /* The protocol's `cmu` — the leaf the note-commitment tree stores — is
         * exactly this x-coordinate, so tie the wire to the production API a
         * wallet calls, not only to a point this test assembled. */
        struct fr cm_api_fr;
        bool cm_api_wire_ok = cm_api_ok
            && fr_from_bytes(&cm_api_fr, cm_api)
            && probe.cm_x < cs.num_vars
            && fr_eq(&cs.witness[probe.cm_x], &cm_api_fr);
        PROVER_CHECK("in-circuit cm.x == sapling_compute_cm() `cmu` "
                     "(section 20)", cm_api_wire_ok);

        /* Section 17's own wire pair must be a real curve point carrying the
         * hash: subtract [rcm] G_rcm from the reference commitment and compare.
         * Doing it by subtraction rather than by re-hashing keeps ONE reference
         * for both sections, so a wrong section-19 generator cannot cancel out
         * of both sides at once. */
        struct fr grcm_x, grcm_y;
        sapling_note_commit_randomness_generator(&grcm_x, &grcm_y);
        bool hash_wire_ok = synth_ok && cm_ref_ok;
        if (hash_wire_ok) {
            uint8_t grcm_comp[32], grcm_xb[32];
            fr_to_bytes(grcm_comp, &grcm_y);
            fr_to_bytes(grcm_xb, &grcm_x);
            hash_wire_ok = (grcm_comp[31] & 0x80u) == 0;
            if (hash_wire_ok) {
                grcm_comp[31] |= (uint8_t)((grcm_xb[0] & 1u) << 7);
                struct jub_point g_rcm, rcm_pt, hash_pt;
                hash_wire_ok = jub_from_bytes(&g_rcm, grcm_comp);
                if (hash_wire_ok) {
                    jub_scalar_mul(&rcm_pt, &g_rcm, wit.rcm);
                    jub_neg(&rcm_pt, &rcm_pt);
                    jub_add(&hash_pt, &cm_ref_pt, &rcm_pt);
                    struct fr hx, hy;
                    jub_get_x(&hx, &hash_pt);
                    jub_get_y(&hy, &hash_pt);
                    hash_wire_ok = probe.note_hash_x < cs.num_vars
                                && probe.note_hash_y < cs.num_vars
                                && fr_eq(&cs.witness[probe.note_hash_x], &hx)
                                && fr_eq(&cs.witness[probe.note_hash_y], &hy);
                }
            }
        }
        PROVER_CHECK("in-circuit note hash wire == "
                     "PedersenHash(NoteCommitment, note) (section 17)",
                     hash_wire_ok);
    }

    /* (2f) Sections 17..21 END TO END — the assertion that only exists once the
     *      seam between them is open. Fold the witnessed authentication path out
     *      of circuit starting from sapling_compute_cm()'s OWN cm.x, and require
     *      the circuit's anchor wire to equal it. Section 20 correct plus section
     *      21 correct does not imply the commitment section 20 produced is the
     *      value section 21 folded; a wrong handover leaves both halves green and
     *      only this check red. */
    {
        uint8_t anchor_ref[32];
        struct fr anchor_ref_fr;
        bool ok = cm_api_ok;
        if (ok) {
            uint8_t cur[32];
            memcpy(cur, cm_api, 32);
            for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
                uint8_t next[32];
                if (wit.auth_path_bits[d])
                    pedersen_merkle_hash(d, wit.auth_path[d], cur, next);
                else
                    pedersen_merkle_hash(d, cur, wit.auth_path[d], next);
                memcpy(cur, next, 32);
            }
            memcpy(anchor_ref, cur, 32);
            ok = fr_from_bytes(&anchor_ref_fr, anchor_ref)
              && probe.anchor < cs.num_vars
              && fr_eq(&cs.witness[probe.anchor], &anchor_ref_fr);
        }
        PROVER_CHECK("in-circuit anchor == out-of-circuit fold seeded from the "
                     "circuit's own cm.x (sections 17..21)", ok);
    }

    /* (3) Determinism: identical inputs => byte-identical witness. */
    struct constraint_system cs2;
    cs_init(&cs2);
    bool synth2 = sapling_spend_synthesize_traced(
        &cs2, &wit, &pub, NULL, 0, NULL, NULL);
    bool det_ok = synth2 && cs.num_vars == cs2.num_vars
        && cs.num_constraints == cs2.num_constraints
        && memcmp(cs.witness, cs2.witness,
                  cs.num_vars * sizeof(struct fr)) == 0;
    PROVER_CHECK("synthesis is deterministic (byte-identical witness)", det_ok);

    cs_free(&cs);
    cs_free(&cs2);

    printf("--- end H3 shape gate (%d failure[s]) ---\n", failures);
    return failures;
}

/* H2 lane: reference differential oracle (test-only librustzcash bridge).
 * Runs FIRST and unconditionally — it is params-free, so it gates even when
 * ~/.zcash-params is absent and the prover self-test below SKIPs. */
int groth16_spend_reference_oracle(void);

/* H4 lane: standing differential parity oracle over a corpus of witnesses.
 * Params-free; auto-tightens off the reference section-boundary table as the
 * H3 port advances. Lives in tests/harness/src/groth16_spend_parity.c. */
int groth16_spend_parity_oracle(void);

/* Section 21: the 32-level Merkle authentication path — 44224 constraints, the
 * largest section of the spend circuit. Gated out of line (constraint count,
 * per-level breakdown, anchor value against an out-of-circuit fold, swap
 * sensitivity and wire boundness) because it sits after sections 17..20 in
 * synthesis order and cannot be recorded in the traced prefix until those land.
 * Params-free. Lives in tests/harness/src/groth16_merkle_path.c. */
int groth16_merkle_path_gate(void);

/* H5 lane: adversarial + negative-control gate over the production native C23
 * prove -> independent native C23 verify round-trip, plus a
 * proving-key-parser fuzz spot-check and zeroization spot-checks. Requires
 * proving params (guarded below by the same is-ready check the rest of this
 * self-test block uses). Lives in tests/harness/src/groth16_spend_adversarial.c. */
int groth16_spend_adversarial_gate(void);

int test_groth16_selfverify(void);
int test_groth16_selfverify(void)
{
    printf("\n=== Sapling prover -> consensus verifier capability ===\n");
    int failures = 0;

    failures += output_circuit_shape_gate();
    failures += groth16_spend_reference_oracle();
    failures += spend_circuit_shape_gate();
    failures += groth16_spend_parity_oracle();
    failures += groth16_merkle_path_gate();

    const char *home = getenv("HOME");
    char params_dir[512];
    char output_path[640];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    snprintf(output_path, sizeof(output_path),
             "%s/sapling-output.params", params_dir);

    FILE *probe = fopen(output_path, "rb");
    if (!probe) {
        printf("  params absent — SKIP (prover self-test); "
               "H2 oracle already ran above\n");
        return failures;
    }
    fclose(probe);

    const bool initialized = sapling_init_params(params_dir);
    PROVER_CHECK("parameter loader completed", initialized);
    PROVER_CHECK("backend provenance is native C23",
                 strcmp(zclassic_sapling_prover_backend(),
                        "native-c23-groth16") == 0);
    PROVER_CHECK("full Spend+Output+binding self-test returned true",
                 initialized && zclassic_sapling_prover_run_self_test());
    PROVER_CHECK("proving capability is READY",
                 zclassic_sapling_prover_is_ready() &&
                 strcmp(zclassic_sapling_prover_status(), "ready") == 0);

    if (zclassic_sapling_prover_is_ready()) {
        uint8_t diversifier[11];
        uint8_t ask[32], nsk[32], ovk[32];
        uint8_t ak[32], nk[32], ivk[32], pk_d[32];
        bool keys_ok = find_diversifier(diversifier) &&
                       sapling_generate_r(ask) &&
                       sapling_generate_r(nsk) &&
                       sapling_generate_r(ovk);
        if (keys_ok) {
            sapling_ask_to_ak(ask, ak);
            sapling_nsk_to_nk(nsk, nk);
            sapling_crh_ivk(ak, nk, ivk);
            keys_ok = sapling_ivk_to_pkd(ivk, diversifier, pk_d);
        }
        PROVER_CHECK("independent output recipient constructed", keys_ok);

        void *pctx = keys_ok ? zclassic_sapling_proving_ctx_init() : NULL;
        uint8_t cv[32], cm[32], epk[32], proof[192];
        uint8_t enc[580], out[80];
        bool built = pctx && sapling_build_output_with_ctx(
            pctx, ovk, diversifier, pk_d, UINT64_C(54321), NULL,
            cv, cm, epk, enc, out, proof);
        PROVER_CHECK("public proving API produced an output proof", built);

        if (built) {
            struct sapling_verification_ctx vctx;
            sapling_verification_ctx_init(&vctx);
            PROVER_CHECK("independent C23 consensus verifier accepts proof",
                         sapling_check_output(&vctx, cv, cm, epk, proof));

            uint8_t bad_proof[192];
            memcpy(bad_proof, proof, sizeof(bad_proof));
            bad_proof[191] ^= 1;
            sapling_verification_ctx_init(&vctx);
            PROVER_CHECK("tampered proof is rejected",
                         !sapling_check_output(
                             &vctx, cv, cm, epk, bad_proof));
        }
        if (pctx)
            zclassic_sapling_proving_ctx_free(pctx);
    }

    /* H5: adversarial + negative-control gate over the production SPEND
     * prove->verify round-trip. Gated on proving readiness (needs a real
     * proof to tamper with), independent of the OUTPUT-only checks above. */
    if (zclassic_sapling_prover_is_ready())
        failures += groth16_spend_adversarial_gate();

    /* Non-gating: emit native C23 circuit baseline counts for the
     * spend-prover campaign. Only meaningful once params are loaded. */
    if (initialized)
        native_circuit_baseline();

    printf("Sapling prover capability: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
