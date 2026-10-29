/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Positive Sapling prover capability gate.
 *
 * The production parameter loader runs a complete Spend + Output +
 * binding-signature bundle through the independent C23 consensus verifier
 * before enabling proving. This test makes that result a hard assertion and
 * independently exercises the public Output API.
 */

#include "test/test_core.h"

#include "sapling/params_init.h"
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/sapling_prover.h"
#include "sapling/groth16_prover.h"
#include "sapling/pedersen_hash.h"
#include "sapling/fr.h"
#include "sapling/circuit_bits.h"
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

/* First diversifier whose group_hash lands on a Jubjub point (~50% of tags
 * miss, so a hard-coded diversifier is a coin flip); spend sections 11 and
 * 12 need a real point. */
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

static void native_output_baseline(void)
{
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
}

static void native_spend_baseline(void)
{
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
}

/* ── Native C23 Groth16 prover baseline ───────────────────────────────
 *
 * NON-GATING diagnostic: measures the native circuits
 * (sapling_output_synthesize / sapling_spend_synthesize) against the
 * trusted-setup proving keys and reports var/constraint counts.
 *
 * A native circuit only round-trips when its auxiliary assignment matches the
 * pk L query and its query densities match the key. `a_len` is a compact
 * query density, not the total variable count, so it is not compared to
 * num_vars; groth16_prove() validates the densities. The exact circuit gates
 * below carry the assertions. */
static void native_circuit_baseline(void)
{
    printf("\n--- H1 baseline: native C23 circuit counts (NON-GATING) ---\n");

    native_output_baseline();
    native_spend_baseline();
    printf("--- end H1 baseline (informational) ---\n");
}


/* Output is gated as one exact production circuit. Params-free: proves the
 * C23 synthesis has the trusted-setup shape and an honest, fully-derived
 * public witness before any multi-minute proof runs. */
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

/* State shared by the spend shape-gate helpers below: the witness and public
 * inputs, the traced constraint system, and the values each section derives
 * for the sections after it to check. */
struct spend_sec10_flips {
    size_t first_var, last_var;
    size_t digest_tried, digest_detected;
    size_t flips_tried, flips_detected;
};

struct spend_gate_ctx {
    uint8_t ak[32];
    struct sapling_spend_witness wit;
    struct sapling_spend_inputs pub;
    uint8_t rk_bytes[32];
    bool rk_ok;
    uint8_t cv_bytes[32];
    bool cv_ok;
    struct spend_section_shape sections[29];
    size_t nsec;
    struct spend_wire_probe probe;
    struct constraint_system cs;
    bool synth_ok;
    uint8_t nk_bytes[32];
    uint8_t ivk_full[32];
    uint8_t ivk_truncated[32];
    uint8_t gd_bytes[32];
    uint8_t pkd_bytes[32];
    bool pkd_derived;
    uint8_t cm_api[32];
    bool cm_api_ok;
    struct jub_point cm_ref_pt;
    bool cm_ref_ok;
    struct spend_sec10_flips sec10;
};

/* Builds the fixed spend witness, including the authentication path, then
 * checks that its diversifier is a Jubjub point. Returns the failure count. */
static int spend_gate_build_witness(struct spend_gate_ctx *g)
{
    int failures = 0;
    struct sapling_spend_witness *wit = &g->wit;

    /* Fixed witness reusing the H2 KAT scalars so the nk wire ties to the
     * pinned librustzcash reference vector. */
    sapling_ask_to_ak(SPEND_ORACLE_KAT_ASK, g->ak);

    memset(wit, 0, sizeof *wit);
    memcpy(wit->ak, g->ak, 32);
    memcpy(wit->nsk, SPEND_ORACLE_KAT_NSK, 32);
    wit->ar[0] = 0x03;               /* small fixed re-randomization scalar */
    memcpy(wit->pk_d, g->ak, 32);
    wit->value = UINT64_C(54321);
    wit->rcv[0] = 0x71;              /* small canonical Fs scalar (< 2^252) */
    wit->rcv[1] = 0x0d;
    wit->rcm[0] = 0x5c;              /* note commitment randomness (sections 18-20) */
    wit->rcm[1] = 0x23;
    /* The 32 authentication-path siblings section 21 folds cm.x through:
     * canonical Fr encodings from a Pedersen Merkle hash, with position bits
     * that are not a function of depth parity alone. */
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t pa[32] = {0}, pb[32] = {0};
        pa[0] = (uint8_t)(0x10u + d);
        pa[1] = 0x5b;
        pb[0] = (uint8_t)(d * 7u);
        pb[3] = 0x11;
        pedersen_merkle_hash(0, pa, pb, wit->auth_path[d]);
        wit->auth_path_bits[d] = (((d * 5u) + (d / 3u)) & 1u) != 0u;
    }
    PROVER_CHECK("found a diversifier whose group_hash is a Jubjub point",
                 find_diversifier(wit->diversifier));
    return failures;
}

/* Derives rk and cv from the witness, then every public input from it. */
static int spend_gate_derive_publics(struct spend_gate_ctx *g)
{
    int failures = 0;

    g->rk_ok = sapling_compute_rk(g->ak, g->wit.ar, g->rk_bytes);
    PROVER_CHECK("compute_rk produced rk for the fixed witness", g->rk_ok);

    /* cv is a bound PUBLIC INPUT (section 14) and must be the real value
     * commitment. */
    g->cv_ok = sapling_value_commit(g->wit.value, g->wit.rcv, g->cv_bytes);
    PROVER_CHECK("value_commit produced cv for the fixed witness", g->cv_ok);

    memset(&g->pub, 0, sizeof g->pub);
    /* Sections 5, 14, 22 and 28 bind rk, cv, the anchor and the nullifier,
     * so all four are real fixture values (placeholders are unsatisfiable). */
    PROVER_CHECK("derived every public input from the witness",
                 sapling_spend_derive_public(&g->wit, &g->pub));
    return failures;
}

/* Runs the traced spend synthesis into the shared constraint system. */
static int spend_gate_synthesize(struct spend_gate_ctx *g)
{
    int failures = 0;

    g->nsec = 0;
    cs_init(&g->cs);
    g->synth_ok = sapling_spend_synthesize_traced(
        &g->cs, &g->wit, &g->pub, g->sections, 29, &g->nsec, &g->probe);
    PROVER_CHECK("traced spend synthesis succeeded", g->synth_ok);
    return failures;
}

/* Per-section cumulative counts and the total against the reference trace. */
static int spend_gate_check_section_counts(struct spend_gate_ctx *g)
{
    int failures = 0;
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
    PROVER_CHECK("synthesized all 28 sections", g->nsec == 28);
    for (size_t i = 0; i < 28 && i < g->nsec; i++)
        PROVER_CHECK(REF_NAME[i], g->sections[i].num_constraints == REF_CUM[i]);
    PROVER_CHECK("7 public inputs allocated (bellman-faithful low indices)",
                 g->cs.num_inputs == 7);
    PROVER_CHECK("full spend constraint count == 98777",
                 g->cs.num_constraints == 98777);
    return failures;
}

/* Per-section deltas against the reference trace and the section-10 cost. */
static int spend_gate_check_section_deltas(struct spend_gate_ctx *g)
{
    int failures = 0;
    /* Per-section DELTAS as well as cumulative totals (compensating errors
     * in adjacent sections cancel only in the total).
     * 3252 = 13*251 - 11 is double-and-add over the 251 truncated ivk bits;
     * 1265 = 64 + 191 + 252 + 750 + 6 + 2 is expose_value_commitment;
     * 44224 = 32 * 1382 is the whole Merkle fold. */
    if (g->nsec >= 21) {
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
                         g->sections[10 + i].num_constraints
                             - g->sections[9 + i].num_constraints
                                 == REF_DELTA[i]);
    }
    /* Section 10 alone must cost what the reference blake2s costs for a
     * 512-bit all-allocated input: 21518 constraints, of which 512 are the
     * input allocs the caller pays, leaving 21006 for the hash. */
    PROVER_CHECK("S10 delta == 21006 (bellman blake2s, 512-bit input)",
                 g->nsec >= 10 && g->sections[9].num_constraints
                             - g->sections[8].num_constraints == 21006);
    return failures;
}

/* (2) nk wire: the out-of-circuit nk is pinned to the reference, and the
 * in-circuit nk wires carry the same Jubjub point. */
static int spend_gate_check_nk_wire(struct spend_gate_ctx *g)
{
    int failures = 0;

    /* (2) Value gate: in-circuit wires carry reference-correct points; nk is
     *     pinned to the librustzcash reference (H2 KAT). */
    sapling_nsk_to_nk(g->wit.nsk, g->nk_bytes);
    PROVER_CHECK("out-of-circuit nk == pinned librustzcash reference (H2 KAT)",
                 memcmp(g->nk_bytes, SPEND_ORACLE_KAT_NK, 32) == 0);

    struct jub_point nk_pt;
    struct fr nk_x, nk_y;
    bool nk_dec = jub_from_bytes(&nk_pt, g->nk_bytes);
    if (nk_dec) { jub_get_x(&nk_x, &nk_pt); jub_get_y(&nk_y, &nk_pt); }

    bool nk_wire_ok = g->synth_ok && nk_dec
        && g->probe.nk_x < g->cs.num_vars && g->probe.nk_y < g->cs.num_vars
        && fr_eq(&g->cs.witness[g->probe.nk_x], &nk_x)
        && fr_eq(&g->cs.witness[g->probe.nk_y], &nk_y);
    PROVER_CHECK("in-circuit nk wire == [nsk] ProofGenerationKeyGenerator",
                 nk_wire_ok);
    return failures;
}

/* rk wire: the in-circuit rk wires carry ak + [ar] SpendAuthGenerator. */
static int spend_gate_check_rk_wire(struct spend_gate_ctx *g)
{
    int failures = 0;

    struct jub_point rk_pt;
    struct fr rk_x, rk_y;
    bool rk_dec = g->rk_ok && jub_from_bytes(&rk_pt, g->rk_bytes);
    if (rk_dec) { jub_get_x(&rk_x, &rk_pt); jub_get_y(&rk_y, &rk_pt); }

    bool rk_wire_ok = g->synth_ok && rk_dec
        && g->probe.rk_x < g->cs.num_vars && g->probe.rk_y < g->cs.num_vars
        && fr_eq(&g->cs.witness[g->probe.rk_x], &rk_x)
        && fr_eq(&g->cs.witness[g->probe.rk_y], &rk_y);
    PROVER_CHECK("in-circuit rk wire == ak + [ar] SpendAuthGenerator",
                 rk_wire_ok);
    return failures;
}

/* Section 10 digest value: the blake2s digest and the truncated ivk, computed
 * out of circuit, are the references the wire bits are read against. */
static int spend_gate_check_ivk_value(struct spend_gate_ctx *g)
{
    int failures = 0;

    /* (2b) Section 10 VALUE gate: read the digest back off the circuit's
     *      wires and diff it against ground truth twice:
     *
     *        - all 256 bits vs the out-of-circuit C23 BLAKE2s over the same
     *          preimage, and
     *        - the 251 bits after `truncate(Fs::CAPACITY)` vs the librustzcash
     *          `SPEND_ORACLE_KAT_IVK` vector.
     *
     *      blake2s returns Booleans that may be NEGATED views of a wire, so
     *      the probe's negation flag must be applied. */
    {
        struct blake2s_ctx bctx;
        blake2s_init_personal(&bctx, 32, (const uint8_t *)"Zcashivk");
        blake2s_update(&bctx, g->ak, 32);
        blake2s_update(&bctx, g->nk_bytes, 32);
        blake2s_final(&bctx, g->ivk_full, 32);
    }
    sapling_crh_ivk(g->ak, g->nk_bytes, g->ivk_truncated);
    PROVER_CHECK("out-of-circuit CRH^ivk == pinned librustzcash ivk (H2 KAT)",
                 memcmp(g->ivk_truncated, SPEND_ORACLE_KAT_IVK, 32) == 0);
    return failures;
}

/* Section 10 digest bits: the 256 digest wires and the 251 truncated bits
 * are read back and diffed against the out-of-circuit ground truth. */
static int spend_gate_check_ivk_bits(struct spend_gate_ctx *g)
{
    int failures = 0;
    struct constraint_system *cs = &g->cs;
    struct spend_wire_probe *probe = &g->probe;
    struct fr one_fr;
    fr_one(&one_fr);
    bool ivk_bits_ok = g->synth_ok;
    bool ivk_trunc_ok = g->synth_ok;
    size_t first_bad_ivk_bit = SIZE_MAX;
    for (size_t b = 0; b < 256; b++) {
        const size_t v = probe->ivk_bit[b];
        if (v >= cs->num_vars) { ivk_bits_ok = false; ivk_trunc_ok = false;
                                if (first_bad_ivk_bit == SIZE_MAX)
                                    first_bad_ivk_bit = b;
                                continue; }
        bool wire = fr_eq(&cs->witness[v], &one_fr);
        bool got = probe->ivk_bit_negated[b] ? !wire : wire;
        bool want_full = ((g->ivk_full[b / 8] >> (b % 8)) & 1) == 1;
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
    return failures;
}

/* Flips each section-10 digest bit (keeping booleanity) and counts the flips
 * the system rejects. The witness is restored after every flip. */
static void spend_gate_sec10_flip_digest(struct spend_gate_ctx *g)
{
    struct constraint_system *cs = &g->cs;
    struct fr one_fr, zero_fr;
    fr_one(&one_fr);
    fr_zero(&zero_fr);
    size_t ignored = SIZE_MAX;
    for (size_t b = 0; b < 256; b++) {
        const size_t v = g->probe.ivk_bit[b];
        if (v >= cs->num_vars)
            continue;
        struct fr saved = cs->witness[v];
        cs->witness[v] = fr_eq(&saved, &one_fr) ? zero_fr : one_fr;
        g->sec10.digest_tried++;
        if (!cs_is_satisfied(cs, &ignored))
            g->sec10.digest_detected++;
        cs->witness[v] = saved;
    }
}

/* Flips a deterministic stride of the internal section-10 wires and counts
 * the flips the system rejects. The witness is restored after every flip. */
static void spend_gate_sec10_flip_internal(struct spend_gate_ctx *g)
{
    struct constraint_system *cs = &g->cs;
    struct fr one_fr, zero_fr;
    fr_one(&one_fr);
    fr_zero(&zero_fr);
    size_t ignored = SIZE_MAX;
    const size_t span = g->sec10.last_var - g->sec10.first_var;
    const size_t stride = (span / 96) ? (span / 96) : 1;
    for (size_t v = g->sec10.first_var; v < g->sec10.last_var; v += stride) {
        struct fr saved = cs->witness[v];
        cs->witness[v] = fr_eq(&saved, &one_fr) ? zero_fr : one_fr;
        g->sec10.flips_tried++;
        if (!cs_is_satisfied(cs, &ignored))
            g->sec10.flips_detected++;
        cs->witness[v] = saved;
    }
}

/* (2c) ADVERSARIAL: are section 10's wires BOUND? Count and value gates
 *      pass for an UNDER-constrained gadget. Flip one section-10 wire at
 *      a time (0<->1, keeping booleanity) and require the system to
 *      become UNSATISFIED: a free digest bit would let a prover choose
 *      the CRH^ivk that binds the spend to its viewing key.
 *
 *      Probed: the 256 digest wires, and a deterministic stride across
 *      every wire section 10 allocated (round state, carries, XORs). */
static int spend_gate_sec10_probe(struct spend_gate_ctx *g)
{
    int failures = 0;
    memset(&g->sec10, 0, sizeof g->sec10);
    g->sec10.first_var = (g->nsec >= 10) ? g->sections[8].num_vars : 0;
    g->sec10.last_var  = (g->nsec >= 10) ? g->sections[9].num_vars : 0;
    if (g->synth_ok && g->nsec >= 10 && g->sec10.last_var > g->sec10.first_var) {
        size_t ignored = SIZE_MAX;

        /* The honest witness must satisfy the system before any mutation,
         * otherwise "flip detected" is vacuous; this also proves the cv
         * public input is the real value commitment (section 14 binds it). */
        PROVER_CHECK("honest witness satisfies the full 98777-constraint system",
                     cs_is_satisfied(&g->cs, &ignored));

        spend_gate_sec10_flip_digest(g);
        spend_gate_sec10_flip_internal(g);

        /* Restoring must return the system to satisfied. */
        PROVER_CHECK("witness restored after mutation probe",
                     cs_is_satisfied(&g->cs, &ignored));
    }
    return failures;
}

/* Prints the section-10 flip counts and checks that every digest wire and
 * every probed internal wire is bound. */
static int spend_gate_sec10_bound_checks(struct spend_gate_ctx *g)
{
    int failures = 0;
    printf("  section 10 wires %zu..%zu; single-bit flips detected: "
           "%zu/%zu digest, %zu/%zu strided internal\n",
           g->sec10.first_var, g->sec10.last_var,
           g->sec10.digest_detected, g->sec10.digest_tried,
           g->sec10.flips_detected, g->sec10.flips_tried);
    PROVER_CHECK("every section-10 digest wire is bound (a flipped digest bit "
                 "breaks the R1CS)",
                 g->sec10.digest_tried == 256 && g->sec10.digest_detected == 256);
    PROVER_CHECK("every probed section-10 internal wire is bound (no free "
                 "wire = no under-constrained gadget)",
                 g->sec10.flips_tried > 0 && g->sec10.flips_detected == g->sec10.flips_tried);
    return failures;
}

/* (2d) Sections 11..16 VALUE gate: derives g_d and pk_d = [ivk] g_d out of
 * circuit for the point and repr checks below. */
static int spend_gate_derive_gd_pkd(struct spend_gate_ctx *g)
{
    int failures = 0;
    /* (2d) Sections 11..16 VALUE gate, each against an out-of-circuit
     *      ground truth:
     *
     *        11  g_d          == GH("Zcash_gd", d)
     *        13  pk_d         == sapling_ivk_to_pkd(ivk, d)  (the reference
     *                            variable-base multiplication)
     *        14  cv           == sapling_value_commit(value, rcv), and the 64
     *                            value bits are the note's value little-endian
     *        15  repr(g_d)    == compressed g_d, bit for bit
     *        16  repr(pk_d)   == compressed pk_d, bit for bit
     *
     *      The cv/pk_d bindings are also covered by the satisfaction check
     *      above. */
    struct jub_point gd_pt;
    bool gd_derived = sapling_diversifier_to_gd(&gd_pt, g->wit.diversifier);
    if (gd_derived)
        jub_to_bytes(g->gd_bytes, &gd_pt);
    else
        memset(g->gd_bytes, 0, sizeof g->gd_bytes);
    g->pkd_derived = gd_derived
        && sapling_ivk_to_pkd(g->ivk_truncated, g->wit.diversifier, g->pkd_bytes);
    if (!g->pkd_derived)
        memset(g->pkd_bytes, 0, sizeof g->pkd_bytes);
    PROVER_CHECK("reference g_d and pk_d = [ivk] g_d derived out of circuit",
                 gd_derived && g->pkd_derived);
    return failures;
}

/* Section 11, 13 and 14 point wires: each decodes its reference encoding and
 * compares both coordinate wires. */
static int spend_gate_check_point_wires(struct spend_gate_ctx *g)
{
    int failures = 0;

    /* One helper for all three point-wire diffs (g_d, pk_d, cv): decode the
     * reference encoding and compare both coordinate wires. */
    struct point_wire_case {
        const char *label;
        const uint8_t *want;
        size_t x_var, y_var;
    };
    const struct point_wire_case point_cases[3] = {
        { "in-circuit g_d wire == GH(\"Zcash_gd\", d) (section 11)",
          g->gd_bytes,  g->probe.gd_x,  g->probe.gd_y },
        { "in-circuit pk_d wire == reference [ivk] g_d (section 13)",
          g->pkd_bytes, g->probe.pkd_x, g->probe.pkd_y },
        { "in-circuit cv wire == [value]G_v + [rcv]G_rcv (section 14)",
          g->cv_bytes,  g->probe.cv_x,  g->probe.cv_y },
    };
    for (size_t i = 0; i < 3; i++) {
        struct jub_point p;
        struct fr px, py;
        bool ok = g->synth_ok && jub_from_bytes(&p, point_cases[i].want);
        if (ok) {
            jub_get_x(&px, &p);
            jub_get_y(&py, &p);
            ok = point_cases[i].x_var < g->cs.num_vars
              && point_cases[i].y_var < g->cs.num_vars
              && fr_eq(&g->cs.witness[point_cases[i].x_var], &px)
              && fr_eq(&g->cs.witness[point_cases[i].y_var], &py);
        }
        PROVER_CHECK(point_cases[i].label, ok);
    }
    return failures;
}

/* Sections 15 and 16: the repr bits are the compressed g_d and pk_d. */
static int spend_gate_check_repr_wires(struct spend_gate_ctx *g)
{
    int failures = 0;
    struct fr one_fr;
    fr_one(&one_fr);

    /* repr(g_d) / repr(pk_d): Jubjub's compressed encoding is y with x's low
     * bit in the top bit, so repr's 256 little-endian bits ARE the bits of
     * the 32-byte encoding. */
    const struct { const char *label; const uint8_t *want; const size_t *bits; }
    repr_cases[2] = {
        { "repr(g_d) 256 bits == compressed g_d (section 15)",
          g->gd_bytes,  g->probe.gd_repr },
        { "repr(pk_d) 256 bits == compressed pk_d (section 16)",
          g->pkd_bytes, g->probe.pkd_repr },
    };
    for (size_t i = 0; i < 2; i++) {
        bool ok = g->synth_ok;
        for (size_t b = 0; b < 256 && ok; b++) {
            const size_t v = repr_cases[i].bits[b];
            bool want = ((repr_cases[i].want[b / 8] >> (b % 8)) & 1) == 1;
            ok = v < g->cs.num_vars
              && fr_eq(&g->cs.witness[v], &one_fr) == want;
        }
        PROVER_CHECK(repr_cases[i].label, ok);
    }
    return failures;
}

/* Section 14's 64 value bits, little-endian (the order section 17 hashes them in). */
static int spend_gate_check_value_bits(struct spend_gate_ctx *g)
{
    int failures = 0;
    struct fr one_fr;
    fr_one(&one_fr);

    /* Section 14's 64 value bits, little-endian (the order section 17
     * hashes them in). */
    bool ok = g->synth_ok;
    for (size_t b = 0; b < 64 && ok; b++) {
        const size_t v = g->probe.value_bit[b];
        bool want = ((g->wit.value >> b) & 1) == 1;
        ok = v < g->cs.num_vars && fr_eq(&g->cs.witness[v], &one_fr) == want;
    }
    PROVER_CHECK("64 value bits == note value little-endian (section 14)",
                 ok);
    return failures;
}

/* Section 20: the in-circuit cm wires equal the reference note commitment,
 * and cm.x equals the production sapling_compute_cm() output. */
static int spend_gate_check_cm_wire(struct spend_gate_ctx *g)
{
    int failures = 0;
    /* (2e) Sections 17 and 20 — the note commitment. Read the two points
     * back off the circuit's wires:
     *
     *        section 17  note_hash == PedersenHash(NoteCommitment,
     *                                 value(64) || repr(g_d) || repr(pk_d))
     *        section 20  cm        == note_hash + [rcm] G_rcm
     *
     *      Both references come from sapling_note_commitment_point(), a
     *      different algorithm from the in-circuit Montgomery windows. x AND
     *      y are compared. */
    g->cm_api_ok = g->synth_ok && g->pkd_derived
        && sapling_compute_cm(g->wit.diversifier, g->pkd_bytes, g->wit.value,
                              g->wit.rcm, g->cm_api);
    {
        g->cm_ref_ok = g->pkd_derived
            && sapling_note_commitment_point(g->wit.diversifier, g->pkd_bytes,
                                             g->wit.value, g->wit.rcm,
                                             &g->cm_ref_pt);
        PROVER_CHECK("reference note commitment derived out of circuit",
                     g->cm_ref_ok);

        struct fr cm_x, cm_y;
        bool cm_wire_ok = g->synth_ok && g->cm_ref_ok;
        if (cm_wire_ok) {
            jub_get_x(&cm_x, &g->cm_ref_pt);
            jub_get_y(&cm_y, &g->cm_ref_pt);
            cm_wire_ok = g->probe.cm_x < g->cs.num_vars
                      && g->probe.cm_y < g->cs.num_vars
                      && fr_eq(&g->cs.witness[g->probe.cm_x], &cm_x)
                      && fr_eq(&g->cs.witness[g->probe.cm_y], &cm_y);
        }
        PROVER_CHECK("in-circuit cm wire == note hash + [rcm] G_rcm "
                     "(section 20)", cm_wire_ok);

        /* The protocol's `cmu` (the note-commitment tree leaf) is this
         * x-coordinate; tie the wire to the production API. */
        struct fr cm_api_fr;
        bool cm_api_wire_ok = g->cm_api_ok
            && fr_from_bytes(&cm_api_fr, g->cm_api)
            && g->probe.cm_x < g->cs.num_vars
            && fr_eq(&g->cs.witness[g->probe.cm_x], &cm_api_fr);
        PROVER_CHECK("in-circuit cm.x == sapling_compute_cm() `cmu` "
                     "(section 20)", cm_api_wire_ok);
    }
    return failures;
}

/* Section 17: the note hash wire is the reference commitment minus [rcm] G_rcm,
 * checked x and y. */
static int spend_gate_check_note_hash_wire(struct spend_gate_ctx *g)
{
    int failures = 0;
    {
        /* Section 17's wire pair must be a real curve point carrying the
         * hash: subtract [rcm] G_rcm from the reference commitment and
         * compare. Subtraction keeps ONE reference for both sections. */
        struct fr grcm_x, grcm_y;
        sapling_note_commit_randomness_generator(&grcm_x, &grcm_y);
        bool hash_wire_ok = g->synth_ok && g->cm_ref_ok;
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
                    jub_scalar_mul(&rcm_pt, &g_rcm, g->wit.rcm);
                    jub_neg(&rcm_pt, &rcm_pt);
                    jub_add(&hash_pt, &g->cm_ref_pt, &rcm_pt);
                    struct fr hx, hy;
                    jub_get_x(&hx, &hash_pt);
                    jub_get_y(&hy, &hash_pt);
                    hash_wire_ok = g->probe.note_hash_x < g->cs.num_vars
                                && g->probe.note_hash_y < g->cs.num_vars
                                && fr_eq(&g->cs.witness[g->probe.note_hash_x], &hx)
                                && fr_eq(&g->cs.witness[g->probe.note_hash_y], &hy);
                }
            }
        }
        PROVER_CHECK("in-circuit note hash wire == "
                     "PedersenHash(NoteCommitment, note) (section 17)",
                     hash_wire_ok);
    }
    return failures;
}

/* (2f) end-to-end anchor: fold the witnessed path from the circuit's own cm.x
 * and compare with the anchor wire. */
static int spend_gate_check_anchor(struct spend_gate_ctx *g)
{
    int failures = 0;
    /* (2f) Sections 17..21 end to end: fold the witnessed authentication
     * path out of circuit from sapling_compute_cm()'s OWN cm.x and require
     * the circuit's anchor wire to equal it (a wrong handover between
     * sections 20 and 21 leaves both halves green). */
    {
        uint8_t anchor_ref[32];
        struct fr anchor_ref_fr;
        bool ok = g->cm_api_ok;
        if (ok) {
            uint8_t cur[32];
            memcpy(cur, g->cm_api, 32);
            for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
                uint8_t next[32];
                if (g->wit.auth_path_bits[d])
                    pedersen_merkle_hash(d, g->wit.auth_path[d], cur, next);
                else
                    pedersen_merkle_hash(d, cur, g->wit.auth_path[d], next);
                memcpy(cur, next, 32);
            }
            memcpy(anchor_ref, cur, 32);
            ok = fr_from_bytes(&anchor_ref_fr, anchor_ref)
              && g->probe.anchor < g->cs.num_vars
              && fr_eq(&g->cs.witness[g->probe.anchor], &anchor_ref_fr);
        }
        PROVER_CHECK("in-circuit anchor == out-of-circuit fold seeded from the "
                     "circuit's own cm.x (sections 17..21)", ok);
    }
    return failures;
}

/* Determinism: a second synthesis gives a byte-identical witness. */
static int spend_gate_check_determinism(struct spend_gate_ctx *g)
{
    int failures = 0;
    /* (3) Determinism: identical inputs => byte-identical witness. */
    struct constraint_system cs2;
    cs_init(&cs2);
    bool synth2 = sapling_spend_synthesize_traced(
        &cs2, &g->wit, &g->pub, NULL, 0, NULL, NULL);
    bool det_ok = synth2 && g->cs.num_vars == cs2.num_vars
        && g->cs.num_constraints == cs2.num_constraints
        && memcmp(g->cs.witness, cs2.witness,
                  g->cs.num_vars * sizeof(struct fr)) == 0;
    PROVER_CHECK("synthesis is deterministic (byte-identical witness)", det_ok);

    cs_free(&g->cs);
    cs_free(&cs2);
    return failures;
}

/* Sapling SPEND circuit port: shape + value + determinism gate.
 *
 * Params-free (pure R1CS synthesis, no proving key); pins the ported prefix
 * (sections 1..21) against ground truth:
 *   (1) cumulative constraint counts per section == the reference trace's
 *       cumulative boundaries;
 *   (2) the in-circuit nk / rk wires carry the reference-correct Jubjub
 *       points, nk also pinned to the librustzcash reference vector;
 *  (2b) section 10's 256 blake2s digest bits == the out-of-circuit CRH^ivk
 *       over the same preimage, and its 251 truncated bits == the pinned
 *       librustzcash ivk (a matching COUNT cannot see a wrong rotation
 *       constant or SIGMA row);
 *  (2c) every section-10 wire is BOUND: flipping any one (keeping
 *       booleanity) must make the R1CS unsatisfiable (count and value checks
 *       read only the honest witness and cannot see an UNDER-constrained
 *       gadget, which would let a prover choose its own ivk);
 *  (2d) sections 11..16, the note-content half: g_d == GH("Zcash_gd", d);
 *       pk_d == [ivk] g_d (the first variable-base multiplication);
 *       repr(g_d)/repr(pk_d) match the compressed encodings; cv is BOUND to
 *       public input 3/4, so the witness must carry the real
 *       [value]G_v + [rcv]G_rcv;
 *  (2e) sections 17..20, the note commitment: the section-17 hash point and
 *       the section-20 commitment point are diffed, x AND y, against the
 *       out-of-circuit table-driven Pedersen hash + Jubjub scalar mul, and
 *       cm.x is tied to sapling_compute_cm() (the note-commitment tree leaf);
 *  (2f) sections 17..21 end to end: the anchor wire is diffed against an
 *       out-of-circuit fold seeded from sapling_compute_cm()'s own output
 *       over the same witnessed path;
 *   (3) synthesis is deterministic (identical inputs => byte-identical witness).
 * Sections 22..28 are not yet ported, so this is a PARTIAL-prefix gate, not a
 * spend round-trip. Returns the number of failures (0 == green). */
static int spend_circuit_shape_gate(void)
{
    printf("\n--- H3: Sapling SPEND circuit port shape gate (sections 1-28) ---\n");
    int failures = 0;
    struct spend_gate_ctx g;

    failures += spend_gate_build_witness(&g);
    failures += spend_gate_derive_publics(&g);
    failures += spend_gate_synthesize(&g);
    failures += spend_gate_check_section_counts(&g);
    failures += spend_gate_check_section_deltas(&g);
    failures += spend_gate_check_nk_wire(&g);
    failures += spend_gate_check_rk_wire(&g);
    failures += spend_gate_check_ivk_value(&g);
    failures += spend_gate_check_ivk_bits(&g);
    failures += spend_gate_sec10_probe(&g);
    failures += spend_gate_sec10_bound_checks(&g);
    failures += spend_gate_derive_gd_pkd(&g);
    failures += spend_gate_check_point_wires(&g);
    failures += spend_gate_check_repr_wires(&g);
    failures += spend_gate_check_value_bits(&g);
    failures += spend_gate_check_cm_wire(&g);
    failures += spend_gate_check_note_hash_wire(&g);
    failures += spend_gate_check_anchor(&g);
    failures += spend_gate_check_determinism(&g);

    printf("--- end H3 shape gate (%d failure[s]) ---\n", failures);
    return failures;
}

/* Reference differential oracle (test-only librustzcash bridge). Runs FIRST
 * and unconditionally: params-free, so it gates even when ~/.zcash-params is
 * absent and the prover self-test below SKIPs. */
int groth16_spend_reference_oracle(void);

/* Standing differential parity oracle over a corpus of witnesses.
 * Params-free. Lives in tests/harness/src/groth16_spend_parity.c. */
int groth16_spend_parity_oracle(void);

/* Section 21: the 32-level Merkle authentication path (44224 constraints,
 * the largest spend-circuit section). Gated out of line: constraint count,
 * per-level breakdown, anchor value against an out-of-circuit fold, swap
 * sensitivity and wire boundness. Params-free. Lives in
 * tests/harness/src/groth16_merkle_path.c. */
int groth16_merkle_path_gate(void);

/* Adversarial + negative-control gate over the production native C23
 * prove -> independent verify round-trip, plus a proving-key-parser fuzz
 * spot-check and zeroization spot-checks. Requires proving params. Lives in
 * tests/harness/src/groth16_spend_adversarial.c. */
int groth16_spend_adversarial_gate(void);

int test_groth16_selfverify(void);
/* Output proof built through the public proving API, checked by the independent
 * consensus verifier and against a tampered copy. Runs only when the prover is
 * ready. Returns the failure count. */
static int prover_output_roundtrip_checks(void)
{
    int failures = 0;
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
    return failures;
}

/* ── BLAKE2s gadget (circuit_bits.c gadget_blake2s) ────────────────────── */

/* 21006 constraints for a 512-bit all-allocated input (circuit_bits.h). */
#define BLAKE2S_GADGET_512_CONSTRAINTS 21006u
#define BLAKE2S_GADGET_MAX_BYTES       65u

static const uint8_t BLAKE2S_PERS_IVK[8]  = { 'Z', 'c', 'a', 's', 'h', 'i', 'v', 'k' };
static const uint8_t BLAKE2S_PERS_NF[8]   = { 'Z', 'c', 'a', 's', 'h', '_', 'n', 'f' };
static const uint8_t BLAKE2S_PERS_ZERO[8] = { 0 };

static void fill_message(uint8_t *msg, size_t n)
{
    for (size_t i = 0; i < n; i++)
        msg[i] = (uint8_t)(i * 37u + 11u);
}

/* The witnessed value of a Boolean, read from the wire rather than the cached
 * cbit_value(), with the NOT view applied. */
static bool witness_bit(const struct constraint_system *cs, struct cbit b)
{
    if (b.kind == CBIT_CONSTANT)
        return b.constant;
    struct fr one_fr;
    fr_one(&one_fr);
    const bool on_wire = fr_eq(&cs->witness[b.var], &one_fr);
    return b.kind == CBIT_NOT ? !on_wire : on_wire;
}

/* LSB-first within each byte, as the gadget reads its input. */
static void message_to_cbits(struct constraint_system *cs, const uint8_t *msg,
                             size_t len, struct cbit *bits)
{
    for (size_t i = 0; i < len; i++)
        for (size_t b = 0; b < 8; b++)
            bits[i * 8 + b] = cbit_alloc(cs, ((msg[i] >> b) & 1u) != 0u);
}

/* Output bit q is digest bit q (byte q/8, bit q%8). */
static void cbits_to_digest(const struct constraint_system *cs,
                            const struct cbit *out, uint8_t digest[32])
{
    for (size_t k = 0; k < 32; k++) {
        uint8_t byte = 0;
        for (size_t b = 0; b < 8; b++)
            if (witness_bit(cs, out[k * 8 + b]))
                byte |= (uint8_t)(1u << b);
        digest[k] = byte;
    }
}

static bool native_blake2s_pers(uint8_t digest[32], const uint8_t pers[8],
                                const uint8_t *msg, size_t len)
{
    struct blake2s_ctx ctx;
    if (blake2s_init_personal(&ctx, 32, pers) != 0)
        return false;
    if (len > 0 && blake2s_update(&ctx, msg, len) != 0)
        return false;
    return blake2s_final(&ctx, digest, 32) == 0;
}

/* One gadget run over `len` allocated bytes: the witness-read digest must equal
 * the native BLAKE2s-256 of the same bytes and personalization, and the R1CS
 * must be satisfied. Returns the failure count. */
static int check_gadget_digest(const uint8_t *msg, size_t len,
                               const uint8_t pers[8], const char *label)
{
    int failures = 0;
    struct constraint_system cs;
    cs_init(&cs);
    struct cbit in[BLAKE2S_GADGET_MAX_BYTES * 8u];
    struct cbit out[256];
    message_to_cbits(&cs, msg, len, in);
    const bool ok = gadget_blake2s(&cs, in, len * 8u, pers, out);

    uint8_t got[32], want[32];
    cbits_to_digest(&cs, out, got);
    const bool native_ok = native_blake2s_pers(want, pers, msg, len);
    size_t bad = SIZE_MAX;
    const bool sat = cs_is_satisfied(&cs, &bad);
    PROVER_CHECK(label, ok && native_ok && sat
                 && memcmp(got, want, 32) == 0);
    cs_free(&cs);
    return failures;
}

static int gate_blake2s_gadget_matches_native(void)
{
    int failures = 0;
    uint8_t msg[BLAKE2S_GADGET_MAX_BYTES];
    fill_message(msg, sizeof msg);
    static const size_t lens[] = { 0, 1, 63, 64, 65 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        char label[128];
        snprintf(label, sizeof label,
                 "gadget_blake2s(\"Zcashivk\", %zu bytes) == native BLAKE2s-256",
                 lens[i]);
        failures += check_gadget_digest(msg, lens[i], BLAKE2S_PERS_IVK, label);
        snprintf(label, sizeof label,
                 "gadget_blake2s(\"Zcash_nf\", %zu bytes) == native BLAKE2s-256",
                 lens[i]);
        failures += check_gadget_digest(msg, lens[i], BLAKE2S_PERS_NF, label);
    }
    return failures;
}

/* BLAKE2s-256("") with zero personalization is the published vector already
 * pinned in test_sapling.c (test_sapling_blake2s_256). Returns the failure
 * count. */
static int gate_blake2s_gadget_literal_vector(void)
{
    int failures = 0;
    static const uint8_t want[32] = {
        0x69,0x21,0x7a,0x30, 0x79,0x90,0x80,0x94,
        0xe1,0x11,0x21,0xd0, 0x42,0x35,0x4a,0x7c,
        0x1f,0x55,0xb6,0x48, 0x2c,0xa1,0xa5,0x1e,
        0x1b,0x25,0x0d,0xfd, 0x1e,0xd0,0xee,0xf9
    };
    struct constraint_system cs;
    cs_init(&cs);
    struct cbit out[256];
    const bool ok = gadget_blake2s(&cs, NULL, 0, BLAKE2S_PERS_ZERO, out);
    uint8_t got[32];
    cbits_to_digest(&cs, out, got);
    PROVER_CHECK("gadget_blake2s(zero personalization, empty input) == "
                 "BLAKE2s-256(\"\") = 69217a30...eef9",
                 ok && memcmp(got, want, 32) == 0);
    cs_free(&cs);
    return failures;
}

/* The 512-bit all-allocated cost, measured around the gadget only. Returns the
 * failure count. */
static int gate_blake2s_gadget_cost(void)
{
    int failures = 0;
    uint8_t msg[64];
    fill_message(msg, sizeof msg);
    struct constraint_system cs;
    cs_init(&cs);
    struct cbit in[64 * 8u];
    message_to_cbits(&cs, msg, sizeof msg, in);
    struct cbit out[256];
    const size_t before = cs.num_constraints;
    const bool ok = gadget_blake2s(&cs, in, 64u * 8u, BLAKE2S_PERS_IVK, out);
    PROVER_CHECK("gadget_blake2s over 512 allocated bits costs exactly "
                 "21006 constraints",
                 ok && cs.num_constraints - before
                         == BLAKE2S_GADGET_512_CONSTRAINTS);
    cs_free(&cs);
    return failures;
}

/* Every refusal returns false before touching the system, and the accepted
 * zero-length input runs one empty block. Returns the failure count. */
static int gate_blake2s_gadget_refusals(void)
{
    int failures = 0;
    struct cbit in[8];
    for (size_t i = 0; i < 8; i++)
        in[i] = cbit_constant(false);
    struct cbit out[256];
    struct constraint_system cs;
    cs_init(&cs);

    PROVER_CHECK("NULL constraint system is refused",
                 !gadget_blake2s(NULL, in, 8, BLAKE2S_PERS_IVK, out));
    PROVER_CHECK("NULL personalization is refused",
                 !gadget_blake2s(&cs, in, 8, NULL, out));
    PROVER_CHECK("NULL output is refused",
                 !gadget_blake2s(&cs, in, 8, BLAKE2S_PERS_IVK, NULL));
    PROVER_CHECK("12 bits (not whole bytes) is refused",
                 !gadget_blake2s(&cs, in, 12, BLAKE2S_PERS_IVK, out));
    PROVER_CHECK("8 bits with NULL input is refused",
                 !gadget_blake2s(&cs, NULL, 8, BLAKE2S_PERS_IVK, out));
    PROVER_CHECK("refusals add no constraints",
                 cs.num_constraints == 0);
    PROVER_CHECK("0 bits with NULL input is accepted (empty message)",
                 gadget_blake2s(&cs, NULL, 0, BLAKE2S_PERS_IVK, out));
    cs_free(&cs);
    return failures;
}

static int gate_blake2s_gadget(void)
{
    printf("\n--- BLAKE2s gadget (circuit_bits.c gadget_blake2s) ---\n");
    int failures = 0;
    failures += gate_blake2s_gadget_matches_native();
    failures += gate_blake2s_gadget_literal_vector();
    failures += gate_blake2s_gadget_cost();
    failures += gate_blake2s_gadget_refusals();
    printf("--- end BLAKE2s gadget (%d failure[s]) ---\n", failures);
    return failures;
}

int test_groth16_selfverify(void)
{
    printf("\n=== Sapling prover -> consensus verifier capability ===\n");
    int failures = 0;

    failures += output_circuit_shape_gate();
    failures += groth16_spend_reference_oracle();
    failures += spend_circuit_shape_gate();
    failures += groth16_spend_parity_oracle();
    failures += groth16_merkle_path_gate();
    failures += gate_blake2s_gadget();

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

    if (zclassic_sapling_prover_is_ready())
        failures += prover_output_roundtrip_checks();

    /* Adversarial + negative-control gate over the production SPEND
     * prove->verify round-trip (needs proving readiness). */
    if (zclassic_sapling_prover_is_ready())
        failures += groth16_spend_adversarial_gate();

    /* Non-gating: emit native C23 circuit baseline counts (needs params). */
    if (initialized)
        native_circuit_baseline();

    printf("Sapling prover capability: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
