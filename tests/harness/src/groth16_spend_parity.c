/* Sapling SPEND-circuit standing differential parity oracle (test-only).
 *
 * Portions interoperate with librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Fixed
 * externally-derived reference bytes are checked in; no Rust code is fetched,
 * built or linked.
 *
 * Standing differential parity oracle. The C-must-beat-Rust ratchet requires
 * it before any native-crypto claim. The H2 oracle (groth16_spend_oracle.c)
 * proves the key-derivation / commitment / nullifier building blocks match
 * librustzcash for one KAT witness; the H3 shape gate
 * (test_groth16_selfverify.c) pins per-section constraint boundaries for
 * that witness. This oracle generalizes both: over a corpus of deterministic
 * spend witnesses it re-runs the native C23 spend synthesis and asserts:
 *
 *   (A) Section-boundary parity (auto-tightening). Each recorded section's
 *       cumulative constraint count equals the pinned reference trace
 *       boundary (the 28-section table from commit 06da3b9...). Only the
 *       n_sections actually recorded are compared, so new sections are
 *       validated against REF_SECTIONS[i] with no edit here.
 *
 *   (B) Structural invariance. An R1CS circuit's shape must not depend on
 *       witness values; every corpus witness must match witness 0's section
 *       shape (constraints/vars/inputs per section).
 *
 *   (C) Per-wire value parity vs the external KAT where available: the
 *       in-circuit nk wire ([nsk] ProofGenerationKeyGenerator, section 7)
 *       against ground truth for the pinned witness; ak (section 1) and rk
 *       (section 4) against native scalar derivations.
 *
 *   (D) Determinism. Re-synthesizing an identical witness yields a
 *       byte-identical witness vector.
 *
 *   (E) R1CS satisfaction, the coefficient-level check: every emitted
 *       constraint is evaluated against the honest witness and must satisfy
 *       A*B==C (bellman's TestConstraintSystem::which_is_unsatisfied).
 *       Counts and probed wires cannot see a wrong coefficient.
 *
 * On the first divergence the oracle prints (witness index, section name,
 * expected vs actual).
 *
 * The oracle is params-free and hermetic (Jubjub/blake2s/Pedersen crypto +
 * R1CS synthesis; no ~/.zcash-params), so it gates unconditionally. It
 * proves parity only over the sections currently ported; the scoreboard
 * (ported prefix vs the 98777-constraint target) is documented in
 * docs/quality/GROTH16-SPEND-PARITY.md.
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

/* Reference nk for one corpus witness. The checked-in KAT supplies it for
 * the one witness whose nsk is pinned; other entries report no external
 * reference rather than compare native code against itself. */
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
 * ONE). The native port is correct for a prefix iff its per-section
 * cumulative counts equal this table over that prefix. */
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

/* Deterministic corpus. Index 0 is the pinned H2 KAT witness (ties the nk
 * wire to the librustzcash vector); 1..N-1 are distinct canonical witnesses
 * (small Fs scalars < 2^252 so decomposition and full reduction agree). */
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
        /* Distinct, canonical, small scalars, deterministic per index. */
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
    /* Note commitment randomness (sections 18/19/20), kept a canonical small
     * Fs scalar (the in-circuit decomposition keeps 252 bits, the
     * out-of-circuit jub_scalar_mul reads 256). A zero rcm would select the
     * identity slot in every window. */
    w->rcm[0] = (uint8_t)(idx * 13u + 0x5cu);
    w->rcm[1] = (uint8_t)(idx * 3u + 0x23u);

    /* The authentication path section 21 folds cm.x up (32 siblings + 32
     * position bits). Siblings come from a Pedersen Merkle hash (canonical
     * Fr); position bits are not a function of depth parity alone, so a
     * swapped-every-level bug is visible. */
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t a[32] = {0}, b[32] = {0};
        a[0] = (uint8_t)(0x10u + d);
        a[1] = (uint8_t)(0x5bu + idx);
        b[0] = (uint8_t)(d * 7u);
        b[3] = 0x11;
        pedersen_merkle_hash(0, a, b, w->auth_path[d]);
        w->auth_path_bits[d] = ((((d * 5u) + (d / 3u)) ^ idx) & 1u) != 0u;
    }

    /* Section 11 witnesses g_d = GH("Zcash_gd", d) and section 12 requires it
     * not small order, so scan d from 0 until group_hash hits a point. */
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
    /* cv is bound to public inputs 3/4 by section 14. */
    if (!sapling_value_commit(w->value, w->rcv, pw->pub.cv))
        return;                         /* pw->ok stays false */
    /* Sections 22 and 28 bind the anchor and packed nullifier, so the whole
     * public-input vector must be the honest one. */
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
 * (core/modules/sapling/src/pedersen_hash.c, Edwards coordinates) over the 6
 * NoteCommitment personalization bits plus value(64) || repr(g_d) ||
 * repr(pk_d). The circuit reaches the same point through Montgomery window
 * lookups, so agreement is a differential between two algorithms.
 * Section 20's reference is the production sapling_note_commitment_point(). */
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

/* Reference section-21 anchor: fold the witnessed authentication path over
 * the same leaf (the note commitment's x-coordinate, sections 17..20's
 * output) with the out-of-circuit pedersen_merkle_hash. */
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

/* Public entry point: standing differential parity oracle for the Sapling
 * spend circuit. Returns the number of failures (0 == green). Non-skippable, params-free. */
int groth16_spend_parity_oracle(void);
#define pw (*pw_storage)
#define cs (*cs_storage)
#define probe (*probe_storage)
#define label (*label_storage)
#define flagged (*flag_storage)
#define failures (*failure_count)
#define sections (*sections_storage)
#define shape0 (*shape_storage)
#define nsec0 (*nsec_storage)
#define have_shape0 (*have_shape_storage)
#define nk_ref (*nk_ref_storage)
#define pkd_ref (*pkd_ref_storage)
#define cm_api (*cm_api_storage)
static void parity_check_reference_boundaries(
    unsigned c, const struct spend_section_shape (*sections_storage)[REF_NUM_SECTIONS],
    size_t nsec,
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
        /* (A) Section-boundary parity vs the reference, auto-tightening: only
         *     the `nsec` recorded sections are diffed. */
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
}

static void parity_check_corpus_shape_invariance(
    unsigned c, const struct spend_section_shape (*sections_storage)[REF_NUM_SECTIONS],
    size_t nsec, struct spend_section_shape (*shape_storage)[REF_NUM_SECTIONS],
    size_t *nsec_storage, bool *have_shape_storage,
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
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
}

static void parity_check_external_nk_wire(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, const struct spend_wire_probe *probe_storage,
    const uint8_t (*nk_ref_storage)[32], bool have_nk_ref,
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
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
}

static void parity_check_signing_and_randomized_key_wires(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, const struct spend_wire_probe *probe_storage,
    char (*label_storage)[160], int *failure_count)
{
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
}

static bool parity_check_note_reference_points(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, const struct spend_wire_probe *probe_storage,
    uint8_t (*pkd_ref_storage)[32],
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
        /* Sections 11/13/14/17/20: the note-content points, per witness. pk_d
         * is the output of the circuit's only variable-base multiplication;
         * cv is the first public input past rk. References come from the
         * independent scalar implementations (group_hash / ivk_to_pkd /
         * value_commit), not the circuit. */
        uint8_t nk_for_ivk[32], ivk_ref[32];
        sapling_nsk_to_nk(pw.wit.nsk, nk_for_ivk);
        sapling_crh_ivk(pw.wit.ak, nk_for_ivk, ivk_ref);

        struct jub_point gd_ref_pt;
        uint8_t gd_ref[32], cv_ref[32];
        bool refs_ok = sapling_diversifier_to_gd(&gd_ref_pt, pw.wit.diversifier);
        if (refs_ok) {
            jub_to_bytes(gd_ref, &gd_ref_pt);
            refs_ok = sapling_ivk_to_pkd(ivk_ref, pw.wit.diversifier, pkd_ref)
                   && sapling_value_commit(pw.wit.value, pw.wit.rcv, cv_ref);
        }

        /* Sections 17/20: the note-content Pedersen hash and randomized note
         * commitment from the out-of-circuit table-driven Pedersen hash +
         * Jubjub scalar mul, compressed to join the same comparison. */
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
    return refs_ok;
}

static bool parity_check_note_commitment_api_wire(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, const struct spend_wire_probe *probe_storage,
    const uint8_t (*pkd_ref_storage)[32], bool refs_ok, uint8_t (*cm_api_storage)[32],
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
        /* Section 20 tied to the production note-commitment API:
         * sapling_compute_cm() (the wallet/output-proof commitment; cmu is
         * its x-coordinate) must agree with the circuit's cm.x wire. */
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
    return cm_api_ok;
}

static void parity_check_note_commitment_anchor_handover(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, const struct spend_wire_probe *probe_storage,
    const uint8_t (*cm_api_storage)[32], bool cm_api_ok,
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
        /* Sections 17..21 end to end: fold the witnessed authentication path
         * out of circuit from sapling_compute_cm()'s own leaf and require the
         * circuit's anchor wire to match; this checks the section 20 -> 21
         * handover, which neither half proves alone. */
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
}

static void parity_check_compressed_key_representation(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, const struct spend_wire_probe *probe_storage,
    const uint8_t (*nk_ref_storage)[32], bool have_nk_ref,
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
        /* Sections 8/9: the EdwardsPoint::repr bit wires. repr's 256 bits
         * (y[0..255] then x[0]) are the point's 32-byte compressed encoding,
         * LSB first; for nk that is librustzcash's own output, so this is a
         * per-witness differential. */
        bool ak_repr_ok = true, nk_repr_ok = true;
        for (size_t b = 0; b < 256; b++) {
            bool want_ak = (pw.wit.ak[b / 8] >> (b % 8)) & 1;
            bool want_nk = have_nk_ref && ((nk_ref[b / 8] >> (b % 8)) & 1);
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
         * runs only where the reference exists (linked librustzcash or the
         * baked KAT witness). repr(ak) comes from the witness and stays
         * unconditional. */
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
}

static void parity_check_honest_witness_satisfaction(
    unsigned c, const struct constraint_system *cs_storage,
    bool *flag_storage, char (*label_storage)[160], int *failure_count)
{
        /* (E) R1CS SATISFACTION, the coefficient-level check: (A) compares
         *     counts and (C) probes three wires, neither sees a wrong
         *     coefficient in a correctly-shaped constraint. Assert A*B==C
         *     over the real witness for every emitted constraint. */
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
}

static void parity_check_witness_synthesis_determinism(
    unsigned c, const struct parity_witness *pw_storage,
    const struct constraint_system *cs_storage, char (*label_storage)[160],
    int *failure_count)
{
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
}

#undef cm_api
#undef pkd_ref
#undef nk_ref
#undef have_shape0
#undef nsec0
#undef shape0
#undef sections
#undef failures
#undef flagged
#undef label
#undef probe
#undef cs
#undef pw

int groth16_spend_parity_oracle(void)
{
    printf("\n--- H4: Sapling SPEND standing differential parity oracle ---\n");
    int failures = 0;

    /* Reference table self-consistency: strictly increasing, ending at the trace total. */
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

        parity_check_reference_boundaries(c, &sections, nsec, &flagged, &label, &failures);

        parity_check_corpus_shape_invariance(c, &sections, nsec, &shape0,
            &nsec0, &have_shape0, &flagged, &label, &failures);

        /* (C) Per-wire value parity. */
        /* nk wire vs the librustzcash reference (the differential). */
        uint8_t nk_ref[32];
        const bool have_nk_ref = parity_reference_nk(pw.wit.nsk, nk_ref);
        parity_check_external_nk_wire(c, &pw, &cs, &probe, &nk_ref,
            have_nk_ref, &flagged, &label, &failures);

        parity_check_signing_and_randomized_key_wires(c, &pw, &cs, &probe,
            &label, &failures);

        uint8_t pkd_ref[32];
        bool refs_ok = parity_check_note_reference_points(c, &pw, &cs, &probe,
            &pkd_ref, &flagged, &label, &failures);

        uint8_t cm_api[32];
        bool cm_api_ok = parity_check_note_commitment_api_wire(c, &pw, &cs, &probe,
            &pkd_ref, refs_ok, &cm_api, &flagged, &label, &failures);

        parity_check_note_commitment_anchor_handover(c, &pw, &cs, &probe,
            &cm_api, cm_api_ok, &flagged, &label, &failures);

        parity_check_compressed_key_representation(c, &pw, &cs, &probe,
            have_nk_ref ? &nk_ref : NULL, have_nk_ref, &flagged, &label, &failures);

        parity_check_honest_witness_satisfaction(c, &cs, &flagged, &label, &failures);

        parity_check_witness_synthesis_determinism(c, &pw, &cs, &label, &failures);
        cs_free(&cs);
    }

    /* Index-0 tie: corpus witness 0 nk must equal the baked SPEND_ORACLE_KAT_NK. */
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
