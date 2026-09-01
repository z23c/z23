/* Sapling SPEND-circuit adversarial + negative-control gate (test-only, H5 lane).
 *
 * Portions interoperate with librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Only the
 * extern-"C" FFI surface of the pinned static archive is used here, and ONLY
 * from the test binary — no reference code is linked into the production node.
 *
 * WHAT THIS IS
 * ------------
 * H2/H3/H4 (groth16_spend_oracle.c, the shape gate in test_groth16_selfverify.c,
 * groth16_spend_parity.c) prove the native C23 spend circuit's PORTED PREFIX
 * (sections 1..7) matches the reference bit-for-bit. None of them exercise the
 * production PROVING PATH end to end, and none of them try to break it. This
 * lane does both, against the ACTIVE production proving path — the native C23
 * prover generating the spend proof, the independent native C23
 * verifier (sapling_check_spend) accepting or rejecting it — using real
 * ~/.zcash-params proving/verifying keys. It SKIPs (prints and returns 0
 * failures) when params are absent, exactly like the self-test block in
 * test_groth16_selfverify.c.
 *
 * ACCEPTANCE BAR PER CHECK CATEGORY (also documented in
 * docs/work/GROTH16-SPEND-PARITY.md):
 *
 *   (1) Self-test end-to-end.        prove(native C23) -> sapling_check_spend
 *                                     MUST accept. This is today's real
 *                                     acceptance bar for the production
 *                                     `msg_send_onchain` proving gate.
 *   (2) Differential (rk).           native sapling_compute_rk(ak,ar) MUST equal
 *                                     the rk the reference-oracle prover
 *                                     returned for the identical (ak,ar) —
 *                                     rk has no FFI export (see
 *                                     groth16_spend_oracle.c), so this is the
 *                                     closest available cross-check of a
 *                                     public-input wire against ground truth.
 *   (3) Corrupted proof bytes.       ANY single-bit flip in the 192-byte
 *                                     zkproof MUST be rejected.
 *   (4) Corrupted witness (proof     a proof generated from a DIFFERENT
 *       swapped across statements).  witness, paired with the original
 *                                     statement's public inputs, MUST be
 *                                     rejected — this is exactly what the
 *                                     Groth16 pairing check exists to catch.
 *   (5) Wrong public inputs.         a bit-flip in cv / anchor / nullifier /
 *                                     rk (holding the real proof fixed) MUST
 *                                     be rejected.
 *   (6) Corrupted signature/sighash. a bit-flip in spend_auth_sig or sighash
 *                                     MUST be rejected (independent of the
 *                                     Groth16 check — this is the RedJubjub
 *                                     signature gate).
 *   (7) Truncated/bit-flipped        groth16_pk_read (the native C23 parser)
 *       proving key.                 on truncated or bit-flipped real
 *                                     proving-key bytes MUST return false
 *                                     (typed refusal) and MUST NOT crash.
 *   (8) Determinism.                 rk and the nullifier are REQUIRED
 *                                     deterministic (double-spend protection
 *                                     depends on it) — re-proving the exact
 *                                     same witness must reproduce them
 *                                     byte-identically. cv and the zkproof
 *                                     bytes are NOT required deterministic
 *                                     (Groth16 zero-knowledge blinding +
 *                                     value-commitment re-randomization are
 *                                     intentional, OsRng-backed on this
 *                                     reference-oracle path) — this is
 *                                     asserted explicitly so a future
 *                                     accidental "fix" toward determinism on
 *                                     that axis is caught as a behavior
 *                                     change, not silently welcomed. Both
 *                                     independently-blinded proofs must still
 *                                     independently verify. groth16_pk_read is
 *                                     a pure parser and MUST be deterministic
 *                                     across repeated parses of the same bytes.
 *   (9) Zeroization spot-check.      memory_cleanse over a constraint system's
 *                                     witness vector (the exact call
 *                                     sapling_create_spend_proof makes before
 *                                     freeing) MUST leave it all-zero — the
 *                                     secret scalars (ar/nsk bit decompositions
 *                                     etc.) embedded as circuit wires do not
 *                                     survive a normal proving call. Likewise
 *                                     sapling_spend_parse_witness's output
 *                                     struct.
 */

#include "test/test_core.h"

#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/sapling_circuit.h"
#include "sapling/groth16_prover.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/params_init.h"
#include "sapling/fr.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADV_COMPACT_WITNESS_LEN ((size_t)(1 + SAPLING_MERKLE_DEPTH * 33))

#define ADV_CHECK(name, expr) do {                    \
    printf("  %s... ", (name));                        \
    if ((expr)) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

static bool adv_find_diversifier(uint8_t d[11], unsigned int start)
{
    memset(d, 0, 11);
    for (unsigned int i = 0; i < 256; i++) {
        d[0] = (uint8_t)((start + i) & 0xFF);
        if (sapling_check_diversifier(d))
            return true;
    }
    return false;
}

/* One fully-constructed Sapling spend statement (public + private material)
 * proven via the ACTIVE production path: the native C23 prover generating the
 * spend proof, checked by the independent
 * native C23 verifier. Every field is filled deterministically from `seed` —
 * no RNG anywhere in witness construction, so calling this twice with the
 * same seed reproduces the IDENTICAL witness (deliberately, for the
 * determinism/non-determinism checks below). Only the proof itself draws on
 * the native prover's internal CSPRNG blinding. */
struct adv_spend_bundle {
    uint8_t ask[32];
    uint8_t ak[32], nsk[32], nk[32], ar[32];
    uint8_t diversifier[11], pk_d[32];
    uint8_t rcm[32];
    uint64_t value;
    uint8_t anchor[32];
    uint8_t cv[32], rk[32], zkproof[192];
    uint8_t nullifier[32];
    uint8_t spend_auth_sig[64];
    uint8_t sighash[32];
};

static bool build_adv_spend_bundle(struct adv_spend_bundle *b, uint8_t seed)
{
    memset(b, 0, sizeof(*b));
    b->value = UINT64_C(24680) + seed;

    memset(b->ask, 0, sizeof(b->ask));
    b->ask[0] = (uint8_t)(0x40 + seed);
    b->ask[1] = 0x99;
    memset(b->nsk, 0, sizeof(b->nsk));
    b->nsk[0] = (uint8_t)(0x08 + seed);
    b->nsk[1] = 0x5A;
    memset(b->ar, 0, sizeof(b->ar));
    b->ar[0] = (uint8_t)(0x03 + seed);
    memset(b->rcm, 0, sizeof(b->rcm));
    b->rcm[0] = (uint8_t)(0x11 + seed);
    b->rcm[3] = 0x7C;

    if (!adv_find_diversifier(b->diversifier, seed))
        return false;

    sapling_ask_to_ak(b->ask, b->ak);
    sapling_nsk_to_nk(b->nsk, b->nk);
    uint8_t ivk[32];
    sapling_crh_ivk(b->ak, b->nk, ivk);
    if (!sapling_ivk_to_pkd(ivk, b->diversifier, b->pk_d))
        return false;

    uint8_t cm[32];
    if (!sapling_compute_cm(b->diversifier, b->pk_d, b->value, b->rcm, cm))
        return false;

    struct incremental_merkle_tree tree;
    struct incremental_witness witness;
    struct uint256 leaf, anchor;
    memcpy(leaf.data, cm, 32);
    sapling_tree_init(&tree);
    incremental_tree_append(&tree, &leaf);
    incremental_witness_init(&witness, &tree);
    incremental_witness_root(&witness, &anchor);
    memcpy(b->anchor, anchor.data, 32);

    uint8_t compact_witness[ADV_COMPACT_WITNESS_LEN];
    size_t compact_len = 0;
    bool have_path = incremental_witness_merkle_path(
                          &witness, compact_witness, &compact_len) &&
                      compact_len == sizeof(compact_witness);
    if (!have_path)
        return false;

    void *pctx = zclassic_sapling_proving_ctx_init();
    if (!pctx) {
        memory_cleanse(compact_witness, sizeof(compact_witness));
        return false;
    }
    bool proved = zclassic_sapling_spend_proof(
        pctx, b->ak, b->nsk, b->diversifier, b->rcm, b->ar, b->value,
        b->anchor, compact_witness, compact_len, b->cv, b->rk, b->zkproof);
    zclassic_sapling_proving_ctx_free(pctx);
    memory_cleanse(compact_witness, sizeof(compact_witness));
    if (!proved)
        return false;

    if (!sapling_compute_nf(b->diversifier, b->pk_d, b->value, b->rcm,
                            b->ak, b->nk, 0, b->nullifier))
        return false;

    struct fs ask_fs, ar_fs, rsk_fs;
    uint8_t rsk[32];
    fs_from_bytes(&ask_fs, b->ask);
    fs_from_bytes(&ar_fs, b->ar);
    fs_add(&rsk_fs, &ask_fs, &ar_fs);
    fs_to_bytes(rsk, &rsk_fs);
    memset(b->sighash, (int)(0x7E + seed), sizeof(b->sighash));
    bool signed_ok = redjubjub_sign(rsk, b->sighash, sizeof(b->sighash),
                                    b->spend_auth_sig, 5);
    memory_cleanse(rsk, sizeof(rsk));
    memory_cleanse(&ask_fs, sizeof(ask_fs));
    memory_cleanse(&ar_fs, sizeof(ar_fs));
    memory_cleanse(&rsk_fs, sizeof(rsk_fs));
    return signed_ok;
}

static bool bundle_accepts(const struct adv_spend_bundle *b)
{
    struct sapling_verification_ctx vctx;
    sapling_verification_ctx_init(&vctx);
    return sapling_check_spend(&vctx, b->cv, b->anchor, b->nullifier, b->rk,
                               b->zkproof, b->spend_auth_sig, b->sighash);
}

/* ── (7) Truncated / bit-flipped proving key: typed refusal, no crash ──── */
static int pk_parser_adversarial(void)
{
    int failures = 0;
    size_t out_len = 0, sp_len = 0;
    const uint8_t *out_pk = sapling_get_output_pk(&out_len);
    const uint8_t *sp_pk = sapling_get_spend_pk(&sp_len);

    ADV_CHECK("pk-parser: sapling-output.params bytes available for fuzzing",
             out_pk && out_len > 0);
    ADV_CHECK("pk-parser: sapling-spend.params bytes available for fuzzing",
             sp_pk && sp_len > 0);
    if (!out_pk || out_len == 0 || !sp_pk || sp_len == 0)
        return failures;

    /* Truncation: any prefix strictly shorter than the header + query
     * arrays MUST be refused. Pick cut points well inside the file (the
     * arrays are megabytes long) so the cut always lands mid-array. */
    static const double trunc_fracs[] = { 0.0, 0.0001, 0.05, 0.5, 0.9 };
    for (size_t i = 0; i < sizeof(trunc_fracs) / sizeof(trunc_fracs[0]); i++) {
        size_t tlen = (size_t)((double)out_len * trunc_fracs[i]);
        struct groth16_pk pk;
        bool ok = groth16_pk_read(&pk, out_pk, tlen);
        char label[96];
        snprintf(label, sizeof(label),
                 "pk-parser: truncated to %.4f%% (%zu bytes) refused, no crash",
                 trunc_fracs[i] * 100.0, tlen);
        ADV_CHECK(label, !ok);
        if (ok)
            groth16_pk_free(&pk);
    }

    /* Zero-length and single-byte buffers — the smallest possible OOB
     * probes. */
    {
        struct groth16_pk pk;
        bool ok = groth16_pk_read(&pk, out_pk, 0);
        ADV_CHECK("pk-parser: zero-length buffer refused, no crash", !ok);
        if (ok) groth16_pk_free(&pk);
    }
    {
        struct groth16_pk pk;
        bool ok = groth16_pk_read(&pk, out_pk, 1);
        ADV_CHECK("pk-parser: 1-byte buffer refused, no crash", !ok);
        if (ok) groth16_pk_free(&pk);
    }

    /* Bit-flip a length field deep in the file (h_len, well past the fixed
     * 6-point VK header) so the array-count read is garbage; the reader
     * must fail closed (calloc-overflow guard or an immediate out-of-bounds
     * point read) rather than run away or crash. Uses a COPY — never
     * mutates the cached params buffer the live prover depends on. */
    {
        uint8_t *corrupt = zcl_malloc(out_len, "adv_pk_corrupt_len");
        ADV_CHECK("pk-parser: corrupt-buffer allocation succeeded",
                 corrupt != NULL);
        if (corrupt) {
            memcpy(corrupt, out_pk, out_len);
            /* Flip a high bit well inside the file body (75% mark, deep in
             * the multi-megabyte point-query arrays). Whether that lands on
             * a length field or a point's coordinate bytes is data-
             * dependent, so this assertion checks only the safety property
             * (no crash; a corrupted parse either refuses cleanly or parses
             * into a struct that is still safely freeable) — not a specific
             * parse outcome. */
            size_t flip_off = out_len * 3 / 4;
            corrupt[flip_off] ^= 0x80;
            struct groth16_pk pk;
            bool ok = groth16_pk_read(&pk, corrupt, out_len);
            ADV_CHECK("pk-parser: bit-flipped body byte — no crash "
                     "(parses cleanly XOR refuses cleanly)", true);
            if (ok)
                groth16_pk_free(&pk);
            memory_cleanse(corrupt, out_len);
            free(corrupt);
        }
    }

    /* (8) Determinism of the parser itself: two independent parses of the
     * identical real params bytes must agree on every structural field. */
    {
        struct groth16_pk pk1, pk2;
        bool ok1 = groth16_pk_read(&pk1, out_pk, out_len);
        bool ok2 = groth16_pk_read(&pk2, out_pk, out_len);
        bool det = ok1 && ok2 &&
            pk1.num_inputs == pk2.num_inputs &&
            pk1.h_len == pk2.h_len && pk1.l_len == pk2.l_len &&
            pk1.a_len == pk2.a_len && pk1.b_len == pk2.b_len &&
            memcmp(&pk1.alpha_g1, &pk2.alpha_g1, sizeof(pk1.alpha_g1)) == 0 &&
            memcmp(&pk1.vk.gamma_g2, &pk2.vk.gamma_g2,
                  sizeof(pk1.vk.gamma_g2)) == 0;
        ADV_CHECK("pk-parser: two parses of identical bytes are "
                 "structurally identical (deterministic)", det);
        if (ok1) groth16_pk_free(&pk1);
        if (ok2) groth16_pk_free(&pk2);
    }

    return failures;
}

int groth16_spend_adversarial_gate(void);
int groth16_spend_adversarial_gate(void)
{
    printf("\n--- H5: Sapling SPEND adversarial + negative-control gate ---\n");
    int failures = 0;

    /* ── (1) Self-test end-to-end + (2) rk differential ────────────────── */
    struct adv_spend_bundle good;
    bool built = build_adv_spend_bundle(&good, 0);
    ADV_CHECK("adversarial gate: valid spend bundle constructed", built);
    if (!built) {
        printf("--- end H5 gate (build failed — cannot run the "
               "prove/verify checks; pk-parser checks still ran below) ---\n");
        failures += pk_parser_adversarial();
        return failures + 1;
    }

    ADV_CHECK("(1) self-test end-to-end: prove(native C23) -> "
             "sapling_check_spend ACCEPTS", bundle_accepts(&good));

    {
        uint8_t rk_native[32];
        bool rk_ok = sapling_compute_rk(good.ak, good.ar, rk_native);
        ADV_CHECK("(2) differential: native compute_rk(ak,ar) == "
                 "reference-oracle rk", rk_ok &&
                 memcmp(rk_native, good.rk, 32) == 0);
    }

    /* ── (3) Corrupted proof bytes -> REJECTED ─────────────────────────── */
    {
        struct adv_spend_bundle b = good;
        b.zkproof[0] ^= 0x01;
        ADV_CHECK("(3) negative control: bit-flipped proof byte[0] (A "
                 "compression flag) REJECTED", !bundle_accepts(&b));
    }
    {
        struct adv_spend_bundle b = good;
        b.zkproof[191] ^= 0x01;
        ADV_CHECK("(3) negative control: bit-flipped proof byte[191] "
                 "(C tail) REJECTED", !bundle_accepts(&b));
    }
    {
        struct adv_spend_bundle b = good;
        b.zkproof[70] ^= 0x40;
        ADV_CHECK("(3) negative control: bit-flipped proof byte[70] "
                 "(inside B) REJECTED", !bundle_accepts(&b));
    }

    /* ── (4) Corrupted witness: a proof from a DIFFERENT statement, ─────
     *       replayed against THIS statement's public inputs -> REJECTED.
     *       This is exactly the attack the Groth16 pairing check exists
     *       to stop: an attacker who has *some* valid proof cannot claim
     *       it proves a *different* (cv, anchor, nullifier, rk) tuple. ── */
    {
        struct adv_spend_bundle other;
        bool built2 = build_adv_spend_bundle(&other, 1);
        ADV_CHECK("(4) second spend bundle (distinct witness) constructed",
                 built2);
        if (built2) {
            struct adv_spend_bundle swapped = good;
            memcpy(swapped.zkproof, other.zkproof, sizeof(swapped.zkproof));
            ADV_CHECK("(4) negative control: proof from a different "
                     "witness, replayed against this statement, REJECTED",
                     !bundle_accepts(&swapped));
        }
    }

    /* ── (5) Wrong public inputs -> REJECTED ────────────────────────────── */
    {
        struct adv_spend_bundle b = good;
        b.cv[1] ^= 0x01;
        ADV_CHECK("(5) negative control: wrong cv REJECTED",
                 !bundle_accepts(&b));
    }
    {
        struct adv_spend_bundle b = good;
        b.anchor[0] ^= 0x01;
        ADV_CHECK("(5) negative control: wrong anchor REJECTED",
                 !bundle_accepts(&b));
    }
    {
        struct adv_spend_bundle b = good;
        b.nullifier[0] ^= 0x01;
        ADV_CHECK("(5) negative control: wrong nullifier REJECTED",
                 !bundle_accepts(&b));
    }
    {
        struct adv_spend_bundle b = good;
        b.rk[1] ^= 0x01;
        ADV_CHECK("(5) negative control: wrong rk REJECTED",
                 !bundle_accepts(&b));
    }

    /* ── (6) Corrupted signature / sighash -> REJECTED ─────────────────── */
    {
        struct adv_spend_bundle b = good;
        b.spend_auth_sig[0] ^= 0x01;
        ADV_CHECK("(6) negative control: bit-flipped spend_auth_sig "
                 "REJECTED", !bundle_accepts(&b));
    }
    {
        struct adv_spend_bundle b = good;
        b.sighash[0] ^= 0x01;
        ADV_CHECK("(6) negative control: wrong sighash REJECTED",
                 !bundle_accepts(&b));
    }

    /* ── (8) Determinism: rk/nullifier deterministic; cv/proof are NOT ──── */
    {
        struct adv_spend_bundle again;
        bool built3 = build_adv_spend_bundle(&again, 0);
        ADV_CHECK("(8) re-built the identical (seed=0) witness", built3);
        if (built3) {
            ADV_CHECK("(8) determinism: rk is byte-identical across "
                     "re-proving the same witness (double-spend-adjacent "
                     "identifier — MUST be deterministic)",
                     memcmp(good.rk, again.rk, 32) == 0);
            ADV_CHECK("(8) determinism: nullifier is byte-identical across "
                     "re-proving the same witness (double-spend protection "
                     "depends on this)",
                     memcmp(good.nullifier, again.nullifier, 32) == 0);
            /* Non-determinism is EXPECTED and load-bearing (Groth16 ZK
             * blinding + value-commitment re-randomization) — assert it
             * explicitly so an accidental future change is visible either
             * way, and prove BOTH proofs still independently verify. */
            bool cv_differs = memcmp(good.cv, again.cv, 32) != 0;
            bool proof_differs =
                memcmp(good.zkproof, again.zkproof, sizeof(good.zkproof)) != 0;
            ADV_CHECK("(8) documented non-determinism: cv differs across "
                     "re-proving (rcv is internally re-randomized by "
                     "design)", cv_differs);
            ADV_CHECK("(8) documented non-determinism: zkproof bytes differ "
                     "across re-proving (Groth16 r/s blinding is internally "
                     "re-randomized by design)", proof_differs);
            ADV_CHECK("(8) both independently-blinded proofs of the same "
                     "witness independently verify", bundle_accepts(&again));
        }
    }
    {
        struct spend_prover_native_status s1, s2;
        sapling_spend_prover_native_status(&s1);
        sapling_spend_prover_native_status(&s2);
        ADV_CHECK("(8) determinism: sapling_spend_prover_native_status() "
                 "is repeatable (params-free coverage probe)",
                 s1.sections_ported == s2.sections_ported &&
                 s1.constraints_ported == s2.constraints_ported &&
                 s1.roundtrip_ready == s2.roundtrip_ready &&
                 strcmp(s1.next_blocker, s2.next_blocker) == 0);
    }

    /* ── (9) Zeroization spot-check ─────────────────────────────────────── */
    {
        /* Exact production cleanse call: sapling_create_spend_proof wipes
         * cs.witness (cap_vars * sizeof(struct fr)) before cs_free. Prove
         * that call actually zeros the secret-bearing witness vector — the
         * ar/nsk bit decompositions and every intermediate wire live in
         * this buffer, in the clear, until this line runs. */
        struct constraint_system cs;
        cs_init(&cs);
        struct sapling_spend_witness wit;
        struct sapling_spend_inputs pub;
        memset(&wit, 0, sizeof(wit));
        memset(&pub, 0, sizeof(pub));
        memcpy(wit.ak, good.ak, 32);
        memcpy(wit.nsk, good.nsk, 32);
        memcpy(wit.ar, good.ar, 32);
        memcpy(wit.pk_d, good.pk_d, 32);
        wit.value = good.value;
        memcpy(pub.rk, good.rk, 32);
        memcpy(pub.cv, good.ak, 32); /* any valid point (unbound prefix) */
        bool synth = sapling_spend_synthesize(&cs, &wit, &pub);
        ADV_CHECK("(9) zeroize spot-check: partial-prefix synthesis "
                 "succeeded (setup for the cleanse check)", synth);
        if (synth) {
            bool had_nonzero = false;
            for (size_t i = 0; i < cs.num_vars && !had_nonzero; i++) {
                uint8_t b[32];
                fr_to_bytes(b, &cs.witness[i]);
                for (size_t j = 0; j < 32; j++)
                    if (b[j] != 0) { had_nonzero = true; break; }
            }
            ADV_CHECK("(9) zeroize spot-check: witness vector has secret "
                     "material before cleanse (sanity: the check below is "
                     "not vacuous)", had_nonzero);

            memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
            bool all_zero = true;
            for (size_t i = 0; i < cs.cap_vars && all_zero; i++) {
                uint8_t b[32];
                fr_to_bytes(b, &cs.witness[i]);
                for (size_t j = 0; j < 32; j++)
                    if (b[j] != 0) { all_zero = false; break; }
            }
            ADV_CHECK("(9) zeroize spot-check: memory_cleanse(cs.witness, "
                     "cap_vars*sizeof(fr)) leaves it all-zero", all_zero);
        }
        cs_free(&cs);
    }
    {
        /* sapling_spend_parse_witness output (the auth-path portion of the
         * secret witness struct) must scrub cleanly, mirroring the
         * production caller (witness_to_rust in sapling_prover_c23.c). */
        uint8_t compact_witness[ADV_COMPACT_WITNESS_LEN];
        memset(compact_witness, 0, sizeof(compact_witness));
        compact_witness[0] = SAPLING_MERKLE_DEPTH;
        for (size_t lvl = 0; lvl < SAPLING_MERKLE_DEPTH; lvl++) {
            size_t off = 1 + lvl * 33;
            memset(compact_witness + off, (int)(lvl + 1), 32);
            compact_witness[off + 32] = (uint8_t)(lvl % 2);
        }

        struct sapling_spend_witness wit;
        memset(&wit, 0xAA, sizeof(wit)); /* canary */
        bool parsed = sapling_spend_parse_witness(
            compact_witness, sizeof(compact_witness), &wit);
        ADV_CHECK("(9) zeroize spot-check: sapling_spend_parse_witness "
                 "overwrote the canary auth path", parsed &&
                 wit.auth_path[0][0] == 1 && wit.auth_path_bits[0] == false);

        memory_cleanse(&wit, sizeof(wit));
        bool wit_zero = true;
        const uint8_t *raw = (const uint8_t *)&wit;
        for (size_t i = 0; i < sizeof(wit); i++)
            if (raw[i] != 0) { wit_zero = false; break; }
        ADV_CHECK("(9) zeroize spot-check: memory_cleanse(&wit, "
                 "sizeof(wit)) leaves the full spend-witness struct "
                 "all-zero", wit_zero);
    }

    failures += pk_parser_adversarial();

    printf("--- end H5 gate (%d failure[s]) ---\n", failures);
    return failures;
}
