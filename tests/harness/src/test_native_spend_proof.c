/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native (no-Rust) Sapling SPEND proof, verified against the OFFICIAL Sapling
 * verifying key.
 *
 * This is the round-trip the whole spend-circuit port exists for: the C23
 * circuit + the C23 Groth16 prover produce a 192-byte proof from
 * ~/.zcash-params/sapling-spend.params, and the node's own consensus verifier
 * accepts it under the verifying key parsed out of that same SHA-512-pinned
 * file. Nothing here links or invokes a Rust prover.
 *
 * Self-skips when the params file is absent. It is never "passed" by absence:
 * the skip prints a SKIP marker the suite counts.
 */

#include "test/test_core.h"

#include "sapling/params_init.h"
#include "sapling/groth16_prover.h"
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/sapling_prover.h"
#include "sapling/pedersen_hash.h"
#include "sapling/fr.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NSP_CHECK(name, expr) do {             \
    printf("  %s... ", (name));                \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

/* RedJubjub generator index for SpendAuthSig (see redjubjub_sign's contract). */
#define NSP_GEN_SPENDAUTH 5

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

/* Two proofs made at once against one shared parsed key. */
struct nsp_par_job {
    const struct groth16_pk *pk;
    const struct sapling_spend_witness *wit;
    const struct sapling_spend_inputs *pub;
    uint8_t proof[192];
    bool ok;
};

static void *nsp_par_prove(void *arg)
{
    struct nsp_par_job *job = arg;
    job->ok = sapling_create_spend_proof_parsed(job->pk, job->wit, job->pub,
                                                job->proof);
    return NULL;
}

#ifdef ZCL_TESTING
/* Deterministic blinding scalars (below the field modulus) for comparing the
 * two proving paths byte for byte. */
static bool nsp_det_fill(void *user, uint8_t *out, size_t n)
{
    uint32_t *ctr = user;
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(0x11u + 13u * (unsigned)i + 29u * *ctr);
    out[n - 1] = 0x10;
    (*ctr)++;
    return true;
}
#endif

/* Two proofs made at once against one shared parsed key, each then accepted by
 * the consensus verifier. */
static int nsp_concurrent_shared_proofs(const struct groth16_pk *shared,
                                        const struct sapling_spend_witness *wit,
                                        const struct sapling_spend_inputs *pub,
                                        const uint8_t sig[64],
                                        const uint8_t sighash[32])
{
    int failures = 0;
    struct nsp_par_job jobs[2];
    memset(jobs, 0, sizeof jobs);
    pthread_t th[2];
    bool started[2] = {false, false};
    for (int i = 0; i < 2; i++) {
        jobs[i].pk = shared;
        jobs[i].wit = wit;
        jobs[i].pub = pub;
        started[i] = pthread_create(&th[i], NULL, nsp_par_prove, &jobs[i]) == 0;
    }
    for (int i = 0; i < 2; i++)
        if (started[i])
            pthread_join(th[i], NULL);
    for (int i = 0; i < 2; i++) {
        struct sapling_verification_ctx vctx;
        sapling_verification_ctx_init(&vctx);
        char name[96];
        snprintf(name, sizeof name,
                 "concurrent proof %d on the shared key is ACCEPTED", i);
        bool accepted = started[i] && jobs[i].ok &&
            sapling_check_spend(&vctx, pub->cv, pub->anchor, pub->nullifier,
                                pub->rk, jobs[i].proof, sig, sighash);
        NSP_CHECK(name, accepted);
    }
    return failures;
}

#ifdef ZCL_TESTING
/* Same blinding scalars, same witness: parsing the key for the proof and
 * proving against the shared parsed key give the same 192 bytes. */
static int nsp_same_blinding_check(const uint8_t *pk_data, size_t pk_len,
                                   const struct groth16_pk *shared,
                                   const struct sapling_spend_witness *wit,
                                   const struct sapling_spend_inputs *pub)
{
    int failures = 0;
    uint8_t pa[192], pb[192];
    uint32_t c1 = 0, c2 = 0;
    groth16_set_test_rng_hook(nsp_det_fill, &c1);
    bool oka = sapling_create_spend_proof(pk_data, pk_len, wit, pub, pa);
    groth16_set_test_rng_hook(nsp_det_fill, &c2);
    bool okb = sapling_create_spend_proof_parsed(shared, wit, pub, pb);
    groth16_set_test_rng_hook(NULL, NULL);
    NSP_CHECK("same blinding: the parsed-key proof is byte-identical to the "
              "per-proof-parse proof",
              oka && okb && memcmp(pa, pb, sizeof pa) == 0);
    return failures;
}
#endif

#ifdef ZCL_TESTING
/* ── Proof bytes pinned across the prover-memory change ─────────────────────
 * With Groth16 blinding drawn from a fixed stream, the proofs made by the
 * original entry points (sapling_create_{spend,output}_proof) are pinned to
 * the bytes the tree produced BEFORE the exact-size-constraint and
 * parse-once-key change (captured on origin/main b3ac820997..717a259e2d). The
 * change is prover-side memory only: proof bytes must not move. */
static const char NSP_GOLDEN_SPEND_PROOF[] =
    "a2cbfd42d26deef3117d6194dc0d78ca97c99a1101ebbf3d94dc488660d852e3f69727a5a1d443328d8f712994013302"
    "a73b9b7fc64453d7d07bfa7dc331a16467ebc030b117b629c761d8904f9aa93129ca251c41f05027dc35644a79cdab8d07e6320ea14026816cf4f96a6cb1b0f1d3c4b69aacb730bb76a4b6f77c6d6aa7540326c3976168862bbfa7027f873001959366872be46068e92e5d16a935d1a18b0baf158a4bafba5bf0ee0dd11ef04bac08b23846bc7e975d395b7c5d7db257";
static const char NSP_GOLDEN_OUTPUT_PROOF[] =
    "a3cfd450d096d4826f0a2745548398020ef79e8fea7f7790f40e661a54a1243dff0c36667bbcc412df1f92863001f051"
    "976506d0d1cf3e9b815f3ba3ef837d85af6bfa484b1ab9475a339fe71fcb683a480f82f6d93b5c12cff8b8ed30fdc77503eeb9a974d4bbd25bbd450ba0b28cbc054247264c4979a65d8da105defd1578089325750c71f868ccd326ece54e16bbb985eea5f8b259d36831725863c283855059837eb37e7278f8941b98dad1b91e0051e1d56ed33b53e3e943b445ab4a7f";

static void nsp_hex(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = '\0';
}

static bool nsp_output_fixture(struct sapling_output_witness *wit,
                               struct sapling_output_inputs *pub)
{
    memset(wit, 0, sizeof *wit);
    memset(pub, 0, sizeof *pub);
    wit->value = UINT64_C(54321);
    wit->rcv[0] = 0x31;
    wit->esk[0] = 0x29;
    wit->rcm[0] = 0x47;
    uint8_t ivk[32] = {0};
    ivk[0] = 0x19;
    return find_diversifier(wit->diversifier) &&
        sapling_ivk_to_pkd(ivk, wit->diversifier, wit->pk_d) &&
        sapling_value_commit(wit->value, wit->rcv, pub->cv) &&
        sapling_ka_derivepublic(wit->diversifier, wit->esk, pub->epk) &&
        sapling_compute_cm(wit->diversifier, wit->pk_d, wit->value, wit->rcm,
                           pub->cm);
}

/* One fixed-blinding proof from either entry point, against its pin, and
 * accepted by the consensus verifier. */
struct nsp_pin_case {
    const uint8_t *spend_pk; size_t spend_len;
    const uint8_t *out_pk; size_t out_len;
    const struct groth16_pk *spend_parsed, *out_parsed;
    const struct sapling_spend_witness *wit;
    const struct sapling_spend_inputs *pub;
    const struct sapling_output_witness *ow;
    const struct sapling_output_inputs *op;
    const uint8_t *sig, *sighash;
};

static bool nsp_pin_one(const struct nsp_pin_case *c, bool spend, bool parsed)
{
    uint8_t proof[192];
    char hex[2 * 192 + 1];
    uint32_t ctr = 0;
    bool ok;
    groth16_set_test_rng_hook(nsp_det_fill, &ctr);
    if (spend)
        ok = parsed ? sapling_create_spend_proof_parsed(c->spend_parsed, c->wit,
                                                        c->pub, proof)
                    : sapling_create_spend_proof(c->spend_pk, c->spend_len,
                                                 c->wit, c->pub, proof);
    else
        ok = parsed ? sapling_create_output_proof_parsed(c->out_parsed, c->ow,
                                                         c->op, proof)
                    : sapling_create_output_proof(c->out_pk, c->out_len, c->ow,
                                                  c->op, proof);
    groth16_set_test_rng_hook(NULL, NULL);
    nsp_hex(proof, sizeof proof, hex);
    if (!ok || strcmp(hex, spend ? NSP_GOLDEN_SPEND_PROOF
                                 : NSP_GOLDEN_OUTPUT_PROOF) != 0)
        return false;
    struct sapling_verification_ctx vctx;
    sapling_verification_ctx_init(&vctx);
    return spend ? sapling_check_spend(&vctx, c->pub->cv, c->pub->anchor,
                                       c->pub->nullifier, c->pub->rk, proof,
                                       c->sig, c->sighash)
                 : sapling_check_output(&vctx, c->op->cv, c->op->cm,
                                        c->op->epk, proof);
}

/* Both entry points, both circuits, on 1, 4 and 8 prover threads: every proof
 * equals its pre-change pin and verifies. */
static int nsp_pin_across_threads(const struct nsp_pin_case *c)
{
    int failures = 0;
    static const unsigned threads[] = {1u, 4u, 8u};
    for (size_t t = 0; t < sizeof threads / sizeof threads[0]; t++) {
        groth16_prover_set_threads(threads[t]);
        for (int k = 0; k < 4; k++) {
            bool spend = k < 2, parsed = (k & 1) != 0;
            char name[160];
            snprintf(name, sizeof name,
                     "threads=%u %s %s proof equals the pin and verifies",
                     threads[t], parsed ? "parsed-key" : "per-proof-parse",
                     spend ? "spend" : "output");
            NSP_CHECK(name, nsp_pin_one(c, spend, parsed));
        }
    }
    groth16_prover_set_threads(0);
    return failures;
}

/* Old entry points only: spend and output proof bytes against the pins. */
static int nsp_pin_old_entry_points(const uint8_t *spend_pk, size_t spend_len,
                                    const struct sapling_spend_witness *wit,
                                    const struct sapling_spend_inputs *pub)
{
    int failures = 0;
    char hex[2 * 192 + 1];
    uint8_t proof[192];
    uint32_t ctr = 0;

    groth16_set_test_rng_hook(nsp_det_fill, &ctr);
    bool ok = sapling_create_spend_proof(spend_pk, spend_len, wit, pub, proof);
    groth16_set_test_rng_hook(NULL, NULL);
    nsp_hex(proof, sizeof proof, hex);
    printf("  PIN spend  %s\n", hex);
    NSP_CHECK("fixed blinding: spend proof bytes equal the pre-change pin",
              ok && strcmp(hex, NSP_GOLDEN_SPEND_PROOF) == 0);

    size_t out_len = 0;
    const uint8_t *out_pk = sapling_get_output_pk(&out_len);
    struct sapling_output_witness ow;
    struct sapling_output_inputs op;
    bool fix = nsp_output_fixture(&ow, &op);
    NSP_CHECK("output fixture and proving key available",
              fix && out_pk != NULL && out_len > 0);
    if (!fix || !out_pk)
        return failures;
    ctr = 0;
    groth16_set_test_rng_hook(nsp_det_fill, &ctr);
    ok = sapling_create_output_proof(out_pk, out_len, &ow, &op, proof);
    groth16_set_test_rng_hook(NULL, NULL);
    nsp_hex(proof, sizeof proof, hex);
    printf("  PIN output %s\n", hex);
    NSP_CHECK("fixed blinding: output proof bytes equal the pre-change pin",
              ok && strcmp(hex, NSP_GOLDEN_OUTPUT_PROOF) == 0);
    return failures;
}

/* The parsed entry points give the same bytes as the original ones for the
 * same inputs and blinding stream (output; the spend leg is compared above in
 * nsp_same_blinding_check). */
static int nsp_output_parsed_matches_old(void)
{
    int failures = 0;
    size_t out_len = 0;
    const uint8_t *out_pk = sapling_get_output_pk(&out_len);
    const struct groth16_pk *shared = sapling_get_output_pk_parsed();
    struct sapling_output_witness ow;
    struct sapling_output_inputs op;
    bool fix = nsp_output_fixture(&ow, &op);
    NSP_CHECK("the shared parsed output key is available",
              shared != NULL && shared == sapling_get_output_pk_parsed());
    if (!fix || !out_pk || !shared)
        return failures;
    uint8_t pa[192], pb[192];
    uint32_t c1 = 0, c2 = 0;
    groth16_set_test_rng_hook(nsp_det_fill, &c1);
    bool oka = sapling_create_output_proof(out_pk, out_len, &ow, &op, pa);
    groth16_set_test_rng_hook(nsp_det_fill, &c2);
    bool okb = sapling_create_output_proof_parsed(shared, &ow, &op, pb);
    groth16_set_test_rng_hook(NULL, NULL);
    NSP_CHECK("same blinding: the parsed-key output proof is byte-identical "
              "to the per-proof-parse proof",
              oka && okb && memcmp(pa, pb, sizeof pa) == 0);
    return failures;
}
#endif

/* The verified statement again against the key parsed once and shared by every
 * proof (the one the native prover reads): one copy however often it is asked
 * for, two threads proving against it at once, and the same bytes as parsing
 * for the proof. */
static int nsp_shared_key_checks(const uint8_t *pk_data, size_t pk_len,
                                 const struct sapling_spend_witness *wit,
                                 const struct sapling_spend_inputs *pub,
                                 const uint8_t sig[64],
                                 const uint8_t sighash[32])
{
    int failures = 0;
    (void)pk_data;
    (void)pk_len;
    const struct groth16_pk *shared = sapling_get_spend_pk_parsed();
    NSP_CHECK("the shared parsed spend key is available", shared != NULL);
    NSP_CHECK("asked again, the same parsed key (one copy)",
              shared != NULL && shared == sapling_get_spend_pk_parsed());
    if (!shared)
        return failures;
    failures += nsp_concurrent_shared_proofs(shared, wit, pub, sig, sighash);
#ifdef ZCL_TESTING
    failures += nsp_same_blinding_check(pk_data, pk_len, shared, wit, pub);
    failures += nsp_output_parsed_matches_old();
#endif
    return failures;
}

#ifdef ZCL_TESTING
/* Builds the pin case (both keys raw and parsed, spend and output fixtures)
 * and runs the 1/4/8-thread pin matrix over it. */
static int nsp_pin_thread_matrix(const uint8_t *pk_data, size_t pk_len,
                                 const struct sapling_spend_witness *wit,
                                 const struct sapling_spend_inputs *pub,
                                 const uint8_t sig[64],
                                 const uint8_t sighash[32])
{
    int failures = 0;
    struct sapling_output_witness ow;
    struct sapling_output_inputs op;
    struct nsp_pin_case pc = {
        .spend_pk = pk_data, .spend_len = pk_len,
        .wit = wit, .pub = pub, .ow = &ow, .op = &op,
        .sig = sig, .sighash = sighash,
    };
    pc.out_pk = sapling_get_output_pk(&pc.out_len);
    pc.spend_parsed = sapling_get_spend_pk_parsed();
    pc.out_parsed = sapling_get_output_pk_parsed();
    bool ready = nsp_output_fixture(&ow, &op) && pc.out_pk &&
                 pc.spend_parsed && pc.out_parsed;
    NSP_CHECK("thread-count pin fixture ready", ready);
    if (ready)
        failures += nsp_pin_across_threads(&pc);
    return failures;
}
#endif

/* sapling_init_params SHA-512-pins every params file before installing the
 * verifying keys, so "official" is checked, not assumed. Its boot self-test
 * proves against the shared parsed keys; with no proving session open they
 * must not stay resident after it. */
static int nsp_load_params(const char *params_dir)
{
    int failures = 0;
#ifdef ZCL_TESTING
    int self_tests_before = zclassic_test_prover_self_test_runs();
#endif
    NSP_CHECK("sapling_init_params loaded the SHA-512-pinned params",
              sapling_init_params(params_dir));
#ifdef ZCL_TESTING
    if (zclassic_test_prover_self_test_runs() > self_tests_before)
        NSP_CHECK("after the boot self-test no parsed proving key stays "
                  "resident",
                  !sapling_test_pk_parsed_resident());
#endif
    return failures;
}

int test_native_spend_proof(void)
{
    printf("\n=== native_spend_proof: C23 prover vs the OFFICIAL Sapling "
           "verifying key ===\n");
    int failures = 0;

    const char *home = getenv("HOME");
    char params_dir[512];
    char spend_path[640];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    snprintf(spend_path, sizeof(spend_path), "%s/sapling-spend.params",
             params_dir);

    FILE *probe = fopen(spend_path, "rb");
    if (!probe) {
        printf("  SKIP (native spend proof) — %s absent; the trusted-setup "
               "key is what makes this a real round-trip, so there is nothing "
               "honest to assert without it\n", spend_path);
        return 0;
    }
    fclose(probe);

    failures += nsp_load_params(params_dir);

    size_t pk_len = 0;
    const uint8_t *pk_data = sapling_get_spend_pk(&pk_len);
    NSP_CHECK("spend proving key is available", pk_data != NULL && pk_len > 0);
    if (!pk_data || pk_len == 0) {
        printf("=== native_spend_proof: %d failure(s) ===\n", failures);
        return failures;
    }

    /* ── Witness ───────────────────────────────────────────────────── */
    uint8_t ask[32] = {0};
    ask[0] = 0x2a;
    ask[1] = 0x17;

    struct sapling_spend_witness wit;
    memset(&wit, 0, sizeof wit);
    sapling_ask_to_ak(ask, wit.ak);
    wit.nsk[0] = 0x11;
    wit.ar[0] = 0x03;
    wit.value = UINT64_C(12345);
    wit.rcv[0] = 0x2f;
    wit.rcv[1] = 0x91;
    wit.rcm[0] = 0x5c;
    wit.rcm[1] = 0x23;
    NSP_CHECK("found a diversifier whose group_hash is a Jubjub point",
              find_diversifier(wit.diversifier));
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t pa[32] = {0}, pb[32] = {0};
        pa[0] = (uint8_t)(0x10u + d);
        pa[1] = 0x5b;
        pb[0] = (uint8_t)(d * 7u);
        pb[3] = 0x11;
        pedersen_merkle_hash(0, pa, pb, wit.auth_path[d]);
        wit.auth_path_bits[d] = (((d * 5u) + (d / 3u)) & 1u) != 0u;
    }

    struct sapling_spend_inputs pub;
    memset(&pub, 0, sizeof pub);
    NSP_CHECK("every public input derived from the witness",
              sapling_spend_derive_public(&wit, &pub));

    /* ── Native proof ──────────────────────────────────────────────── */
    uint8_t proof[192];
    memset(proof, 0, sizeof proof);
    bool proved = sapling_create_spend_proof(pk_data, pk_len, &wit, &pub,
                                             proof);
    NSP_CHECK("native C23 prover produced a spend proof", proved);

    /* ── Verify under the official verifying key ───────────────────── */
    /* rsk = ask + ar; rk = [rsk] G_spendauth is exactly what the circuit
     * bound as public inputs 1/2, so this signature verifies against the
     * same rk the proof commits to. */
    uint8_t sighash[32];
    for (size_t i = 0; i < 32; i++)
        sighash[i] = (uint8_t)(0xA0u + i);

    uint8_t rsk_bytes[32];
    {
        struct fs ask_fs, ar_fs, rsk_fs;
        bool ok = fs_from_bytes(&ask_fs, ask) && fs_from_bytes(&ar_fs, wit.ar);
        if (ok) {
            fs_add(&rsk_fs, &ask_fs, &ar_fs);
            fs_to_bytes(rsk_bytes, &rsk_fs);
        } else {
            memset(rsk_bytes, 0, sizeof rsk_bytes);
        }
        NSP_CHECK("rsk = ask + ar decoded as canonical Fs scalars", ok);
    }

    uint8_t sig[64];
    NSP_CHECK("spend_auth_sig signed with rsk",
              redjubjub_sign(rsk_bytes, sighash, 32, sig,
                             NSP_GEN_SPENDAUTH));

    struct sapling_verification_ctx ctx;
    sapling_verification_ctx_init(&ctx);
    bool verified = proved
        && sapling_check_spend(&ctx, pub.cv, pub.anchor, pub.nullifier,
                               pub.rk, proof, sig, sighash);
    NSP_CHECK("OFFICIAL Sapling verifying key ACCEPTS the native proof "
              "(sapling_check_spend, the consensus path)", verified);

    /* A verifier that accepts anything proves nothing: flip one public input
     * and require rejection. */
    if (verified) {
        uint8_t bad_anchor[32];
        memcpy(bad_anchor, pub.anchor, 32);
        bad_anchor[0] ^= 0x01;
        struct sapling_verification_ctx ctx2;
        sapling_verification_ctx_init(&ctx2);
        NSP_CHECK("the same proof is REJECTED under a mutated anchor",
                  !sapling_check_spend(&ctx2, pub.cv, bad_anchor,
                                       pub.nullifier, pub.rk, proof, sig,
                                       sighash));
    }

#ifdef ZCL_TESTING
    failures += nsp_pin_old_entry_points(pk_data, pk_len, &wit, &pub);
    if (verified)
        failures += nsp_pin_thread_matrix(pk_data, pk_len, &wit, &pub, sig,
                                          sighash);
#endif
    if (verified)
        failures += nsp_shared_key_checks(pk_data, pk_len, &wit, &pub, sig,
                                          sighash);

    printf("=== native_spend_proof: %d failure(s) ===\n", failures);
    return failures;
}
