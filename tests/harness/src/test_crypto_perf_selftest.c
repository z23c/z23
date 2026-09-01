/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * crypto_perf_selftest — the TEETH for the crypto-vs-Rust benchmark
 * (`build/bin/zclassic23 -bench-crypto-vs-rust`, engine/entry/main.c) and its gate
 * (tools/scripts/check_crypto_perf.sh / `make check-crypto-perf`).
 *
 * The gate lets a primitive's baseline "ratchet down" as we optimise. A
 * benchmark of a HOLLOW primitive — a hash that no-ops, a verify that always
 * returns true, a multiply that returns an operand — would get fast for free
 * and let the gate ratchet a broken primitive. This test forbids that: it
 * exercises the EXACT primitives `-bench-crypto-vs-rust` times, on the same
 * kind of fixtures, and pins correctness in BOTH directions so a hollow-fast
 * regression fails HERE (in the fast test pool) before the gate ever records a
 * number.
 *
 * Consensus verify LOGIC is frozen — this is measurement/teeth only, calling
 * the production predicates. Hermetic legs (equihash, BLS fp_mul + pairing,
 * secp256k1 ECDSA, ed25519, SHA256/SHA3-256/BLAKE2b) always run. The
 * params-heavy Groth16 leg self-skips unless ZCL_PARAMS_TESTS=1 (same rationale
 * as verify_bench_selftest).
 */

#include "test/test_core.h"
#include "chain/equihash.h"
#include "sapling/params_init.h"
#include "test/verify_bench_fixture.h"       /* baked real (200,9) witness */
#include "domain/consensus/equihash.h"
#include "sapling/bls12_381.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "crypto/ed25519.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "crypto/blake2b.h"
#include <string.h>

#define CP_CHECK(name, expr) do {               \
    printf("  %s... ", (name));                 \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* Canonical BLS12-381 generators (compressed, big-endian, with flags) —
 * same fixtures the bench decompresses for the pairing timing. */
static const uint8_t CP_G1_GEN[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,
    0x4f,0xa9,0xac,0x0f,0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,0x6c,0x55,0xe8,0x3f,
    0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb };
static const uint8_t CP_G2_GEN[96] = {
    0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,0x7d,0xac,0xd3,0xa0,
    0x88,0x27,0x4f,0x65,0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,0x33,0x4c,0xf1,0x12,
    0x13,0x94,0x5d,0x57,0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,0x26,0x08,0x05,0x27,
    0x2d,0xc5,0x10,0x51,0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,0x0b,0xac,0x03,0x26,
    0xa8,0x05,0xbb,0xef,0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8 };

/* RFC 8032 Test 2 (ed25519, msg = 0x72) — same fixture the bench times. */
static const uint8_t CP_ED_PK[32] = {
    0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,
    0x4d,0x1b,0x7e,0xbc,0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,
    0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
static const uint8_t CP_ED_SIG[64] = {
    0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,
    0x5f,0x64,0x25,0x40,0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,
    0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,0x08,0x5a,0xc1,0xe4,
    0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
    0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,
    0x12,0xbb,0x0c,0x00 };

/* Host SHA-NI capability, probed independently of core/modules/crypto/src/sha256.c so
 * the check below cannot be satisfied by that module agreeing with itself. */
static bool cp_host_has_sha_ni(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("sha") != 0;
#else
    return false;
#endif
}

static bool cp_find_diversifier(uint8_t diversifier[11])
{
    memset(diversifier, 0, 11);
    for (int i = 0; i < 256; i++) {
        diversifier[0] = (uint8_t)i;
        if (sapling_check_diversifier(diversifier))
            return true;
    }
    return false;
}

int test_crypto_perf_selftest(void)
{
    printf("\n=== crypto_perf_selftest (teeth for -bench-crypto-vs-rust) ===\n");
    int failures = 0;

    /* ── Equihash (200,9) ─────────────────────────────────────────── */
    printf("Equihash 200,9 verify (baked real witness)\n");
    {
        struct block_header h;
        verify_bench_fill_eh_header(&h);
        CP_CHECK("valid witness -> true", check_equihash_solution(&h, NULL));
        struct block_header bad = h;
        bad.nSolution[600] ^= 0x01;
        CP_CHECK("one-bit-flipped -> false", !check_equihash_solution(&bad, NULL));
    }

    /* ── BLS12-381 Fp multiply (square-consistency, Montgomery-agnostic) ── */
    printf("BLS12-381 Fp multiply\n");
    {
        uint8_t ba[48], bb[48];
        memset(ba, 0x11, sizeof(ba));
        memset(bb, 0x07, sizeof(bb));  /* both < field modulus q (top byte 0x1a) */
        struct fp a, b;
        bool va = fp_from_bytes(&a, ba);
        bool vb = fp_from_bytes(&b, bb);
        CP_CHECK("fixtures are canonical field elements", va && vb);
        struct fp sq, mm, ab;
        fp_sq(&sq, &a);
        fp_mul(&mm, &a, &a);
        fp_mul(&ab, &a, &b);
        /* mul must agree with the independent square routine (defeats a no-op
         * / constant-output multiply) and be non-trivial. */
        CP_CHECK("fp_mul(a,a) == fp_sq(a)", fp_eq(&sq, &mm));
        CP_CHECK("a*b non-degenerate (!=0, !=a, !=b)",
                 !fp_is_zero(&ab) && !fp_eq(&ab, &a) && !fp_eq(&ab, &b));
    }

    /* ── BLS12-381 optimal-Ate pairing ────────────────────────────── */
    printf("BLS12-381 Ate pairing (canonical generators)\n");
    {
        struct g1_point g1;
        struct g2_point g2;
        bool g1_ok = g1_from_compressed(&g1, CP_G1_GEN);
        bool g2_ok = g2_from_compressed(&g2, CP_G2_GEN);
        CP_CHECK("generators decompress", g1_ok && g2_ok);
        if (g1_ok && g2_ok) {
            struct fp12 r, one12, diff;
            bls12_381_pairing(&r, &g1, &g2);
            fp12_one(&one12);
            fp12_sub(&diff, &one12, &r);
            /* e(G1,G2) is a non-degenerate GT element: not 0 and not 1. A
             * degenerate/always-1 pairing engine fails here. */
            CP_CHECK("e(G1,G2) != 0", !fp12_is_zero(&r));
            CP_CHECK("e(G1,G2) != 1", !fp12_is_zero(&diff));
        }
    }

    /* ── secp256k1 ECDSA verify (locally signed round-trip) ────────── */
    printf("secp256k1 ECDSA verify\n");
    {
        /* The harness (test_parallel.c) has already called ecc_start() +
         * ecc_verify_init() for this group — the signing/verify contexts are
         * process-wide singletons; re-initialising them asserts. */
        struct privkey k;
        privkey_make_new(&k, true);
        struct pubkey pk;
        struct uint256 hash;
        for (int i = 0; i < 32; ++i) hash.data[i] = (uint8_t)(i * 7 + 1);
        unsigned char sig[80];
        size_t siglen = sizeof(sig);
        bool signed_ok = privkey_get_pubkey(&k, &pk) &&
                         privkey_sign(&k, &hash, sig, &siglen);
        CP_CHECK("sign round-trip produced a signature", signed_ok);
        CP_CHECK("valid sig -> true", signed_ok &&
                 pubkey_verify(&pk, &hash, sig, siglen));
        struct uint256 bad = hash;
        bad.data[0] ^= 0x01;
        CP_CHECK("corrupted message -> false", signed_ok &&
                 !pubkey_verify(&pk, &bad, sig, siglen));
    }

    /* ── ed25519 verify (JoinSplit) ───────────────────────────────── */
    printf("ed25519 verify (RFC 8032 Test 2)\n");
    {
        const uint8_t msg[1] = { 0x72 };
        CP_CHECK("valid sig -> true",
                 ed25519_verify(CP_ED_SIG, msg, 1, CP_ED_PK));
        uint8_t bad_sig[64];
        memcpy(bad_sig, CP_ED_SIG, 64);
        bad_sig[10] ^= 0x01;
        CP_CHECK("corrupted sig -> false",
                 !ed25519_verify(bad_sig, msg, 1, CP_ED_PK));
    }

    /* ── Hash primitives (avalanche + not-a-copy of input) ─────────── */
    printf("Hash primitives (SHA256 / SHA3-256 / BLAKE2b, 1 KiB)\n");
    {
        uint8_t msg[1024], flip[1024];
        for (size_t i = 0; i < sizeof(msg); ++i) msg[i] = (uint8_t)(i * 131 + 7);
        memcpy(flip, msg, sizeof(flip));
        flip[500] ^= 0x01;

        uint8_t a[64], b[64];
        struct sha256_ctx sc;
        sha256_init(&sc); sha256_write(&sc, msg, sizeof(msg)); sha256_finalize(&sc, a);
        sha256_init(&sc); sha256_write(&sc, flip, sizeof(flip)); sha256_finalize(&sc, b);
        CP_CHECK("SHA256 avalanche + not-a-copy",
                 memcmp(a, b, 32) != 0 && memcmp(a, msg, 32) != 0);

        /* The `sha256` baseline row is pinned at the SHA-NI number and gated
         * `beat`. That row is only meaningful if the bench actually exercises
         * the hardware transform on a host that has it — measuring the
         * portable fallback would trip the ratchet with a misleading message,
         * and (worse) a silently-portable build would look like a perf
         * regression rather than the build defect it is. Byte-for-byte parity
         * between the two transforms is proven by the sha256_isa_parity group;
         * this is only the "are we measuring what we pinned" check. */
        CP_CHECK("SHA256 bench runs the transform the node ships",
                 !cp_host_has_sha_ni() || sha256_shani_available());

        zcl_sha3_256(msg, sizeof(msg), a);
        zcl_sha3_256(flip, sizeof(flip), b);
        CP_CHECK("SHA3-256 avalanche + not-a-copy",
                 memcmp(a, b, 32) != 0 && memcmp(a, msg, 32) != 0);

        struct blake2b_ctx bc;
        blake2b_init(&bc, 64); blake2b_update(&bc, msg, sizeof(msg)); blake2b_final(&bc, a, 64);
        blake2b_init(&bc, 64); blake2b_update(&bc, flip, sizeof(flip)); blake2b_final(&bc, b, 64);
        CP_CHECK("BLAKE2b avalanche + not-a-copy",
                 memcmp(a, b, 32) != 0 && memcmp(a, msg, 32) != 0);
    }

    /* ── Groth16 / BLS12-381 output verify — params-heavy, opt-in ──── */
    printf("Groth16 BLS12-381 output-proof verify\n");
    if (getenv("ZCL_PARAMS_TESTS") == NULL) {
        printf("  ZCL_PARAMS_TESTS unset -> SKIPPING Groth16 leg "
               "(set ZCL_PARAMS_TESTS=1 to run the prover round-trip)\n");
    } else {
        const char *home = getenv("HOME");
        char params_dir[512];
        snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
                 (home && *home) ? home : ".");
        if (!sapling_init_params(params_dir)) {
            printf("  ~/.zcash-params absent -> SKIPPING Groth16 leg\n");
        } else if (!zclassic_sapling_prover_is_ready()) {
            printf("  SKIP (Groth16 proving leg) — %s (status=%s)\n",
                   zclassic_sapling_prover_backend(),
                   zclassic_sapling_prover_status());
        } else {
            uint8_t diversifier[11];
            bool div_ok = cp_find_diversifier(diversifier);
            uint8_t ask[32], nsk[32], ovk[32];
            sapling_generate_r(ask);
            sapling_generate_r(nsk);
            sapling_generate_r(ovk);
            uint8_t ak[32], nk[32], ivk[32], pk_d[32];
            sapling_ask_to_ak(ask, ak);
            sapling_nsk_to_nk(nsk, nk);
            sapling_crh_ivk(ak, nk, ivk);
            bool pk_ok = div_ok && sapling_ivk_to_pkd(ivk, diversifier, pk_d);
            void *pctx = zclassic_sapling_proving_ctx_init();
            uint8_t cv[32], cm[32], epk[32], enc[580], out_ct[80], proof[192];
            bool built = pctx && pk_ok &&
                sapling_build_output_with_ctx(pctx, ovk, diversifier, pk_d,
                                              54321, NULL,
                                              cv, cm, epk, enc, out_ct, proof);
            CP_CHECK("production prover produced an output proof", built);
            if (built) {
                struct sapling_verification_ctx vctx;
                sapling_verification_ctx_init(&vctx);
                CP_CHECK("valid proof -> true",
                         sapling_check_output(&vctx, cv, cm, epk, proof));
                uint8_t bad_proof[192];
                memcpy(bad_proof, proof, 192);
                bad_proof[64] ^= 0x01;
                sapling_verification_ctx_init(&vctx);
                CP_CHECK("one-bit-flipped proof -> false",
                         !sapling_check_output(&vctx, cv, cm, epk, bad_proof));
            }
            if (pctx) zclassic_sapling_proving_ctx_free(pctx);
        }
    }

    printf("crypto_perf_selftest: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
