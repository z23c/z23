/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * verify_bench_selftest — the TEETH for the consensus-verify
 * microbenchmark (`build/bin/zclassic23 -bench-crypto-verify`,
 * engine/entry/main.c). The benchmark times the two dominant per-block verify
 * primitives — the pure-C23 BLS12-381 Groth16 pairing verify and the
 * Equihash (200,9) solution verify — and appends ns/op rows to
 * docs/bench-history.csv, which `-bench-regress` gates at ±20%.
 *
 * A benchmark of a verifier that always returns `true` (or is optimised
 * to a no-op) is worthless: it would "get fast" for free and the gate
 * would wave a broken verifier through. This test forbids that. It
 * exercises the EXACT primitives the benchmark times, on the EXACT
 * fixtures the benchmark uses, and pins BOTH directions:
 *
 *   Equihash (200,9), hermetic (always runs):
 *     - the baked real witness verifies TRUE, and
 *     - a one-BIT-flipped copy verifies FALSE.
 *   If a change makes the verifier always-true, leg 2 fails here; if it
 *   makes it always-false, leg 1 fails.
 *
 *   Groth16 / BLS12-381 pairing (params-heavy; opt-in, see
 *   test_parallel.c::group_is_params_heavy):
 *     - a real output proof from the production prover verifies TRUE
 *       through sapling_check_output (the full pairing check), and
 *     - a one-BIT-flipped proof verifies FALSE.
 *   Skipped cleanly when ~/.zcash-params is absent (the VK/proving keys
 *   are not vendored), exactly like snark_kat.
 */

#include "test/test_core.h"
#include "chain/equihash.h"
#include "sapling/sapling.h"
#include "sapling/params_init.h"
#include "test/verify_bench_fixture.h"
#include "sapling/sapling_prover.h"
#include "domain/consensus/equihash.h"

#define VB_CHECK(name, expr) do {               \
    printf("  %s... ", (name));                 \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

static bool vb_find_diversifier(uint8_t diversifier[11])
{
    memset(diversifier, 0, 11);
    for (int i = 0; i < 256; i++) {
        diversifier[0] = (uint8_t)i;
        if (sapling_check_diversifier(diversifier))
            return true;
    }
    return false;
}

int test_verify_bench_selftest(void)
{
    printf("\n=== verify_bench_selftest (teeth for -bench-crypto-verify) ===\n");
    int failures = 0;

    /* ── Equihash (200,9) — hermetic, always runs ──────────────────── */
    printf("Equihash 200,9 solution verify (baked real witness)\n");
    {
        struct block_header h;
        verify_bench_fill_eh_header(&h);

        /* POSITIVE (HARD): the baked witness must verify TRUE. If it does
         * not, the benchmark would be timing a rejecting/broken verifier. */
        VB_CHECK("valid witness -> check_equihash_solution() == true",
                 check_equihash_solution(&h, NULL));

        /* NEGATIVE (HARD): flip a single BIT of the packed solution and the
         * verifier must return FALSE. This is what forbids an always-true
         * (hollow-fast) regression from passing. */
        struct block_header bad = h;
        bad.nSolution[600] ^= 0x01;
        VB_CHECK("one-bit-flipped witness -> check_equihash_solution() == false",
                 !check_equihash_solution(&bad, NULL));

        /* The verify path the benchmark uses must agree with the pure
         * domain function (belt-and-suspenders that we bench the real
         * consensus predicate, not a divergent shim). */
        bool dom_valid = false;
        struct zcl_result r =
            domain_consensus_verify_equihash_solution(&h, NULL, &dom_valid);
        VB_CHECK("domain verify agrees: ok && valid",
                 r.ok && dom_valid);
    }

    /* ── Groth16 / BLS12-381 pairing verify — params-heavy ─────────── */
    printf("Groth16 BLS12-381 output-proof verify (production prover round-trip)\n");
    if (getenv("ZCL_PARAMS_TESTS") == NULL) {
        /* Loading the Sapling proving keys + running a real prove costs
         * seconds of CPU and tens of MB — too heavy for the fast default
         * pool (same rationale as test_parallel.c::group_is_params_heavy).
         * The hermetic Equihash teeth above always run; opt into this leg
         * with ZCL_PARAMS_TESTS=1. */
        printf("  ZCL_PARAMS_TESTS unset -> SKIPPING Groth16 leg "
               "(set ZCL_PARAMS_TESTS=1 to run the prover round-trip)\n");
    } else {
        const char *home = getenv("HOME");
        char params_dir[512];
        snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
                 (home && *home) ? home : ".");

        if (!sapling_init_params(params_dir)) {
            printf("  ~/.zcash-params absent -> SKIPPING Groth16 leg "
                   "(VK/proving keys not vendored)\n");
        } else if (!zclassic_sapling_prover_is_ready()) {
            printf("  SKIP (Groth16 proving leg) — %s (status=%s)\n",
                   zclassic_sapling_prover_backend(),
                   zclassic_sapling_prover_status());
        } else {
            uint8_t diversifier[11];
            bool div_ok = vb_find_diversifier(diversifier);

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
            uint8_t cv[32], cm[32], epk[32];
            uint8_t enc[580], out_ct[80], proof[192];
            bool built = pctx && pk_ok &&
                sapling_build_output_with_ctx(pctx, ovk, diversifier, pk_d,
                                              54321, NULL,
                                              cv, cm, epk, enc, out_ct, proof);
            VB_CHECK("production prover produced an output proof", built);

            if (built) {
                /* POSITIVE (HARD): full Groth16 pairing verify must accept. */
                struct sapling_verification_ctx vctx;
                sapling_verification_ctx_init(&vctx);
                VB_CHECK("valid proof -> sapling_check_output() == true",
                         sapling_check_output(&vctx, cv, cm, epk, proof));

                /* NEGATIVE (HARD): one-bit-flipped proof must reject —
                 * forbids an always-true pairing regression. */
                uint8_t bad_proof[192];
                memcpy(bad_proof, proof, 192);
                bad_proof[64] ^= 0x01;
                sapling_verification_ctx_init(&vctx);
                VB_CHECK("one-bit-flipped proof -> sapling_check_output() == false",
                         !sapling_check_output(&vctx, cv, cm, epk, bad_proof));
            }

            if (pctx) zclassic_sapling_proving_ctx_free(pctx);
        }
    }

    printf("verify_bench_selftest: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
