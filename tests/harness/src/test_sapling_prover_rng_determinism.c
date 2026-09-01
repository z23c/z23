/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Determinism pin for the Sapling prover RNG seam (Sapling Lane B).
 * =====================================================================
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The deterministic simulator's contract is: same 64-bit seed →
 * byte-identical run. That was broken for shielded ops because the
 * Sapling note randomness (rcv / esk / rcm / ar) is drawn inside
 * `sapling_generate_r()` (core/modules/sapling/src/sapling.c) which routes to
 * `zcl_random_secret_bytes` → `GetRandBytes` → the real kernel
 * CSPRNG. Proofs VERIFY, but tx bytes / txids are non-reproducible
 * run-to-run — a simulator can't bisect a shielded failure into a
 * stable seed.
 *
 * Lane B adds a TEST-ONLY, DEFAULT-OFF hook
 * (`sapling_set_test_rng_hook`, declared only under `-DZCL_TESTING`)
 * that lets a test/sim feed `sapling_generate_r()` from a seedable
 * deterministic stream. This file pins:
 *
 *   1. WITH the hook, the SAME seed produces the SAME rcm/rcv/esk and
 *      the SAME value-commitment bytes (params-free).
 *   2. WITH the hook, a DIFFERENT seed produces DIFFERENT output.
 *   3. WITHOUT the hook (the production/default path), two draws
 *      DIFFER — i.e. real entropy is still in force and the hook has
 *      NOT silently taken over. This is the crypto-hygiene guard: it
 *      would fail loudly if the default ever stopped being
 *      GetRandBytes.
 *   4. (params-gated) the SAME seed drives the native C23 note randomness to
 *      identical cv/cm/epk bytes end-to-end, while independent Groth16
 *      blinding keeps proof bytes distinct unless its own test hook is set.
 *
 * HONEST SCOPE NOTE
 * -----------------
 * Native C23 value-commitment randomness uses the Sapling test hook. Groth16
 * proof blinding has a separate, default-off test hook, so this test leaves
 * proof bytes non-deterministic while pinning the note description fields.
 * Production builds contain neither hook path and always use the CSPRNG.
 */

#include "test/test_core.h"

#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"
#include "platform/rng.h"
#include "sim/seed_tape.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RNG_CHECK(name, expr) do {              \
    printf("  %s... ", (name));                 \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* Deterministic fill callback for the Sapling prover RNG hook.
 *
 * Draws bytes from `rng_u64()`, which — when a seed_tape has been
 * installed via `seed_tape_install()` — returns the tape's next
 * xoshiro256++ word (deterministic, seeded from a single uint64).
 * This is exactly the source the deterministic simulator installs,
 * so this test exercises the intended sim wiring, not a bespoke
 * stream. */
static bool fill_from_rng_u64(void *user, uint8_t *out, size_t n)
{
    (void)user;
    size_t i = 0;
    while (i < n) {
        uint64_t w = rng_u64();
        size_t chunk = (n - i < sizeof(w)) ? (n - i) : sizeof(w);
        memcpy(out + i, &w, chunk);
        i += chunk;
    }
    return true;
}

/* Generate rcm/rcv/esk under a seed_tape seeded with `seed`, with the
 * prover RNG hook installed. Leaves the process in a clean state
 * (hook cleared, tape uninstalled + closed) on return. */
static void draw_under_seed(uint64_t seed,
                            uint8_t rcm[32], uint8_t rcv[32], uint8_t esk[32])
{
    seed_tape_t *tape = seed_tape_open(seed, 0);
    seed_tape_install(tape);
    sapling_set_test_rng_hook(fill_from_rng_u64, NULL);

    sapling_generate_r(rcm);
    sapling_generate_r(rcv);
    sapling_generate_r(esk);

    sapling_set_test_rng_hook(NULL, NULL);
    seed_tape_uninstall();
    seed_tape_close(tape);
}

int test_sapling_prover_rng_determinism(void)
{
    printf("\n=== Sapling prover RNG determinism (Lane B seam) ===\n");
    int failures = 0;

    const uint64_t SEED_A = 0xC0FFEE123456789AULL;
    const uint64_t SEED_B = 0x0123456789ABCDEFULL;

    /* ── 1. Same seed → identical note randomness (params-free) ── */
    uint8_t a_rcm[32], a_rcv[32], a_esk[32];
    uint8_t a2_rcm[32], a2_rcv[32], a2_esk[32];
    draw_under_seed(SEED_A, a_rcm, a_rcv, a_esk);
    draw_under_seed(SEED_A, a2_rcm, a2_rcv, a2_esk);

    RNG_CHECK("same seed -> identical rcm", memcmp(a_rcm, a2_rcm, 32) == 0);
    RNG_CHECK("same seed -> identical rcv", memcmp(a_rcv, a2_rcv, 32) == 0);
    RNG_CHECK("same seed -> identical esk", memcmp(a_esk, a2_esk, 32) == 0);

    /* Distinct draws within a run must differ (the stream advances,
     * it is not returning a constant). */
    RNG_CHECK("consecutive draws differ (rcm != rcv)",
              memcmp(a_rcm, a_rcv, 32) != 0);
    RNG_CHECK("consecutive draws differ (rcv != esk)",
              memcmp(a_rcv, a_esk, 32) != 0);

    /* ── 2. Different seed → different note randomness ── */
    uint8_t b_rcm[32], b_rcv[32], b_esk[32];
    draw_under_seed(SEED_B, b_rcm, b_rcv, b_esk);
    RNG_CHECK("different seed -> different rcm", memcmp(a_rcm, b_rcm, 32) != 0);
    RNG_CHECK("different seed -> different rcv", memcmp(a_rcv, b_rcv, 32) != 0);

    /* ── 3. Value-commitment bytes are deterministic (params-free) ──
     * cv = value*G_v + rcv*G_rcv. Same rcv (same seed) => same cv;
     * different rcv (different seed) => different cv. This is the
     * "same output-proof value-commitment bytes twice from the same
     * seed" pin, computed without any proving params. */
    {
        const uint64_t VALUE = 500000000ULL;
        uint8_t cv_a[32], cv_a2[32], cv_b[32];
        bool ok_a  = sapling_value_commit(VALUE, a_rcv,  cv_a);
        bool ok_a2 = sapling_value_commit(VALUE, a2_rcv, cv_a2);
        bool ok_b  = sapling_value_commit(VALUE, b_rcv,  cv_b);
        RNG_CHECK("value_commit computed for all rcv", ok_a && ok_a2 && ok_b);
        RNG_CHECK("same seed -> identical value commitment cv",
                  ok_a && ok_a2 && memcmp(cv_a, cv_a2, 32) == 0);
        RNG_CHECK("different seed -> different value commitment cv",
                  ok_a && ok_b && memcmp(cv_a, cv_b, 32) != 0);
    }

    /* ── 4. WITHOUT the hook: real entropy, NON-reproducible ──
     * This is the production/default path. No hook set, no tape
     * installed => sapling_generate_r() draws from GetRandBytes. Two
     * draws MUST differ. If this ever failed it would mean the hook
     * (or a fake RNG iface) had silently taken over the default path —
     * exactly the crypto-hygiene regression this guards against. */
    {
        /* Belt-and-braces: guarantee no hook / tape leaked from above. */
        sapling_set_test_rng_hook(NULL, NULL);
        platform_rng_clear_source();

        uint8_t r1[32], r2[32];
        bool g1 = sapling_generate_r(r1);
        bool g2 = sapling_generate_r(r2);
        RNG_CHECK("default path draws succeed", g1 && g2);
        RNG_CHECK("WITHOUT hook: two draws differ (real entropy)",
                  memcmp(r1, r2, 32) != 0);
    }

    /* ── 5. (params-gated) native prover entropy boundary ──
     * Prove the Sapling hook reaches rcm, esk, and rcv: the same seed yields
     * identical cv/cm/epk out of sapling_build_output_with_ctx. The separate
     * Groth16 blinding hook is intentionally unset, so proofs retain real
     * entropy.
     * SKIPS cleanly when ~/.zcash-params is absent (test_snark_kat
     * pattern). We do NOT assert proof-byte equality (Groth16
     * blinding is an independent RNG source — see scope note). */
    {
        const char *home = getenv("HOME");
        char params_dir[512];
        snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
                 (home && *home) ? home : ".");

        if (!sapling_init_params(params_dir)) {
            printf("  ~/.zcash-params absent — SKIPPING end-to-end prover leg\n");
        } else if (!zclassic_sapling_prover_is_ready()) {
            printf("  SKIP (end-to-end prover leg) — %s (status=%s)\n",
                   zclassic_sapling_prover_backend(),
                   zclassic_sapling_prover_status());
        } else {
            const uint64_t SEED_E = 0xABCDEF0011223344ULL;
            const uint64_t VALUE = 12345ULL;

            /* Fixed recipient key material (not the RNG under test). */
            uint8_t ovk[32], to_d[11] = {0}, to_pk_d[32];
            memset(ovk, 0x11, sizeof(ovk));
            /* Derive a valid pk_d from a fixed ivk + a scanned diversifier. */
            uint8_t ivk[32]; memset(ivk, 0x22, sizeof(ivk));
            bool have_recipient = false;
            for (unsigned d0 = 0; d0 < 256 && !have_recipient; d0++) {
                memset(to_d, 0, sizeof(to_d));
                to_d[0] = (uint8_t)d0;
                if (sapling_ivk_to_pkd(ivk, to_d, to_pk_d))
                    have_recipient = true;
            }
            RNG_CHECK("derived a valid recipient pk_d", have_recipient);

            uint8_t cv1[32], cm1[32], epk1[32], enc1[580], out1[80], proof1[192];
            uint8_t cv2[32], cm2[32], epk2[32], enc2[580], out2[80], proof2[192];
            bool b1 = false, b2 = false;

            if (have_recipient) {
                void *pctx = zclassic_sapling_proving_ctx_init();
                if (pctx) {
                    seed_tape_t *t1 = seed_tape_open(SEED_E, 0);
                    seed_tape_install(t1);
                    sapling_set_test_rng_hook(fill_from_rng_u64, NULL);
                    b1 = sapling_build_output_with_ctx(pctx, ovk, to_d, to_pk_d,
                                                       VALUE, NULL,
                                                       cv1, cm1, epk1,
                                                       enc1, out1, proof1);
                    sapling_set_test_rng_hook(NULL, NULL);
                    seed_tape_uninstall();
                    seed_tape_close(t1);
                    zclassic_sapling_proving_ctx_free(pctx);
                }

                void *pctx2 = zclassic_sapling_proving_ctx_init();
                if (pctx2) {
                    seed_tape_t *t2 = seed_tape_open(SEED_E, 0);
                    seed_tape_install(t2);
                    sapling_set_test_rng_hook(fill_from_rng_u64, NULL);
                    b2 = sapling_build_output_with_ctx(pctx2, ovk, to_d, to_pk_d,
                                                       VALUE, NULL,
                                                       cv2, cm2, epk2,
                                                       enc2, out2, proof2);
                    sapling_set_test_rng_hook(NULL, NULL);
                    seed_tape_uninstall();
                    seed_tape_close(t2);
                    zclassic_sapling_proving_ctx_free(pctx2);
                }
            }

            RNG_CHECK("native C23 prover produced two output descriptions",
                      b1 && b2);
            RNG_CHECK("same C seed -> identical cv",
                      b1 && b2 && memcmp(cv1, cv2, 32) == 0);
            RNG_CHECK("same seed -> identical cm (native prover)",
                      b1 && b2 && memcmp(cm1, cm2, 32) == 0);
            RNG_CHECK("same seed -> identical epk (native prover)",
                      b1 && b2 && memcmp(epk1, epk2, 32) == 0);
            RNG_CHECK("same C seed -> distinct proof (Groth16 entropy)",
                      b1 && b2 && memcmp(proof1, proof2, 192) != 0);
        }
    }

    printf("Sapling prover RNG determinism: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
