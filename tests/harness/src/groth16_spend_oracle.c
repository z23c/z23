/* Sapling SPEND-circuit fixed-reference oracle (test-only, H2 lane).
 *
 * Portions interoperate with librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. The reference
 * bytes are checked in as an inert KAT; Z23 fetches, builds and links
 * no Rust code.
 *
 * WHAT THIS IS
 * ------------
 * The native C23 key-derivation, commitment and nullifier implementation runs
 * against that fixed external ground truth. This is params-free and hermetic.
 */

#include "test/test_core.h"
#include "test/groth16_spend_oracle_kat.h"

#include "sapling/sapling.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Reference ground truth for the fixed KAT witness. */
struct spend_oracle_reference {
    uint8_t diversifier[11];
    uint8_t ak[32];
    uint8_t nk[32];
    uint8_t ivk[32];
    uint8_t pk_d[32];
    uint8_t cm[32];
    uint8_t nf[32];
    bool valid;
};

/* Load the checked-in external reference vector. */
static void spend_oracle_load_baked_reference(struct spend_oracle_reference *ref)
{
    memset(ref, 0, sizeof(*ref));
#if SPEND_ORACLE_KAT_BAKED
    memcpy(ref->diversifier, SPEND_ORACLE_KAT_DIVERSIFIER, 11);
    memcpy(ref->ak,   SPEND_ORACLE_KAT_AK,   32);
    memcpy(ref->nk,   SPEND_ORACLE_KAT_NK,   32);
    memcpy(ref->ivk,  SPEND_ORACLE_KAT_IVK,  32);
    memcpy(ref->pk_d, SPEND_ORACLE_KAT_PK_D, 32);
    memcpy(ref->cm,   SPEND_ORACLE_KAT_CM,   32);
    memcpy(ref->nf,   SPEND_ORACLE_KAT_NF,   32);
    ref->valid = true;
#endif
}

#define ORACLE_CHECK(name, expr) do {                 \
    printf("  %s... ", (name));                        \
    if ((expr)) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

#define ORACLE_EQ(name, a, b, n) \
    ORACLE_CHECK(name, memcmp((a), (b), (n)) == 0)

/* Public entry point: reference differential oracle for the Sapling spend
 * circuit. Returns the number of failures (0 == green). Params-free — it needs
 * no on-disk state. It loads the fixed external reference vector and checks
 * the native C23 implementation against it. */
int groth16_spend_reference_oracle(void);
int groth16_spend_reference_oracle(void)
{
    printf("\n--- H2: Sapling SPEND reference differential oracle ---\n");
    int failures = 0;

    struct spend_oracle_reference ref;
    spend_oracle_load_baked_reference(&ref);
    ORACLE_CHECK("baked KAT vector is present as ground truth", ref.valid);
    if (!ref.valid) {
        printf("--- end H2 oracle (%d failure[s]) ---\n", failures + 1);
        return failures + 1;
    }

#if SPEND_ORACLE_KAT_BAKED
    /* The native C23 spend-circuit building blocks must reproduce the
     * reference wire values exactly. Each C23 stage is fed the preceding C23
     * stage's output, so an all-green chain proves end-to-end agreement on
     * nk / ivk / pk_d / cm / nf. */
    uint8_t ak_c23[32], nk_c23[32], ivk_c23[32], pk_d_c23[32];
    uint8_t cm_c23[32], nf_c23[32];
    uint8_t d_c23[11];
    memset(d_c23, 0, sizeof(d_c23));
    for (unsigned i = 0; i < 256; i++) {
        d_c23[0] = (uint8_t)i;
        if (sapling_check_diversifier(d_c23)) break;
    }
    ORACLE_EQ("C23 first valid diversifier == baked KAT",
              d_c23, SPEND_ORACLE_KAT_DIVERSIFIER, 11);
    sapling_ask_to_ak(SPEND_ORACLE_KAT_ASK, ak_c23);
    ORACLE_EQ("C23 sapling_ask_to_ak == baked KAT (circuit input ak)",
              ak_c23, SPEND_ORACLE_KAT_AK, 32);
    sapling_nsk_to_nk(SPEND_ORACLE_KAT_NSK, nk_c23);
    sapling_crh_ivk(ref.ak, nk_c23, ivk_c23);
    bool pkd_ok = sapling_ivk_to_pkd(ivk_c23, ref.diversifier, pk_d_c23);
    ORACLE_CHECK("C23 sapling_ivk_to_pkd succeeded", pkd_ok);
    bool cm_ok = pkd_ok &&
        sapling_compute_cm(ref.diversifier, pk_d_c23, SPEND_ORACLE_KAT_VALUE,
                           SPEND_ORACLE_KAT_RCM, cm_c23);
    ORACLE_CHECK("C23 sapling_compute_cm succeeded", cm_ok);
    bool nf_ok = pkd_ok &&
        sapling_compute_nf(ref.diversifier, pk_d_c23, SPEND_ORACLE_KAT_VALUE,
                           SPEND_ORACLE_KAT_RCM, ref.ak, nk_c23,
                           SPEND_ORACLE_KAT_POSITION, nf_c23);
    ORACLE_CHECK("C23 sapling_compute_nf succeeded", nf_ok);

    ORACLE_EQ("C23 nk   == reference (section 7)",  nk_c23,   ref.nk,   32);
    ORACLE_EQ("C23 ivk  == reference (section 10)", ivk_c23,  ref.ivk,  32);
    if (pkd_ok)
        ORACLE_EQ("C23 pk_d == reference (section 13)", pk_d_c23, ref.pk_d, 32);
    if (cm_ok)
        ORACLE_EQ("C23 cm   == reference (section 17)", cm_c23,   ref.cm,   32);
    if (nf_ok)
        ORACLE_EQ("C23 nf   == reference (sections 27/28)", nf_c23, ref.nf, 32);
#else
    printf("  [oracle] required checked-in reference KAT is absent\n");
    failures++;
#endif

    printf("--- end H2 oracle (%d failure[s]) ---\n", failures);
    return failures;
}
