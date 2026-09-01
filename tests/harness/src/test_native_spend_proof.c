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
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "sapling/pedersen_hash.h"
#include "sapling/fr.h"

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

    /* sapling_init_params SHA-512-pins every params file before installing the
     * verifying keys, so "official" is checked, not assumed. */
    NSP_CHECK("sapling_init_params loaded the SHA-512-pinned params",
              sapling_init_params(params_dir));

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

    printf("=== native_spend_proof: %d failure(s) ===\n", failures);
    return failures;
}
