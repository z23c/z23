/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the crypto_registry scheme catalog and verifier dispatch.
 * Groth16 coverage uses malformed-input rejection because loading the
 * multi-megabyte proving params is too fragile for a unit test; the wrapper
 * still exercises groth16_proof_read + groth16_vk_read_raw, which is the same
 * parse path real proofs use.
 */

#include "test/test_core.h"
#include "keys/key.h"
#include "json/json.h"
#include "crypto_registry/crypto_registry.h"
#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include "platform/time_compat.h"

#include <secp256k1.h>

static size_t make_equihash_96_5_fixture(uint8_t *input,
                                         size_t input_cap,
                                         uint8_t *solution,
                                         size_t solution_cap)
{
    const char *msg = "Equihash is an asymmetric PoW based on the "
                      "Generalised Birthday problem.";
    const size_t msg_len = strlen(msg);
    if (input_cap < msg_len + 32)
        return 0;
    memcpy(input, msg, msg_len);
    memset(input + msg_len, 0, 32);
    input[msg_len] = 1;

    struct equihash_params ep;
    equihash_params_init(&ep, 96, 5);
    eh_index valid_indices[32] = {
        2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041,
        32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
        15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
        23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568
    };
    size_t sol_len = eh_get_minimal_from_indices(
        valid_indices, 32, ep.collision_bit_length, solution, solution_cap);
    return sol_len == 68 ? msg_len + 32 : 0;
}

static bool equihash_verify_direct(const uint8_t *input, size_t input_len,
                                   const uint8_t *solution,
                                   size_t solution_len)
{
    unsigned int n = 0;
    unsigned int k = 0;
    if (!equihash_solution_params(solution_len, &n, &k))
        return false;

    struct equihash_params ep;
    equihash_params_init(&ep, n, k);
    struct blake2b_ctx state;
    equihash_initialise_state(&ep, &state);
    blake2b_update(&state, input, input_len);
    return equihash_is_valid_solution(&ep, &state, solution, solution_len);
}

static int64_t test_now_ns(void)
{
    struct timespec ts;
#ifdef CLOCK_THREAD_CPUTIME_ID
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) == 0)  // platform-ok:test-benchmark-cpu-time
        return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
#endif
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static bool ecdsa_verify_direct(secp256k1_context *ctx,
                                const struct pubkey *pk,
                                const struct uint256 *hash,
                                const uint8_t *sig,
                                size_t sig_len)
{
    secp256k1_pubkey parsed_pubkey;
    secp256k1_ecdsa_signature parsed_sig;
    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pubkey, pk->vch, pk->size))
        return false;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &parsed_sig, sig, sig_len))
        return false;
    secp256k1_ecdsa_signature_normalize(ctx, &parsed_sig, &parsed_sig);
    return secp256k1_ecdsa_verify(ctx, &parsed_sig, hash->data,
                                   &parsed_pubkey);
}

static bool pubkey_verify_direct_baseline(secp256k1_context *ctx,
                                          const struct pubkey *pk,
                                          const struct uint256 *hash,
                                          const uint8_t *sig,
                                          size_t sig_len)
{
    if (!pubkey_is_valid(pk))
        return false;
    if (!hash || !sig || sig_len == 0)
        return false;
    return ecdsa_verify_direct(ctx, pk, hash, sig, sig_len);
}

int test_crypto_registry(void)
{
    int failures = 0;
    uint8_t out[32];

    printf("\n=== crypto_registry ===\n");

    /* Case 1: register_lookup_basic — all four wrappers registered at
     * constructor time with the expected per-kind counts. */
    printf("registry has expected schemes... ");
    const struct crypto_scheme *sha =
        crypto_registry_lookup(CRYPTO_HASH_SHA256);
    const struct crypto_scheme *blake =
        crypto_registry_lookup(CRYPTO_HASH_BLAKE2B_256);
    const struct crypto_scheme *ecdsa =
        crypto_registry_lookup(CRYPTO_SIG_ECDSA_SECP256K1);
    const struct crypto_scheme *groth =
        crypto_registry_lookup(CRYPTO_ZK_GROTH16_BLS12_381);
    const struct crypto_scheme *equihash =
        crypto_registry_lookup(CRYPTO_PROOF_EQUIHASH_200_9);
    if (sha && blake && ecdsa && groth && equihash &&
        crypto_registry_count() == 5 &&
        crypto_registry_count_by_kind(CRYPTO_KIND_HASH) == 2 &&
        crypto_registry_count_by_kind(CRYPTO_KIND_SIG) == 1 &&
        crypto_registry_count_by_kind(CRYPTO_KIND_ZK) == 2) {
        printf("OK\n");
    } else {
        printf("FAIL (have sha=%d blake=%d ecdsa=%d groth=%d count=%zu)\n",
               sha != NULL, blake != NULL, ecdsa != NULL, groth != NULL,
               crypto_registry_count());
        failures++;
    }

    /* Case 2: register_collision_rejected — try to re-register the
     * SHA256 slot. The CAS must fail and the original wrapper must
     * remain in place. */
    printf("re-register collision rejected... ");
    {
        const struct crypto_scheme original_sha =
            *crypto_registry_lookup(CRYPTO_HASH_SHA256);
        struct crypto_scheme dup = original_sha;
        dup.name = "sha256-duplicate";
        dup.impl = "test fixture";
        bool ok = !crypto_registry_register(&dup);
        const struct crypto_scheme *after =
            crypto_registry_lookup(CRYPTO_HASH_SHA256);
        if (ok && after &&
            after->fn.hash == original_sha.fn.hash &&
            strcmp(after->name, original_sha.name) == 0) {
            printf("OK\n");
        } else {
            printf("FAIL (collision_register=%s, name_after=%s)\n",
                   ok ? "rejected" : "ACCEPTED",
                   after ? after->name : "(null)");
            failures++;
        }
    }

    /* Case 3: lookup of an unregistered slot returns NULL. */
    printf("lookup_unregistered_returns_null... ");
    {
        const struct crypto_scheme *miss =
            crypto_registry_lookup((enum crypto_scheme_id)999);
        const struct crypto_scheme *ed =
            crypto_registry_lookup(CRYPTO_SIG_ED25519);
        if (miss == NULL && ed == NULL)
            printf("OK\n");
        else {
            printf("FAIL (id=999 -> %p, ed25519 -> %p)\n",
                   (const void *)miss, (const void *)ed);
            failures++;
        }
    }

    /* Case 4: is_usable returns false for unregistered + out-of-range. */
    printf("is_usable_false_for_unregistered... ");
    {
        bool a = !crypto_registry_is_usable((enum crypto_scheme_id)999);
        bool b = !crypto_registry_is_usable(CRYPTO_SIG_ED25519);
        bool c = !crypto_registry_is_usable((enum crypto_scheme_id)0);
        bool d = crypto_registry_is_usable(CRYPTO_HASH_SHA256);
        if (a && b && c && d)
            printf("OK\n");
        else {
            printf("FAIL (999=%d ed=%d 0=%d sha=%d)\n", a, b, c, d);
            failures++;
        }
    }

    printf("sha256 wrapper vector... ");
    if (sha && sha->fn.hash("hello", 5, out) == 0)
        failures += check_hex(out, 32,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    else {
        printf("FAIL\n");
        failures++;
    }

    printf("blake2b-256 wrapper vector... ");
    if (blake && blake->fn.hash("abc", 3, out) == 0)
        failures += check_hex(out, 32,
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    else {
        printf("FAIL\n");
        failures++;
    }

    printf("ecdsa wrapper verifies generated signature... ");
    {
        struct privkey k;
        privkey_make_new(&k, true);
        struct pubkey pk;
        privkey_get_pubkey(&k, &pk);

        struct uint256 hash;
        memset(hash.data, 0x5a, sizeof(hash.data));

        uint8_t sig[SIGNATURE_SIZE];
        size_t sig_len = sizeof(sig);
        bool signed_ok = privkey_sign(&k, &hash, sig, &sig_len);
        bool verified = ecdsa && ecdsa->fn.sig_verify(pk.vch, pk.size,
                                                      hash.data, 32,
                                                      sig, sig_len);
        hash.data[0] ^= 0x01;
        bool rejected = ecdsa && !ecdsa->fn.sig_verify(pk.vch, pk.size,
                                                       hash.data, 32,
                                                       sig, sig_len);
        if (signed_ok && verified && rejected)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("groth16 wrapper rejects malformed inputs... ");
    {
        uint8_t bad_vk[4] = {0};
        uint8_t bad_proof[192] = {0};
        bool ok = groth && !groth->fn.zk_verify(bad_vk, sizeof(bad_vk),
                                                NULL, 0,
                                                bad_proof,
                                                sizeof(bad_proof) - 1);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("equihash wrapper verifies known-good fixture... ");
    {
        uint8_t input[128];
        uint8_t solution[68];
        size_t input_len = make_equihash_96_5_fixture(
            input, sizeof(input), solution, sizeof(solution));
        bool ok = input_len > 0 && equihash &&
                  equihash->fn.zk_verify(NULL, 0, input, input_len,
                                         solution, sizeof(solution));
        solution[0] ^= 0x01;
        bool rejected = equihash &&
                        !equihash->fn.zk_verify(NULL, 0, input, input_len,
                                                solution, sizeof(solution));
        if (ok && rejected)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("equihash registry indirection cost... ");
    {
        uint8_t input[128];
        uint8_t solution[68];
        size_t input_len = make_equihash_96_5_fixture(
            input, sizeof(input), solution, sizeof(solution));
        const int iters = 1000;
        bool ok = input_len > 0 && equihash;
        int direct_true = 0;
        int registry_true = 0;

        int64_t t0 = test_now_ns();
        for (int i = 0; ok && i < iters; i++)
            direct_true += equihash_verify_direct(
                input, input_len, solution, sizeof(solution));
        int64_t t1 = test_now_ns();
        for (int i = 0; ok && i < iters; i++)
            registry_true += equihash->fn.zk_verify(
                NULL, 0, input, input_len, solution, sizeof(solution));
        int64_t t2 = test_now_ns();

        int64_t direct_ns = t1 - t0;
        int64_t registry_ns = t2 - t1;
        if (ok && direct_true == iters && registry_true == iters) {
            printf("OK (direct=%lldns registry=%lldns)\n",
                   (long long)direct_ns, (long long)registry_ns);
        } else {
            printf("FAIL (direct=%lldns registry=%lldns direct_ok=%d "
                   "registry_ok=%d)\n",
                   (long long)direct_ns, (long long)registry_ns,
                   direct_true, registry_true);
            failures++;
        }
    }

    printf("ecdsa pubkey_verify registry indirection cost... ");
    {
        struct privkey k;
        privkey_make_new(&k, true);
        struct pubkey pk;
        privkey_get_pubkey(&k, &pk);

        struct uint256 hash;
        memset(hash.data, 0x33, sizeof(hash.data));

        uint8_t sig[SIGNATURE_SIZE];
        size_t sig_len = sizeof(sig);
        bool ok = privkey_sign(&k, &hash, sig, &sig_len);
        secp256k1_context *ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        ok = ok && ctx &&
             pubkey_verify_direct_baseline(ctx, &pk, &hash, sig, sig_len) &&
             pubkey_verify(&pk, &hash, sig, sig_len);

        const int batches = 100;
        const int batch_iters = 1000;
        const int iters = batches * batch_iters;
        volatile int direct_true = 0;
        volatile int registry_true = 0;

        int64_t direct_ns = 0;
        int64_t registry_ns = 0;
        for (int b = 0; ok && b < batches; b++) {
            int64_t t0, t1, t2;
            if ((b & 1) == 0) {
                t0 = test_now_ns();
                for (int i = 0; i < batch_iters; i++)
                    direct_true += pubkey_verify_direct_baseline(
                        ctx, &pk, &hash, sig, sig_len);
                t1 = test_now_ns();
                for (int i = 0; i < batch_iters; i++)
                    registry_true += pubkey_verify(&pk, &hash, sig, sig_len);
                t2 = test_now_ns();
                direct_ns += t1 - t0;
                registry_ns += t2 - t1;
            } else {
                t0 = test_now_ns();
                for (int i = 0; i < batch_iters; i++)
                    registry_true += pubkey_verify(&pk, &hash, sig, sig_len);
                t1 = test_now_ns();
                for (int i = 0; i < batch_iters; i++)
                    direct_true += pubkey_verify_direct_baseline(
                        ctx, &pk, &hash, sig, sig_len);
                t2 = test_now_ns();
                registry_ns += t1 - t0;
                direct_ns += t2 - t1;
            }
        }

        if (ctx)
            secp256k1_context_destroy(ctx);

        ok = ok && direct_true == iters && registry_true == iters;
        if (ok) {
            long long overhead_ppm = direct_ns > 0
                ? ((long long)(registry_ns - direct_ns) * 1000000LL) /
                      (long long)direct_ns
                : 0;
            printf("OK (direct=%lldns registry=%lldns overhead=%lldppm)\n",
                   (long long)direct_ns, (long long)registry_ns,
                   overhead_ppm);
        } else {
            printf("FAIL (direct=%lldns registry=%lldns direct_ok=%d "
                   "registry_ok=%d)\n",
                   (long long)direct_ns, (long long)registry_ns,
                   direct_true, registry_true);
            failures++;
        }
    }

    printf("diagnostics dump exposes schemes... ");
    {
        struct json_value dump;
        json_init(&dump);
        bool ok = crypto_registry_dump_state_json(&dump, NULL);
        const struct json_value *total = json_get(&dump, "total_registered");
        const struct json_value *schemes = json_get(&dump, "schemes");
        ok = ok && total && json_get_int(total) == 5 &&
             schemes && json_size(schemes) == 5;
        json_free(&dump);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}
