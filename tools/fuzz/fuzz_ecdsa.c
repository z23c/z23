/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_ecdsa — libFuzzer harness that runs the secp256k1 DIFFERENTIAL ORACLE
 * over unbounded input.
 *
 * The hand-written corpus in tests/harness/src/test_secp256k1_differential.c covers
 * the adversarial shapes we thought of. This covers the ones we did not: every
 * input is decoded into a (pubkey, message, signature) triple and fed to BOTH
 * the candidate (whatever the crypto registry serves for
 * CRYPTO_SIG_ECDSA_SECP256K1) and a reference built directly on the vendored
 * libsecp256k1 archive. Any disagreement on the accept/reject verdict aborts,
 * so libFuzzer reports it as a crash with a reproducer file — and because the
 * wire format is the same one the oracle's seed dump writes, that reproducer
 * drops straight back into the test corpus.
 *
 * The seed corpus (tests/harness/fuzz_seeds/ecdsa/) IS the oracle's adversarial
 * vector list, exported by
 *   ZCL_SECP_DUMP_SEEDS=tests/harness/fuzz_seeds/ecdsa \
 *     build/bin/test_parallel --only=secp256k1_differential
 * so the fuzzer starts on the interesting boundaries instead of on noise.
 *
 * Beyond the differential, this also drives the parse/serialize/recover
 * surfaces the node exposes to untrusted bytes — pubkey_is_fully_valid,
 * pubkey_decompress, pubkey_check_low_s, pubkey_recover_compact — under ASan
 * and UBSan. Those must never read out of bounds for ANY input; a malicious
 * peer's scriptSig reaches them.
 */

#include "test/secp256k1_corpus.h"
#include "crypto_registry/crypto_registry.h"
#include "keys/pubkey.h"

#include <secp256k1.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

/* Required by process_block.c / sync_controller — provided by main.c in the
 * real binary and by test.c in the test suite. The fuzzer is neither. */
volatile sig_atomic_t g_shutdown_requested = 0;

static secp256k1_context *g_ref_ctx;
static crypto_sig_verify_fn g_candidate;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Reference = the documented crypto_sig_verify_fn contract implemented
 * straight onto the vendored archive. Kept byte-identical in behaviour to the
 * oracle's ref_ecdsa_verify(); the two must not drift. */
static bool ref_verify(const uint8_t *pub, size_t publen,
                       const uint8_t *msg, size_t msglen,
                       const uint8_t *sig, size_t siglen)
{
    if (!pub || !msg || !sig)
        return false;
    if (msglen != 32 || publen == 0 || publen > PUBLIC_KEY_SIZE || siglen == 0)
        return false;
    secp256k1_pubkey p;
    secp256k1_ecdsa_signature s;
    if (!secp256k1_ec_pubkey_parse(g_ref_ctx, &p, pub, publen))
        return false;
    if (!secp256k1_ecdsa_signature_parse_der(g_ref_ctx, &s, sig, siglen))
        return false;
    secp256k1_ecdsa_signature_normalize(g_ref_ctx, &s, &s);
    return secp256k1_ecdsa_verify(g_ref_ctx, &s, msg, &p);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    /* contexts/wallet/modules/keys/src/pubkey.c keeps a file-static verify context that the node
     * creates once at boot (init.c -> ecc_verify_init) and every subsequent
     * pubkey_* call assumes is live. The fuzzer is not the node, so it must
     * perform the same boot step: without it pubkey_recover_compact /
     * pubkey_decompress / pubkey_check_low_s hand a NULL context straight to
     * libsecp256k1. (That is reachable ONLY here — the node's boot sequence
     * makes it unreachable in production, so this is a harness obligation,
     * not a node defect. It was found by this harness on its 5th input.) */
    ecc_verify_init();
    g_ref_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!g_ref_ctx)
        abort();
    const struct crypto_scheme *s =
        crypto_registry_lookup(CRYPTO_SIG_ECDSA_SECP256K1);
    if (!s || s->kind != CRYPTO_KIND_SIG || !s->fn.sig_verify) {
        fprintf(stderr, "fuzz_ecdsa: no ecdsa-secp256k1 scheme registered\n");
        abort();
    }
    g_candidate = s->fn.sig_verify;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct secp_vector v;
    if (!secp_vector_decode(&v, data, size))
        return 0;

    /* ── the differential — the whole point of this harness ─────────── */
    bool cand = g_candidate(v.pub, v.publen, v.msg, v.msglen,
                            v.sig, v.siglen);
    bool ref  = ref_verify(v.pub, v.publen, v.msg, v.msglen,
                           v.sig, v.siglen);
    if (cand != ref) {
        fprintf(stderr,
                "fuzz_ecdsa: DIVERGENCE candidate=%d reference=%d "
                "(publen=%zu msglen=%zu siglen=%zu)\n",
                cand, ref, v.publen, v.msglen, v.siglen);
        abort();
    }

    /* ── the consensus entry point must agree with the registry ─────── */
    if (v.publen > 0 && v.publen <= PUBLIC_KEY_SIZE && v.msglen == 32) {
        struct pubkey pk;
        pubkey_init(&pk);
        pubkey_set(&pk, v.pub, (unsigned int)v.publen);
        struct uint256 h;
        memcpy(h.data, v.msg, 32);
        if (pubkey_verify(&pk, &h, v.sig, v.siglen) != cand) {
            fprintf(stderr, "fuzz_ecdsa: pubkey_verify disagrees with "
                            "the registry wrapper\n");
            abort();
        }

        /* Stateless parse/serialize surfaces on the same untrusted bytes.
         * Each must be bounds-safe for any input; ASan/UBSan enforce that. */
        (void)pubkey_is_fully_valid(&pk);
        struct pubkey decomp = pk;
        if (pubkey_decompress(&decomp)) {
            /* A key that decompresses must still be a curve point, and the
             * uncompressed form must verify identically to the compressed
             * one — a re-serialization that changed the point would be a
             * silent consensus divergence. */
            if (!pubkey_is_fully_valid(&decomp)) {
                fprintf(stderr, "fuzz_ecdsa: decompress produced a "
                                "non-point\n");
                abort();
            }
            bool as_decomp = g_candidate(decomp.vch, decomp.size,
                                         v.msg, v.msglen, v.sig, v.siglen);
            if (as_decomp != cand) {
                fprintf(stderr, "fuzz_ecdsa: compressed/uncompressed verdict "
                                "mismatch (%d vs %d)\n", cand, as_decomp);
                abort();
            }
        }

        /* Recovery path — pure bounds exercise; a recovered key is only
         * meaningful for a real recoverable signature. */
        if (v.siglen >= COMPACT_SIGNATURE_SIZE) {
            struct pubkey rec;
            pubkey_init(&rec);
            (void)pubkey_recover_compact(&rec, &h, v.sig);
        }
    }

    if (v.siglen > 0)
        (void)pubkey_check_low_s(v.sig, v.siglen);

    return 0;
}
