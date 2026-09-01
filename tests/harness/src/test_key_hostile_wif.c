/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hostile-WIF hardening tests — importprivkey/signrawtransaction reach
 * privkey_get_pubkey with attacker-supplied scalars, and the old
 * assert(ret) pattern let a WIF encoding 0 or >= the secp256k1 group
 * order abort() the whole node (assert is live in release builds).
 *
 * Contract under test:
 *   - decode_secret rejects out-of-range scalars at the boundary
 *     (zero, the group order) and accepts in-range ones (order - 1);
 *   - privkey_get_pubkey / privkey_sign / privkey_sign_compact are
 *     total: a bad scalar that somehow bypasses the boundary check
 *     returns false instead of aborting the process.
 */

#include "test/test_core.h"

#include "domain/encoding/base58.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

#define KHW_CHECK(name, expr) do {                    \
    printf("key_hostile_wif: %s... ", (name));        \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

/* secp256k1 group order n, big-endian. */
static const unsigned char K_ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

/* Build a compressed-key mainnet WIF: base58check(0x80||scalar||0x01). */
static bool khw_make_wif(const unsigned char scalar[32],
                         char *out, size_t out_size)
{
    unsigned char payload[34];
    payload[0] = 0x80;
    memcpy(payload + 1, scalar, 32);
    payload[33] = 0x01;
    size_t out_len = 0;
    return domain_encoding_base58check_encode(payload, sizeof(payload),
                                              out, out_size, &out_len);
}

int test_key_hostile_wif(void)
{
    printf("\n=== hostile WIF / out-of-range scalar tests ===\n");
    int failures = 0;
    const unsigned char sec_pfx[1] = { 0x80 };
    char wif[128];
    struct privkey key;

    /* 1. Zero scalar: encodes fine, must be REJECTED at decode. */
    {
        unsigned char zero[32] = { 0 };
        bool built = khw_make_wif(zero, wif, sizeof(wif));
        KHW_CHECK("zero-scalar WIF rejected by decode_secret",
                  built && !decode_secret(wif, sec_pfx, 1, &key));
    }

    /* 2. Scalar == group order: out of range, must be rejected. */
    {
        bool built = khw_make_wif(K_ORDER, wif, sizeof(wif));
        KHW_CHECK("order-scalar WIF rejected by decode_secret",
                  built && !decode_secret(wif, sec_pfx, 1, &key));
    }

    /* 3. Scalar == order - 1: the largest valid key — must decode and
     * derive a pubkey. */
    {
        unsigned char max_valid[32];
        memcpy(max_valid, K_ORDER, 32);
        max_valid[31] -= 1;
        bool built = khw_make_wif(max_valid, wif, sizeof(wif));
        bool decoded = built && decode_secret(wif, sec_pfx, 1, &key);
        struct pubkey pk;
        KHW_CHECK("order-minus-1 WIF decodes and derives a pubkey",
                  decoded && privkey_get_pubkey(&key, &pk));
    }

    /* 4. Totality: a bad scalar forced past the boundary (fValid set by
     * hand, as an unvalidated legacy path might) must FAIL CLEANLY in
     * pubkey derivation and both sign paths — reaching the end of this
     * test at all proves no abort(). */
    {
        struct privkey forced;
        privkey_init(&forced);
        memset(forced.vch, 0, sizeof(forced.vch));
        forced.fValid = true;
        forced.fCompressed = true;

        struct pubkey pk;
        struct uint256 h;
        memset(&h, 0x42, sizeof(h));
        unsigned char sig[80];
        size_t siglen = sizeof(sig);
        unsigned char csig[COMPACT_SIGNATURE_SIZE];

        KHW_CHECK("forced zero scalar: get_pubkey returns false (no abort)",
                  !privkey_get_pubkey(&forced, &pk));
        KHW_CHECK("forced zero scalar: sign returns false (no abort)",
                  !privkey_sign(&forced, &h, sig, &siglen));
        KHW_CHECK("forced zero scalar: sign_compact returns false (no abort)",
                  !privkey_sign_compact(&forced, &h, csig));
        KHW_CHECK("range check exposes the truth",
                  !privkey_range_check(&forced));
    }

    return failures;
}
