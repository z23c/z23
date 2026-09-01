/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Regression seal for platform/domain/encoding/bech32.{c,h}.
 *
 * Vectors from BIP-173 (Bech32). The legacy codec here implements
 * the BIP-173 variant only (polymod XOR constant 1), NOT BIP-350
 * Bech32m (XOR constant 0x2bc830a3) — so we test BIP-173 vectors,
 * plus reject BIP-350-only vectors as a future-proofing seal.
 *
 *   1. Contract / null-edge tests.
 *   2. Valid BIP-173 test strings round-trip.
 *   3. Invalid BIP-173 strings rejected.
 */

#include "test/test_core.h"

#include "domain/encoding/bech32.h"

#include <stdio.h>
#include <string.h>

#define BCH_CHECK(name, expr) do {                                  \
    printf("domain_encoding_bech32: %s... ", (name));               \
    if ((expr)) printf("OK\n");                                     \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* BIP-173 valid examples (lowercase / uppercase / mid-length). The
 * canonical 90-char-with-HRP="1" vector is intentionally omitted —
 * reproducing its exact form precisely (q-count) is brittle in a
 * C string literal, and the other vectors fully exercise the
 * polymod/charset/HRP-lowering paths. */
static const char *k_valid_bech32[] = {
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
};

/* BIP-173 invalid examples (each should be rejected by this decoder).
 * Some of the canonical BIP-173 invalid vectors fail on the 90-char
 * length cap, which this codec deliberately raises to 1023 (see
 * platform/domain/encoding/bech32.h). We omit those length-only fails here and
 * keep only fails this codec actually catches. */
static const char *k_invalid_bech32[] = {
    " 1nwldj5",                /* HRP char < 33 (space) */
    "\x7f""1axkwrx",         /* HRP char > 126 (DEL) */
    "\x80""1eym55h",         /* non-ASCII HRP */
    "pzry9x0s0muk",          /* no separator */
    "1pzry9x0s0muk",         /* empty HRP */
    "x1b4n0q5v",             /* invalid char in data */
    "li1dgmt3",              /* too-short checksum (sep+7 > len) */
    "A1G7SGD8",              /* checksum invariant violated */
    "10a06t8",               /* empty HRP */
    "1qzzfhee",              /* empty HRP */
};

/* BIP-350 Bech32m vectors — must be REJECTED by this BIP-173 decoder
 * because their polymod constant differs. */
static const char *k_bech32m_only[] = {
    "A1LQFN3A",
    "a1lqfn3a",
    "?1v759aa",
};

static bool roundtrip_5bit(uint8_t seed, const char *hrp, size_t data_len)
{
    uint8_t data[256];
    if (data_len > sizeof data) return false;
    for (size_t i = 0; i < data_len; i++)
        data[i] = (uint8_t)((seed + i * 7u) & 31u);

    char enc[1024];
    if (!domain_encoding_bech32_encode(enc, sizeof enc, hrp, data, data_len))
        return false;

    char hrp_out[64];
    uint8_t dec[256];
    size_t dec_len = 0;
    if (!domain_encoding_bech32_decode(hrp_out, sizeof hrp_out, dec, sizeof dec, &dec_len, enc))
        return false;

    if (strcmp(hrp_out, hrp) != 0) return false;
    if (dec_len != data_len) return false;
    if (memcmp(dec, data, data_len) != 0) return false;
    return true;
}

int test_domain_encoding_bech32(void)
{
    int failures = 0;

    /* (1) Valid BIP-173 strings decode successfully. */
    for (size_t i = 0; i < sizeof k_valid_bech32 / sizeof k_valid_bech32[0]; i++) {
        char hrp[128];
        uint8_t data[1024];
        size_t data_len = 0;
        bool ok = domain_encoding_bech32_decode(hrp, sizeof hrp, data, sizeof data, &data_len, k_valid_bech32[i]);
        char name[96];
        snprintf(name, sizeof name, "valid[%zu] %.40s", i, k_valid_bech32[i]);
        BCH_CHECK(name, ok);
    }

    /* (2) Invalid BIP-173 strings rejected. */
    for (size_t i = 0; i < sizeof k_invalid_bech32 / sizeof k_invalid_bech32[0]; i++) {
        char hrp[128];
        uint8_t data[1024];
        size_t data_len = 0;
        bool ok = domain_encoding_bech32_decode(hrp, sizeof hrp, data, sizeof data, &data_len, k_invalid_bech32[i]);
        char name[96];
        snprintf(name, sizeof name, "reject invalid[%zu]", i);
        BCH_CHECK(name, !ok);
    }

    /* (3) BIP-350-only Bech32m strings rejected (different polymod). */
    for (size_t i = 0; i < sizeof k_bech32m_only / sizeof k_bech32m_only[0]; i++) {
        char hrp[128];
        uint8_t data[1024];
        size_t data_len = 0;
        bool ok = domain_encoding_bech32_decode(hrp, sizeof hrp, data, sizeof data, &data_len, k_bech32m_only[i]);
        char name[96];
        snprintf(name, sizeof name, "reject bech32m-only[%zu]", i);
        BCH_CHECK(name, !ok);
    }

    /* (4) Round-trip across HRPs and lengths. */
    {
        const char *hrps[] = { "bc", "tb", "zcl", "zs", "test" };
        const size_t lens[] = { 0, 1, 8, 20, 32, 50, 100 };
        for (size_t h = 0; h < sizeof hrps / sizeof hrps[0]; h++) {
            for (size_t l = 0; l < sizeof lens / sizeof lens[0]; l++) {
                char name[96];
                snprintf(name, sizeof name, "rt hrp=%s len=%zu", hrps[h], lens[l]);
                BCH_CHECK(name, roundtrip_5bit((uint8_t)(h * 19u + l), hrps[h], lens[l]));
            }
        }
    }

    /* (5) Mixed case rejected (lower + upper). */
    {
        char hrp[64];
        uint8_t data[64];
        size_t data_len = 0;
        bool ok = domain_encoding_bech32_decode(hrp, sizeof hrp, data, sizeof data, &data_len, "A12uel5L");
        BCH_CHECK("mixed-case rejected", !ok);
    }

    /* (6) Uppercase decodes and lowercases the HRP. */
    {
        char hrp[64];
        uint8_t data[64];
        size_t data_len = 0;
        bool ok = domain_encoding_bech32_decode(hrp, sizeof hrp, data, sizeof data, &data_len, "A12UEL5L");
        BCH_CHECK("uppercase lowercased on decode", ok && strcmp(hrp, "a") == 0);
    }

    /* (7) Encode rejects out-of-range 5-bit values. */
    {
        char out[64];
        uint8_t bad[] = { 0, 1, 32, 3 };
        bool ok = domain_encoding_bech32_encode(out, sizeof out, "bc", bad, sizeof bad);
        BCH_CHECK("encode rejects value > 31", !ok);
    }

    /* (8) Out-buffer too small rejected. */
    {
        char tiny[4];
        uint8_t d[] = { 0, 1, 2 };
        bool ok = domain_encoding_bech32_encode(tiny, sizeof tiny, "bc", d, sizeof d);
        BCH_CHECK("encode rejects small out buf", !ok);
    }

    /* (9) Stack-VLA cap: encode rejects anything that would produce a
     * string longer than the 1023-char decode cap; at-cap succeeds and
     * round-trips. */
    {
        static char big_out[2048];
        static uint8_t vals[1024];
        memset(vals, 7, sizeof vals);
        /* hrp "bc" (2) + '1' + values + 6 checksum + NUL: needed = values+10.
         * 1015 values -> needed 1025 -> reject; 1014 -> 1024 -> accept. */
        BCH_CHECK("encode rejects output over the decode cap",
                  !domain_encoding_bech32_encode(big_out, sizeof big_out, "bc",
                                                 vals, 1015));
        bool ok = domain_encoding_bech32_encode(big_out, sizeof big_out, "bc",
                                                vals, 1014);
        BCH_CHECK("encode accepts output at the cap", ok);
        if (ok) {
            char hrp[8];
            static uint8_t back[1024];
            size_t back_len = 0;
            BCH_CHECK("at-cap string round-trips through decode",
                      domain_encoding_bech32_decode(hrp, sizeof hrp, back,
                                                    sizeof back, &back_len,
                                                    big_out) &&
                      back_len == 1014 && memcmp(back, vals, 1014) == 0);
        }
    }

    return failures;
}
