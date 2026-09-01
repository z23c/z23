/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for contexts/wallet/domain/mnemonic.{c,h}.
 *
 * Pins the pure BIP39 encoding + PBKDF2 seed derivation extracted from
 * contexts/wallet/src/mnemonic.c. Four layers:
 *
 *   1. Contract / null-edge tests on the typed zcl_result API.
 *   2. BIP39 standard test vectors (Trezor/python-mnemonic reference):
 *      entropy → mnemonic, mnemonic → entropy, PBKDF2 seed with the
 *      canonical "TREZOR" passphrase.
 *   3. Round-trip property: entropy → mnemonic → entropy over
 *      synthetic random-looking inputs and all five valid lengths.
 *   4. Wrapper-vs-domain regression seal: the contexts/wallet/modules/wallet wrappers must
 *      produce byte-identical output to the pure domain functions.
 */

#include "test/test_core.h"

#include "domain/wallet/mnemonic.h"
#include "wallet/mnemonic.h"

#include <stdio.h>
#include <string.h>

#define DWM_CHECK(name, expr) do {                                  \
    printf("domain_wallet_mnemonic: %s... ", (name));               \
    if ((expr)) printf("OK\n");                                     \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* ── Canonical BIP39 test vectors (Trezor/python-mnemonic) ────────── */

/* Vector 1: 128-bit zero entropy. */
static const uint8_t tv1_entropy[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const char *tv1_mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
/* PBKDF2-HMAC-SHA512 seed with passphrase = "TREZOR" (the canonical vector). */
static const uint8_t tv1_seed_trezor[] = {
    0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72,
    0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
    0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e,
    0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
    0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82,
    0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
    0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b,
    0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
};
/* PBKDF2-HMAC-SHA512 seed with empty passphrase. */
static const uint8_t tv1_seed_empty[] = {
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
    0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
    0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
    0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
    0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
};

/* Vector 2: 256-bit zero entropy → 24-word phrase ending in "art". */
static const uint8_t tv2_entropy[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const char *tv2_mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon art";

/* Vector 3: "legal winner thank year wave sausage worth useful legal
 * winner thank yellow" — entropy = 0x7f7f...7f, 16 bytes.
 * Seed with TREZOR passphrase per BIP39 spec. */
static const uint8_t tv3_entropy[] = {
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
};
static const char *tv3_mnemonic =
    "legal winner thank year wave sausage worth useful "
    "legal winner thank yellow";
static const uint8_t tv3_seed_trezor[] = {
    0x2e, 0x89, 0x05, 0x81, 0x9b, 0x87, 0x23, 0xfe,
    0x2c, 0x1d, 0x16, 0x18, 0x60, 0xe5, 0xee, 0x18,
    0x30, 0x31, 0x8d, 0xbf, 0x49, 0xa8, 0x3b, 0xd4,
    0x51, 0xcf, 0xb8, 0x44, 0x0c, 0x28, 0xbd, 0x6f,
    0xa4, 0x57, 0xfe, 0x12, 0x96, 0x10, 0x65, 0x59,
    0xa3, 0xc8, 0x09, 0x37, 0xa1, 0xc1, 0x06, 0x9b,
    0xe3, 0xa3, 0xa5, 0xbd, 0x38, 0x1e, 0xe6, 0x26,
    0x0e, 0x8d, 0x97, 0x39, 0xfc, 0xe1, 0xf6, 0x07,
};

static bool bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

/* Small linear-congruential PRNG for synthetic round-trip entropy.
 * Deterministic — never calls platform.rng. */
static uint32_t lcg_state;
static void lcg_seed(uint32_t s) { lcg_state = s ? s : 0xa5a5a5a5u; }
static uint8_t lcg_byte(void)
{
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return (uint8_t)(lcg_state >> 24);
}

int test_domain_wallet_mnemonic(void)
{
    int failures = 0;

    /* ── Layer 1: contract / null-edge ────────────────────────────── */

    /* mnemonic_from_entropy: null entropy / null buf / null written / bad len. */
    {
        char buf[256];
        size_t w = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                NULL, 16, buf, sizeof(buf), &w);
        DWM_CHECK("from_entropy null entropy -> NULL_ENTROPY",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_ENTROPY);
    }
    {
        size_t w = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv1_entropy, 16, NULL, 256, &w);
        DWM_CHECK("from_entropy null buf -> NULL_BUF",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_BUF);
    }
    {
        char buf[256];
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv1_entropy, 16, buf, sizeof(buf), NULL);
        DWM_CHECK("from_entropy null written -> NULL_OUT",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_OUT);
    }
    {
        char buf[256];
        size_t w = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv1_entropy, 17 /* bad */, buf, sizeof(buf), &w);
        DWM_CHECK("from_entropy bad entropy_len -> ENTROPY_LEN",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_ENTROPY_LEN);
    }
    {
        /* 12 words need >=89 chars; "abandon ...about" is 100+ bytes. Tiny
         * buf must reject. */
        char buf[16];
        size_t w = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv1_entropy, 16, buf, sizeof(buf), &w);
        DWM_CHECK("from_entropy tiny buf -> BUF_TOO_SMALL",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_BUF_TOO_SMALL);
    }
    {
        char buf[256];
        size_t w = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv1_entropy, 16, buf, 0, &w);
        DWM_CHECK("from_entropy zero buf_size -> BUF_TOO_SMALL",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_BUF_TOO_SMALL);
    }

    /* ── normalize: the one canonical form ────────────────────────
     *
     * Everything below is a way a user's twelve words arrive after a copy,
     * a paste or a transcription. They are all the same phrase, so they
     * must all normalise to the same bytes — that equality is what stops a
     * pasted phrase from opening a valid-looking, empty, WRONG wallet. */
    {
        struct { const char *in, *want; } cases[] = {
            { "abandon about",        "abandon about" },
            { " abandon about",       "abandon about" },
            { "abandon about ",       "abandon about" },
            { "abandon about\n",      "abandon about" },
            { "\tabandon\tabout\r\n", "abandon about" },
            { "abandon   about",      "abandon about" },
            { "  \n abandon \t\r\n about \n ", "abandon about" },
            { "",                     ""              },
            { "   \t\n ",             ""              },
            { "abandon",              "abandon"       },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char out[64];
            size_t n = 0;
            struct zcl_result r = domain_wallet_mnemonic_normalize(
                    cases[i].in, out, sizeof(out), &n);
            DWM_CHECK("normalize collapses whitespace to the canonical form",
                      r.ok && strcmp(out, cases[i].want) == 0 &&
                      n == strlen(cases[i].want));
        }
    }
    {
        char out[64];
        struct zcl_result r =
            domain_wallet_mnemonic_normalize(NULL, out, sizeof(out), NULL);
        DWM_CHECK("normalize null phrase -> NULL_PHRASE",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_PHRASE);
    }
    {
        struct zcl_result r =
            domain_wallet_mnemonic_normalize("abandon", NULL, 8, NULL);
        DWM_CHECK("normalize null out -> NULL_BUF",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_BUF);
    }
    {
        char out[4];
        struct zcl_result r = domain_wallet_mnemonic_normalize(
                "abandon about", out, sizeof(out), NULL);
        DWM_CHECK("normalize tiny out -> BUF_TOO_SMALL",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_BUF_TOO_SMALL);
    }
    {
        /* NFKD is not implemented, so a phrase that might NEED it is
         * refused rather than derived from un-normalised bytes. */
        char out[64];
        struct zcl_result r = domain_wallet_mnemonic_normalize(
                "abandon ab\xc3\xa1ndon", out, sizeof(out), NULL);
        DWM_CHECK("normalize non-ASCII -> NON_ASCII (refused, not guessed)",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NON_ASCII);
    }
    {
        /* And the refusal reaches the two calls that matter, so no caller
         * can derive a seed from bytes this node cannot normalise. */
        uint8_t seed[64];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                "abandon ab\xc3\xa1ndon", "", seed, sizeof(seed));
        DWM_CHECK("to_seed refuses a non-ASCII phrase",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NON_ASCII);
        struct zcl_result v =
            domain_wallet_mnemonic_validate("abandon ab\xc3\xa1ndon");
        DWM_CHECK("validate refuses a non-ASCII phrase",
                  !v.ok && v.code == DOMAIN_WALLET_MNEMONIC_ERR_NON_ASCII);
    }
    {
        /* The seed a sloppy spelling derives IS the canonical one — the
         * whole point — and the canonical vector still holds, so this is
         * not a normalisation that quietly changed every wallet. */
        uint8_t canon[64], messy[64];
        struct zcl_result a = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, "TREZOR", canon, sizeof(canon));
        char sloppy[512];
        snprintf(sloppy, sizeof(sloppy), "  %s \n", tv1_mnemonic);
        for (char *p = sloppy; *p; p++)
            if (*p == ' ' && p[1] == 'a') *p = '\t';
        struct zcl_result b = domain_wallet_mnemonic_to_seed(
                sloppy, "TREZOR", messy, sizeof(messy));
        DWM_CHECK("a sloppily-pasted phrase derives the canonical BIP39 seed",
                  a.ok && b.ok && bytes_equal(canon, messy, 64) &&
                  bytes_equal(canon, tv1_seed_trezor, 64));
    }
    {
        /* The PASSPHRASE is a secret string, not a word list: its
         * whitespace is deliberate and must NOT be collapsed. */
        uint8_t with_space[64], without[64];
        struct zcl_result a = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, " TREZOR ", with_space, sizeof(with_space));
        struct zcl_result b = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, "TREZOR", without, sizeof(without));
        DWM_CHECK("passphrase whitespace is NOT normalised away",
                  a.ok && b.ok && !bytes_equal(with_space, without, 64));
    }

    /* mnemonic_to_entropy: null phrase / null out / tiny capacity. */
    {
        uint8_t e[32];
        size_t el = 0;
        struct zcl_result r = domain_wallet_mnemonic_to_entropy(
                NULL, e, sizeof(e), &el);
        DWM_CHECK("to_entropy null phrase -> NULL_PHRASE",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_PHRASE);
    }
    {
        size_t el = 0;
        struct zcl_result r = domain_wallet_mnemonic_to_entropy(
                tv1_mnemonic, NULL, 32, &el);
        DWM_CHECK("to_entropy null entropy_out -> NULL_OUT",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_OUT);
    }
    {
        uint8_t e[32];
        struct zcl_result r = domain_wallet_mnemonic_to_entropy(
                tv1_mnemonic, e, sizeof(e), NULL);
        DWM_CHECK("to_entropy null entropy_len_out -> NULL_OUT",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_OUT);
    }
    {
        uint8_t e[16];
        size_t el = 0;
        struct zcl_result r = domain_wallet_mnemonic_to_entropy(
                tv1_mnemonic, e, sizeof(e), &el);
        DWM_CHECK("to_entropy tiny capacity -> BUF_TOO_SMALL",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_BUF_TOO_SMALL);
    }

    /* mnemonic_validate / decode: unknown word + bad checksum + bad count. */
    {
        struct zcl_result r = domain_wallet_mnemonic_validate(
                "abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon notaword");
        DWM_CHECK("validate unknown word -> UNKNOWN_WORD",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_UNKNOWN_WORD);
    }
    {
        /* Same as tv1 but last word swapped to a different valid word
         * (breaks the checksum). */
        struct zcl_result r = domain_wallet_mnemonic_validate(
                "abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon abandon");
        DWM_CHECK("validate bad checksum -> CHECKSUM",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_CHECKSUM);
    }
    {
        struct zcl_result r = domain_wallet_mnemonic_validate(
                "abandon abandon abandon");
        DWM_CHECK("validate wrong count -> BAD_WORD_COUNT",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_BAD_WORD_COUNT);
    }
    {
        struct zcl_result r = domain_wallet_mnemonic_validate(NULL);
        DWM_CHECK("validate null phrase -> NULL_PHRASE",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_PHRASE);
    }

    /* to_seed: null phrase / null seed / tiny seed buf. */
    {
        uint8_t seed[64];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                NULL, "", seed, sizeof(seed));
        DWM_CHECK("to_seed null phrase -> NULL_PHRASE",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_PHRASE);
    }
    {
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, "", NULL, 64);
        DWM_CHECK("to_seed null seed_out -> NULL_SEED",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_NULL_SEED);
    }
    {
        uint8_t seed[16];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, "", seed, sizeof(seed));
        DWM_CHECK("to_seed tiny seed_buf -> BUF_TOO_SMALL",
                  !r.ok && r.code == DOMAIN_WALLET_MNEMONIC_ERR_BUF_TOO_SMALL);
    }

    /* Bytes-needed table. */
    DWM_CHECK("entropy_bytes_for_words(12) = 16",
              domain_wallet_mnemonic_entropy_bytes_for_words(12) == 16);
    DWM_CHECK("entropy_bytes_for_words(24) = 32",
              domain_wallet_mnemonic_entropy_bytes_for_words(24) == 32);
    DWM_CHECK("entropy_bytes_for_words(13) = 0",
              domain_wallet_mnemonic_entropy_bytes_for_words(13) == 0);
    DWM_CHECK("entropy_bytes_for_words(0)  = 0",
              domain_wallet_mnemonic_entropy_bytes_for_words(0) == 0);

    /* Wordlist sanity. */
    DWM_CHECK("wordlist[0] == \"abandon\"",
              strcmp(domain_wallet_mnemonic_wordlist_get(0), "abandon") == 0);
    DWM_CHECK("wordlist[2047] == \"zoo\"",
              strcmp(domain_wallet_mnemonic_wordlist_get(2047), "zoo") == 0);
    DWM_CHECK("wordlist OOB low -> NULL",
              domain_wallet_mnemonic_wordlist_get(-1) == NULL);
    DWM_CHECK("wordlist OOB high -> NULL",
              domain_wallet_mnemonic_wordlist_get(2048) == NULL);
    DWM_CHECK("wordlist_find(\"abandon\") = 0",
              domain_wallet_mnemonic_wordlist_find("abandon") == 0);
    DWM_CHECK("wordlist_find(\"zoo\") = 2047",
              domain_wallet_mnemonic_wordlist_find("zoo") == 2047);
    DWM_CHECK("wordlist_find(\"satoshi\") roundtrip via get",
              domain_wallet_mnemonic_wordlist_find("satoshi") >= 0 &&
              strcmp(domain_wallet_mnemonic_wordlist_get(
                          domain_wallet_mnemonic_wordlist_find("satoshi")),
                     "satoshi") == 0);
    DWM_CHECK("wordlist_find(unknown) = -1",
              domain_wallet_mnemonic_wordlist_find("notaword") == -1);
    DWM_CHECK("wordlist_find(NULL) = -1",
              domain_wallet_mnemonic_wordlist_find(NULL) == -1);

    /* ── Layer 2: BIP39 standard vectors ──────────────────────────── */

    /* TV1: 128-bit zero entropy → "abandon ... about". */
    {
        char phrase[256];
        size_t written = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv1_entropy, sizeof(tv1_entropy),
                phrase, sizeof(phrase), &written);
        DWM_CHECK("TV1 from_entropy matches canonical 12-word phrase",
                  r.ok && strcmp(phrase, tv1_mnemonic) == 0 &&
                  written == strlen(tv1_mnemonic));
    }
    /* TV1: phrase → entropy round-trip. */
    {
        uint8_t entropy[32];
        size_t entropy_len = 0;
        struct zcl_result r = domain_wallet_mnemonic_to_entropy(
                tv1_mnemonic, entropy, sizeof(entropy), &entropy_len);
        DWM_CHECK("TV1 to_entropy decodes canonical 12-word phrase",
                  r.ok && entropy_len == sizeof(tv1_entropy) &&
                  bytes_equal(entropy, tv1_entropy, entropy_len));
    }
    /* TV1: PBKDF2 seed with "TREZOR" passphrase (canonical BIP39 vector). */
    {
        uint8_t seed[64];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, "TREZOR", seed, sizeof(seed));
        DWM_CHECK("TV1 to_seed(phrase, \"TREZOR\") matches canonical seed",
                  r.ok && bytes_equal(seed, tv1_seed_trezor, 64));
    }
    /* TV1: PBKDF2 seed with empty passphrase. */
    {
        uint8_t seed[64];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, "", seed, sizeof(seed));
        DWM_CHECK("TV1 to_seed(phrase, \"\") matches empty-passphrase seed",
                  r.ok && bytes_equal(seed, tv1_seed_empty, 64));
    }
    /* TV1: passphrase=NULL is treated as "". */
    {
        uint8_t seed[64];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                tv1_mnemonic, NULL, seed, sizeof(seed));
        DWM_CHECK("TV1 to_seed(phrase, NULL) == to_seed(phrase, \"\")",
                  r.ok && bytes_equal(seed, tv1_seed_empty, 64));
    }

    /* TV2: 256-bit zero entropy → 24-word phrase. */
    {
        char phrase[256];
        size_t written = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv2_entropy, sizeof(tv2_entropy),
                phrase, sizeof(phrase), &written);
        DWM_CHECK("TV2 from_entropy matches canonical 24-word phrase",
                  r.ok && strcmp(phrase, tv2_mnemonic) == 0);
    }
    /* TV2 round-trip. */
    {
        uint8_t entropy[32];
        size_t entropy_len = 0;
        struct zcl_result r = domain_wallet_mnemonic_to_entropy(
                tv2_mnemonic, entropy, sizeof(entropy), &entropy_len);
        DWM_CHECK("TV2 to_entropy decodes canonical 24-word phrase",
                  r.ok && entropy_len == 32 &&
                  bytes_equal(entropy, tv2_entropy, 32));
    }

    /* TV3: 0x7f-repeat → "legal winner...yellow". */
    {
        char phrase[256];
        size_t written = 0;
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                tv3_entropy, sizeof(tv3_entropy),
                phrase, sizeof(phrase), &written);
        DWM_CHECK("TV3 from_entropy matches \"legal winner...yellow\"",
                  r.ok && strcmp(phrase, tv3_mnemonic) == 0);
    }
    /* TV3 seed with "TREZOR" passphrase. */
    {
        uint8_t seed[64];
        struct zcl_result r = domain_wallet_mnemonic_to_seed(
                tv3_mnemonic, "TREZOR", seed, sizeof(seed));
        DWM_CHECK("TV3 to_seed(\"legal winner...\", \"TREZOR\") canonical",
                  r.ok && bytes_equal(seed, tv3_seed_trezor, 64));
    }

    /* ── Layer 3: round-trip property over synthetic entropy ──────── */

    {
        const size_t lens[] = { 16, 20, 24, 28, 32 };
        bool all_ok = true;
        lcg_seed(0xdeadbeef);
        for (size_t li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) {
            size_t L = lens[li];
            for (int trial = 0; trial < 8; trial++) {
                uint8_t entropy[32];
                for (size_t i = 0; i < L; i++)
                    entropy[i] = lcg_byte();

                char phrase[512];
                size_t written = 0;
                struct zcl_result enc = domain_wallet_mnemonic_from_entropy(
                        entropy, L, phrase, sizeof(phrase), &written);
                if (!enc.ok) { all_ok = false; break; }

                uint8_t back[32];
                size_t back_len = 0;
                struct zcl_result dec = domain_wallet_mnemonic_to_entropy(
                        phrase, back, sizeof(back), &back_len);
                if (!dec.ok || back_len != L
                    || !bytes_equal(entropy, back, L)) {
                    all_ok = false;
                    break;
                }

                /* Validate accepts what from_entropy produces. */
                struct zcl_result v = domain_wallet_mnemonic_validate(phrase);
                if (!v.ok) { all_ok = false; break; }
            }
            if (!all_ok) break;
        }
        DWM_CHECK("round-trip entropy -> mnemonic -> entropy (5 lens × 8 trials)",
                  all_ok);
    }

    /* ── Layer 4: wrapper-vs-domain regression seal ───────────────── */

    /* Wrapper mnemonic_from_entropy must produce the same phrase as the
     * pure domain function. */
    {
        const size_t lens[] = { 16, 20, 24, 28, 32 };
        bool all_match = true;
        lcg_seed(0xa1b2c3d4);
        for (size_t li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) {
            size_t L = lens[li];
            for (int trial = 0; trial < 4; trial++) {
                uint8_t entropy[32];
                for (size_t i = 0; i < L; i++) entropy[i] = lcg_byte();

                char phrase_wrap[512];
                if (!mnemonic_from_entropy(entropy, L,
                                           phrase_wrap, sizeof(phrase_wrap))) {
                    all_match = false; break;
                }

                char phrase_dom[512];
                size_t written = 0;
                struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                        entropy, L, phrase_dom, sizeof(phrase_dom), &written);
                if (!r.ok || strcmp(phrase_wrap, phrase_dom) != 0) {
                    all_match = false; break;
                }

                /* Wrapper validate accepts it too. */
                if (!mnemonic_validate(phrase_wrap)) {
                    all_match = false; break;
                }

                /* Wrapper seed derivation must match domain seed derivation
                 * for the same (phrase, passphrase). */
                uint8_t seed_wrap[64], seed_dom[64];
                if (!mnemonic_to_seed(phrase_wrap, "TREZOR", seed_wrap)) {
                    all_match = false; break;
                }
                struct zcl_result rs = domain_wallet_mnemonic_to_seed(
                        phrase_wrap, "TREZOR", seed_dom, sizeof(seed_dom));
                if (!rs.ok || !bytes_equal(seed_wrap, seed_dom, 64)) {
                    all_match = false; break;
                }
            }
            if (!all_match) break;
        }
        DWM_CHECK("wrapper vs domain: 5 lens × 4 trials byte-identical "
                  "(phrase + seed)", all_match);
    }

    /* Wrapper wordlist_get/find delegate cleanly. */
    DWM_CHECK("wrapper wordlist_get[0] == domain wordlist_get[0]",
              mnemonic_wordlist_get(0) ==
              domain_wallet_mnemonic_wordlist_get(0));
    DWM_CHECK("wrapper wordlist_find delegates",
              mnemonic_wordlist_find("satoshi") ==
              domain_wallet_mnemonic_wordlist_find("satoshi"));

    return failures;
}
