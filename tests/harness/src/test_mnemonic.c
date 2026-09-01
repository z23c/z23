/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for BIP39 mnemonic seed phrases: generation, validation,
 * seed derivation, and compliance with BIP39 test vectors.
 */

#include "test/test_core.h"
#include "wallet/mnemonic.h"
#include "wallet/hd_keychain.h"
#include "support/cleanse.h"
#include <string.h>
#include <stdio.h>

/* BIP39 test vector — 128-bit entropy (from trezor/python-mnemonic reference) */
static const uint8_t tv_entropy_128[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const char *tv_mnemonic_128 =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

/* BIP39 test vector — 256-bit entropy (all zeros) */
static const uint8_t tv_entropy_256[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const char *tv_mnemonic_256 =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon art";

/* BIP39 test vector — 128-bit known entropy with known seed (no passphrase) */
static const uint8_t tv_seed_128_expected[] = {
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
    0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
    0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
    0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
    0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4
};

/* Helper to print hex for debugging */
static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

int test_mnemonic(void)
{
    int failures = 0;

    /* ── Test 1: wordlist access ─────────────────────────────────── */
    printf("mnemonic wordlist first/last... ");
    {
        const char *first = mnemonic_wordlist_get(0);
        const char *last = mnemonic_wordlist_get(2047);
        if (first && last &&
            strcmp(first, "abandon") == 0 &&
            strcmp(last, "zoo") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 2: wordlist lookup ─────────────────────────────────── */
    printf("mnemonic wordlist binary search... ");
    {
        int idx_abandon = mnemonic_wordlist_find("abandon");
        int idx_zoo = mnemonic_wordlist_find("zoo");
        int idx_satoshi = mnemonic_wordlist_find("satoshi");
        int idx_bad = mnemonic_wordlist_find("notaword");
        int idx_null = mnemonic_wordlist_find(NULL);

        if (idx_abandon == 0 && idx_zoo == 2047 &&
            idx_satoshi > 0 && idx_bad == -1 && idx_null == -1)
            printf("OK\n");
        else {
            printf("FAIL (abandon=%d zoo=%d satoshi=%d bad=%d)\n",
                   idx_abandon, idx_zoo, idx_satoshi, idx_bad);
            failures++;
        }
    }

    /* ── Test 3: wordlist out of range ───────────────────────────── */
    printf("mnemonic wordlist out of range... ");
    {
        if (mnemonic_wordlist_get(-1) == NULL &&
            mnemonic_wordlist_get(2048) == NULL)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 4: generate 12-word mnemonic ───────────────────────── */
    printf("mnemonic generate 12 words... ");
    {
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        if (mnemonic_generate(12, phrase, sizeof(phrase))) {
            /* Count words */
            int count = 1;
            for (size_t i = 0; phrase[i]; i++)
                if (phrase[i] == ' ') count++;
            if (count == 12 && mnemonic_validate(phrase))
                printf("OK\n");
            else { printf("FAIL (count=%d)\n", count); failures++; }
        } else { printf("FAIL (generate)\n"); failures++; }
    }

    /* ── Test 5: generate 24-word mnemonic ───────────────────────── */
    printf("mnemonic generate 24 words... ");
    {
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        if (mnemonic_generate(24, phrase, sizeof(phrase))) {
            int count = 1;
            for (size_t i = 0; phrase[i]; i++)
                if (phrase[i] == ' ') count++;
            if (count == 24 && mnemonic_validate(phrase))
                printf("OK\n");
            else { printf("FAIL (count=%d)\n", count); failures++; }
        } else { printf("FAIL (generate)\n"); failures++; }
    }

    /* ── Test 6: reject invalid word count ───────────────────────── */
    printf("mnemonic generate rejects bad count... ");
    {
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        bool ok13 = mnemonic_generate(13, phrase, sizeof(phrase));
        bool ok0 = mnemonic_generate(0, phrase, sizeof(phrase));
        if (!ok13 && !ok0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 7: BIP39 test vector — 128-bit entropy ─────────────── */
    printf("BIP39 test vector 128-bit entropy... ");
    {
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        if (mnemonic_from_entropy(tv_entropy_128, sizeof(tv_entropy_128),
                                  phrase, sizeof(phrase))) {
            if (strcmp(phrase, tv_mnemonic_128) == 0)
                printf("OK\n");
            else {
                printf("FAIL\n  got:    %s\n  expect: %s\n", phrase, tv_mnemonic_128);
                failures++;
            }
        } else { printf("FAIL (from_entropy)\n"); failures++; }
    }

    /* ── Test 8: BIP39 test vector — 256-bit entropy ─────────────── */
    printf("BIP39 test vector 256-bit entropy... ");
    {
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        if (mnemonic_from_entropy(tv_entropy_256, sizeof(tv_entropy_256),
                                  phrase, sizeof(phrase))) {
            if (strcmp(phrase, tv_mnemonic_256) == 0)
                printf("OK\n");
            else {
                printf("FAIL\n  got:    %s\n  expect: %s\n", phrase, tv_mnemonic_256);
                failures++;
            }
        } else { printf("FAIL (from_entropy)\n"); failures++; }
    }

    /* ── Test 9: validate known good mnemonic ────────────────────── */
    printf("mnemonic validate known good... ");
    {
        if (mnemonic_validate(tv_mnemonic_128))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 10: validate rejects bad checksum ──────────────────── */
    printf("mnemonic validate rejects bad checksum... ");
    {
        /* Change last word to break checksum */
        const char *bad =
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon zoo";
        if (!mnemonic_validate(bad))
            printf("OK\n");
        else { printf("FAIL (accepted bad checksum)\n"); failures++; }
    }

    /* ── Test 11: validate rejects unknown word ──────────────────── */
    printf("mnemonic validate rejects unknown word... ");
    {
        const char *bad =
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon notaword";
        if (!mnemonic_validate(bad))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 12: validate rejects wrong word count ──────────────── */
    printf("mnemonic validate rejects wrong count... ");
    {
        const char *bad = "abandon abandon abandon abandon abandon";
        if (!mnemonic_validate(bad))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 13: seed derivation — BIP39 test vector ────────────── */
    printf("BIP39 seed derivation (no passphrase)... ");
    {
        uint8_t seed[MNEMONIC_SEED_SIZE];
        if (mnemonic_to_seed(tv_mnemonic_128, "", seed)) {
            if (memcmp(seed, tv_seed_128_expected, MNEMONIC_SEED_SIZE) == 0)
                printf("OK\n");
            else {
                printf("FAIL\n  got:    ");
                print_hex(seed, 64);
                printf("\n  expect: ");
                print_hex(tv_seed_128_expected, 64);
                printf("\n");
                failures++;
            }
        } else { printf("FAIL (to_seed)\n"); failures++; }
        memory_cleanse(seed, sizeof(seed));
    }

    /* ── Test 14: seed derivation with passphrase ────────────────── */
    printf("BIP39 seed derivation (with passphrase)... ");
    {
        uint8_t seed_no_pass[MNEMONIC_SEED_SIZE];
        uint8_t seed_with_pass[MNEMONIC_SEED_SIZE];
        mnemonic_to_seed(tv_mnemonic_128, "", seed_no_pass);
        mnemonic_to_seed(tv_mnemonic_128, "my secret", seed_with_pass);

        /* Different passphrases must produce different seeds */
        if (memcmp(seed_no_pass, seed_with_pass, MNEMONIC_SEED_SIZE) != 0)
            printf("OK\n");
        else { printf("FAIL (same seed with different passphrase)\n"); failures++; }
        memory_cleanse(seed_no_pass, sizeof(seed_no_pass));
        memory_cleanse(seed_with_pass, sizeof(seed_with_pass));
    }

    /* ── Test 15: NULL passphrase treated as empty ───────────────── */
    printf("mnemonic_to_seed NULL passphrase == empty... ");
    {
        uint8_t seed_null[MNEMONIC_SEED_SIZE];
        uint8_t seed_empty[MNEMONIC_SEED_SIZE];
        mnemonic_to_seed(tv_mnemonic_128, NULL, seed_null);
        mnemonic_to_seed(tv_mnemonic_128, "", seed_empty);

        if (memcmp(seed_null, seed_empty, MNEMONIC_SEED_SIZE) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        memory_cleanse(seed_null, sizeof(seed_null));
        memory_cleanse(seed_empty, sizeof(seed_empty));
    }

    /* ── Test 16: from_entropy roundtrip ─────────────────────────── */
    printf("mnemonic from_entropy + validate roundtrip... ");
    {
        uint8_t entropy[20]; /* 160 bits = 15 words */
        memset(entropy, 0x42, sizeof(entropy));
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        if (mnemonic_from_entropy(entropy, sizeof(entropy),
                                  phrase, sizeof(phrase))) {
            int count = 1;
            for (size_t i = 0; phrase[i]; i++)
                if (phrase[i] == ' ') count++;
            if (count == 15 && mnemonic_validate(phrase))
                printf("OK\n");
            else { printf("FAIL (count=%d)\n", count); failures++; }
        } else { printf("FAIL (from_entropy)\n"); failures++; }
    }

    /* ── Test 17: mnemonic → seed → BIP32 master key pipeline ────── */
    printf("mnemonic → seed → BIP32 master key pipeline... ");
    {
        uint8_t seed[MNEMONIC_SEED_SIZE];
        mnemonic_to_seed(tv_mnemonic_128, "", seed);

        struct ext_key master;
        if (hd_master_from_seed(&master, seed, MNEMONIC_SEED_SIZE)) {
            if (privkey_is_valid(&master.key) && master.nDepth == 0)
                printf("OK\n");
            else { printf("FAIL (bad master)\n"); failures++; }
        } else { printf("FAIL (master_from_seed)\n"); failures++; }
        memory_cleanse(seed, sizeof(seed));
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 18: from_entropy rejects bad length ────────────────── */
    printf("mnemonic from_entropy rejects bad length... ");
    {
        uint8_t bad[15]; /* not 16/20/24/28/32 */
        char phrase[MNEMONIC_MAX_PHRASE_SIZE];
        if (!mnemonic_from_entropy(bad, sizeof(bad), phrase, sizeof(phrase)))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    (void)print_hex; /* suppress unused warning if test 13 passes */

    return failures;
}
