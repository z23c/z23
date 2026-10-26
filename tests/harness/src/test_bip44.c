/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for BIP44 multi-account hierarchy: m/44'/147'/account'/change/index.
 * Covers derivation, path formatting, wallet HD integration, and determinism.
 */

#include "test/test_core.h"
#include "wallet/bip44.h"
#include "wallet/hd_keychain.h"
#include "wallet/mnemonic.h"
#include "wallet/wallet.h"
#include "chain/chainparams.h"
#include "support/cleanse.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Fixed seed for deterministic tests (BIP32 test vector 1) */
static const unsigned char test_seed[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static struct ext_key master;
static bool master_initialized = false;

static bool ensure_master(void)
{
    if (!master_initialized) {
        if (!hd_master_from_seed(&master, test_seed, sizeof(test_seed)))
            return false;
        master_initialized = true;
    }
    return true;
}

/* Wallet struct is ~68MB — must be heap-allocated. */
static struct wallet *alloc_wallet(void)
{
    struct wallet *w = calloc(1, sizeof(*w));
    if (w)
        wallet_init(w);
    return w;
}

static void free_wallet(struct wallet *w)
{
    if (w) {
        wallet_free(w);
        free(w);
    }
}

enum {
    BIP44_DEPTH_ACCOUNT = 0,
    BIP44_DEPTH_CHAIN = 1,
    BIP44_DEPTH_ADDRESS = 2
};

enum {
    BIP44_REL_SAME_KEY = 0,
    BIP44_REL_DIFF_INDEX = 1,
    BIP44_REL_EXT_INT = 2,
    BIP44_REL_MANUAL_PATH = 3
};

static int check_bip44_derived_depth(const char *label, int kind,
                                     uint32_t change, int depth,
                                     bool report_valid)
{
    printf("%s", label);
    if (!ensure_master()) {
        printf("FAIL (no master)\n");
        return 1;
    }
    struct ext_key key;
    bool ok = false;
    if (kind == BIP44_DEPTH_ACCOUNT)
        ok = bip44_derive_account(&master, &key, 0);
    else if (kind == BIP44_DEPTH_CHAIN)
        ok = bip44_derive_chain(&master, &key, 0, change);
    else
        ok = bip44_derive_key(&master, &key, 0, change, 0);
    int fail = 0;
    if (ok) {
        if (privkey_is_valid(&key.key) && key.nDepth == depth)
            printf("OK\n");
        else {
            if (report_valid)
                printf("FAIL (depth=%d valid=%d)\n", key.nDepth,
                       privkey_is_valid(&key.key));
            else
                printf("FAIL (depth=%d)\n", key.nDepth);
            fail = 1;
        }
    } else {
        printf("FAIL (returned false)\n");
        fail = 1;
    }
    memory_cleanse(&key, sizeof(key));
    return fail;
}

static int check_bip44_keypair(void)
{
    printf("bip44_derive_keypair... ");
    if (!ensure_master()) {
        printf("FAIL (no master)\n");
        return 1;
    }
    struct privkey priv;
    struct pubkey pub;
    privkey_init(&priv);
    int fail = 0;
    if (bip44_derive_keypair(&master, &priv, &pub, 0, 0, 0)) {
        if (privkey_is_valid(&priv) && pubkey_is_valid(&pub) &&
            pubkey_is_compressed(&pub))
            printf("OK\n");
        else {
            printf("FAIL (priv_valid=%d pub_valid=%d)\n",
                   privkey_is_valid(&priv), pubkey_is_valid(&pub));
            fail = 1;
        }
    } else {
        printf("FAIL (returned false)\n");
        fail = 1;
    }
    memory_cleanse(priv.vch, 32);
    return fail;
}

static int report_bip44_key_match(bool ok_a, bool ok_b,
                                  const struct ext_key *a,
                                  const struct ext_key *b,
                                  bool expect_equal, bool verbose_fail)
{
    if (ok_a && ok_b) {
        int cmp = memcmp(a->key.vch, b->key.vch, 32);
        if ((expect_equal && cmp == 0) || (!expect_equal && cmp != 0)) {
            printf("OK\n");
            return 0;
        }
    }
    if (verbose_fail)
        printf("FAIL (ok1=%d ok2=%d)\n", ok_a, ok_b);
    else
        printf("FAIL\n");
    return 1;
}

static int check_bip44_key_relation(const char *label, int mode)
{
    printf("%s", label);
    if (!ensure_master()) {
        printf("FAIL (no master)\n");
        return 1;
    }
    struct ext_key a, b;
    bool ok_a = false;
    bool ok_b = false;
    bool expect_equal = false;
    bool verbose_fail = false;
    if (mode == BIP44_REL_SAME_KEY) {
        ok_a = bip44_derive_key(&master, &a, 0, 0, 5);
        ok_b = bip44_derive_key(&master, &b, 0, 0, 5);
        expect_equal = true;
        verbose_fail = true;
    } else if (mode == BIP44_REL_DIFF_INDEX) {
        ok_a = bip44_derive_key(&master, &a, 0, 0, 0);
        ok_b = bip44_derive_key(&master, &b, 0, 0, 1);
    } else if (mode == BIP44_REL_EXT_INT) {
        ok_a = bip44_derive_key(&master, &a, 0, BIP44_EXTERNAL, 0);
        ok_b = bip44_derive_key(&master, &b, 0, BIP44_INTERNAL, 0);
    } else {
        ok_a = bip44_derive_key(&master, &a, 0, 0, 7);
        ok_b = hd_derive_path_str(&master, &b, "m/44'/147'/0'/0/7");
        expect_equal = true;
    }
    int fail = report_bip44_key_match(ok_a, ok_b, &a, &b,
                                      expect_equal, verbose_fail);
    memory_cleanse(&a, sizeof(a));
    memory_cleanse(&b, sizeof(b));
    return fail;
}

static int check_bip44_format_path(const char *label, uint32_t account,
                                   uint32_t change, uint32_t index,
                                   const char *expect)
{
    printf("%s", label);
    char buf[64];
    int n = bip44_format_path(buf, sizeof(buf), account, change, index);
    if (n > 0 && strcmp(buf, expect) == 0)
        printf("OK\n");
    else {
        printf("FAIL (got \"%s\")\n", buf);
        return 1;
    }
    return 0;
}

static int check_bip44_rejects_change(void)
{
    printf("bip44 rejects bad change value... ");
    if (!ensure_master()) {
        printf("FAIL (no master)\n");
        return 1;
    }
    struct ext_key out;
    bool ok = bip44_derive_key(&master, &out, 0, 2, 0); /* change=2 invalid */
    if (!ok)
        printf("OK\n");
    else {
        printf("FAIL (should reject change=2)\n");
        return 1;
    }
    return 0;
}

static int check_wallet_hd_init_state(void)
{
    printf("wallet_init_hd from seed... ");
    struct wallet *w = alloc_wallet();
    if (!w) {
        printf("FAIL (alloc)\n");
        return 1;
    }
    unsigned char seed[32];
    memset(seed, 0x42, sizeof(seed));
    int fail = 0;
    if (wallet_init_hd(w, seed, sizeof(seed))) {
        if (w->has_master_key && w->hd_external_counter == 0 &&
            w->hd_internal_counter == 0 && w->hd_account == 0)
            printf("OK\n");
        else {
            printf("FAIL (bad state)\n");
            fail = 1;
        }
    } else {
        printf("FAIL (returned false)\n");
        fail = 1;
    }
    free_wallet(w);
    return fail;
}

static int check_wallet_hd_same_address(void)
{
    printf("wallet HD getnewaddress deterministic... ");
    struct wallet *w1 = alloc_wallet();
    struct wallet *w2 = alloc_wallet();
    if (!w1 || !w2) {
        printf("FAIL (alloc)\n");
        free_wallet(w1);
        free_wallet(w2);
        return 1;
    }

    unsigned char seed[32];
    memset(seed, 0xAB, sizeof(seed));
    bool ok1 = wallet_init_hd(w1, seed, sizeof(seed));
    bool ok2 = wallet_init_hd(w2, seed, sizeof(seed));

    int fail = 0;
    if (ok1 && ok2) {
        char addr1[64], addr2[64];
        bool g1 = wallet_get_new_address(w1, addr1, sizeof(addr1));
        bool g2 = wallet_get_new_address(w2, addr2, sizeof(addr2));
        if (g1 && g2 && strcmp(addr1, addr2) == 0)
            printf("OK\n");
        else {
            printf("FAIL (addr1=%s addr2=%s)\n",
                   g1 ? addr1 : "err", g2 ? addr2 : "err");
            fail = 1;
        }
    } else {
        printf("FAIL (init)\n");
        fail = 1;
    }

    free_wallet(w1);
    free_wallet(w2);
    return fail;
}

static int check_wallet_hd_counter_step(void)
{
    printf("wallet HD counter increments... ");
    struct wallet *w = alloc_wallet();
    if (!w) {
        printf("FAIL (alloc)\n");
        return 1;
    }
    unsigned char seed[32];
    memset(seed, 0xCD, sizeof(seed));

    int fail = 0;
    if (wallet_init_hd(w, seed, sizeof(seed))) {
        char addr1[64], addr2[64];
        wallet_get_new_address(w, addr1, sizeof(addr1));
        wallet_get_new_address(w, addr2, sizeof(addr2));

        if (w->hd_external_counter == 2 && strcmp(addr1, addr2) != 0)
            printf("OK\n");
        else {
            printf("FAIL (counter=%u same=%d)\n",
                   w->hd_external_counter,
                   strcmp(addr1, addr2) == 0);
            fail = 1;
        }
    } else {
        printf("FAIL (init)\n");
        fail = 1;
    }

    free_wallet(w);
    return fail;
}

static int check_wallet_has_hd_after_init(void)
{
    printf("wallet_has_hd... ");
    struct wallet *w = alloc_wallet();
    if (!w) {
        printf("FAIL (alloc)\n");
        return 1;
    }
    bool before = wallet_has_hd(w);
    unsigned char seed[32];
    memset(seed, 0xEF, sizeof(seed));
    wallet_init_hd(w, seed, sizeof(seed));
    bool after = wallet_has_hd(w);
    int fail = 0;
    if (!before && after)
        printf("OK\n");
    else {
        printf("FAIL (before=%d after=%d)\n", before, after);
        fail = 1;
    }
    free_wallet(w);
    return fail;
}

static int check_wallet_change_on_internal(void)
{
    printf("wallet change address uses internal chain... ");
    struct wallet *w = alloc_wallet();
    if (!w) {
        printf("FAIL (alloc)\n");
        return 1;
    }
    unsigned char seed[32];
    memset(seed, 0x77, sizeof(seed));

    int fail = 0;
    if (wallet_init_hd(w, seed, sizeof(seed))) {
        char ext_addr[64], chg_addr[64];
        wallet_get_new_address(w, ext_addr, sizeof(ext_addr));
        wallet_get_new_change_address(w, chg_addr, sizeof(chg_addr));

        if (strcmp(ext_addr, chg_addr) != 0 &&
            w->hd_external_counter == 1 &&
            w->hd_internal_counter == 1)
            printf("OK\n");
        else {
            printf("FAIL (ext=%s chg=%s ext_ctr=%u int_ctr=%u)\n",
                   ext_addr, chg_addr,
                   w->hd_external_counter, w->hd_internal_counter);
            fail = 1;
        }
    } else {
        printf("FAIL (init)\n");
        fail = 1;
    }

    free_wallet(w);
    return fail;
}

static int check_wallet_hd_from_mnemonic(void)
{
    printf("wallet_init_hd_from_mnemonic... ");
    struct wallet *w = alloc_wallet();
    if (!w) {
        printf("FAIL (alloc)\n");
        return 1;
    }
    /* BIP39 test vector: 128-bit all-zero entropy → "abandon" x11 + "about" */
    const char *mnemonic = "abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon abandon "
                           "abandon about";
    int fail = 0;
    if (wallet_init_hd_from_mnemonic(w, mnemonic, NULL)) {
        if (w->has_master_key) {
            char addr[64];
            if (wallet_get_new_address(w, addr, sizeof(addr)))
                printf("OK (%s)\n", addr);
            else {
                printf("FAIL (no address)\n");
                fail = 1;
            }
        } else {
            printf("FAIL (no master)\n");
            fail = 1;
        }
    } else {
        printf("FAIL (returned false)\n");
        fail = 1;
    }
    free_wallet(w);
    return fail;
}

int test_bip44(void)
{
    int failures = 0;

    /* ── Test 1: account derivation ────────────────────────────────── */
    failures += check_bip44_derived_depth("bip44_derive_account(0)... ",
                                          BIP44_DEPTH_ACCOUNT, 0, 3, true);

    /* ── Test 2: chain derivation (external) ───────────────────────── */
    failures += check_bip44_derived_depth("bip44_derive_chain external... ",
                                          BIP44_DEPTH_CHAIN, BIP44_EXTERNAL,
                                          4, false);

    /* ── Test 3: chain derivation (internal) ───────────────────────── */
    failures += check_bip44_derived_depth("bip44_derive_chain internal... ",
                                          BIP44_DEPTH_CHAIN, BIP44_INTERNAL,
                                          4, false);

    /* ── Test 4: full address key derivation ───────────────────────── */
    failures += check_bip44_derived_depth(
        "bip44_derive_key m/44'/147'/0'/0/0... ",
        BIP44_DEPTH_ADDRESS, BIP44_EXTERNAL, 5, false);

    /* ── Test 5: keypair derivation ────────────────────────────────── */
    failures += check_bip44_keypair();

    /* ── Test 6: determinism — same seed same keys ─────────────────── */
    failures += check_bip44_key_relation("bip44 deterministic derivation... ",
                                         BIP44_REL_SAME_KEY);

    /* ── Test 7: different indices produce different keys ──────────── */
    failures += check_bip44_key_relation("bip44 different indices differ... ",
                                         BIP44_REL_DIFF_INDEX);

    /* ── Test 8: external vs internal differ ───────────────────────── */
    failures += check_bip44_key_relation("bip44 external vs internal differ... ",
                                         BIP44_REL_EXT_INT);

    /* ── Test 9: path format ───────────────────────────────────────── */
    failures += check_bip44_format_path("bip44_format_path... ",
                                        0, 0, 5, "m/44'/147'/0'/0/5");

    /* ── Test 10: path format account 2 internal ───────────────────── */
    failures += check_bip44_format_path(
        "bip44_format_path account 2 internal... ",
        2, 1, 42, "m/44'/147'/2'/1/42");

    /* ── Test 11: reject bad change value ──────────────────────────── */
    failures += check_bip44_rejects_change();

    /* ── Test 12: wallet HD init from seed ─────────────────────────── */
    failures += check_wallet_hd_init_state();

    /* ── Test 13: wallet HD generates deterministic addresses ──────── */
    failures += check_wallet_hd_same_address();

    /* ── Test 14: wallet HD counter increments ─────────────────────── */
    failures += check_wallet_hd_counter_step();

    /* ── Test 15: wallet_has_hd ────────────────────────────────────── */
    failures += check_wallet_has_hd_after_init();

    /* ── Test 16: BIP44 matches manual BIP32 path derivation ──────── */
    failures += check_bip44_key_relation(
        "bip44 matches hd_derive_path_str... ", BIP44_REL_MANUAL_PATH);

    /* ── Test 17: change address uses internal chain ───────────────── */
    failures += check_wallet_change_on_internal();

    /* ── Test 18: wallet HD init from mnemonic ─────────────────────── */
    failures += check_wallet_hd_from_mnemonic();

    memory_cleanse(&master, sizeof(master));
    master_initialized = false;

    printf("bip44: %d failures\n", failures);
    return failures;
}
