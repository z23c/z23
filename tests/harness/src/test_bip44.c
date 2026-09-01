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

int test_bip44(void)
{
    int failures = 0;

    /* ── Test 1: account derivation ────────────────────────────────── */
    printf("bip44_derive_account(0)... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t2; }
        struct ext_key acct;
        if (bip44_derive_account(&master, &acct, 0)) {
            if (privkey_is_valid(&acct.key) && acct.nDepth == 3)
                printf("OK\n");
            else { printf("FAIL (depth=%d valid=%d)\n", acct.nDepth,
                          privkey_is_valid(&acct.key)); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(&acct, sizeof(acct));
    }

    /* ── Test 2: chain derivation (external) ───────────────────────── */
t2:
    printf("bip44_derive_chain external... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t3; }
        struct ext_key chain;
        if (bip44_derive_chain(&master, &chain, 0, BIP44_EXTERNAL)) {
            if (privkey_is_valid(&chain.key) && chain.nDepth == 4)
                printf("OK\n");
            else { printf("FAIL (depth=%d)\n", chain.nDepth); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(&chain, sizeof(chain));
    }

    /* ── Test 3: chain derivation (internal) ───────────────────────── */
t3:
    printf("bip44_derive_chain internal... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t4; }
        struct ext_key chain;
        if (bip44_derive_chain(&master, &chain, 0, BIP44_INTERNAL)) {
            if (privkey_is_valid(&chain.key) && chain.nDepth == 4)
                printf("OK\n");
            else { printf("FAIL (depth=%d)\n", chain.nDepth); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(&chain, sizeof(chain));
    }

    /* ── Test 4: full address key derivation ───────────────────────── */
t4:
    printf("bip44_derive_key m/44'/147'/0'/0/0... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t5; }
        struct ext_key child;
        if (bip44_derive_key(&master, &child, 0, BIP44_EXTERNAL, 0)) {
            if (privkey_is_valid(&child.key) && child.nDepth == 5)
                printf("OK\n");
            else { printf("FAIL (depth=%d)\n", child.nDepth); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(&child, sizeof(child));
    }

    /* ── Test 5: keypair derivation ────────────────────────────────── */
t5:
    printf("bip44_derive_keypair... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t6; }
        struct privkey priv;
        struct pubkey pub;
        privkey_init(&priv);
        if (bip44_derive_keypair(&master, &priv, &pub, 0, 0, 0)) {
            if (privkey_is_valid(&priv) && pubkey_is_valid(&pub) &&
                pubkey_is_compressed(&pub))
                printf("OK\n");
            else { printf("FAIL (priv_valid=%d pub_valid=%d)\n",
                          privkey_is_valid(&priv), pubkey_is_valid(&pub)); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(priv.vch, 32);
    }

    /* ── Test 6: determinism — same seed same keys ─────────────────── */
t6:
    printf("bip44 deterministic derivation... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t7; }
        struct ext_key k1, k2;
        bool ok1 = bip44_derive_key(&master, &k1, 0, 0, 5);
        bool ok2 = bip44_derive_key(&master, &k2, 0, 0, 5);
        if (ok1 && ok2 && memcmp(k1.key.vch, k2.key.vch, 32) == 0)
            printf("OK\n");
        else { printf("FAIL (ok1=%d ok2=%d)\n", ok1, ok2); failures++; }
        memory_cleanse(&k1, sizeof(k1));
        memory_cleanse(&k2, sizeof(k2));
    }

    /* ── Test 7: different indices produce different keys ──────────── */
t7:
    printf("bip44 different indices differ... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t8; }
        struct ext_key k0, k1;
        bool ok0 = bip44_derive_key(&master, &k0, 0, 0, 0);
        bool ok1 = bip44_derive_key(&master, &k1, 0, 0, 1);
        if (ok0 && ok1 && memcmp(k0.key.vch, k1.key.vch, 32) != 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        memory_cleanse(&k0, sizeof(k0));
        memory_cleanse(&k1, sizeof(k1));
    }

    /* ── Test 8: external vs internal differ ───────────────────────── */
t8:
    printf("bip44 external vs internal differ... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t9; }
        struct ext_key ext_k, int_k;
        bool ok_e = bip44_derive_key(&master, &ext_k, 0, BIP44_EXTERNAL, 0);
        bool ok_i = bip44_derive_key(&master, &int_k, 0, BIP44_INTERNAL, 0);
        if (ok_e && ok_i && memcmp(ext_k.key.vch, int_k.key.vch, 32) != 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        memory_cleanse(&ext_k, sizeof(ext_k));
        memory_cleanse(&int_k, sizeof(int_k));
    }

    /* ── Test 9: path format ───────────────────────────────────────── */
t9:
    printf("bip44_format_path... ");
    {
        char buf[64];
        int n = bip44_format_path(buf, sizeof(buf), 0, 0, 5);
        if (n > 0 && strcmp(buf, "m/44'/147'/0'/0/5") == 0)
            printf("OK\n");
        else { printf("FAIL (got \"%s\")\n", buf); failures++; }
    }

    /* ── Test 10: path format account 2 internal ───────────────────── */
    printf("bip44_format_path account 2 internal... ");
    {
        char buf[64];
        int n = bip44_format_path(buf, sizeof(buf), 2, 1, 42);
        if (n > 0 && strcmp(buf, "m/44'/147'/2'/1/42") == 0)
            printf("OK\n");
        else { printf("FAIL (got \"%s\")\n", buf); failures++; }
    }

    /* ── Test 11: reject bad change value ──────────────────────────── */
    printf("bip44 rejects bad change value... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t12; }
        struct ext_key out;
        bool ok = bip44_derive_key(&master, &out, 0, 2, 0); /* change=2 invalid */
        if (!ok)
            printf("OK\n");
        else { printf("FAIL (should reject change=2)\n"); failures++; }
    }

    /* ── Test 12: wallet HD init from seed ─────────────────────────── */
t12:
    printf("wallet_init_hd from seed... ");
    {
        struct wallet *w = alloc_wallet();
        if (!w) { printf("FAIL (alloc)\n"); failures++; goto t13; }
        unsigned char seed[32];
        memset(seed, 0x42, sizeof(seed));
        if (wallet_init_hd(w, seed, sizeof(seed))) {
            if (w->has_master_key && w->hd_external_counter == 0 &&
                w->hd_internal_counter == 0 && w->hd_account == 0)
                printf("OK\n");
            else { printf("FAIL (bad state)\n"); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        free_wallet(w);
    }

    /* ── Test 13: wallet HD generates deterministic addresses ──────── */
t13:
    printf("wallet HD getnewaddress deterministic... ");
    {
        struct wallet *w1 = alloc_wallet();
        struct wallet *w2 = alloc_wallet();
        if (!w1 || !w2) { printf("FAIL (alloc)\n"); failures++;
                          free_wallet(w1); free_wallet(w2); goto t14; }

        unsigned char seed[32];
        memset(seed, 0xAB, sizeof(seed));
        bool ok1 = wallet_init_hd(w1, seed, sizeof(seed));
        bool ok2 = wallet_init_hd(w2, seed, sizeof(seed));

        if (ok1 && ok2) {
            char addr1[64], addr2[64];
            bool g1 = wallet_get_new_address(w1, addr1, sizeof(addr1));
            bool g2 = wallet_get_new_address(w2, addr2, sizeof(addr2));
            if (g1 && g2 && strcmp(addr1, addr2) == 0)
                printf("OK\n");
            else { printf("FAIL (addr1=%s addr2=%s)\n",
                          g1 ? addr1 : "err", g2 ? addr2 : "err"); failures++; }
        } else { printf("FAIL (init)\n"); failures++; }

        free_wallet(w1);
        free_wallet(w2);
    }

    /* ── Test 14: wallet HD counter increments ─────────────────────── */
t14:
    printf("wallet HD counter increments... ");
    {
        struct wallet *w = alloc_wallet();
        if (!w) { printf("FAIL (alloc)\n"); failures++; goto t15; }
        unsigned char seed[32];
        memset(seed, 0xCD, sizeof(seed));

        if (wallet_init_hd(w, seed, sizeof(seed))) {
            char addr1[64], addr2[64];
            wallet_get_new_address(w, addr1, sizeof(addr1));
            wallet_get_new_address(w, addr2, sizeof(addr2));

            if (w->hd_external_counter == 2 && strcmp(addr1, addr2) != 0)
                printf("OK\n");
            else { printf("FAIL (counter=%u same=%d)\n",
                          w->hd_external_counter,
                          strcmp(addr1, addr2) == 0); failures++; }
        } else { printf("FAIL (init)\n"); failures++; }

        free_wallet(w);
    }

    /* ── Test 15: wallet_has_hd ────────────────────────────────────── */
t15:
    printf("wallet_has_hd... ");
    {
        struct wallet *w = alloc_wallet();
        if (!w) { printf("FAIL (alloc)\n"); failures++; goto t16; }
        bool before = wallet_has_hd(w);
        unsigned char seed[32];
        memset(seed, 0xEF, sizeof(seed));
        wallet_init_hd(w, seed, sizeof(seed));
        bool after = wallet_has_hd(w);
        if (!before && after)
            printf("OK\n");
        else { printf("FAIL (before=%d after=%d)\n", before, after); failures++; }
        free_wallet(w);
    }

    /* ── Test 16: BIP44 matches manual BIP32 path derivation ──────── */
t16:
    printf("bip44 matches hd_derive_path_str... ");
    {
        if (!ensure_master()) { printf("FAIL (no master)\n"); failures++; goto t17; }
        struct ext_key bip44_k, manual_k;
        bool ok1 = bip44_derive_key(&master, &bip44_k, 0, 0, 7);
        bool ok2 = hd_derive_path_str(&master, &manual_k, "m/44'/147'/0'/0/7");
        if (ok1 && ok2 && memcmp(bip44_k.key.vch, manual_k.key.vch, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        memory_cleanse(&bip44_k, sizeof(bip44_k));
        memory_cleanse(&manual_k, sizeof(manual_k));
    }

    /* ── Test 17: change address uses internal chain ───────────────── */
t17:
    printf("wallet change address uses internal chain... ");
    {
        struct wallet *w = alloc_wallet();
        if (!w) { printf("FAIL (alloc)\n"); failures++; goto t18; }
        unsigned char seed[32];
        memset(seed, 0x77, sizeof(seed));

        if (wallet_init_hd(w, seed, sizeof(seed))) {
            char ext_addr[64], chg_addr[64];
            wallet_get_new_address(w, ext_addr, sizeof(ext_addr));
            wallet_get_new_change_address(w, chg_addr, sizeof(chg_addr));

            if (strcmp(ext_addr, chg_addr) != 0 &&
                w->hd_external_counter == 1 &&
                w->hd_internal_counter == 1)
                printf("OK\n");
            else { printf("FAIL (ext=%s chg=%s ext_ctr=%u int_ctr=%u)\n",
                          ext_addr, chg_addr,
                          w->hd_external_counter, w->hd_internal_counter); failures++; }
        } else { printf("FAIL (init)\n"); failures++; }

        free_wallet(w);
    }

    /* ── Test 18: wallet HD init from mnemonic ─────────────────────── */
t18:
    printf("wallet_init_hd_from_mnemonic... ");
    {
        struct wallet *w = alloc_wallet();
        if (!w) { printf("FAIL (alloc)\n"); failures++; goto done; }
        /* BIP39 test vector: 128-bit all-zero entropy → "abandon" x11 + "about" */
        const char *mnemonic = "abandon abandon abandon abandon abandon "
                               "abandon abandon abandon abandon abandon "
                               "abandon about";
        if (wallet_init_hd_from_mnemonic(w, mnemonic, NULL)) {
            if (w->has_master_key) {
                char addr[64];
                if (wallet_get_new_address(w, addr, sizeof(addr)))
                    printf("OK (%s)\n", addr);
                else { printf("FAIL (no address)\n"); failures++; }
            } else { printf("FAIL (no master)\n"); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        free_wallet(w);
    }

done:
    memory_cleanse(&master, sizeof(master));
    master_initialized = false;

    printf("bip44: %d failures\n", failures);
    return failures;
}
