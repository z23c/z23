/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for BIP32 HD keychain: seed generation, master key derivation,
 * path parsing, child derivation, xpub/xprv serialization, and
 * compliance with BIP32 test vectors.
 */

#include "test/test_core.h"
#include "wallet/hd_keychain.h"
#include "chain/chainparams.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <stdio.h>

/* BIP32 test vector 1 seed (from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) */
static const unsigned char tv1_seed[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* Mainnet version bytes */
static const unsigned char xpub_ver[] = { 0x04, 0x88, 0xB2, 0x1E };
static const unsigned char xprv_ver[] = { 0x04, 0x88, 0xAD, 0xE4 };

int test_hd_keychain(void)
{
    int failures = 0;

    /* ── Test 1: seed generation ─────────────────────────────────── */
    printf("hd_generate_seed basic... ");
    {
        unsigned char seed[32];
        memset(seed, 0, sizeof(seed));
        if (hd_generate_seed(seed, 32)) {
            /* Check it's not all zeros (astronomically unlikely) */
            bool all_zero = true;
            for (int i = 0; i < 32; i++) {
                if (seed[i] != 0) { all_zero = false; break; }
            }
            if (!all_zero)
                printf("OK\n");
            else { printf("FAIL (all zeros)\n"); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(seed, sizeof(seed));
    }

    /* ── Test 2: seed length validation ──────────────────────────── */
    printf("hd_generate_seed rejects bad length... ");
    {
        unsigned char buf[8];
        bool too_small = hd_generate_seed(buf, 8);   /* < 16 */
        bool too_big = hd_generate_seed(buf, 128);    /* > 64, buf is tiny but should fail before write */
        if (!too_small && !too_big)
            printf("OK\n");
        else { printf("FAIL (small=%d big=%d)\n", too_small, too_big); failures++; }
    }

    /* ── Test 3: master key from seed ────────────────────────────── */
    printf("hd_master_from_seed... ");
    {
        struct ext_key master;
        if (hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed))) {
            if (privkey_is_valid(&master.key) &&
                master.key.fCompressed &&
                master.nDepth == 0 &&
                master.nChild == 0)
                printf("OK\n");
            else { printf("FAIL (invalid master state)\n"); failures++; }
        } else { printf("FAIL (returned false)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 4: path parsing — standard BIP44 path ──────────────── */
    printf("hd_parse_path m/44'/147'/0'/0/5... ");
    {
        uint32_t indices[16];
        int count = hd_parse_path("m/44'/147'/0'/0/5", indices, 16);
        if (count == 5 &&
            indices[0] == (44 | BIP32_HARDENED) &&
            indices[1] == (147 | BIP32_HARDENED) &&
            indices[2] == (0 | BIP32_HARDENED) &&
            indices[3] == 0 &&
            indices[4] == 5)
            printf("OK\n");
        else { printf("FAIL (count=%d)\n", count); failures++; }
    }

    /* ── Test 5: path parsing — just master ──────────────────────── */
    printf("hd_parse_path m... ");
    {
        uint32_t indices[16];
        int count = hd_parse_path("m", indices, 16);
        if (count == 0)
            printf("OK\n");
        else { printf("FAIL (count=%d)\n", count); failures++; }
    }

    /* ── Test 6: path parsing — hardened 'h' notation ────────────── */
    printf("hd_parse_path m/0h/1h... ");
    {
        uint32_t indices[16];
        int count = hd_parse_path("m/0h/1h", indices, 16);
        if (count == 2 &&
            indices[0] == (0 | BIP32_HARDENED) &&
            indices[1] == (1 | BIP32_HARDENED))
            printf("OK\n");
        else { printf("FAIL (count=%d)\n", count); failures++; }
    }

    /* ── Test 7: path parsing rejects invalid paths ──────────────── */
    printf("hd_parse_path rejects invalid... ");
    {
        uint32_t indices[16];
        bool ok = true;
        if (hd_parse_path("m/", indices, 16) != -1) ok = false;    /* trailing slash */
        if (hd_parse_path("m/abc", indices, 16) != -1) ok = false;  /* non-numeric */
        if (hd_parse_path(NULL, indices, 16) != -1) ok = false;     /* NULL */
        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Test 8: child derivation from master ────────────────────── */
    printf("hd_derive_child_index... ");
    {
        struct ext_key master, child;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        if (hd_derive_child_index(&master, &child, BIP32_HARDENED)) {
            if (privkey_is_valid(&child.key) &&
                child.nDepth == 1 &&
                child.nChild == BIP32_HARDENED)
                printf("OK\n");
            else { printf("FAIL (bad child state)\n"); failures++; }
        } else { printf("FAIL (derivation failed)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* ── Test 9: full path derivation ────────────────────────────── */
    printf("hd_derive_path_str m/0'/1... ");
    {
        struct ext_key master, child;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        if (hd_derive_path_str(&master, &child, "m/0'/1")) {
            if (privkey_is_valid(&child.key) && child.nDepth == 2)
                printf("OK\n");
            else { printf("FAIL (bad child state)\n"); failures++; }
        } else { printf("FAIL (derivation failed)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* ── Test 10: xprv serialization roundtrip ───────────────────── */
    printf("hd_serialize/deserialize xprv roundtrip... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        char xprv_str[HD_XKEY_STRING_SIZE];
        if (hd_serialize_xprv(&master, xprv_ver, xprv_str, sizeof(xprv_str))) {
            struct ext_key decoded;
            if (hd_deserialize_xprv(xprv_str, xprv_ver, &decoded)) {
                if (decoded.nDepth == master.nDepth &&
                    decoded.nChild == master.nChild &&
                    memcmp(decoded.key.vch, master.key.vch, 32) == 0 &&
                    memcmp(decoded.chaincode.data, master.chaincode.data, 32) == 0)
                    printf("OK\n");
                else { printf("FAIL (mismatch after roundtrip)\n"); failures++; }
                memory_cleanse(&decoded, sizeof(decoded));
            } else { printf("FAIL (deserialize)\n"); failures++; }
        } else { printf("FAIL (serialize)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 11: xpub serialization roundtrip ───────────────────── */
    printf("hd_serialize/deserialize xpub roundtrip... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        struct ext_pubkey epk;
        ext_key_neuter(&master, &epk);

        char xpub_str[HD_XKEY_STRING_SIZE];
        if (hd_serialize_xpub(&epk, xpub_ver, xpub_str, sizeof(xpub_str))) {
            struct ext_pubkey decoded;
            if (hd_deserialize_xpub(xpub_str, xpub_ver, &decoded)) {
                if (decoded.nDepth == epk.nDepth &&
                    decoded.nChild == epk.nChild &&
                    decoded.pubkey.size == epk.pubkey.size &&
                    memcmp(decoded.pubkey.vch, epk.pubkey.vch, epk.pubkey.size) == 0 &&
                    memcmp(decoded.chaincode.data, epk.chaincode.data, 32) == 0)
                    printf("OK\n");
                else { printf("FAIL (mismatch after roundtrip)\n"); failures++; }
            } else { printf("FAIL (deserialize)\n"); failures++; }
        } else { printf("FAIL (serialize)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 12: xprv version mismatch detection ────────────────── */
    printf("hd_deserialize_xprv rejects wrong version... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        char xprv_str[HD_XKEY_STRING_SIZE];
        hd_serialize_xprv(&master, xprv_ver, xprv_str, sizeof(xprv_str));

        struct ext_key decoded;
        /* Try to decode with xpub version — should fail */
        if (!hd_deserialize_xprv(xprv_str, xpub_ver, &decoded))
            printf("OK\n");
        else { printf("FAIL (accepted wrong version)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 13: public key derivation (non-hardened) ───────────── */
    printf("hd_derive_pubkey_path non-hardened... ");
    {
        struct ext_key master, child_priv;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        /* Derive m/0'/1 with private key */
        hd_derive_path_str(&master, &child_priv, "m/0'/1");

        /* Neuter to get the pubkey at m/0'/1 */
        struct ext_pubkey child_pub;
        ext_key_neuter(&child_priv, &child_pub);

        /* Derive index 2 from pubkey (non-hardened) */
        struct ext_pubkey grandchild_pub;
        uint32_t idx = 2;
        if (hd_derive_pubkey_path(&child_pub, &grandchild_pub, &idx, 1)) {
            /* Also derive m/0'/1/2 from private and neuter */
            struct ext_key grandchild_priv;
            hd_derive_path_str(&master, &grandchild_priv, "m/0'/1/2");
            struct ext_pubkey grandchild_pub_from_priv;
            ext_key_neuter(&grandchild_priv, &grandchild_pub_from_priv);

            /* Both pubkeys should match */
            if (grandchild_pub.pubkey.size == grandchild_pub_from_priv.pubkey.size &&
                memcmp(grandchild_pub.pubkey.vch,
                       grandchild_pub_from_priv.pubkey.vch,
                       grandchild_pub.pubkey.size) == 0)
                printf("OK\n");
            else { printf("FAIL (pubkey mismatch)\n"); failures++; }
            memory_cleanse(&grandchild_priv, sizeof(grandchild_priv));
        } else { printf("FAIL (pubkey derivation)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child_priv, sizeof(child_priv));
    }

    /* ── Test 14: pubkey derivation rejects hardened ──────────────── */
    printf("hd_derive_pubkey_path rejects hardened... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));
        struct ext_pubkey epk;
        ext_key_neuter(&master, &epk);

        struct ext_pubkey child;
        uint32_t idx = 0 | BIP32_HARDENED;
        if (!hd_derive_pubkey_path(&epk, &child, &idx, 1))
            printf("OK\n");
        else { printf("FAIL (accepted hardened)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 15: fingerprint matches parent tracking ────────────── */
    printf("hd_get_key_id fingerprint matches child's vchFingerprint... ");
    {
        struct ext_key master, child;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));
        hd_derive_child_index(&master, &child, BIP32_HARDENED);

        struct key_id kid = hd_get_key_id(&master);
        unsigned char master_fp[4];
        memcpy(master_fp, kid.id.data, 4);

        if (memcmp(master_fp, child.vchFingerprint, 4) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* ── Test 16: deep derivation (5 levels) ─────────────────────── */
    printf("hd_derive_path_str 5-level path... ");
    {
        struct ext_key master, child;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        if (hd_derive_path_str(&master, &child, "m/44'/147'/0'/0/0")) {
            if (privkey_is_valid(&child.key) && child.nDepth == 5)
                printf("OK\n");
            else { printf("FAIL (depth=%d)\n", child.nDepth); failures++; }
        } else { printf("FAIL (derivation)\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* ── Test 17: BIP32 test vector 1 — master xpub/xprv ────────── */
    printf("BIP32 test vector 1 master xpub... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        /* Check master xpub matches BIP32 test vector 1 */
        const char *expected_xpub =
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        struct ext_pubkey epk;
        ext_key_neuter(&master, &epk);

        char xpub_str[HD_XKEY_STRING_SIZE];
        hd_serialize_xpub(&epk, xpub_ver, xpub_str, sizeof(xpub_str));

        if (strcmp(xpub_str, expected_xpub) == 0)
            printf("OK\n");
        else { printf("FAIL\n  got:    %s\n  expect: %s\n", xpub_str, expected_xpub); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    printf("BIP32 test vector 1 master xprv... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));

        const char *expected_xprv =
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        char xprv_str[HD_XKEY_STRING_SIZE];
        hd_serialize_xprv(&master, xprv_ver, xprv_str, sizeof(xprv_str));

        if (strcmp(xprv_str, expected_xprv) == 0)
            printf("OK\n");
        else { printf("FAIL\n  got:    %s\n  expect: %s\n", xprv_str, expected_xprv); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 18: BIP32 test vector 1 chain m/0' ─────────────────── */
    printf("BIP32 test vector 1 m/0' xpub... ");
    {
        struct ext_key master, child;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));
        hd_derive_path_str(&master, &child, "m/0'");

        const char *expected =
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

        struct ext_pubkey epk;
        ext_key_neuter(&child, &epk);
        char xpub_str[HD_XKEY_STRING_SIZE];
        hd_serialize_xpub(&epk, xpub_ver, xpub_str, sizeof(xpub_str));

        if (strcmp(xpub_str, expected) == 0)
            printf("OK\n");
        else { printf("FAIL\n  got:    %s\n  expect: %s\n", xpub_str, expected); failures++; }
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* ── Test 19: hd_get_key_id produces valid key_id ────────────── */
    printf("hd_get_key_id... ");
    {
        struct ext_key master;
        hd_master_from_seed(&master, tv1_seed, sizeof(tv1_seed));
        struct key_id kid = hd_get_key_id(&master);
        if (!uint160_is_null(&kid.id))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Test 20: chainparams version bytes match standard ───────── */
    printf("chainparams BIP32 version bytes... ");
    {
        const struct chain_params *cp = chain_params_get();
        size_t xpub_len, xprv_len;
        const unsigned char *xpub_pfx = chain_params_base58_prefix(
            cp, B58_EXT_PUBLIC_KEY, &xpub_len);
        const unsigned char *xprv_pfx = chain_params_base58_prefix(
            cp, B58_EXT_SECRET_KEY, &xprv_len);

        if (xpub_len == 4 && xprv_len == 4 &&
            memcmp(xpub_pfx, xpub_ver, 4) == 0 &&
            memcmp(xprv_pfx, xprv_ver, 4) == 0)
            printf("OK\n");
        else { printf("FAIL (len=%zu/%zu)\n", xpub_len, xprv_len); failures++; }
    }

    return failures;
}
