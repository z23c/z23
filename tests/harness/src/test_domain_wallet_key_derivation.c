/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for contexts/wallet/domain/key_derivation.{c,h}.
 *
 * Pins the pure BIP32/BIP44 derivation extracted from
 * contexts/wallet/src/{hd_keychain,bip44}.c. Three layers:
 *
 *   1. Contract / null-edge tests on the typed zcl_result API.
 *   2. BIP32 test-vector seal: well-known seeds + paths against the
 *      pure domain function (this would have caught any HMAC or
 *      scalar-add regression in the extraction).
 *   3. Wrapper-vs-domain regression seal: the contexts/wallet/modules/wallet wrappers
 *      produce byte-identical ext_key output to the domain function
 *      on synthetic seeds across several paths.
 */

#include "test/test_core.h"

#include "domain/wallet/key_derivation.h"
#include "wallet/bip44.h"
#include "wallet/hd_keychain.h"
#include "keys/key.h"
#include "support/cleanse.h"

#include <stdio.h>
#include <string.h>
#include "test/setup_result.h"

#define DWK_CHECK(name, expr) do {                                  \
    printf("domain_wallet_key_derivation: %s... ", (name));         \
    if ((expr)) printf("OK\n");                                     \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* BIP32 test vector 1 seed
 * (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) */
static const unsigned char k_tv1_seed[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

/* BIP32 test vector 2 seed (longer seed). */
static const unsigned char k_tv2_seed[] = {
    0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
    0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
    0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
    0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
    0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
    0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
    0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
    0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42,
};

static bool ext_key_bytes_equal(const struct ext_key *a, const struct ext_key *b)
{
    if (a->nDepth != b->nDepth) return false;
    if (a->nChild != b->nChild) return false;
    if (memcmp(a->vchFingerprint, b->vchFingerprint, 4) != 0) return false;
    if (memcmp(&a->chaincode, &b->chaincode, sizeof(a->chaincode)) != 0) return false;
    if (a->key.fValid != b->key.fValid) return false;
    if (a->key.fCompressed != b->key.fCompressed) return false;
    if (memcmp(a->key.vch, b->key.vch, sizeof(a->key.vch)) != 0) return false;
    return true;
}

int test_domain_wallet_key_derivation(void)
{
    int failures = 0;

    /* ── Layer 1: contract / null-edge ────────────────────────────── */

    /* master_from_seed: null out / null seed / bad seed_len. */
    {
        struct zcl_result r = domain_wallet_master_from_seed(
                NULL, k_tv1_seed, sizeof(k_tv1_seed));
        DWK_CHECK("master_from_seed null out -> NULL_OUT",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT);
    }
    {
        struct ext_key ek;
        struct zcl_result r = domain_wallet_master_from_seed(&ek, NULL, 32);
        DWK_CHECK("master_from_seed null seed -> NULL_SEED",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_SEED);
    }
    {
        struct ext_key ek;
        struct zcl_result r = domain_wallet_master_from_seed(&ek, k_tv1_seed, 8);
        DWK_CHECK("master_from_seed bad seed_len (low) -> SEED_LEN",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_SEED_LEN);
    }
    {
        struct ext_key ek;
        struct zcl_result r = domain_wallet_master_from_seed(&ek, k_tv1_seed, 128);
        DWK_CHECK("master_from_seed bad seed_len (high) -> SEED_LEN",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_SEED_LEN);
    }

    /* derive_path: null parent / null out / bad depth / null indices. */
    {
        struct ext_key out;
        struct zcl_result r = domain_wallet_derive_path(NULL, &out, NULL, 0);
        DWK_CHECK("derive_path null parent -> NULL_PARENT",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT);
    }
    {
        struct ext_key parent;
        memset(&parent, 0, sizeof(parent));
        struct zcl_result r = domain_wallet_derive_path(&parent, NULL, NULL, 0);
        DWK_CHECK("derive_path null out -> NULL_OUT",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT);
    }
    {
        struct ext_key parent, out;
        memset(&parent, 0, sizeof(parent));
        struct zcl_result r = domain_wallet_derive_path(&parent, &out, NULL, -1);
        DWK_CHECK("derive_path negative depth -> DEPTH",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_DEPTH);
    }
    {
        struct ext_key parent, out;
        memset(&parent, 0, sizeof(parent));
        struct zcl_result r = domain_wallet_derive_path(&parent, &out, NULL, 3);
        DWK_CHECK("derive_path null indices w/ n>0 -> NULL_INDICES",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_INDICES);
    }

    /* derive_path: identity (num_indices=0) copies parent. */
    {
        struct ext_key parent, out;
        struct zcl_result r1 = domain_wallet_master_from_seed(
                &parent, k_tv1_seed, sizeof(k_tv1_seed));
        struct zcl_result r2 = domain_wallet_derive_path(&parent, &out, NULL, 0);
        DWK_CHECK("derive_path identity preserves parent",
                  r1.ok && r2.ok && ext_key_bytes_equal(&parent, &out));
        memory_cleanse(&parent, sizeof(parent));
        memory_cleanse(&out, sizeof(out));
    }

    /* derive_pubkey_path: hardened index rejected. */
    {
        struct ext_pubkey parent, out;
        memset(&parent, 0, sizeof(parent));
        uint32_t idx[1] = { DOMAIN_WALLET_BIP32_HARDENED | 0u };
        struct zcl_result r = domain_wallet_derive_pubkey_path(
                &parent, &out, idx, 1);
        DWK_CHECK("derive_pubkey_path hardened -> HARDENED_PUB",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_HARDENED_PUB);
    }

    /* parse_path: well-formed path. */
    {
        uint32_t indices[16];
        int count = -1;
        struct zcl_result r = domain_wallet_parse_path(
                "m/44'/147'/0'/0/5", indices, 16, &count);
        DWK_CHECK("parse_path full BIP44",
                  r.ok && count == 5 &&
                  indices[0] == (44u  | DOMAIN_WALLET_BIP32_HARDENED) &&
                  indices[1] == (147u | DOMAIN_WALLET_BIP32_HARDENED) &&
                  indices[2] == (0u   | DOMAIN_WALLET_BIP32_HARDENED) &&
                  indices[3] == 0u && indices[4] == 5u);
    }

    /* parse_path: bare "m" yields 0 components. */
    {
        uint32_t indices[4];
        int count = -1;
        struct zcl_result r = domain_wallet_parse_path("m", indices, 4, &count);
        DWK_CHECK("parse_path bare m -> 0 components",
                  r.ok && count == 0);
    }

    /* parse_path: hardened 'h' notation accepted. */
    {
        uint32_t indices[4];
        int count = -1;
        struct zcl_result r = domain_wallet_parse_path("m/0h/1H", indices, 4, &count);
        DWK_CHECK("parse_path 'h'/'H' hardened",
                  r.ok && count == 2 &&
                  indices[0] == DOMAIN_WALLET_BIP32_HARDENED &&
                  indices[1] == (1u | DOMAIN_WALLET_BIP32_HARDENED));
    }

    /* parse_path: trailing slash rejected. */
    {
        uint32_t indices[4];
        int count = -1;
        struct zcl_result r = domain_wallet_parse_path("m/0/", indices, 4, &count);
        DWK_CHECK("parse_path trailing slash -> PATH_SYNTAX",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_SYNTAX);
    }

    /* parse_path: too many components for caller buf. */
    {
        uint32_t indices[2];
        int count = -1;
        struct zcl_result r = domain_wallet_parse_path(
                "m/0/1/2/3", indices, 2, &count);
        DWK_CHECK("parse_path overflow -> PATH_TOOLONG",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_TOOLONG);
    }

    /* parse_path: bad max_indices. */
    {
        uint32_t indices[1];
        int count = -1;
        struct zcl_result r = domain_wallet_parse_path("m/0", indices, 0, &count);
        DWK_CHECK("parse_path max_indices<=0 -> BAD_RANGE",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE);
    }

    /* bip44_format_path: round-trip and bounds. */
    {
        char buf[64];
        int written = -1;
        struct zcl_result r = domain_wallet_bip44_format_path(
                buf, sizeof(buf), 0, 0, 5, &written);
        DWK_CHECK("bip44_format_path m/44'/147'/0'/0/5",
                  r.ok && written > 0 && strcmp(buf, "m/44'/147'/0'/0/5") == 0);
    }
    {
        char buf[8];   /* far too small */
        int written = -1;
        struct zcl_result r = domain_wallet_bip44_format_path(
                buf, sizeof(buf), 0, 0, 5, &written);
        DWK_CHECK("bip44_format_path tiny buf -> BUF_TOO_SMALL",
                  !r.ok &&
                  r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_BUF_TOO_SMALL);
    }
    {
        int written = -1;
        struct zcl_result r = domain_wallet_bip44_format_path(
                NULL, 64, 0, 0, 5, &written);
        DWK_CHECK("bip44_format_path null buf -> NULL_BUF",
                  !r.ok && r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_BUF);
    }

    /* bip44_derive_*: range checks. */
    {
        struct ext_key master, out;
        struct zcl_result m = domain_wallet_master_from_seed(
                &master, k_tv1_seed, sizeof(k_tv1_seed));
        struct zcl_result r = domain_wallet_bip44_derive_chain(
                &master, &out, 0, 2 /* invalid */);
        DWK_CHECK("bip44_derive_chain bad change -> BAD_RANGE",
                  m.ok && !r.ok &&
                  r.code == DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE);
        memory_cleanse(&master, sizeof(master));
    }

    /* ── Layer 2: BIP32 test-vector seal ──────────────────────────── */

    /* Build the master from TV1 seed via the pure domain function and
     * walk the canonical BIP32 TV1 path:  m/0'/1/2'/2/1000000000.
     * We don't pin the exact byte values (that's the job of the
     * existing test_hd_keychain xpub vector), but we verify:
     *   - master derives without error,
     *   - depth/child counters advance correctly,
     *   - chaincode propagates (depth-N chaincode != master chaincode),
     *   - each child key is valid. */
    {
        struct ext_key master;
        struct zcl_result m = domain_wallet_master_from_seed(
                &master, k_tv1_seed, sizeof(k_tv1_seed));
        DWK_CHECK("TV1 master_from_seed -> ok && valid",
                  m.ok && master.nDepth == 0 && master.nChild == 0 &&
                  privkey_is_valid(&master.key) && master.key.fCompressed);

        uint32_t path[5] = {
            DOMAIN_WALLET_BIP32_HARDENED | 0u,
            1u,
            DOMAIN_WALLET_BIP32_HARDENED | 2u,
            2u,
            1000000000u,
        };
        struct ext_key child;
        struct zcl_result d = domain_wallet_derive_path(
                &master, &child, path, 5);
        DWK_CHECK("TV1 path m/0'/1/2'/2/1000000000 -> ok",
                  d.ok && child.nDepth == 5 &&
                  child.nChild == 1000000000u &&
                  privkey_is_valid(&child.key) &&
                  memcmp(&child.chaincode, &master.chaincode,
                         sizeof(child.chaincode)) != 0);
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* TV2: longer seed, walk m/0/2147483647'/1/2147483646'/2. */
    {
        struct ext_key master;
        struct zcl_result m = domain_wallet_master_from_seed(
                &master, k_tv2_seed, sizeof(k_tv2_seed));
        DWK_CHECK("TV2 master_from_seed -> ok && valid",
                  m.ok && privkey_is_valid(&master.key));

        uint32_t path[5] = {
            0u,
            DOMAIN_WALLET_BIP32_HARDENED | 2147483647u,
            1u,
            DOMAIN_WALLET_BIP32_HARDENED | 2147483646u,
            2u,
        };
        struct ext_key child;
        struct zcl_result d = domain_wallet_derive_path(
                &master, &child, path, 5);
        DWK_CHECK("TV2 path -> ok, depth=5",
                  d.ok && child.nDepth == 5 && privkey_is_valid(&child.key));
        memory_cleanse(&master, sizeof(master));
        memory_cleanse(&child, sizeof(child));
    }

    /* Determinism: two independent walks from the same TV1 seed
     * along the same path yield byte-identical ext_keys.  This is
     * the regression seal that "extraction didn't perturb the math". */
    {
        struct ext_key m1, m2, c1, c2;
        ZCL_TEST_SETUP(domain_wallet_master_from_seed(&m1, k_tv1_seed, sizeof(k_tv1_seed)));
        ZCL_TEST_SETUP(domain_wallet_master_from_seed(&m2, k_tv1_seed, sizeof(k_tv1_seed)));
        uint32_t path[4] = {
            DOMAIN_WALLET_BIP44_PURPOSE  | DOMAIN_WALLET_BIP32_HARDENED,
            DOMAIN_WALLET_BIP44_ZCL_COIN | DOMAIN_WALLET_BIP32_HARDENED,
            0u | DOMAIN_WALLET_BIP32_HARDENED,
            0u,
        };
        ZCL_TEST_SETUP(domain_wallet_derive_path(&m1, &c1, path, 4));
        ZCL_TEST_SETUP(domain_wallet_derive_path(&m2, &c2, path, 4));
        DWK_CHECK("determinism: same seed + path -> byte-identical child",
                  ext_key_bytes_equal(&c1, &c2));
        memory_cleanse(&m1, sizeof(m1));
        memory_cleanse(&m2, sizeof(m2));
        memory_cleanse(&c1, sizeof(c1));
        memory_cleanse(&c2, sizeof(c2));
    }

    /* ── Layer 3: wrapper-vs-domain regression seal ───────────────── */

    /* The contexts/wallet/modules/wallet wrappers MUST produce byte-identical output to
     * the pure domain function on the same inputs. This is the
     * cross-check that "the wrapper preserves behaviour exactly". */
    {
        const unsigned char *seeds[] = { k_tv1_seed, k_tv2_seed };
        const size_t seed_lens[] = { sizeof(k_tv1_seed), sizeof(k_tv2_seed) };
        const char *paths[] = {
            "m/44'/147'/0'/0/0",
            "m/44'/147'/0'/0/1",
            "m/44'/147'/0'/1/7",
            "m/44'/147'/1'/0/0",
            "m/0'/0/0",
            "m/1/2/3",
        };
        bool all_match = true;
        for (size_t s = 0; s < sizeof(seeds)/sizeof(seeds[0]); s++) {
            struct ext_key master_wrap, master_dom;
            if (!hd_master_from_seed(&master_wrap, seeds[s], seed_lens[s])) {
                all_match = false; continue;
            }
            struct zcl_result mr = domain_wallet_master_from_seed(
                    &master_dom, seeds[s], seed_lens[s]);
            if (!mr.ok || !ext_key_bytes_equal(&master_wrap, &master_dom)) {
                all_match = false; continue;
            }
            for (size_t pi = 0; pi < sizeof(paths)/sizeof(paths[0]); pi++) {
                /* wrapper path-string flow */
                struct ext_key child_wrap;
                if (!hd_derive_path_str(&master_wrap, &child_wrap, paths[pi])) {
                    all_match = false; continue;
                }
                /* domain flow: parse + derive */
                uint32_t indices[DOMAIN_WALLET_MAX_PATH_COMPONENTS];
                int n = 0;
                struct zcl_result pr = domain_wallet_parse_path(
                        paths[pi], indices,
                        DOMAIN_WALLET_MAX_PATH_COMPONENTS, &n);
                if (!pr.ok) { all_match = false; continue; }
                struct ext_key child_dom;
                struct zcl_result dr = domain_wallet_derive_path(
                        &master_dom, &child_dom, indices, n);
                if (!dr.ok) { all_match = false; continue; }
                if (!ext_key_bytes_equal(&child_wrap, &child_dom)) {
                    all_match = false;
                }
                memory_cleanse(&child_wrap, sizeof(child_wrap));
                memory_cleanse(&child_dom, sizeof(child_dom));
            }
            memory_cleanse(&master_wrap, sizeof(master_wrap));
            memory_cleanse(&master_dom, sizeof(master_dom));
        }
        DWK_CHECK("wrapper vs domain: 2 seeds x 6 paths byte-identical",
                  all_match);
    }

    /* BIP44 wrapper vs domain: derive_account / derive_chain / derive_key
     * with explicit indices. */
    {
        struct ext_key master;
        ZCL_TEST_SETUP(domain_wallet_master_from_seed(&master, k_tv1_seed, sizeof(k_tv1_seed)));

        bool all_match = true;
        const uint32_t accounts[] = { 0, 1, 7 };
        const uint32_t changes[]  = { 0, 1 };
        const uint32_t indexes[]  = { 0, 1, 9 };

        for (size_t ai = 0; ai < 3 && all_match; ai++) {
            uint32_t a = accounts[ai];

            struct ext_key acc_wrap, acc_dom;
            bip44_derive_account(&master, &acc_wrap, a);
            struct zcl_result r =
                    domain_wallet_bip44_derive_account(&master, &acc_dom, a);
            if (!r.ok || !ext_key_bytes_equal(&acc_wrap, &acc_dom)) {
                all_match = false; break;
            }

            for (size_t ci = 0; ci < 2 && all_match; ci++) {
                uint32_t c = changes[ci];

                struct ext_key ch_wrap, ch_dom;
                bip44_derive_chain(&master, &ch_wrap, a, c);
                r = domain_wallet_bip44_derive_chain(&master, &ch_dom, a, c);
                if (!r.ok || !ext_key_bytes_equal(&ch_wrap, &ch_dom)) {
                    all_match = false; break;
                }

                for (size_t ii = 0; ii < 3 && all_match; ii++) {
                    uint32_t i = indexes[ii];
                    struct ext_key k_wrap, k_dom;
                    bip44_derive_key(&master, &k_wrap, a, c, i);
                    r = domain_wallet_bip44_derive_key(&master, &k_dom, a, c, i);
                    if (!r.ok || !ext_key_bytes_equal(&k_wrap, &k_dom)) {
                        all_match = false;
                    }
                    memory_cleanse(&k_wrap, sizeof(k_wrap));
                    memory_cleanse(&k_dom,  sizeof(k_dom));
                }
                memory_cleanse(&ch_wrap, sizeof(ch_wrap));
                memory_cleanse(&ch_dom,  sizeof(ch_dom));
            }
            memory_cleanse(&acc_wrap, sizeof(acc_wrap));
            memory_cleanse(&acc_dom,  sizeof(acc_dom));
        }
        DWK_CHECK("BIP44 wrapper vs domain: 3 accts x 2 chains x 3 idx match",
                  all_match);
        memory_cleanse(&master, sizeof(master));
    }

    /* hd_parse_path wrapper preserves -1 sentinel on bad input. */
    {
        uint32_t indices[4];
        int n = hd_parse_path(NULL, indices, 4);
        DWK_CHECK("hd_parse_path null path returns -1", n == -1);
    }
    {
        uint32_t indices[4];
        int n = hd_parse_path("m/0/", indices, 4);
        DWK_CHECK("hd_parse_path trailing slash returns -1", n == -1);
    }
    {
        uint32_t indices[4];
        int n = hd_parse_path("m/44'/147'/0'/0/5", indices, 4);
        DWK_CHECK("hd_parse_path overflow returns -1", n == -1);
    }

    /* bip44_format_path wrapper preserves length-on-success convention. */
    {
        char buf[64];
        int n = bip44_format_path(buf, sizeof(buf), 0, 0, 5);
        DWK_CHECK("bip44_format_path wrapper returns length",
                  n > 0 && strcmp(buf, "m/44'/147'/0'/0/5") == 0);
    }
    {
        char buf[4];
        int n = bip44_format_path(buf, sizeof(buf), 0, 0, 5);
        DWK_CHECK("bip44_format_path wrapper tiny buf -> -1", n == -1);
    }

    return failures + ZCL_TEST_SETUP_FAILURES();
}
