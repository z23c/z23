/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "bloom/merkle.h"
#include "net/msgprocessor.h"

int test_bloom(void)
{
    int failures = 0;

    printf("bloom_filter_init... ");
    {
        struct bloom_filter f = {0};
        bool ok = bloom_filter_init(&f, 10, 0.0001, 0, BLOOM_UPDATE_ALL);
        if (ok && f.data != NULL && f.data_size > 0 &&
            f.num_hash_funcs > 0 && f.num_hash_funcs <= MAX_BLOOM_HASH_FUNCS) {
            printf("OK (size=%zu, hashes=%u)\n", f.data_size, f.num_hash_funcs);
        } else {
            printf("FAIL\n"); failures++;
        }
        bloom_filter_free(&f);
    }

    printf("bloom_filter insert/contains... ");
    {
        struct bloom_filter f = {0};
        bloom_filter_init(&f, 10, 0.0001, 0, BLOOM_UPDATE_ALL);
        const unsigned char data1[] = "hello";
        const unsigned char data2[] = "world";
        const unsigned char data3[] = "missing";
        bloom_filter_insert(&f, data1, 5);
        bloom_filter_insert(&f, data2, 5);
        bool has1 = bloom_filter_contains(&f, data1, 5);
        bool has2 = bloom_filter_contains(&f, data2, 5);
        bool has3 = bloom_filter_contains(&f, data3, 7);
        if (has1 && has2 && !has3)
            printf("OK\n");
        else {
            printf("FAIL (has1=%d has2=%d has3=%d)\n", has1, has2, has3);
            failures++;
        }
        bloom_filter_free(&f);
    }

    printf("bloom_filter uint256 insert/contains... ");
    {
        struct bloom_filter f = {0};
        bloom_filter_init(&f, 10, 0.0001, 0, BLOOM_UPDATE_ALL);
        struct uint256 h1, h2;
        memset(h1.data, 0xAA, 32);
        memset(h2.data, 0xBB, 32);
        bloom_filter_insert_uint256(&f, &h1);
        bool found1 = bloom_filter_contains_uint256(&f, &h1);
        bool found2 = bloom_filter_contains_uint256(&f, &h2);
        if (found1 && !found2)
            printf("OK\n");
        else {
            printf("FAIL (found1=%d found2=%d)\n", found1, found2);
            failures++;
        }
        bloom_filter_free(&f);
    }

    printf("bloom_filter_clear... ");
    {
        struct bloom_filter f = {0};
        bloom_filter_init(&f, 10, 0.0001, 0, BLOOM_UPDATE_ALL);
        const unsigned char data[] = "test";
        bloom_filter_insert(&f, data, 4);
        bloom_filter_clear(&f);
        bool found = bloom_filter_contains(&f, data, 4);
        if (!found)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        bloom_filter_free(&f);
    }

    printf("bloom_filter size constraints... ");
    {
        struct bloom_filter f = {0};
        bloom_filter_init(&f, 10, 0.0001, 0, BLOOM_UPDATE_ALL);
        bool within = bloom_filter_is_within_size_constraints(&f);
        if (within)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        bloom_filter_free(&f);
    }

    printf("bloom_filter false positive rate... ");
    {
        struct bloom_filter f = {0};
        bloom_filter_init(&f, 100, 0.01, 42, BLOOM_UPDATE_NONE);
        for (int i = 0; i < 100; i++) {
            unsigned char buf[4];
            buf[0] = (unsigned char)(i & 0xFF);
            buf[1] = (unsigned char)((i >> 8) & 0xFF);
            buf[2] = 0;
            buf[3] = 0;
            bloom_filter_insert(&f, buf, 4);
        }
        int false_positives = 0;
        int test_count = 10000;
        for (int i = 100; i < 100 + test_count; i++) {
            unsigned char buf[4];
            buf[0] = (unsigned char)(i & 0xFF);
            buf[1] = (unsigned char)((i >> 8) & 0xFF);
            buf[2] = (unsigned char)((i >> 16) & 0xFF);
            buf[3] = 1;
            if (bloom_filter_contains(&f, buf, 4))
                false_positives++;
        }
        double fp_rate = (double)false_positives / (double)test_count;
        if (fp_rate < 0.05)
            printf("OK (fp_rate=%.4f)\n", fp_rate);
        else {
            printf("FAIL (fp_rate=%.4f, expected <0.05)\n", fp_rate);
            failures++;
        }
        bloom_filter_free(&f);
    }

    printf("bloom_filter_reset... ");
    {
        struct bloom_filter f = {0};
        bloom_filter_init(&f, 10, 0.0001, 0, BLOOM_UPDATE_ALL);
        const unsigned char data[] = "resetme";
        bloom_filter_insert(&f, data, 7);
        bloom_filter_reset(&f, 99);
        bool found = bloom_filter_contains(&f, data, 7);
        if (!found && f.tweak == 99)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        bloom_filter_free(&f);
    }

    printf("compute_merkle_root single tx... ");
    {
        struct uint256 txid;
        memset(txid.data, 0x11, 32);
        struct uint256 root = compute_merkle_root(&txid, 1);
        if (uint256_eq(&root, &txid))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("compute_merkle_root two txs... ");
    {
        struct uint256 txids[2];
        memset(txids[0].data, 0xAA, 32);
        memset(txids[1].data, 0xBB, 32);
        struct uint256 root = compute_merkle_root(txids, 2);
        struct uint256 expected;
        merkle_hash_pair(&txids[0], &txids[1], &expected);
        if (uint256_eq(&root, &expected))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("compute_merkle_root four txs... ");
    {
        struct uint256 txids[4];
        for (int i = 0; i < 4; i++)
            memset(txids[i].data, (unsigned char)(i + 1), 32);
        struct uint256 root = compute_merkle_root(txids, 4);
        struct uint256 h01, h23, expected;
        merkle_hash_pair(&txids[0], &txids[1], &h01);
        merkle_hash_pair(&txids[2], &txids[3], &h23);
        merkle_hash_pair(&h01, &h23, &expected);
        if (uint256_eq(&root, &expected))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("compute_merkle_root three txs (odd)... ");
    {
        struct uint256 txids[3];
        for (int i = 0; i < 3; i++)
            memset(txids[i].data, (unsigned char)(0x10 + i), 32);
        struct uint256 root = compute_merkle_root(txids, 3);
        struct uint256 h01, h22, expected;
        merkle_hash_pair(&txids[0], &txids[1], &h01);
        merkle_hash_pair(&txids[2], &txids[2], &h22);
        merkle_hash_pair(&h01, &h22, &expected);
        if (uint256_eq(&root, &expected))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("compute_merkle_root_mutated no dupes... ");
    {
        struct uint256 txids[2];
        memset(txids[0].data, 0xCC, 32);
        memset(txids[1].data, 0xDD, 32);
        bool mutated = false;
        struct uint256 root = compute_merkle_root_mutated(txids, 2, &mutated);
        struct uint256 root2 = compute_merkle_root(txids, 2);
        if (!mutated && uint256_eq(&root, &root2))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("partial_merkle_tree build/extract... ");
    {
        struct uint256 txids[4];
        for (int i = 0; i < 4; i++)
            memset(txids[i].data, (unsigned char)(0x30 + i), 32);
        bool match[4] = {false, true, false, false};
        struct partial_merkle_tree tree;
        merkle_tree_init(&tree);
        bool built = merkle_tree_build(&tree, txids, 4, match, 4);
        if (!built) {
            printf("FAIL (build)\n"); failures++;
        } else {
            struct uint256 matched[4];
            size_t num_matched = 0;
            struct uint256 merkle_root;
            bool extracted = merkle_tree_extract(&tree, matched, &num_matched, &merkle_root);
            struct uint256 expected_root = compute_merkle_root(txids, 4);
            if (extracted && num_matched == 1 &&
                uint256_eq(&matched[0], &txids[1]) &&
                uint256_eq(&merkle_root, &expected_root))
                printf("OK\n");
            else {
                printf("FAIL (extract: ok=%d matched=%zu)\n", extracted, num_matched);
                failures++;
            }
        }
        merkle_tree_free(&tree);
    }

    printf("partial_merkle_tree multiple matches... ");
    {
        struct uint256 txids[4];
        for (int i = 0; i < 4; i++)
            memset(txids[i].data, (unsigned char)(0x40 + i), 32);
        bool match[4] = {true, false, true, false};
        struct partial_merkle_tree tree;
        merkle_tree_init(&tree);
        bool built = merkle_tree_build(&tree, txids, 4, match, 4);
        if (!built) {
            printf("FAIL (build)\n"); failures++;
        } else {
            struct uint256 matched[4];
            size_t num_matched = 0;
            struct uint256 merkle_root;
            bool extracted = merkle_tree_extract(&tree, matched, &num_matched, &merkle_root);
            struct uint256 expected_root = compute_merkle_root(txids, 4);
            if (extracted && num_matched == 2 &&
                uint256_eq(&merkle_root, &expected_root))
                printf("OK\n");
            else {
                printf("FAIL (extract: ok=%d matched=%zu)\n", extracted, num_matched);
                failures++;
            }
        }
        merkle_tree_free(&tree);
    }

    printf("merkle_hash_pair deterministic... ");
    {
        struct uint256 a, b, out1, out2;
        memset(a.data, 0x55, 32);
        memset(b.data, 0x66, 32);
        merkle_hash_pair(&a, &b, &out1);
        merkle_hash_pair(&a, &b, &out2);
        if (uint256_eq(&out1, &out2))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("merkle_hash_pair order matters... ");
    {
        struct uint256 a, b, out_ab, out_ba;
        memset(a.data, 0x77, 32);
        memset(b.data, 0x88, 32);
        merkle_hash_pair(&a, &b, &out_ab);
        merkle_hash_pair(&b, &a, &out_ba);
        if (!uint256_eq(&out_ab, &out_ba))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── BIP37 gating tests ─────────────────────────────────────── */

    printf("bip37_enabled default off... ");
    {
        unsetenv("ZCL_ENABLE_BIP37");
        if (!bip37_enabled())
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("bip37_enabled with ZCL_ENABLE_BIP37=1... ");
    {
        setenv("ZCL_ENABLE_BIP37", "1", 1);
        if (bip37_enabled())
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        unsetenv("ZCL_ENABLE_BIP37");
    }

    printf("bip37_enabled rejects ZCL_ENABLE_BIP37=0... ");
    {
        setenv("ZCL_ENABLE_BIP37", "0", 1);
        if (!bip37_enabled())
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        unsetenv("ZCL_ENABLE_BIP37");
    }

    printf("bip37_enabled rejects ZCL_ENABLE_BIP37=yes... ");
    {
        setenv("ZCL_ENABLE_BIP37", "yes", 1);
        if (!bip37_enabled())
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        unsetenv("ZCL_ENABLE_BIP37");
    }

    printf("bip37_enabled rejects ZCL_ENABLE_BIP37=10... ");
    {
        setenv("ZCL_ENABLE_BIP37", "10", 1);
        if (!bip37_enabled())
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        unsetenv("ZCL_ENABLE_BIP37");
    }

    printf("NODE_BLOOM not in services when BIP37 off... ");
    {
        unsetenv("ZCL_ENABLE_BIP37");
        uint64_t svc = NODE_NETWORK;
        if (bip37_enabled()) svc |= NODE_BLOOM;
        if (!(svc & NODE_BLOOM))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("NODE_BLOOM in services when BIP37 on... ");
    {
        setenv("ZCL_ENABLE_BIP37", "1", 1);
        uint64_t svc = NODE_NETWORK;
        if (bip37_enabled()) svc |= NODE_BLOOM;
        if (svc & NODE_BLOOM)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        unsetenv("ZCL_ENABLE_BIP37");
    }

    printf("dispatch table has filterload entry... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool found = false;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (strcmp(e->command, "filterload") == 0) {
                found = true;
                break;
            }
        }
        if (found)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("dispatch table has filteradd entry... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool found = false;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (strcmp(e->command, "filteradd") == 0) {
                found = true;
                break;
            }
        }
        if (found)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("dispatch table has filterclear entry... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool found = false;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (strcmp(e->command, "filterclear") == 0) {
                found = true;
                break;
            }
        }
        if (found)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── rolling_bloom must clamp MAX_BLOOM_HASH_FUNCS ────────── */

    printf("rolling_bloom_init clamps num_hash_funcs... ");
    {
        /* Pathological tuning: num_elements=1 (doubled to 2 internally)
         * with fp_rate=1e-30 produces ideal ≈ 97 hash funcs pre-fix.
         * Post-fix both internal filters must clamp to MAX_BLOOM_HASH_FUNCS. */
        struct rolling_bloom_filter rf = {0};
        bool ok = rolling_bloom_init(&rf, 1, 1e-30);
        if (ok &&
            rf.b1.num_hash_funcs == MAX_BLOOM_HASH_FUNCS &&
            rf.b2.num_hash_funcs == MAX_BLOOM_HASH_FUNCS)
            printf("OK (b1=%u b2=%u cap=%d)\n",
                   rf.b1.num_hash_funcs, rf.b2.num_hash_funcs, MAX_BLOOM_HASH_FUNCS);
        else {
            printf("FAIL (ok=%d b1=%u b2=%u expected=%d)\n",
                   ok, rf.b1.num_hash_funcs, rf.b2.num_hash_funcs, MAX_BLOOM_HASH_FUNCS);
            failures++;
        }
        rolling_bloom_free(&rf);
    }

    printf("rolling_bloom_init sane params not over-clamped... ");
    {
        /* Normal tuning: ideal << MAX_BLOOM_HASH_FUNCS. Assert the clamp
         * doesn't regress everyday rolling-bloom behavior. */
        struct rolling_bloom_filter rf = {0};
        bool ok = rolling_bloom_init(&rf, 120000, 0.000001);
        if (ok &&
            rf.b1.num_hash_funcs > 0 && rf.b1.num_hash_funcs <= MAX_BLOOM_HASH_FUNCS &&
            rf.b2.num_hash_funcs > 0 && rf.b2.num_hash_funcs <= MAX_BLOOM_HASH_FUNCS)
            printf("OK (hashes=%u)\n", rf.b1.num_hash_funcs);
        else {
            printf("FAIL (ok=%d b1=%u b2=%u)\n",
                   ok, rf.b1.num_hash_funcs, rf.b2.num_hash_funcs);
            failures++;
        }
        rolling_bloom_free(&rf);
    }

    printf("bloom_filter_init regression (public path still clamps)... ");
    {
        /* Same pathological tuning via the public constrained path.
         * Pre- and post-fix must both clamp; this asserts we didn't
         * break the existing behavior while lifting the clamp. */
        struct bloom_filter f = {0};
        bool ok = bloom_filter_init(&f, 1, 1e-30, 0, BLOOM_UPDATE_NONE);
        if (ok && f.num_hash_funcs == MAX_BLOOM_HASH_FUNCS)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d hashes=%u)\n", ok, f.num_hash_funcs);
            failures++;
        }
        bloom_filter_free(&f);
    }

    return failures;
}
