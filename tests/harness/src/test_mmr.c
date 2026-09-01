/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Merkle Mountain Range + SHA3 UTXO commitment. */

#include "test/test_core.h"
#include "chain/mmr.h"
#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include <string.h>
#include <stdio.h>

int test_mmr(void)
{
    int failures = 0;

    printf("mmr: init produces zero root... ");
    {
        struct mmr m;
        mmr_init(&m);
        uint8_t root[32];
        mmr_root(&m, root);
        uint8_t zero[32] = {0};
        bool ok = (m.num_leaves == 0 && m.num_peaks == 0 &&
                   memcmp(root, zero, 32) == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: single leaf root equals leaf hash... ");
    {
        struct mmr m;
        mmr_init(&m);
        uint8_t block[32];
        memset(block, 0x42, 32);
        mmr_append(&m, block);

        uint8_t expected[32];
        mmr_hash_leaf(block, expected);

        uint8_t root[32];
        mmr_root(&m, root);
        bool ok = (m.num_leaves == 1 && m.num_peaks == 1 &&
                   memcmp(root, expected, 32) == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: two leaves merge into single peak... ");
    {
        struct mmr m;
        mmr_init(&m);
        uint8_t b0[32], b1[32];
        memset(b0, 0x01, 32);
        memset(b1, 0x02, 32);
        mmr_append(&m, b0);
        mmr_append(&m, b1);

        /* Should have 1 peak (merged) */
        uint8_t h0[32], h1[32], expected[32];
        mmr_hash_leaf(b0, h0);
        mmr_hash_leaf(b1, h1);
        mmr_hash_internal(h0, h1, expected);

        uint8_t root[32];
        mmr_root(&m, root);
        bool ok = (m.num_leaves == 2 && m.num_peaks == 1 &&
                   memcmp(root, expected, 32) == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: three leaves produce two peaks... ");
    {
        struct mmr m;
        mmr_init(&m);
        uint8_t blocks[3][32];
        for (int i = 0; i < 3; i++) memset(blocks[i], (uint8_t)(i + 1), 32);
        for (int i = 0; i < 3; i++) mmr_append(&m, blocks[i]);

        bool ok = (m.num_leaves == 3 && m.num_peaks == 2);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: power-of-two leaves produce single peak... ");
    {
        bool ok = true;
        for (int n = 1; n <= 5; n++) {
            struct mmr m;
            mmr_init(&m);
            int count = 1 << n; /* 2, 4, 8, 16, 32 */
            for (int i = 0; i < count; i++) {
                uint8_t b[32] = {0};
                b[0] = (uint8_t)(i & 0xFF);
                b[1] = (uint8_t)((i >> 8) & 0xFF);
                mmr_append(&m, b);
            }
            if (m.num_peaks != 1) { ok = false; break; }
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: deterministic — same inputs same root... ");
    {
        uint8_t root1[32], root2[32];
        for (int trial = 0; trial < 2; trial++) {
            struct mmr m;
            mmr_init(&m);
            for (int i = 0; i < 100; i++) {
                uint8_t b[32];
                memset(b, 0, 32);
                b[0] = (uint8_t)(i & 0xFF);
                mmr_append(&m, b);
            }
            mmr_root(&m, trial == 0 ? root1 : root2);
        }
        bool ok = memcmp(root1, root2, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: serialize/deserialize roundtrip... ");
    {
        struct mmr m;
        mmr_init(&m);
        for (int i = 0; i < 37; i++) {
            uint8_t b[32] = {0};
            b[0] = (uint8_t)i;
            mmr_append(&m, b);
        }

        uint8_t buf[MMR_SERIALIZED_MAX];
        size_t len = mmr_serialize(&m, buf, sizeof(buf));

        struct mmr m2;
        bool ok = mmr_deserialize(&m2, buf, len);
        ok = ok && (m.num_leaves == m2.num_leaves);
        ok = ok && (m.num_peaks == m2.num_peaks);

        uint8_t r1[32], r2[32];
        mmr_root(&m, r1);
        mmr_root(&m2, r2);
        ok = ok && memcmp(r1, r2, 32) == 0;

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: sha3_256 one-shot matches streaming... ");
    {
        uint8_t data[] = "ZClassic23 MMR test data";
        uint8_t h1[32], h2[32];
        sha3_256(data, sizeof(data) - 1, h1);

        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        sha3_256_write(&ctx, data, sizeof(data) - 1);
        sha3_256_finalize(&ctx, h2);

        bool ok = memcmp(h1, h2, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: domain separation — leaf != internal... ");
    {
        uint8_t data[32];
        memset(data, 0x55, 32);

        uint8_t leaf[32], internal[32];
        mmr_hash_leaf(data, leaf);
        mmr_hash_internal(data, data, internal);

        bool ok = memcmp(leaf, internal, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Unified commitment leaf tests ──────────────────── */

    printf("mmr: commitment hash is deterministic... ");
    {
        struct mmr_commitment c = {
            .height = 3056758,
        };
        memset(c.block_hash, 0xAA, 32);
        memset(c.utxo_root, 0xBB, 32);
        memset(c.data_root, 0xCC, 32);

        uint8_t h1[32], h2[32];
        mmr_hash_commitment(&c, h1);
        mmr_hash_commitment(&c, h2);
        bool ok = memcmp(h1, h2, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: commitment hash changes with height... ");
    {
        struct mmr_commitment c1 = { .height = 100 };
        struct mmr_commitment c2 = { .height = 200 };
        memset(c1.block_hash, 0x11, 32); memset(c2.block_hash, 0x11, 32);
        memset(c1.utxo_root, 0x22, 32);  memset(c2.utxo_root, 0x22, 32);
        memset(c1.data_root, 0x33, 32);  memset(c2.data_root, 0x33, 32);

        uint8_t h1[32], h2[32];
        mmr_hash_commitment(&c1, h1);
        mmr_hash_commitment(&c2, h2);
        bool ok = memcmp(h1, h2, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: commitment hash changes with utxo_root... ");
    {
        struct mmr_commitment c1 = { .height = 100 };
        struct mmr_commitment c2 = { .height = 100 };
        memset(c1.block_hash, 0x11, 32); memset(c2.block_hash, 0x11, 32);
        memset(c1.utxo_root, 0x22, 32);  memset(c2.utxo_root, 0xFF, 32);
        memset(c1.data_root, 0x33, 32);  memset(c2.data_root, 0x33, 32);

        uint8_t h1[32], h2[32];
        mmr_hash_commitment(&c1, h1);
        mmr_hash_commitment(&c2, h2);
        bool ok = memcmp(h1, h2, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: commitment append builds valid MMR... ");
    {
        struct mmr m;
        mmr_init(&m);

        for (int i = 0; i < 10; i++) {
            struct mmr_commitment c = { .height = i * 100 };
            memset(c.block_hash, (uint8_t)i, 32);
            memset(c.utxo_root, (uint8_t)(i + 50), 32);
            memset(c.data_root, (uint8_t)(i + 100), 32);
            mmr_append_commitment(&m, &c);
        }

        bool ok = (m.num_leaves == 10 && m.num_peaks > 0);
        uint8_t root[32];
        mmr_root(&m, root);
        uint8_t zero[32] = {0};
        ok = ok && memcmp(root, zero, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: commitment MMR is deterministic... ");
    {
        uint8_t r1[32], r2[32];
        for (int trial = 0; trial < 2; trial++) {
            struct mmr m;
            mmr_init(&m);
            for (int i = 0; i < 30; i++) {
                struct mmr_commitment c = { .height = i * 100 };
                memset(c.block_hash, (uint8_t)i, 32);
                memset(c.utxo_root, (uint8_t)(i + 50), 32);
                memset(c.data_root, (uint8_t)(i + 100), 32);
                mmr_append_commitment(&m, &c);
            }
            mmr_root(&m, trial == 0 ? r1 : r2);
        }
        bool ok = memcmp(r1, r2, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: commitment serializes and deserializes... ");
    {
        struct mmr m;
        mmr_init(&m);
        for (int i = 0; i < 25; i++) {
            struct mmr_commitment c = { .height = i * 100 };
            memset(c.block_hash, (uint8_t)i, 32);
            memset(c.utxo_root, (uint8_t)(i + 1), 32);
            memset(c.data_root, (uint8_t)(i + 2), 32);
            mmr_append_commitment(&m, &c);
        }

        uint8_t buf[MMR_SERIALIZED_MAX];
        size_t len = mmr_serialize(&m, buf, sizeof(buf));

        struct mmr m2;
        bool ok = mmr_deserialize(&m2, buf, len);

        uint8_t r1[32], r2[32];
        mmr_root(&m, r1);
        mmr_root(&m2, r2);
        ok = ok && memcmp(r1, r2, 32) == 0;
        ok = ok && m.num_leaves == m2.num_leaves;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mmr: commitment interval constant defined... ");
    {
        bool ok = (MMR_COMMITMENT_INTERVAL == 100);
        if (ok) printf("OK (every %d blocks)\n", MMR_COMMITMENT_INTERVAL);
        else { printf("FAIL\n"); failures++; }
    }

    printf("\n%d passed, %d failed\n", 16 - failures, failures);
    return failures;
}
