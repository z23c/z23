/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Merkle Mountain Range + SHA3 UTXO commitment. */

#include "test/test_core.h"
#include "chain/mmr.h"
#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include <string.h>
#include <stdio.h>

/* Verifies roots and peak counts for MMRs of 0, 1 and 2 leaves. */
static void test_mmr_basic_root_structure(int *failures)
{
    printf("mmr: init produces zero root... ");
    {
        struct mmr m;
        mmr_init(&m);
        uint8_t root[32];
        mmr_root(&m, root);
        uint8_t zero[32] = {0};
        bool ok = (m.num_leaves == 0 && m.num_peaks == 0 &&
                   memcmp(root, zero, 32) == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}

/* Verifies peak counts for 3 leaves and for power-of-two leaf counts. */
static void test_mmr_peak_counts(int *failures)
{
    printf("mmr: three leaves produce two peaks... ");
    {
        struct mmr m;
        mmr_init(&m);
        uint8_t blocks[3][32];
        for (int i = 0; i < 3; i++) memset(blocks[i], (uint8_t)(i + 1), 32);
        for (int i = 0; i < 3; i++) mmr_append(&m, blocks[i]);

        bool ok = (m.num_leaves == 3 && m.num_peaks == 2);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}

/* Verifies the plain-block MMR is deterministic and roundtrips through serialization. */
static void test_mmr_determinism_and_roundtrip(int *failures)
{
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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

        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}

/* Verifies SHA3-256 one-shot matches streaming and leaf hashes differ from internal. */
static void test_sha3_and_domain_separation(int *failures)
{
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }

    printf("mmr: domain separation — leaf != internal... ");
    {
        uint8_t data[32];
        memset(data, 0x55, 32);

        uint8_t leaf[32], internal[32];
        mmr_hash_leaf(data, leaf);
        mmr_hash_internal(data, data, internal);

        bool ok = memcmp(leaf, internal, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}

/* Verifies mmr_hash_commitment is deterministic and varies with height and utxo_root. */
static void test_mmr_commitment_hash_properties(int *failures)
{
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}

/* Verifies appending commitments builds a valid, deterministic MMR. */
static void test_mmr_commitment_append_and_determinism(int *failures)
{
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}

/* Verifies a commitment MMR roundtrips through serialization with the same root. */
static void test_mmr_commitment_roundtrip(int *failures)
{
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
    }
}
/* ── Mutation-gap tests: independent reference model and exact encodings ── */

static void ref_leaf_of(int i, uint8_t out[32])
{
    uint8_t bh[32];
    memset(bh, 0, sizeof(bh));
    bh[0] = (uint8_t)i;
    bh[31] = (uint8_t)(i * 7 + 1);
    uint8_t buf[33];
    buf[0] = 0x00;
    memcpy(buf + 1, bh, 32);
    sha3_256(buf, 33, out);
}

static void ref_tree(int first, int size, uint8_t out[32])
{
    if (size == 1) { ref_leaf_of(first, out); return; }
    uint8_t buf[65], l[32], r[32];
    ref_tree(first, size / 2, l);
    ref_tree(first + size / 2, size / 2, r);
    buf[0] = 0x01;
    memcpy(buf + 1, l, 32);
    memcpy(buf + 33, r, 32);
    sha3_256(buf, 65, out);
}

/* Builds the reference peaks for n leaves; returns the peak count. */
static int ref_peaks(int n, uint8_t peaks[][32])
{
    int np = 0, pos = 0;
    for (int bit = 20; bit >= 0; bit--) {
        if (!(n & (1 << bit))) continue;
        ref_tree(pos, 1 << bit, peaks[np++]);
        pos += 1 << bit;
    }
    return np;
}

static void ref_root_of(int np, uint8_t peaks[][32], uint8_t out[32])
{
    if (np == 0) { memset(out, 0, 32); return; }
    if (np == 1) { memcpy(out, peaks[0], 32); return; }
    uint8_t buf[1 + 32 * 8];
    buf[0] = 0x02;
    for (int i = 0; i < np; i++) memcpy(buf + 1 + 32 * i, peaks[i], 32);
    sha3_256(buf, (size_t)(1 + 32 * np), out);
}

static bool mmr_matches_ref(const struct mmr *m, int n)
{
    uint8_t rp[8][32], rr[32], root[32];
    int np = ref_peaks(n, rp);
    if (m->num_leaves != (uint64_t)n || m->num_peaks != (uint32_t)np)
        return false;
    for (int i = 0; i < np; i++)
        if (memcmp(m->peaks[i], rp[i], 32) != 0) return false;
    ref_root_of(np, rp, rr);
    mmr_root(m, root);
    return memcmp(root, rr, 32) == 0;
}

/* Returns the number of trailing 1 bits of v: the merges an append performs. */
static int trailing_ones(uint64_t v)
{
    int c = 0;
    while (v & 1) { c++; v >>= 1; }
    return c;
}

/* Verifies every MMR size 1..70 against a reference model, including merge counts. */
static void test_mmr_reference_model_sweep(int *failures)
{
    printf("mmr: peaks, root and merge count match reference for 1..70 leaves... ");
    struct mmr m;
    mmr_init(&m);
    memset(m.peaks, 0xAA, sizeof(m.peaks));
    bool ok = true;
    for (int i = 0; i < 70 && ok; i++) {
        uint8_t bh[32] = {0};
        bh[0] = (uint8_t)i;
        bh[31] = (uint8_t)(i * 7 + 1);
        int merges = mmr_append(&m, bh);
        ok = merges == trailing_ones((uint64_t)i) && mmr_matches_ref(&m, i + 1);
        /* a leaf push must not write past its own 32-byte peak slot */
        if (i == 0) ok = ok && m.peaks[1][0] == 0xAA;
    }
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}

/* Verifies leaf and internal hashes are exactly SHA3-256 over tag||data. */
static void test_mmr_hash_primitives_exact(int *failures)
{
    printf("mmr: leaf and internal hashes are tag-prefixed SHA3-256... ");
    uint8_t a[32], b[32], got[32], want[32], buf[65];
    for (int i = 0; i < 32; i++) { a[i] = (uint8_t)(i + 1); b[i] = (uint8_t)(0xF0 - i); }
    buf[0] = 0x00;
    memcpy(buf + 1, a, 32);
    sha3_256(buf, 33, want);
    mmr_hash_leaf(a, got);
    bool ok = memcmp(got, want, 32) == 0;
    buf[0] = 0x01;
    memcpy(buf + 1, a, 32);
    memcpy(buf + 33, b, 32);
    sha3_256(buf, 65, want);
    mmr_hash_internal(a, b, got);
    ok = ok && memcmp(got, want, 32) == 0;
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}

/* Verifies mmr_root writes exactly 32 bytes and bags 2 and 64 peaks correctly. */
static void test_mmr_root_exact_cases(int *failures)
{
    printf("mmr: root writes 32 bytes; bags 2 and 64 peaks exactly... ");
    uint8_t out[33];
    struct mmr m;
    mmr_init(&m);
    memset(out, 0xFF, sizeof(out));
    out[32] = 0xAB;
    mmr_root(&m, out);
    uint8_t zero[32] = {0};
    bool ok = memcmp(out, zero, 32) == 0 && out[32] == 0xAB;

    m.num_peaks = 1;
    memset(m.peaks[0], 0x5C, 32);
    memset(out, 0xFF, sizeof(out));
    out[32] = 0xAB;
    mmr_root(&m, out);
    ok = ok && memcmp(out, m.peaks[0], 32) == 0 && out[32] == 0xAB;

    uint8_t buf[1 + 64 * 32], want[32], got[32];
    for (uint32_t np = 2; np <= 64; np += 62) {
        m.num_peaks = np;
        buf[0] = 0x02;
        for (uint32_t i = 0; i < np; i++) {
            memset(m.peaks[i], (int)(i + 1), 32);
            memcpy(buf + 1 + 32 * i, m.peaks[i], 32);
        }
        sha3_256(buf, 1 + 32 * (size_t)np, want);
        mmr_root(&m, got);
        ok = ok && memcmp(got, want, 32) == 0;
    }
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}

/* Verifies the exact serialized layout, size boundary and no write past it. */
static void test_mmr_serialize_exact(int *failures)
{
    printf("mmr: serialize layout, length and bounds are exact... ");
    struct mmr m;
    mmr_init(&m);
    m.num_leaves = 0x1122334455667788ULL;
    m.num_peaks = 3;
    for (int i = 0; i < 3; i++) memset(m.peaks[i], 0x10 + i, 32);
    uint8_t buf[12 + 3 * 32 + 1];
    memset(buf, 0xAA, sizeof(buf));
    size_t n = mmr_serialize(&m, buf, 12 + 96);
    static const uint8_t head[12] = { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                                      0x11, 3, 0, 0, 0 };
    bool ok = n == 108 && memcmp(buf, head, 12) == 0 && buf[108] == 0xAA;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 32; j++) ok = ok && buf[12 + 32 * i + j] == 0x10 + i;
    ok = ok && mmr_serialize(&m, buf, 107) == 0;

    m.num_peaks = 0;
    memset(buf, 0xAA, sizeof(buf));
    n = mmr_serialize(&m, buf, 13);
    ok = ok && n == 12 && buf[12] == 0xAA;
    ok = ok && mmr_serialize(&m, buf, 11) == 0;
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}

static bool deser_accepts(const uint8_t *buf, size_t len)
{
    struct mmr m;
    return mmr_deserialize(&m, buf, len);
}

/* Verifies deserialize rejects short, over-count and truncated input at the exact edges. */
static void test_mmr_deserialize_limits(int *failures)
{
    printf("mmr: deserialize accepts and rejects at exact limits... ");
    static uint8_t buf[12 + 65 * 32 + 8];
    memset(buf, 0, sizeof(buf));
    bool ok = !deser_accepts(buf, 11) && deser_accepts(buf, 12);
    buf[8] = 64;
    ok = ok && deser_accepts(buf, 12 + 64 * 32);
    ok = ok && !deser_accepts(buf, 12 + 64 * 32 - 1);
    buf[8] = 65;
    ok = ok && !deser_accepts(buf, 12 + 65 * 32);
    buf[8] = 1;
    ok = ok && !deser_accepts(buf, 43) && deser_accepts(buf, 44);
    /* high count bytes must count: 2^24 and 2^29 are over the maximum */
    buf[8] = 0; buf[11] = 1;
    ok = ok && !deser_accepts(buf, sizeof(buf));
    buf[11] = 0x20;
    ok = ok && !deser_accepts(buf, sizeof(buf));
    buf[11] = 0; buf[9] = 1;
    ok = ok && !deser_accepts(buf, sizeof(buf));
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}

/* Verifies deserialize decodes little-endian fields, clears the rest, copies only its peaks. */
static void test_mmr_deserialize_decoding(int *failures)
{
    printf("mmr: deserialize decodes fields and resets the rest... ");
    uint8_t buf[12 + 2 * 32 + 1];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(i + 1);
    buf[8] = 2; buf[9] = buf[10] = buf[11] = 0;
    memset(buf + 12, 0x31, 32);
    memset(buf + 44, 0x32, 32);
    buf[76] = 0x77; /* trailing byte beyond the declared peaks */
    struct mmr m;
    memset(&m, 0xFF, sizeof(m));
    bool ok = mmr_deserialize(&m, buf, sizeof(buf));
    ok = ok && m.num_leaves == 0x0807060504030201ULL && m.num_peaks == 2;
    ok = ok && m.peaks[0][31] == 0x31 && m.peaks[1][0] == 0x32 && m.peaks[1][31] == 0x32;
    ok = ok && m.peaks[2][0] == 0 && m.peaks[63][31] == 0;
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}

/* Verifies the commitment leaf is SHA3-256(0x00 || height LE32 || block || utxo || data). */
static void test_mmr_commitment_hash_exact(int *failures)
{
    printf("mmr: commitment leaf hash matches the reference encoding... ");
    struct mmr_commitment c = { .height = 0x01020304 };
    memset(c.block_hash, 0xB1, 32);
    memset(c.utxo_root, 0xC2, 32);
    memset(c.data_root, 0xD3, 32);
    uint8_t buf[1 + 4 + 96], want[32], got[32];
    buf[0] = 0x00;
    buf[1] = 0x04; buf[2] = 0x03; buf[3] = 0x02; buf[4] = 0x01;
    memcpy(buf + 5, c.block_hash, 32);
    memcpy(buf + 37, c.utxo_root, 32);
    memcpy(buf + 69, c.data_root, 32);
    sha3_256(buf, sizeof(buf), want);
    mmr_hash_commitment(&c, got);
    bool ok = memcmp(got, want, 32) == 0;
    struct mmr m;
    mmr_init(&m);
    ok = ok && mmr_append_commitment(&m, &c) == 0 && memcmp(m.peaks[0], want, 32) == 0;
    ok = ok && mmr_append_commitment(&m, &c) == 1 && m.num_peaks == 1;
    if (ok) printf("OK\n"); else { printf("FAIL\n"); (*failures)++; }
}


int test_mmr(void)
{
    int failures = 0;

    test_mmr_basic_root_structure(&failures);
    test_mmr_peak_counts(&failures);
    test_mmr_determinism_and_roundtrip(&failures);
    test_sha3_and_domain_separation(&failures);
    test_mmr_commitment_hash_properties(&failures);
    test_mmr_commitment_append_and_determinism(&failures);
    test_mmr_commitment_roundtrip(&failures);
    test_mmr_reference_model_sweep(&failures);
    test_mmr_hash_primitives_exact(&failures);
    test_mmr_root_exact_cases(&failures);
    test_mmr_serialize_exact(&failures);
    test_mmr_deserialize_limits(&failures);
    test_mmr_deserialize_decoding(&failures);
    test_mmr_commitment_hash_exact(&failures);

    printf("mmr: commitment interval constant defined... ");
    {
        bool ok = (MMR_COMMITMENT_INTERVAL == 100);
        if (ok) printf("OK (every %d blocks)\n", MMR_COMMITMENT_INTERVAL);
        else { printf("FAIL\n"); failures++; }
    }

    printf("\n%d passed, %d failed\n", 16 - failures, failures);
    return failures;
}
