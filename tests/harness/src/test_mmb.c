/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Merkle Mountain Belt (MMB) — O(1) append, O(log k) proofs. */

#include "test/test_core.h"
#include "chain/mmb.h"
#include "models/mmb_leaf_store.h"
#include "crypto/sha3.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* Helper: create a test leaf with predictable data */
static void make_test_leaf(struct mmb_leaf *leaf, uint32_t height)
{
    memset(leaf, 0, sizeof(*leaf));
    /* Unique block hash from height */
    sha3_256((const uint8_t *)&height, 4, leaf->block_hash);
    leaf->height = height;
    leaf->timestamp = 1600000000 + height * 75;
    leaf->nBits = 0x1d00ffff;
    /* Sapling root and chain_work derived from height for determinism */
    uint32_t h2 = height + 1000000;
    sha3_256((const uint8_t *)&h2, 4, leaf->sapling_root);
    uint32_t h3 = height + 2000000;
    sha3_256((const uint8_t *)&h3, 4, leaf->chain_work);
}

/* ── Core structure tests ─────────────────────────────────── */

static int test_mmb_init_zero_root(void)
{
    int failures = 0;
    TEST("mmb: init produces zero root") {
        struct mmb m;
        mmb_init(&m);
        uint8_t root[32];
        mmb_root(&m, root);
        uint8_t zeros[32] = {0};
        ASSERT(memcmp(root, zeros, 32) == 0);
        ASSERT(m.num_leaves == 0);
        ASSERT(m.num_mountains == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_single_leaf(void)
{
    int failures = 0;
    TEST("mmb: single leaf root equals leaf hash") {
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;
        make_test_leaf(&leaf, 1);
        mmb_append(&m, &leaf);

        uint8_t root[32], expected[32];
        mmb_root(&m, root);
        mmb_hash_leaf(&leaf, expected);
        ASSERT(memcmp(root, expected, 32) == 0);
        ASSERT(m.num_leaves == 1);
        ASSERT(m.num_mountains == 1);
        ASSERT(m.mountains[0].height == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_two_leaves_merge(void)
{
    int failures = 0;
    TEST("mmb: two leaves merge into height-1 mountain") {
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;
        make_test_leaf(&leaf, 1);
        int merges1 = mmb_append(&m, &leaf);
        ASSERT(merges1 == 0);

        make_test_leaf(&leaf, 2);
        int merges2 = mmb_append(&m, &leaf);
        ASSERT(merges2 == 1);  /* should merge the two height-0 mountains */
        ASSERT(m.num_mountains == 1);
        ASSERT(m.mountains[0].height == 1);
        ASSERT(m.num_leaves == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_three_leaves(void)
{
    int failures = 0;
    TEST("mmb: three leaves produce 2 peaks (lazy merge)") {
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;
        for (int i = 1; i <= 3; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m, &leaf);
        }
        /* After 3 leaves with lazy merging:
         * Append 1: [h0]
         * Append 2: [h0, h0] → merge → [h1]
         * Append 3: [h1, h0] → no merge (different heights)
         * Result: 2 mountains */
        ASSERT(m.num_mountains == 2);
        ASSERT(m.mountains[0].height == 1);
        ASSERT(m.mountains[1].height == 0);
        ASSERT(m.num_leaves == 3);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_power_of_two(void)
{
    int failures = 0;
    TEST("mmb: power-of-two leaves converge to few peaks") {
        /* With lazy merging (max 2 merges per append: rightmost + deferred),
         * the structure stays compact. 4 leaves should produce ≤2 peaks. */
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;
        for (int i = 1; i <= 4; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m, &leaf);
        }
        ASSERT(m.num_mountains <= 2);
        ASSERT(m.num_leaves == 4);

        /* After 8 leaves: should have ≤3 peaks */
        for (int i = 5; i <= 8; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m, &leaf);
        }
        ASSERT(m.num_mountains <= 3);
        ASSERT(m.num_leaves == 8);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_o1_append(void)
{
    int failures = 0;
    TEST("mmb: O(1) append — at most 2 merges per append") {
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;

        /* Append 10000 leaves, verify each append does ≤2 merges
         * (1 rightmost + 1 deferred = O(1) hash operations) */
        for (int i = 1; i <= 10000; i++) {
            make_test_leaf(&leaf, i);
            int merges = mmb_append(&m, &leaf);
            ASSERT(merges >= 0 && merges <= 2);
        }
        ASSERT(m.num_leaves == 10000);
        /* Mountains should be O(log n) — well under 64 */
        ASSERT(m.num_mountains <= 30);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_deterministic(void)
{
    int failures = 0;
    TEST("mmb: deterministic — same inputs same root") {
        struct mmb m1, m2;
        mmb_init(&m1);
        mmb_init(&m2);
        struct mmb_leaf leaf;
        for (int i = 1; i <= 100; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m1, &leaf);
            mmb_append(&m2, &leaf);
        }
        uint8_t root1[32], root2[32];
        mmb_root(&m1, root1);
        mmb_root(&m2, root2);
        ASSERT(memcmp(root1, root2, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_serialize_roundtrip(void)
{
    int failures = 0;
    TEST("mmb: serialize/deserialize roundtrip") {
        struct mmb m1;
        mmb_init(&m1);
        struct mmb_leaf leaf;
        for (int i = 1; i <= 50; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m1, &leaf);
        }

        uint8_t buf[MMB_SERIALIZED_MAX];
        size_t sz = mmb_serialize(&m1, buf, sizeof(buf));
        ASSERT(sz > 0);

        struct mmb m2;
        ASSERT(mmb_deserialize(&m2, buf, sz));
        ASSERT(m2.num_leaves == m1.num_leaves);
        ASSERT(m2.num_mountains == m1.num_mountains);

        uint8_t r1[32], r2[32];
        mmb_root(&m1, r1);
        mmb_root(&m2, r2);
        ASSERT(memcmp(r1, r2, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_leaf_store_append_extends_mapped_file(void)
{
    int failures = 0;
    TEST("mmb leaf store: append after reopen extends file") {
        char path[128];
        snprintf(path, sizeof(path), "/tmp/zcl_mmb_leaf_store_%d.dat",
                 (int)getpid());
        unlink(path);

        uint8_t first[32], second[32];
        memset(first, 0x11, sizeof(first));
        memset(second, 0x22, sizeof(second));

        struct mmb_leaf_store store;
        ASSERT(mmb_leaf_store_open(&store, path));
        ASSERT(mmb_leaf_store_append(&store, first));
        mmb_leaf_store_close(&store);

        ASSERT(mmb_leaf_store_open(&store, path));
        ASSERT(store.num_leaves == 1);
        ASSERT(mmb_leaf_store_get(&store, 0) != NULL);
        ASSERT(memcmp(mmb_leaf_store_get(&store, 0), first, 32) == 0);

        ASSERT(mmb_leaf_store_append(&store, second));
        ASSERT(mmb_leaf_store_remap(&store));
        ASSERT(store.num_leaves == 2);
        ASSERT(memcmp(mmb_leaf_store_get(&store, 0), first, 32) == 0);
        ASSERT(memcmp(mmb_leaf_store_get(&store, 1), second, 32) == 0);

        mmb_leaf_store_close(&store);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Rich leaf tests ──────────────────────────────────────── */

static int test_mmb_leaf_deterministic(void)
{
    int failures = 0;
    TEST("mmb: rich leaf hash is deterministic") {
        struct mmb_leaf leaf;
        make_test_leaf(&leaf, 42);
        uint8_t h1[32], h2[32];
        mmb_hash_leaf(&leaf, h1);
        mmb_hash_leaf(&leaf, h2);
        ASSERT(memcmp(h1, h2, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_leaf_height_sensitive(void)
{
    int failures = 0;
    TEST("mmb: leaf hash changes with height") {
        struct mmb_leaf l1, l2;
        make_test_leaf(&l1, 100);
        l2 = l1;
        l2.height = 101;
        uint8_t h1[32], h2[32];
        mmb_hash_leaf(&l1, h1);
        mmb_hash_leaf(&l2, h2);
        ASSERT(memcmp(h1, h2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_leaf_nbits_sensitive(void)
{
    int failures = 0;
    TEST("mmb: leaf hash changes with nBits") {
        struct mmb_leaf l1, l2;
        make_test_leaf(&l1, 100);
        l2 = l1;
        l2.nBits = 0x1c00ffff;
        uint8_t h1[32], h2[32];
        mmb_hash_leaf(&l1, h1);
        mmb_hash_leaf(&l2, h2);
        ASSERT(memcmp(h1, h2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_leaf_sapling_sensitive(void)
{
    int failures = 0;
    TEST("mmb: leaf hash changes with sapling root") {
        struct mmb_leaf l1, l2;
        make_test_leaf(&l1, 100);
        l2 = l1;
        l2.sapling_root[0] ^= 0xFF;
        uint8_t h1[32], h2[32];
        mmb_hash_leaf(&l1, h1);
        mmb_hash_leaf(&l2, h2);
        ASSERT(memcmp(h1, h2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_leaf_work_sensitive(void)
{
    int failures = 0;
    TEST("mmb: leaf hash changes with chain work") {
        struct mmb_leaf l1, l2;
        make_test_leaf(&l1, 100);
        l2 = l1;
        l2.chain_work[31] ^= 0x01;
        uint8_t h1[32], h2[32];
        mmb_hash_leaf(&l1, h1);
        mmb_hash_leaf(&l2, h2);
        ASSERT(memcmp(h1, h2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_domain_separation(void)
{
    int failures = 0;
    TEST("mmb: domain separation — leaf hash ≠ internal hash") {
        struct mmb_leaf leaf;
        make_test_leaf(&leaf, 1);
        uint8_t lh[32];
        mmb_hash_leaf(&leaf, lh);

        /* Internal hash of the same 32 bytes should differ */
        uint8_t ih[32];
        mmb_hash_internal(lh, lh, ih);
        ASSERT(memcmp(lh, ih, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Proof tests ──────────────────────────────────────────── */

static int test_mmb_prove_verify_first(void)
{
    int failures = 0;
    TEST("mmb: prove + verify leaf 0") {
        int n = 16;
        uint8_t hashes[16][32];
        struct mmb m;
        mmb_init(&m);
        for (int i = 0; i < n; i++) {
            struct mmb_leaf leaf;
            make_test_leaf(&leaf, i);
            mmb_hash_leaf(&leaf, hashes[i]);
            mmb_append(&m, &leaf);
        }

        uint8_t root[32];
        mmb_root(&m, root);

        struct mmb_proof proof;
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 0, &proof));
        ASSERT(mmb_verify(&proof, root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_prove_verify_recent(void)
{
    int failures = 0;
    TEST("mmb: prove + verify most recent leaf") {
        int n = 16;
        uint8_t hashes[16][32];
        struct mmb m;
        mmb_init(&m);
        for (int i = 0; i < n; i++) {
            struct mmb_leaf leaf;
            make_test_leaf(&leaf, i);
            mmb_hash_leaf(&leaf, hashes[i]);
            mmb_append(&m, &leaf);
        }

        uint8_t root[32];
        mmb_root(&m, root);

        struct mmb_proof proof;
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, n - 1, &proof));
        ASSERT(mmb_verify(&proof, root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_prove_verify_middle(void)
{
    int failures = 0;
    TEST("mmb: prove + verify middle leaf") {
        int n = 32;
        uint8_t hashes[32][32];
        struct mmb m;
        mmb_init(&m);
        for (int i = 0; i < n; i++) {
            struct mmb_leaf leaf;
            make_test_leaf(&leaf, i);
            mmb_hash_leaf(&leaf, hashes[i]);
            mmb_append(&m, &leaf);
        }

        uint8_t root[32];
        mmb_root(&m, root);

        struct mmb_proof proof;
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 15, &proof));
        ASSERT(mmb_verify(&proof, root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_reject_tampered_proof(void)
{
    int failures = 0;
    TEST("mmb: verify rejects tampered proof") {
        int n = 16;
        uint8_t hashes[16][32];
        struct mmb m;
        mmb_init(&m);
        for (int i = 0; i < n; i++) {
            struct mmb_leaf leaf;
            make_test_leaf(&leaf, i);
            mmb_hash_leaf(&leaf, hashes[i]);
            mmb_append(&m, &leaf);
        }

        uint8_t root[32];
        mmb_root(&m, root);

        struct mmb_proof proof;
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 5, &proof));
        ASSERT(mmb_verify(&proof, root));

        /* Tamper with a sibling */
        if (proof.num_siblings > 0)
            proof.siblings[0][0] ^= 0xFF;
        ASSERT(!mmb_verify(&proof, root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_reject_wrong_root(void)
{
    int failures = 0;
    TEST("mmb: verify rejects wrong root") {
        int n = 8;
        uint8_t hashes[8][32];
        struct mmb m;
        mmb_init(&m);
        for (int i = 0; i < n; i++) {
            struct mmb_leaf leaf;
            make_test_leaf(&leaf, i);
            mmb_hash_leaf(&leaf, hashes[i]);
            mmb_append(&m, &leaf);
        }

        uint8_t root[32];
        mmb_root(&m, root);

        struct mmb_proof proof;
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 3, &proof));

        /* Wrong root */
        uint8_t bad_root[32];
        memset(bad_root, 0xAA, 32);
        ASSERT(!mmb_verify(&proof, bad_root));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Scale tests ──────────────────────────────────────────── */

static int test_mmb_1000_leaves(void)
{
    int failures = 0;
    TEST("mmb: 1000 leaves builds valid structure") {
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;
        for (int i = 0; i < 1000; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m, &leaf);
        }
        ASSERT(m.num_leaves == 1000);
        ASSERT(m.num_mountains > 0);
        ASSERT(m.num_mountains <= 20); /* O(log n) ≈ 10 */

        uint8_t root[32];
        mmb_root(&m, root);
        uint8_t zeros[32] = {0};
        ASSERT(memcmp(root, zeros, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_root_changes(void)
{
    int failures = 0;
    TEST("mmb: root changes on every append") {
        struct mmb m;
        mmb_init(&m);
        uint8_t prev_root[32] = {0};
        struct mmb_leaf leaf;
        for (int i = 0; i < 100; i++) {
            make_test_leaf(&leaf, i);
            mmb_append(&m, &leaf);
            uint8_t root[32];
            mmb_root(&m, root);
            ASSERT(memcmp(root, prev_root, 32) != 0);
            memcpy(prev_root, root, 32);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_lazy_never_cascades(void)
{
    int failures = 0;
    TEST("mmb: lazy merging bounded (max 2 merges per append)") {
        struct mmb m;
        mmb_init(&m);
        struct mmb_leaf leaf;
        int max_merges = 0;
        for (int i = 0; i < 100000; i++) {
            make_test_leaf(&leaf, i);
            int merges = mmb_append(&m, &leaf);
            if (merges > max_merges) max_merges = merges;
            ASSERT(merges <= 2);
        }
        /* Verify we actually did merges */
        ASSERT(max_merges >= 1);
        /* Verify mountains stay bounded O(log n) */
        ASSERT(m.num_mountains <= 25);
        PASS();
    } _test_next:;
    return failures;
}

/* ── MMB_MAX_HEIGHT deserialize + merge-guard tests ────── */

/* Helper: craft a serialized MMB blob with one mountain at a chosen height */
static size_t craft_mmb_blob(uint8_t *buf, size_t buflen,
                             uint64_t num_leaves, uint32_t mountain_height)
{
    /* version(1) + num_leaves(8) + num_mountains(4) + peak(32) + height(4) */
    const size_t needed = 1 + 8 + 4 + 36;
    if (buflen < needed) return 0;
    size_t pos = 0;
    buf[pos++] = 0x01;  /* version */
    /* num_leaves LE */
    for (int i = 0; i < 8; i++) { buf[pos++] = (uint8_t)(num_leaves >> (8 * i)); }
    /* num_mountains LE = 1 */
    buf[pos++] = 1; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;
    /* peak: 32 bytes of 0xAA */
    memset(buf + pos, 0xAA, 32); pos += 32;
    /* height LE */
    for (int i = 0; i < 4; i++) { buf[pos++] = (uint8_t)(mountain_height >> (8 * i)); }
    return pos;
}

static int test_mmb_deserialize_rejects_oversize_height(void)
{
    int failures = 0;
    TEST("mmb : deserialize rejects mountain height > MMB_MAX_HEIGHT") {
        uint8_t buf[64];
        size_t sz = craft_mmb_blob(buf, sizeof(buf), 1, MMB_MAX_HEIGHT + 1);
        ASSERT(sz > 0);

        struct mmb m;
        ASSERT(!mmb_deserialize(&m, buf, sz));
        /* State must have been cleared, not left in a poisoned half-state. */
        ASSERT(m.num_mountains == 0);
        ASSERT(m.num_leaves == 0);

        /* Also reject the extreme wraparound value. */
        sz = craft_mmb_blob(buf, sizeof(buf), 1, UINT32_MAX);
        ASSERT(sz > 0);
        ASSERT(!mmb_deserialize(&m, buf, sz));
        ASSERT(m.num_mountains == 0);

        /* And one-over-the-cap is rejected. */
        sz = craft_mmb_blob(buf, sizeof(buf), 1, MMB_MAX_HEIGHT);
        ASSERT(sz > 0);
        ASSERT(mmb_deserialize(&m, buf, sz));  /* exact cap value is legal */
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_deserialize_real_chain_under_cap(void)
{
    int failures = 0;
    TEST("mmb : real-chain round-trip stays well below MMB_MAX_HEIGHT") {
        /* Build a realistic MMB — 8192 leaves exercises the same merge
         * logic mainnet runs at 3M+ blocks (log2 scales identically). */
        struct mmb m1;
        mmb_init(&m1);
        struct mmb_leaf leaf;
        for (int i = 0; i < 8192; i++) {
            make_test_leaf(&leaf, i);
            ASSERT(mmb_append(&m1, &leaf) >= 0);
        }
        /* No mountain should be anywhere near the cap. */
        for (uint32_t i = 0; i < m1.num_mountains; i++)
            ASSERT(m1.mountains[i].height < MMB_MAX_HEIGHT);

        uint8_t buf[MMB_SERIALIZED_MAX];
        size_t sz = mmb_serialize(&m1, buf, sizeof(buf));
        ASSERT(sz > 0);

        struct mmb m2;
        ASSERT(mmb_deserialize(&m2, buf, sz));
        ASSERT(m2.num_leaves == m1.num_leaves);
        ASSERT(m2.num_mountains == m1.num_mountains);
        uint8_t r1[32], r2[32];
        mmb_root(&m1, r1);
        mmb_root(&m2, r2);
        ASSERT(memcmp(r1, r2, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_merge_guard_blocks_wraparound(void)
{
    int failures = 0;
    TEST("mmb : merge guard fires before height wraparound") {
        /* Construct a corrupt in-memory MMB with two height=UINT32_MAX-1
         * mountains (bypassing mmb_deserialize's cap). A 
         * mmb_append would have wrapped height to UINT32_MAX then 0,
         * silently destroying the trust root on the next merge. */
        struct mmb m;
        mmb_init(&m);
        m.num_leaves = 2;
        m.num_mountains = 2;
        memset(m.mountains[0].peak, 0x11, 32);
        memset(m.mountains[1].peak, 0x22, 32);
        m.mountains[0].height = UINT32_MAX - 1;
        m.mountains[1].height = UINT32_MAX - 1;

        /* Snapshot pre-call state so we can assert nothing mutated. */
        uint8_t peak0_before[32], peak1_before[32];
        memcpy(peak0_before, m.mountains[0].peak, 32);
        memcpy(peak1_before, m.mountains[1].peak, 32);

        /* Append a fresh leaf — the deferred-merge scan will try to
         * collapse the two UINT32_MAX-1 peaks. Guard must fire. */
        struct mmb_leaf leaf;
        make_test_leaf(&leaf, 999);
        int rc = mmb_append(&m, &leaf);
        ASSERT(rc < 0);  /* refused */

        /* Guard fired after the rightmost-pair merge decision (which
         * is a no-op here since idx 1 and 2 have different heights)
         * but before the deferred-merge mutation of the dangerous
         * pair. mountains[0]/[1] must be intact. */
        ASSERT(m.mountains[0].height == UINT32_MAX - 1);
        ASSERT(m.mountains[1].height == UINT32_MAX - 1);
        ASSERT(memcmp(m.mountains[0].peak, peak0_before, 32) == 0);
        ASSERT(memcmp(m.mountains[1].peak, peak1_before, 32) == 0);

        /* Same test, but with the dangerous pair as the rightmost
         * pair so the rightmost-merge branch of the guard fires. */
        mmb_init(&m);
        m.num_leaves = 2;
        m.num_mountains = 2;
        memset(m.mountains[0].peak, 0x33, 32);
        memset(m.mountains[1].peak, 0x44, 32);
        m.mountains[0].height = MMB_MAX_HEIGHT;
        m.mountains[1].height = MMB_MAX_HEIGHT;
        memcpy(peak0_before, m.mountains[0].peak, 32);
        memcpy(peak1_before, m.mountains[1].peak, 32);
        /* Swap in a trick: give the rightmost pair the dangerous
         * height by pre-seeding then calling mmb_append — the new
         * height-0 leaf goes to idx 2, rightmost-pair check compares
         * idx 1 (MMB_MAX_HEIGHT) vs idx 2 (0) and does not fire.
         * Then the deferred scan finds idx 0/1 at the cap and trips
         * the guard there. Either way: guard fires + state intact. */
        make_test_leaf(&leaf, 1001);
        rc = mmb_append(&m, &leaf);
        ASSERT(rc < 0);
        ASSERT(m.mountains[0].height == MMB_MAX_HEIGHT);
        ASSERT(m.mountains[1].height == MMB_MAX_HEIGHT);
        ASSERT(memcmp(m.mountains[0].peak, peak0_before, 32) == 0);
        ASSERT(memcmp(m.mountains[1].peak, peak1_before, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mmb_leaf_from_block(void)
{
    int failures = 0;
    TEST("mmb: mmb_leaf_from_block builds correct leaf") {
        uint8_t hash[32], sapling[32], work[32], uroot[32];
        memset(hash, 0xAA, 32);
        memset(sapling, 0xBB, 32);
        memset(work, 0xCC, 32);
        memset(uroot, 0xDD, 32);

        struct mmb_leaf leaf;
        mmb_leaf_from_block(&leaf, hash, 100, 1600000000, 0x1d00ffff,
                            sapling, work, uroot);
        ASSERT(memcmp(leaf.block_hash, hash, 32) == 0);
        ASSERT(leaf.height == 100);
        ASSERT(leaf.timestamp == 1600000000);
        ASSERT(leaf.nBits == 0x1d00ffff);
        ASSERT(memcmp(leaf.sapling_root, sapling, 32) == 0);
        ASSERT(memcmp(leaf.chain_work, work, 32) == 0);
        ASSERT(memcmp(leaf.utxo_root, uroot, 32) == 0);

        /* NULL utxo_root → zero sentinel (the non-boundary case). */
        struct mmb_leaf leaf2;
        mmb_leaf_from_block(&leaf2, hash, 100, 1600000000, 0x1d00ffff,
                            sapling, work, NULL);
        uint8_t zeros[32] = {0};
        ASSERT(memcmp(leaf2.utxo_root, zeros, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The auxiliary field MUST be folded into the leaf preimage — a leaf that
 * differs ONLY in utxo_root must hash differently, or its byte-integrity
 * signal is inert. This does not make it a ZClassic-header commitment. */
static int test_mmb_leaf_utxo_root_sensitive(void)
{
    int failures = 0;
    TEST("mmb: leaf hash changes with auxiliary utxo_root") {
        struct mmb_leaf l1, l2;
        make_test_leaf(&l1, 100);
        memset(l1.utxo_root, 0, 32);
        l2 = l1;
        l2.utxo_root[0] = 0x01;
        uint8_t h1[32], h2[32];
        mmb_hash_leaf(&l1, h1);
        mmb_hash_leaf(&l2, h2);
        ASSERT(memcmp(h1, h2, 32) != 0);

        /* Flip a different byte → still distinct from both. */
        struct mmb_leaf l3 = l1;
        l3.utxo_root[31] = 0xFF;
        uint8_t h3[32];
        mmb_hash_leaf(&l3, h3);
        ASSERT(memcmp(h3, h1, 32) != 0);
        ASSERT(memcmp(h3, h2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The preimage is exactly 140 bytes (108 metadata + 32 utxo_root). Lock it
 * so a future field add cannot silently change every persisted leaf hash. */
static int test_mmb_leaf_preimage_size(void)
{
    int failures = 0;
    TEST("mmb: leaf preimage is 140 bytes (utxo_root included)") {
        ASSERT(MMB_LEAF_PREIMAGE_SIZE == 140);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ──────────────────────────────────────────── */

int test_mmb(void)
{
    int failures = 0;

    /* Core structure */
    failures += test_mmb_init_zero_root();
    failures += test_mmb_single_leaf();
    failures += test_mmb_two_leaves_merge();
    failures += test_mmb_three_leaves();
    failures += test_mmb_power_of_two();
    failures += test_mmb_o1_append();
    failures += test_mmb_deterministic();
    failures += test_mmb_serialize_roundtrip();
    failures += test_mmb_leaf_store_append_extends_mapped_file();

    /* Rich leaf */
    failures += test_mmb_leaf_deterministic();
    failures += test_mmb_leaf_height_sensitive();
    failures += test_mmb_leaf_nbits_sensitive();
    failures += test_mmb_leaf_sapling_sensitive();
    failures += test_mmb_leaf_work_sensitive();
    failures += test_mmb_domain_separation();
    failures += test_mmb_leaf_from_block();
    failures += test_mmb_leaf_utxo_root_sensitive();
    failures += test_mmb_leaf_preimage_size();

    /* Proofs */
    failures += test_mmb_prove_verify_first();
    failures += test_mmb_prove_verify_recent();
    failures += test_mmb_prove_verify_middle();
    failures += test_mmb_reject_tampered_proof();
    failures += test_mmb_reject_wrong_root();

    /* Scale */
    failures += test_mmb_1000_leaves();
    failures += test_mmb_root_changes();
    failures += test_mmb_lazy_never_cascades();

    /* height cap on deserialize + merge */
    failures += test_mmb_deserialize_rejects_oversize_height();
    failures += test_mmb_deserialize_real_chain_under_cap();
    failures += test_mmb_merge_guard_blocks_wraparound();

    return failures;
}
