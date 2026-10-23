/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: cap BLOCK_FAILED_CHILD propagation (OOM amplifier). An
 * unguarded BIP30-class stall re-walks the full block_map (~3M entries,
 * ~24 MB scratch + qsort) on every retry.
 *
 * Exercises process_block_propagate_failed_child against a small fixture
 * block_map, asserting the two early returns (SKIP_PARENT_FAILED, see
 * process_block.h) that bound the walk. Guards only; propagation correctness
 * is covered by test_block_scan.c::test_failed_child_propagation.
 */

#include "test/test_core.h"
#include "test/test_block_map.h"
#include "validation/process_block.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include <stdio.h>
#include <string.h>

/* ── Fixture builder ──────────────────────────────────────────────
 * A chain genesis -> h1 -> h2 -> h3 -> h4 of block_index entries in stack
 * memory, inserted into a fresh block_map (phashBlock points into the map's
 * stable bucket). Callers mark failing heights, invoke the helper, and
 * inspect the results. */

#define P146_CHAIN_LEN 5  /* heights 0..4 */

struct p146_fixture {
    struct block_map map;
    struct block_index blocks[P146_CHAIN_LEN];
    struct uint256 hashes[P146_CHAIN_LEN];
};

static void p146_fixture_init(struct p146_fixture *fx)
{
    block_map_init(&fx->map);
    block_map_reserve(&fx->map, P146_CHAIN_LEN);

    for (int h = 0; h < P146_CHAIN_LEN; h++) {
        block_index_init(&fx->blocks[h]);
        fx->blocks[h].nHeight = h;
        fx->blocks[h].pprev = (h == 0) ? NULL : &fx->blocks[h - 1];
        /* Unique per-height hash: 0xA0..0xA4 filled. */
        memset(fx->hashes[h].data, 0xA0 + h, sizeof(fx->hashes[h].data));
        test_block_map_insert(&fx->map, &fx->hashes[h], &fx->blocks[h]);
        /* Option A: phashBlock references stable per-node hashBlock
         * storage (never relocated by a bucket-array grow). */
        fx->blocks[h].hashBlock = fx->hashes[h];
        fx->blocks[h].phashBlock = &fx->blocks[h].hashBlock;
    }
}

static void p146_fixture_free(struct p146_fixture *fx)
{
    block_map_free(&fx->map);
}

/* ── Test 1 — parent already failed → SKIP_PARENT_FAILED ───────── */

static int t_p146_parent_failed_skip(void)
{
    int failures = 0;

    TEST("propagate_failed_child SKIP when pindex_root->pprev already failed") {
        struct p146_fixture fx;
        p146_fixture_init(&fx);

        /* Ancestor at h=1 failed and had already propagated:
         * descendants (h=2,3,4) carry BLOCK_FAILED_CHILD. */
        fx.blocks[1].nStatus |= BLOCK_FAILED_VALID;
        fx.blocks[2].nStatus |= BLOCK_FAILED_CHILD;
        fx.blocks[3].nStatus |= BLOCK_FAILED_CHILD;
        fx.blocks[4].nStatus |= BLOCK_FAILED_CHILD;

        /* pindex_root = h=2 fails on retry; its pprev (h=1) is already in
         * BLOCK_FAILED_MASK, so the map must NOT be walked again. */
        fx.blocks[2].nStatus |= BLOCK_FAILED_VALID;

        size_t propagated = 123;  /* sentinel */
        enum propagate_failed_child_result rv =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[2],
                                                  /*now_sec=*/1000,
                                                  /*last_propagate_sec=*/NULL,
                                                  &propagated);

        ASSERT_EQ(rv, PROPAGATE_FAILED_CHILD_SKIP_PARENT_FAILED);
        /* propagated_out unchanged on SKIP. */
        ASSERT_EQ(propagated, 123u);

        p146_fixture_free(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Test 2 — rate-limited second call within interval ──────────── */

static int t_p146_rate_limit_second_call(void)
{
    int failures = 0;

    TEST("propagate_failed_child rate-limits rapid re-calls") {
        struct p146_fixture fx;
        p146_fixture_init(&fx);

        /* Fresh failure at h=3; pprev (h=2) is clean. */
        fx.blocks[3].nStatus |= BLOCK_FAILED_VALID;

        time_t last = 0;  /* fresh window */
        size_t propagated = 0;

        /* First call: runs the walk, stamps last = now. */
        enum propagate_failed_child_result rv1 =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[3],
                                                  /*now_sec=*/1000,
                                                  &last, &propagated);
        ASSERT_EQ(rv1, PROPAGATE_FAILED_CHILD_OK);
        ASSERT_EQ(propagated, 1u);         /* only h=4 is a descendant */
        ASSERT_EQ((int64_t)last, 1000);    /* stamp updated */

        /* Second call 1 second later: must be rate-limited. */
        propagated = 999;  /* sentinel */
        enum propagate_failed_child_result rv2 =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[3],
                                                  /*now_sec=*/1001,
                                                  &last, &propagated);
        ASSERT_EQ(rv2, PROPAGATE_FAILED_CHILD_SKIP_RATE_LIMITED);
        ASSERT_EQ(propagated, 999u);       /* unchanged on SKIP */
        ASSERT_EQ((int64_t)last, 1000);    /* stamp unchanged */

        /* After the interval elapses: walk runs again. */
        time_t t3 = 1000 + PROPAGATE_FAILED_CHILD_MIN_INTERVAL_SEC;
        enum propagate_failed_child_result rv3 =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[3],
                                                  t3, &last, &propagated);
        ASSERT_EQ(rv3, PROPAGATE_FAILED_CHILD_OK);
        ASSERT_EQ((int64_t)last, (int64_t)t3);

        p146_fixture_free(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Test 3 — control: fresh failure with clean parent propagates ── */

static int t_p146_fresh_failure_propagates(void)
{
    int failures = 0;

    TEST("propagate_failed_child walks map when pprev is clean") {
        struct p146_fixture fx;
        p146_fixture_init(&fx);

        /* pindex_root = h=1 fails fresh; pprev (h=0 / genesis) clean. */
        fx.blocks[1].nStatus |= BLOCK_FAILED_VALID;

        size_t propagated = 0;
        enum propagate_failed_child_result rv =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[1],
                                                  /*now_sec=*/1000,
                                                  /*last_propagate_sec=*/NULL,
                                                  &propagated);
        ASSERT_EQ(rv, PROPAGATE_FAILED_CHILD_OK);
        /* Descendants at h=2,3,4 should now carry BLOCK_FAILED_CHILD. */
        ASSERT_EQ(propagated, 3u);
        ASSERT((fx.blocks[2].nStatus & BLOCK_FAILED_CHILD) != 0);
        ASSERT((fx.blocks[3].nStatus & BLOCK_FAILED_CHILD) != 0);
        ASSERT((fx.blocks[4].nStatus & BLOCK_FAILED_CHILD) != 0);
        /* Genesis must stay clean — it's an ancestor, not a descendant. */
        ASSERT_EQ((int)(fx.blocks[0].nStatus & BLOCK_FAILED_MASK), 0);

        p146_fixture_free(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Test 4 — NULL rate-limit pointer bypasses the interval ─────── */

static int t_p146_null_rate_limit_bypasses(void)
{
    int failures = 0;

    TEST("propagate_failed_child with NULL last_propagate_sec always walks") {
        struct p146_fixture fx;
        p146_fixture_init(&fx);

        fx.blocks[3].nStatus |= BLOCK_FAILED_VALID;

        /* Two back-to-back calls with NULL must both run the walk
         * (tests + explicit flush paths rely on this). */
        size_t propagated = 0;
        enum propagate_failed_child_result rv1 =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[3],
                                                  /*now_sec=*/1000,
                                                  /*last_propagate_sec=*/NULL,
                                                  &propagated);
        ASSERT_EQ(rv1, PROPAGATE_FAILED_CHILD_OK);

        enum propagate_failed_child_result rv2 =
            process_block_propagate_failed_child(&fx.map, &fx.blocks[3],
                                                  /*now_sec=*/1001,
                                                  /*last_propagate_sec=*/NULL,
                                                  &propagated);
        ASSERT_EQ(rv2, PROPAGATE_FAILED_CHILD_OK);

        p146_fixture_free(&fx);
        PASS();
    } _test_next:;
    return failures;
}

int test_failed_child_cap(void);

int test_failed_child_cap(void)
{
    printf("\n=== BLOCK_FAILED_CHILD propagation cap ===\n");
    int failures = 0;
    failures += t_p146_parent_failed_skip();
    failures += t_p146_rate_limit_second_call();
    failures += t_p146_fresh_failure_propagates();
    failures += t_p146_null_rate_limit_bypasses();
    return failures;
}
