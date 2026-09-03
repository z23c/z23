/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "util/pprev_walk.h"
#include "chain/chain.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static struct block_index *bi_new(int height)
{
    struct block_index *bi = calloc(1, sizeof(*bi));
    block_index_init(bi);
    bi->nHeight = height;
    return bi;
}

/* ── pprev_walk_safe itself ────────────────────────────────────────────
 *
 * The wrappers above all route through pprev_walk_safe, but the walker
 * itself was never called directly. Pinned: bad arguments refuse with
 * NULL and no violation record, the predicate stops the walk exactly at
 * the node it rejects, a NULL predicate walks to the chain end, and a
 * cycle refuses with a violation recorded. Violations are process-global,
 * so each case reads the counter before and after. One function per TEST,
 * as the harness's hardcoded `goto _test_next` requires. */
static int t_pprev_walk_safe_refusals(void)
{
    int failures = 0;
    TEST("pprev_walk_safe: NULL start and non-positive cap refuse, no violation") {
        uint64_t v0 = pprev_walk_violations();
        ASSERT(pprev_walk_safe(NULL, NULL, NULL, 100, "test.refusal") == NULL);
        struct block_index *a = bi_new(0);
        ASSERT(pprev_walk_safe(a, NULL, NULL, 0, "test.refusal") == NULL);
        ASSERT(pprev_walk_safe(a, NULL, NULL, -1, "test.refusal") == NULL);
        ASSERT(pprev_walk_violations() == v0);
        free(a);
        PASS();
    } _test_next:;
    return failures;
}

/* Stop as soon as height < 3: rejects chain[2], returns it. */
static bool pred_height_at_least_3(const struct block_index *bi, void *user)
{
    (void)user;
    return bi->nHeight >= 3;
}

static int t_pprev_walk_safe_predicate(void)
{
    int failures = 0;
    TEST("pprev_walk_safe: predicate stops at first rejected node, NULL walks to end") {
        struct block_index *chain[4] = {0};
        for (int i = 0; i < 4; i++) {
            chain[i] = bi_new(i);
            if (i > 0) chain[i]->pprev = chain[i - 1];
        }
        ASSERT(pprev_walk_safe(chain[3], NULL, NULL, 100, "test.pred") == chain[0]);
        uint64_t v0 = pprev_walk_violations();
        struct block_index *res = pprev_walk_safe(
            chain[3], pred_height_at_least_3, NULL, 100, "test.pred");
        ASSERT(res == chain[2]);
        ASSERT(pprev_walk_violations() == v0);
        free(chain[0]); free(chain[1]); free(chain[2]); free(chain[3]);
        PASS();
    } _test_next:;
    return failures;
}

static int t_pprev_walk_safe_cycle(void)
{
    int failures = 0;
    TEST("pprev_walk_safe: pprev ring refuses with a recorded violation") {
        struct block_index *a = bi_new(10);
        struct block_index *b = bi_new(11);
        a->pprev = b;
        b->pprev = a;
        uint64_t v0 = pprev_walk_violations();
        ASSERT(pprev_walk_safe(b, NULL, NULL, 100, "test.cycle") == NULL);
        ASSERT(pprev_walk_violations() > v0);
        free(a); free(b);
        PASS();
    } _test_next:;
    return failures;
}

int test_pprev_walk(void)
{
    int failures = 0;

    printf("pprev_walk_safe: normal walk... ");
    {
        struct block_index *a = bi_new(0);
        struct block_index *b = bi_new(1);
        struct block_index *c = bi_new(2);
        struct block_index *d = bi_new(3);
        b->pprev = a;
        c->pprev = b;
        d->pprev = c;
        uint64_t v0 = pprev_walk_violations();
        struct block_index *res =
            pprev_walk_until_height(d, 0, 100, "test.normal");
        if (res == a && pprev_walk_violations() == v0)
            printf("OK\n");
        else {
            printf("FAIL (res=%p expected a=%p violations_delta=%llu)\n",
                   (void *)res, (void *)a,
                   (unsigned long long)(pprev_walk_violations() - v0));
            failures++;
        }
        free(a); free(b); free(c); free(d);
    }

    printf("pprev_walk_safe: cycle detection (A→B→A)... ");
    {
        struct block_index *a = bi_new(10);
        struct block_index *b = bi_new(11);
        a->pprev = b; /* ring */
        b->pprev = a;
        uint64_t v0 = pprev_walk_violations();
        struct block_index *res =
            pprev_walk_until_height(b, 0, 100, "test.cycle");
        if (res == NULL && pprev_walk_violations() > v0)
            printf("OK\n");
        else {
            printf("FAIL (res=%p violations_delta=%llu)\n",
                   (void *)res,
                   (unsigned long long)(pprev_walk_violations() - v0));
            failures++;
        }
        free(a); free(b);
    }

    printf("pprev_walk_safe: step cap enforced... ");
    {
        /* Build a long chain where height monotonicity is fine but
         * we cap below the chain length. */
        struct block_index *chain[10] = {0};
        for (int i = 0; i < 10; i++) {
            chain[i] = bi_new(i);
            if (i > 0) chain[i]->pprev = chain[i - 1];
        }
        uint64_t v0 = pprev_walk_violations();
        struct block_index *res =
            pprev_walk_until_height(chain[9], 0, 3, "test.cap");
        if (res == NULL && pprev_walk_violations() > v0)
            printf("OK\n");
        else {
            printf("FAIL (res=%p violations_delta=%llu)\n",
                   (void *)res,
                   (unsigned long long)(pprev_walk_violations() - v0));
            failures++;
        }
        for (int i = 0; i < 10; i++) free(chain[i]);
    }

    printf("pprev_walk_safe: non-monotonic height detected... ");
    {
        /* Three nodes where the middle has a LOWER height than its
         * prev — heights run 5 → 3 → 7 (broken). */
        struct block_index *a = bi_new(7);
        struct block_index *b = bi_new(3);
        struct block_index *c = bi_new(5);
        c->pprev = b;
        b->pprev = a; /* b at h=3, a at h=7 → a->nHeight > b->nHeight */
        uint64_t v0 = pprev_walk_violations();
        struct block_index *res =
            pprev_walk_until_height(c, 0, 100, "test.non_monotonic");
        if (res == NULL && pprev_walk_violations() > v0)
            printf("OK\n");
        else {
            printf("FAIL (res=%p violations_delta=%llu)\n",
                   (void *)res,
                   (unsigned long long)(pprev_walk_violations() - v0));
            failures++;
        }
        free(a); free(b); free(c);
    }

    printf("pprev_walk_until_target: hit target... ");
    {
        struct block_index *a = bi_new(0);
        struct block_index *b = bi_new(1);
        struct block_index *c = bi_new(2);
        b->pprev = a;
        c->pprev = b;
        struct block_index *res =
            pprev_walk_until_target(c, a, 100, "test.target_hit");
        if (res == a)
            printf("OK\n");
        else {
            printf("FAIL (res=%p expected a=%p)\n",
                   (void *)res, (void *)a);
            failures++;
        }
        free(a); free(b); free(c);
    }

    printf("pprev_walk_until_target: target not reachable returns NULL... ");
    {
        struct block_index *a = bi_new(0);
        struct block_index *b = bi_new(1);
        struct block_index *off = bi_new(5);
        b->pprev = a;
        struct block_index *res =
            pprev_walk_until_target(b, off, 100, "test.target_miss");
        if (res == NULL)
            printf("OK\n");
        else {
            printf("FAIL (res=%p expected NULL)\n", (void *)res);
            failures++;
        }
        free(a); free(b); free(off);
    }

    printf("pprev_walk_depth: normal chain returns step count... ");
    {
        struct block_index *chain[5] = {0};
        for (int i = 0; i < 5; i++) {
            chain[i] = bi_new(i);
            if (i > 0) chain[i]->pprev = chain[i - 1];
        }
        struct block_index *root = NULL;
        int depth = pprev_walk_depth(chain[4], 100,
                                      "test.depth", &root);
        if (depth == 4 && root == chain[0])
            printf("OK\n");
        else { printf("FAIL (depth=%d root=%p expected_root=%p)\n",
                      depth, (void*)root, (void*)chain[0]); failures++; }
        for (int i = 0; i < 5; i++) free(chain[i]);
    }

    printf("pprev_walk_depth: cycle returns -1... ");
    {
        struct block_index *a = bi_new(0);
        struct block_index *b = bi_new(1);
        a->pprev = b; b->pprev = a;
        struct block_index *root = NULL;
        int depth = pprev_walk_depth(b, 100, "test.depth_cycle", &root);
        if (depth == -1 && root == NULL)
            printf("OK\n");
        else { printf("FAIL (depth=%d root=%p)\n",
                      depth, (void*)root); failures++; }
        free(a); free(b);
    }

    failures += t_pprev_walk_safe_refusals();
    failures += t_pprev_walk_safe_predicate();
    failures += t_pprev_walk_safe_cycle();

    return failures;
}
