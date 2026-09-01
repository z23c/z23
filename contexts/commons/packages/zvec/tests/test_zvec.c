#include "zvec/zvec.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

/* Counting allocator with a failure switch for failure-path tests. */
struct test_alloc {
    size_t mallocs, frees;
    size_t fail_after; /* fail when mallocs reaches this; SIZE_MAX = never */
};
static void *ta_malloc(void *ctx, size_t size)
{
    struct test_alloc *t = ctx;
    if (t->mallocs >= t->fail_after) return NULL;
    t->mallocs++;
    return malloc(size);
}
static void ta_free(void *ctx, void *ptr)
{
    struct test_alloc *t = ctx;
    if (ptr) t->frees++;
    free(ptr);
}
static zvec_alloc ta(struct test_alloc *t, size_t fail_after)
{
    t->mallocs = t->frees = 0;
    t->fail_after = fail_after;
    return (zvec_alloc){ ta_malloc, ta_free, t };
}

static void test_basic(void)
{
    int a = 1, b = 2, c = 3;
    zvec *v = zvec_create((zvec_alloc){0});
    CHECK(v != NULL);
    CHECK(zvec_len(v) == 0);
    CHECK(zvec_pop(v) == NULL);

    CHECK(zvec_push(v, &a));
    CHECK(zvec_push(v, &b));
    CHECK(zvec_push(v, &c));
    CHECK(zvec_len(v) == 3);
    CHECK(zvec_get(v, 0) == &a);
    CHECK(zvec_get(v, 2) == &c);
    CHECK(zvec_get(v, 3) == NULL);
    CHECK(zvec_get(v, (size_t)-1) == NULL);

    CHECK(zvec_set(v, 1, &a) == &b);
    CHECK(zvec_get(v, 1) == &a);
    CHECK(zvec_set(v, 9, &b) == NULL);

    CHECK(zvec_pop(v) == &c);
    CHECK(zvec_len(v) == 2);
    zvec_destroy(v);
    zvec_destroy(NULL);

    /* NULL-vector tolerance. */
    CHECK(zvec_len(NULL) == 0);
    CHECK(zvec_capacity(NULL) == 0);
    CHECK(zvec_get(NULL, 0) == NULL);
    CHECK(!zvec_push(NULL, &a));
    CHECK(zvec_pop(NULL) == NULL);
    CHECK(!zvec_insert(NULL, 0, &a));
    CHECK(zvec_remove(NULL, 0) == NULL);
    CHECK(zvec_swap_remove(NULL, 0) == NULL);
    zvec_clear(NULL);
    CHECK(!zvec_shrink_to_fit(NULL));
    CHECK(zvec_index_of(NULL, &a) == -1);
}

static void test_insert_remove(void)
{
    int vals[5] = {0, 1, 2, 3, 4};
    zvec *v = zvec_create((zvec_alloc){0});
    for (int i = 0; i < 5; i++) CHECK(zvec_push(v, &vals[i]));

    /* Insert middle/front/back. */
    int x = 99;
    CHECK(zvec_insert(v, 2, &x));
    CHECK(zvec_len(v) == 6);
    CHECK(zvec_get(v, 2) == &x);
    CHECK(zvec_get(v, 3) == &vals[2]);
    CHECK(!zvec_insert(v, 7, &x));
    CHECK(zvec_insert(v, 0, &x));
    CHECK(zvec_insert(v, zvec_len(v), &x)); /* append via insert */

    /* Ordered remove. */
    CHECK(zvec_remove(v, 0) == &x);
    CHECK(zvec_remove(v, 2) == &x);
    CHECK(zvec_get(v, 2) == &vals[2]);
    CHECK(zvec_remove(v, 99) == NULL);

    /* Swap remove. */
    size_t n = zvec_len(v);
    void *last = zvec_get(v, n - 1);
    void *at1 = zvec_get(v, 1);
    CHECK(zvec_swap_remove(v, 1) == at1);
    CHECK(zvec_len(v) == n - 1);
    CHECK(zvec_get(v, 1) == last);

    zvec_clear(v);
    CHECK(zvec_len(v) == 0);
    CHECK(zvec_capacity(v) > 0);
    zvec_destroy(v);
}

static void test_index_of(void)
{
    int a = 1, b = 2;
    zvec *v = zvec_create((zvec_alloc){0});
    CHECK(zvec_index_of(v, &a) == -1);
    CHECK(zvec_push(v, &a));
    CHECK(zvec_push(v, &b));
    CHECK(zvec_push(v, &a));
    CHECK(zvec_index_of(v, &a) == 0); /* first match */
    CHECK(zvec_index_of(v, &b) == 1);
    int z = 3;
    CHECK(zvec_index_of(v, &z) == -1);
    zvec_destroy(v);
}

static void test_alloc_failure(void)
{
    struct test_alloc t;
    int x = 1;

    /* Failure on struct allocation. */
    CHECK(zvec_create(ta(&t, 0)) == NULL);

    /* Failure on first grow: vector unchanged. Flip the switch through
     * the shared allocator context — the vector stays opaque. */
    struct test_alloc t2;
    zvec *v = zvec_create(ta(&t2, SIZE_MAX));
    CHECK(v != NULL);
    t2.fail_after = t2.mallocs; /* next malloc fails */
    CHECK(!zvec_push(v, &x));
    CHECK(zvec_len(v) == 0);
    /* Recovers when allocation works again. */
    t2.fail_after = SIZE_MAX;
    CHECK(zvec_push(v, &x));
    CHECK(zvec_len(v) == 1);
    zvec_destroy(v);

    /* Shrink failure leaves the vector usable. */
    struct test_alloc t3;
    zvec *w = zvec_create(ta(&t3, SIZE_MAX));
    for (int i = 0; i < 33; i++) CHECK(zvec_push(w, &x)); /* cap 64 > len */
    t3.fail_after = t3.mallocs; /* next malloc fails */
    CHECK(!zvec_shrink_to_fit(w));
    CHECK(zvec_len(w) == 33);
    zvec_destroy(w);
}

static void test_growth_and_balance(void)
{
    struct test_alloc t;
    zvec *v = zvec_create(ta(&t, SIZE_MAX));
    int x = 1;
    for (int i = 0; i < 10000; i++) CHECK(zvec_push(v, &x));
    CHECK(zvec_len(v) == 10000);
    for (int i = 0; i < 10000; i++) CHECK(zvec_pop(v) == &x);
    CHECK(zvec_len(v) == 0);
    /* Geometric growth: far fewer allocations than pushes. */
    CHECK(t.mallocs < 30);

    CHECK(zvec_shrink_to_fit(v));
    CHECK(zvec_capacity(v) == 0);
    zvec_destroy(v);

    /* Every allocation is eventually freed exactly once. */
    struct test_alloc t3;
    zvec *w = zvec_with_capacity(4, ta(&t3, SIZE_MAX));
    CHECK(w != NULL && zvec_capacity(w) == 4);
    for (int i = 0; i < 100; i++) CHECK(zvec_push(w, &x));
    CHECK(zvec_shrink_to_fit(w));
    CHECK(zvec_capacity(w) == 100);
    zvec_destroy(w);
    CHECK(t3.mallocs == t3.frees);
}

static void test_stress_vs_model(void)
{
    /* Differential test against a simple open-coded model. */
    zvec *v = zvec_create((zvec_alloc){0});
    long model[4096];
    size_t mlen = 0;
    long storage[4096];
    for (int i = 0; i < 4096; i++) storage[i] = i;

    uint64_t rng = 0x0123456789abcdefull;
    for (int op = 0; op < 20000; op++) {
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        unsigned kind = (unsigned)(rng >> 61); /* top 3 bits */
        size_t idx = mlen ? (size_t)((rng >> 13) % (mlen + 1)) : 0;
        if (mlen >= 4096) kind = 3; /* bounded model: force a pop */
        if (kind <= 2 || mlen == 0) { /* push */
            long *val = &storage[op % 4096];
            CHECK(zvec_push(v, val));
            model[mlen++] = (long)(op % 4096);
        } else if (kind == 3) { /* pop */
            void *got = zvec_pop(v);
            CHECK(got == &storage[model[--mlen]]);
        } else if (kind == 4) { /* insert at idx */
            long *val = &storage[op % 4096];
            CHECK(zvec_insert(v, idx, val));
            memmove(model + idx + 1, model + idx, (mlen - idx) * sizeof(long));
            model[idx] = (long)(op % 4096);
            mlen++;
        } else if (kind == 5) { /* ordered remove */
            void *got = zvec_remove(v, idx % mlen);
            CHECK(got == &storage[model[idx % mlen]]);
            memmove(model + idx % mlen, model + idx % mlen + 1,
                    (mlen - idx % mlen - 1) * sizeof(long));
            mlen--;
        } else { /* get/set check */
            size_t gi = idx % mlen;
            CHECK(zvec_get(v, gi) == &storage[model[gi]]);
        }
        CHECK(zvec_len(v) == mlen);
    }
    zvec_destroy(v);
}

int main(void)
{
    test_basic();
    test_insert_remove();
    test_index_of();
    test_alloc_failure();
    test_growth_and_balance();
    test_stress_vs_model();
    puts("test_zvec: all groups passed (basic insert index allocfail growth stress)");
    return 0;
}
