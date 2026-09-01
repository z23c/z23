#include "zpq/zpq.h"

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

static int cmp_int_ptr(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    long va = *(const long *)a, vb = *(const long *)b;
    return (va > vb) - (va < vb);
}

static void test_basic(void)
{
    long vals[] = {5, 1, 9, 3, 7, 2, 8};
    zpq *pq = zpq_create(cmp_int_ptr, NULL, (zpq_alloc){0});
    CHECK(pq != NULL);
    CHECK(zpq_len(pq) == 0);
    CHECK(zpq_peek(pq) == NULL);
    CHECK(zpq_pop(pq) == NULL);

    for (size_t i = 0; i < 7; i++) CHECK(zpq_push(pq, &vals[i]));
    CHECK(zpq_len(pq) == 7);
    CHECK(*(long *)zpq_peek(pq) == 1);

    long prev = -1;
    while (zpq_len(pq) > 0) {
        long v = *(long *)zpq_pop(pq);
        CHECK(v > prev);
        prev = v;
    }
    CHECK(prev == 9);
    zpq_destroy(pq);
    zpq_destroy(NULL);

    /* NULL tolerance. */
    CHECK(zpq_len(NULL) == 0);
    CHECK(zpq_peek(NULL) == NULL);
    CHECK(!zpq_push(NULL, &vals[0]));
    CHECK(zpq_pop(NULL) == NULL);
    CHECK(zpq_replace(NULL, &vals[0]) == NULL);
    CHECK(zpq_create(NULL, NULL, (zpq_alloc){0}) == NULL);
}

static void test_from_and_replace(void)
{
    long vals[] = {42, 17, 99, 3, 55, 8, 71, 23};
    void *items[8];
    for (int i = 0; i < 8; i++) items[i] = &vals[i];

    zpq *pq = zpq_from(items, 8, cmp_int_ptr, NULL, (zpq_alloc){0});
    CHECK(pq != NULL);
    CHECK(zpq_len(pq) == 8);
    CHECK(*(long *)zpq_peek(pq) == 3);

    /* Replace the minimum. */
    long newv = 100;
    CHECK(*(long *)zpq_replace(pq, &newv) == 3);
    CHECK(*(long *)zpq_peek(pq) == 8);
    CHECK(zpq_len(pq) == 8);

    /* Drain must be sorted. */
    long prev = -1;
    size_t n = 0;
    void *p;
    while ((p = zpq_pop(pq)) != NULL) {
        long v = *(long *)p;
        CHECK(v > prev);
        prev = v;
        n++;
    }
    CHECK(n == 8 && prev == 100);
    zpq_destroy(pq);

    /* Empty-from. */
    zpq *e = zpq_from(NULL, 0, cmp_int_ptr, NULL, (zpq_alloc){0});
    CHECK(e != NULL && zpq_len(e) == 0);
    zpq_destroy(e);
}

/* Counting allocator with a failure switch. */
struct test_alloc {
    size_t mallocs, frees;
    size_t fail_after;
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

static void test_alloc_failure(void)
{
    long x = 1;

    /* Struct allocation fails. */
    {
        struct test_alloc t = { 0, 0, 0 };
        zpq_alloc a = { ta_malloc, ta_free, &t };
        CHECK(zpq_create(cmp_int_ptr, NULL, a) == NULL);
    }

    /* Grow allocation fails: heap unchanged, recovers after. */
    {
        struct test_alloc t = { 0, 0, SIZE_MAX };
        zpq_alloc a = { ta_malloc, ta_free, &t };
        zpq *pq = zpq_create(cmp_int_ptr, NULL, a);
        CHECK(pq != NULL);
        for (int i = 0; i < 8; i++) CHECK(zpq_push(pq, &x));
        CHECK(zpq_len(pq) == 8);
        t.fail_after = t.mallocs; /* next malloc fails */
        CHECK(!zpq_push(pq, &x));
        CHECK(zpq_len(pq) == 8);
        CHECK(zpq_peek(pq) == &x);
        t.fail_after = SIZE_MAX;
        CHECK(zpq_push(pq, &x));
        CHECK(zpq_len(pq) == 9);
        zpq_destroy(pq);
        CHECK(t.mallocs == t.frees);
    }

    /* zpq_from allocation failure. */
    {
        struct test_alloc t = { 0, 0, 1 }; /* struct ok, array fails */
        zpq_alloc a = { ta_malloc, ta_free, &t };
        void *items[2] = { &x, &x };
        CHECK(zpq_from(items, 2, cmp_int_ptr, NULL, a) == NULL);
        CHECK(t.mallocs == t.frees);
    }
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_heapsort_property(void)
{
    /* Push N random values, drain must be non-decreasing; repeat with
     * sizes crossing several growth doublings. */
    static long storage[2048];
    for (size_t n = 0; n <= 1024; n = n ? n * 2 : 1) {
        zpq *pq = zpq_create(cmp_int_ptr, NULL, (zpq_alloc){0});
        CHECK(pq != NULL);
        for (size_t i = 0; i < n; i++) {
            storage[i] = (long)(rng_next() % 1000);
            CHECK(zpq_push(pq, &storage[i]));
        }
        long prev = -1;
        for (size_t i = 0; i < n; i++) {
            long v = *(long *)zpq_pop(pq);
            CHECK(v >= prev);
            prev = v;
        }
        zpq_destroy(pq);
    }

    /* Interleaved push/pop stress: pops always return the live min. */
    for (int trial = 0; trial < 50; trial++) {
        zpq *pq = zpq_create(cmp_int_ptr, NULL, (zpq_alloc){0});
        CHECK(pq != NULL);
        long vals[256];
        bool live[256] = {0};
        size_t n = (size_t)(rng_next() % 200) + 1;
        size_t live_count = 0;
        for (size_t i = 0; i < n; i++) {
            vals[i] = (long)(rng_next() % 10000);
            CHECK(zpq_push(pq, &vals[i]));
            live[i] = true;
            live_count++;
            if (rng_next() % 3 == 0 && zpq_len(pq) > 1) {
                long expected = 10001;
                size_t which = 0;
                for (size_t j = 0; j <= i; j++)
                    if (live[j] && vals[j] < expected) {
                        expected = vals[j];
                        which = j;
                    }
                void *got = zpq_pop(pq);
                CHECK(*(long *)got == expected);
                live[which] = false;
                live_count--;
            }
            CHECK(zpq_len(pq) == live_count);
        }
        long prev = -1;
        void *p;
        while ((p = zpq_pop(pq)) != NULL) {
            CHECK(*(long *)p >= prev);
            prev = *(long *)p;
        }
        zpq_destroy(pq);
    }
}

int main(void)
{
    test_basic();
    test_from_and_replace();
    test_alloc_failure();
    test_heapsort_property();
    puts("test_zpq: all groups passed (basic from allocfail heapproperty)");
    return 0;
}
