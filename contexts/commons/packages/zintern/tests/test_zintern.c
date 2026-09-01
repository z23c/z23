/* zintern tests: dedup, dense ids, get-without-insert, binary-safe
 * keys, alloc failure, and a randomized differential test against a
 * linear-scan model. */
#include "zintern/zintern.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    ((void)0)

static void test_basic(void)
{
    zintern *p = zintern_create((zintern_alloc){0});
    CHECK(p != NULL);
    uint32_t a = zintern_put(p, "alpha", 5);
    uint32_t b = zintern_put(p, "beta", 4);
    uint32_t a2 = zintern_put(p, "alpha", 5);
    CHECK(a == 0 && b == 1 && a2 == a);
    CHECK(zintern_count(p) == 2);

    size_t n = 0;
    const char *s = zintern_str(p, a, &n);
    CHECK(s && n == 5 && memcmp(s, "alpha", 5) == 0);
    s = zintern_str(p, b, &n);
    CHECK(s && n == 4 && memcmp(s, "beta", 4) == 0);
    CHECK(zintern_str(p, 2, NULL) == NULL);

    CHECK(zintern_get(p, "alpha", 5) == a);
    CHECK(zintern_get(p, "gamma", 5) == UINT32_MAX);
    CHECK(zintern_count(p) == 2); /* get did not insert */
    zintern_destroy(p);
}

static void test_binary_and_empty(void)
{
    zintern *p = zintern_create((zintern_alloc){0});
    CHECK(p != NULL);
    /* empty string is legal and distinct from "\0" */
    uint32_t e = zintern_put(p, "", 0);
    uint32_t z = zintern_put(p, "\0", 1);
    uint32_t zz = zintern_put(p, "\0\0", 2);
    CHECK(e != z && z != zz && e != zz);
    size_t n = 99;
    const char *s = zintern_str(p, e, &n);
    CHECK(s && n == 0);
    s = zintern_str(p, z, &n);
    CHECK(s && n == 1 && s[0] == '\0');
    /* embedded NULs */
    const char bin[] = { 'a', 0, 'b', 0, 'c' };
    uint32_t x = zintern_put(p, bin, sizeof bin);
    CHECK(zintern_get(p, bin, sizeof bin) == x);
    CHECK(zintern_get(p, bin, 3) != x); /* prefix differs */
    zintern_destroy(p);
}

/* alloc injection with a failure counter */
struct alloc_ctl {
    size_t live;
    long fail_after; /* fail when this hits 0; -1 = never */
};

static void *ctl_malloc(void *ctx, size_t n)
{
    struct alloc_ctl *c = ctx;
    if (c->fail_after == 0) return NULL;
    if (c->fail_after > 0) c->fail_after--;
    size_t *m = malloc(n + sizeof(size_t));
    if (!m) return NULL;
    *m = n;
    c->live++;
    return m + 1;
}

static void ctl_free(void *ctx, void *ptr)
{
    struct alloc_ctl *c = ctx;
    if (!ptr) return;
    c->live--;
    free((size_t *)ptr - 1);
}

static void test_alloc_failure(void)
{
    for (long fail_at = 0; fail_at < 40; fail_at++) {
        struct alloc_ctl ctl = { .live = 0, .fail_after = fail_at };
        zintern *p = zintern_create((zintern_alloc){
            ctl_malloc, ctl_free, &ctl });
        if (!p) { CHECK(ctl.live == 0); continue; }
        unsigned ok = 0;
        for (int i = 0; i < 50; i++) {
            char buf[16];
            int bl = snprintf(buf, sizeof buf, "sym%d", i);
            if (zintern_put(p, buf, (size_t)bl) == UINT32_MAX)
                break; /* clean refusal */
            ok++;
        }
        CHECK(ctl.live != (size_t)-1); /* no underflow */
        /* everything interned so far is still retrievable */
        for (unsigned i = 0; i < ok; i++) {
            char buf[16];
            int bl = snprintf(buf, sizeof buf, "sym%u", i);
            uint32_t id = zintern_get(p, buf, (size_t)bl);
            CHECK(id == i);
            size_t n = 0;
            const char *s = zintern_str(p, id, &n);
            CHECK(s && n == (size_t)bl && memcmp(s, buf, n) == 0);
        }
        zintern_destroy(p);
        CHECK(ctl.live == 0); /* no leaks */
    }
}

/* Differential vs linear model with heavy duplication. */
static unsigned long long rng_state;

static unsigned long long rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_differential(void)
{
    rng_state = 0x0123456789ABCDEFull;
    zintern *p = zintern_create((zintern_alloc){0});
    CHECK(p != NULL);

    static char model[2048][12];
    static size_t model_len[2048];
    size_t model_n = 0;

    for (int op = 0; op < 60000; op++) {
        char key[12];
        size_t len = (size_t)(rng_next() % 8); /* short keys, hot set */
        for (size_t i = 0; i < len; i++)
            key[i] = (char)('a' + rng_next() % 6);

        /* model lookup */
        uint32_t mid = UINT32_MAX;
        for (size_t i = 0; i < model_n; i++)
            if (model_len[i] == len && memcmp(model[i], key, len) == 0) {
                mid = (uint32_t)i;
                break;
            }

        if (rng_next() % 3 == 0) {
            /* get (no insert) */
            CHECK(zintern_get(p, key, len) == mid);
        } else {
            if (mid == UINT32_MAX && model_n >= 2048)
                continue; /* model full; stay in get-only space */
            uint32_t id = zintern_put(p, key, len);
            CHECK(id != UINT32_MAX);
            if (mid == UINT32_MAX) {
                CHECK(id == (uint32_t)model_n);
                memcpy(model[model_n], key, len);
                model_len[model_n] = len;
                model_n++;
            } else {
                CHECK(id == mid);
            }
        }
        CHECK(zintern_count(p) == model_n);
    }

    /* full content verification */
    for (size_t i = 0; i < model_n; i++) {
        size_t n = 0;
        const char *s = zintern_str(p, (uint32_t)i, &n);
        CHECK(s && n == model_len[i]);
        CHECK(memcmp(s, model[i], n) == 0);
        CHECK(zintern_get(p, model[i], model_len[i]) == (uint32_t)i);
    }
    zintern_destroy(p);
}

int main(void)
{
    test_basic();
    test_binary_and_empty();
    test_alloc_failure();
    test_differential();
    puts("test_zintern: all groups passed (basic binary allocfail diff)");
    return 0;
}
