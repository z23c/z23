#include "ztrie/ztrie.h"

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

static bool cstr_put(ztrie *t, const char *k, void *v, void **old)
{
    return ztrie_put(t, k, strlen(k), v, old);
}
static void *cstr_get(ztrie *t, const char *k)
{
    return ztrie_get(t, k, strlen(k));
}
static void *cstr_erase(ztrie *t, const char *k)
{
    return ztrie_erase(t, k, strlen(k));
}
static void *cstr_lpm(ztrie *t, const char *text, size_t *len)
{
    return ztrie_longest_prefix(t, text, strlen(text), len);
}

static void test_basic(void)
{
    int a = 1, b = 2, c = 3;
    ztrie *t = ztrie_create((ztrie_alloc){0});
    CHECK(t != NULL);
    CHECK(ztrie_len(t) == 0);

    CHECK(cstr_put(t, "cat", &a, NULL));
    CHECK(cstr_put(t, "car", &b, NULL));
    CHECK(cstr_put(t, "cart", &c, NULL));
    CHECK(ztrie_len(t) == 3);

    CHECK(cstr_get(t, "cat") == &a);
    CHECK(cstr_get(t, "car") == &b);
    CHECK(cstr_get(t, "cart") == &c);
    CHECK(cstr_get(t, "ca") == NULL);
    CHECK(cstr_get(t, "carts") == NULL);
    CHECK(cstr_get(t, "dog") == NULL);
    CHECK(ztrie_contains(t, "cat", 3));
    CHECK(!ztrie_contains(t, "ca", 2));

    /* Replace reports old value, len unchanged. */
    void *old = NULL;
    CHECK(cstr_put(t, "cat", &c, &old));
    CHECK(old == &a);
    CHECK(ztrie_len(t) == 3);
    CHECK(cstr_get(t, "cat") == &c);

    /* Binary keys with NUL bytes inside. */
    int d = 4;
    const uint8_t binkey[] = {0x00, 0xff, 0x00};
    CHECK(ztrie_put(t, binkey, sizeof binkey, &d, NULL));
    CHECK(ztrie_get(t, binkey, sizeof binkey) == &d);
    const uint8_t prefix2[] = {0x00, 0xff};
    CHECK(ztrie_get(t, prefix2, sizeof prefix2) == NULL);

    /* Empty key. */
    int e = 5;
    CHECK(ztrie_put(t, "", 0, &e, NULL));
    CHECK(ztrie_get(t, "", 0) == &e);
    CHECK(ztrie_len(t) == 5);

    /* NULL tolerance. */
    CHECK(cstr_get(NULL, "cat") == NULL);
    CHECK(!ztrie_contains(NULL, "cat", 3));
    CHECK(!cstr_put(NULL, "x", &a, NULL));
    CHECK(ztrie_len(NULL) == 0);
    CHECK(ztrie_put(t, NULL, 3, &a, NULL) == false);
    ztrie_destroy(t);
    ztrie_destroy(NULL);
}

static void test_longest_prefix(void)
{
    int v_http = 1, v_root = 2, v_api = 3, v_apiv1 = 4;
    ztrie *t = ztrie_create((ztrie_alloc){0});
    cstr_put(t, "/", &v_root, NULL);
    cstr_put(t, "/http", &v_http, NULL);
    cstr_put(t, "/api", &v_api, NULL);
    cstr_put(t, "/api/v1", &v_apiv1, NULL);

    size_t n = 0;
    CHECK(cstr_lpm(t, "/api/v1/users", &n) == &v_apiv1 && n == 7);
    CHECK(cstr_lpm(t, "/api/v2", &n) == &v_api && n == 4);
    CHECK(cstr_lpm(t, "/httpd", &n) == &v_http && n == 5);
    CHECK(cstr_lpm(t, "/other", &n) == &v_root && n == 1);
    CHECK(cstr_lpm(t, "nope", &n) == NULL && n == 0);
    CHECK(cstr_lpm(t, "", &n) == NULL);

    /* Empty key participates. */
    int v_empty = 9;
    CHECK(ztrie_put(t, "", 0, &v_empty, NULL));
    CHECK(cstr_lpm(t, "anything", &n) == &v_empty && n == 0);
    CHECK(cstr_lpm(t, "/api/v1/x", &n) == &v_apiv1 && n == 7);

    CHECK(ztrie_longest_prefix(NULL, "x", 1, &n) == NULL);
    ztrie_destroy(t);
}

static void test_erase_prune(void)
{
    int a = 1, b = 2;
    ztrie *t = ztrie_create((ztrie_alloc){0});
    cstr_put(t, "abc", &a, NULL);
    cstr_put(t, "abd", &b, NULL);
    CHECK(ztrie_len(t) == 2);

    /* Erase prunes the dead branch but keeps the shared one. */
    CHECK(cstr_erase(t, "abc") == &a);
    CHECK(ztrie_len(t) == 1);
    CHECK(cstr_get(t, "abc") == NULL);
    CHECK(cstr_get(t, "abd") == &b);
    CHECK(cstr_erase(t, "abc") == NULL);
    CHECK(cstr_erase(t, "zzz") == NULL);
    CHECK(ztrie_erase(t, NULL, 2) == NULL);
    CHECK(ztrie_erase(NULL, "a", 1) == NULL);

    /* Empty-key erase. */
    int e = 5;
    CHECK(ztrie_put(t, "", 0, &e, NULL));
    CHECK(ztrie_erase(t, "", 0) == &e);
    CHECK(ztrie_erase(t, "", 0) == NULL);
    ztrie_destroy(t);
}

struct walk { char seen[256][64]; size_t count; };

static bool walk_cb(const uint8_t *key, size_t key_len, void *value,
                    void *ctx)
{
    struct walk *w = ctx;
    (void)value;
    if (w->count >= 256) return false;
    if (key_len >= 64) return false;
    memcpy(w->seen[w->count], key, key_len);
    w->seen[w->count][key_len] = '\0';
    w->count++;
    return true;
}

static bool stop_early_cb(const uint8_t *key, size_t key_len,
                          void *value, void *ctx)
{
    (void)key; (void)key_len; (void)value;
    struct walk *w = ctx;
    w->count++;
    return false; /* stop after the first */
}

static void test_foreach(void)
{
    int v = 1;
    ztrie *t = ztrie_create((ztrie_alloc){0});
    const char *keys[] = {"car", "cart", "cat", "dog", "carbon"};
    for (size_t i = 0; i < 5; i++)
        CHECK(cstr_put(t, keys[i], &v, NULL));

    /* All keys, lexicographic order. */
    struct walk w = {0};
    CHECK(ztrie_foreach_prefix(t, "", 0, walk_cb, &w));
    CHECK(w.count == 5);
    CHECK(strcmp(w.seen[0], "car") == 0);
    CHECK(strcmp(w.seen[1], "carbon") == 0);
    CHECK(strcmp(w.seen[2], "cart") == 0);
    CHECK(strcmp(w.seen[3], "cat") == 0);
    CHECK(strcmp(w.seen[4], "dog") == 0);

    /* Prefix-filtered. */
    memset(&w, 0, sizeof w);
    CHECK(ztrie_foreach_prefix(t, "car", 3, walk_cb, &w));
    CHECK(w.count == 3);
    CHECK(strcmp(w.seen[0], "car") == 0);
    CHECK(strcmp(w.seen[1], "carbon") == 0);
    CHECK(strcmp(w.seen[2], "cart") == 0);

    /* Absent prefix: empty walk, still success. */
    memset(&w, 0, sizeof w);
    CHECK(ztrie_foreach_prefix(t, "xyz", 3, walk_cb, &w));
    CHECK(w.count == 0);

    /* Early stop. */
    memset(&w, 0, sizeof w);
    CHECK(!ztrie_foreach_prefix(t, "", 0, stop_early_cb, &w));
    CHECK(w.count == 1);

    /* NULL args. */
    CHECK(!ztrie_foreach_prefix(NULL, "", 0, walk_cb, &w));
    CHECK(!ztrie_foreach_prefix(t, "", 0, NULL, &w));
    ztrie_destroy(t);
}

/* Counting allocator with failure switch. */
struct test_alloc { size_t mallocs, frees, fail_after; };
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
    int a = 1;

    /* Struct allocation fails. */
    struct test_alloc t0 = { 0, 0, 0 };
    CHECK(ztrie_create((ztrie_alloc){ ta_malloc, ta_free, &t0 }) == NULL);

    /* Insert fails partway; existing entries untouched. */
    struct test_alloc t1 = { 0, 0, SIZE_MAX };
    ztrie *tr = ztrie_create((ztrie_alloc){ ta_malloc, ta_free, &t1 });
    CHECK(tr != NULL);
    CHECK(cstr_put(tr, "ok", &a, NULL));
    t1.fail_after = t1.mallocs; /* next malloc fails */
    CHECK(!cstr_put(tr, "zzz-new-branch", &a, NULL));
    CHECK(cstr_get(tr, "ok") == &a);
    CHECK(ztrie_len(tr) == 1);
    t1.fail_after = SIZE_MAX;
    CHECK(cstr_put(tr, "zzz-new-branch", &a, NULL));
    CHECK(ztrie_len(tr) == 2);
    ztrie_destroy(tr);
    CHECK(t1.mallocs == t1.frees);
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_stress_vs_model(void)
{
    /* Random put/get/erase against a sorted-array model. */
    ztrie *t = ztrie_create((ztrie_alloc){0});
    CHECK(t != NULL);

    static char keys[512][8];
    static int values[512];
    static bool present[512];
    size_t nkeys = 0;

    for (int op = 0; op < 20000; op++) {
        unsigned kind = (unsigned)(rng_next() % 3);
        if (kind == 0 && nkeys < 512) {
            /* insert a fresh random key; reuse the slot if the same
               string was seen before so the model keys stay unique */
            char cand[8];
            size_t len = (size_t)(rng_next() % 7) + 1;
            for (size_t i = 0; i < len; i++)
                cand[i] = (char)('a' + rng_next() % 26);
            cand[len] = '\0';
            size_t slot = nkeys;
            for (size_t i = 0; i < nkeys; i++)
                if (strcmp(keys[i], cand) == 0) { slot = i; break; }
            if (slot == nkeys) {
                memcpy(keys[nkeys], cand, len + 1);
                values[nkeys] = (int)nkeys;
                nkeys++;
            }
            bool was = present[slot];
            void *old = NULL;
            CHECK(ztrie_put(t, keys[slot], len, &values[slot], &old));
            if (was) CHECK(old != NULL);
            else CHECK(old == NULL);
            present[slot] = true;
        } else if (kind == 1 && nkeys > 0) {
            size_t i = (size_t)(rng_next() % nkeys);
            void *got = ztrie_get(t, keys[i], strlen(keys[i]));
            if (present[i]) CHECK(got == &values[i]);
            else CHECK(got == NULL);
        } else if (nkeys > 0) {
            size_t i = (size_t)(rng_next() % nkeys);
            void *got = ztrie_erase(t, keys[i], strlen(keys[i]));
            if (present[i]) {
                CHECK(got == &values[i]);
                present[i] = false;
            } else {
                CHECK(got == NULL);
            }
        }

        /* len agrees with model */
        size_t expect = 0;
        for (size_t i = 0; i < nkeys; i++) if (present[i]) expect++;
        CHECK(ztrie_len(t) == expect);
    }

    /* Destroy frees everything (asan leak check). */
    ztrie_destroy(t);
}

int main(void)
{
    test_basic();
    test_longest_prefix();
    test_erase_prune();
    test_foreach();
    test_alloc_failure();
    test_stress_vs_model();
    puts("test_ztrie: all groups passed (basic lpm erase foreach allocfail stress)");
    return 0;
}
