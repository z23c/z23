/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zslot born-red suite. Exits nonzero if any check fails. */

#include "zslot/zslot.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static unsigned char store[4096];

static void test_init(void)
{
    zslot t;
    CHECK(zslot_storage_bytes(4, 4) >= 4u * 16u);
    CHECK(zslot_storage_bytes(0, 4) == 0);
    CHECK(!zslot_init(NULL, store, sizeof(store), 4));
    CHECK(!zslot_init(&t, NULL, sizeof(store), 4));
    CHECK(!zslot_init(&t, store, 7, 4));
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    CHECK(zslot_cap(&t) >= 1);
    CHECK(zslot_live(&t) == 0);
    CHECK(zslot_live(NULL) == 0);
    CHECK(zslot_cap(NULL) == 0);
}

static void test_insert_get_remove(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    uint32_t a = 11, b = 22, c = 33;
    zslot_id ia = zslot_insert(&t, &a);
    zslot_id ib = zslot_insert(&t, &b);
    zslot_id ic = zslot_insert(&t, &c);
    CHECK(ia != ZSLOT_INVALID && ib != ZSLOT_INVALID && ic != ZSLOT_INVALID);
    CHECK(ia != ib && ib != ic && ia != ic);
    CHECK(zslot_live(&t) == 3);
    CHECK(zslot_id_generation(ia) == 1);
    CHECK(*((uint32_t *)zslot_get(&t, ia)) == 11);
    CHECK(*((uint32_t *)zslot_get(&t, ib)) == 22);
    CHECK(*((const uint32_t *)zslot_get_const(&t, ic)) == 33);
    CHECK(zslot_contains(&t, ia));
    CHECK(zslot_remove(&t, ib));
    CHECK(!zslot_contains(&t, ib));
    CHECK(zslot_get(&t, ib) == NULL);
    CHECK(zslot_live(&t) == 2);
    CHECK(!zslot_remove(&t, ib)); /* double-remove */
    CHECK(*((uint32_t *)zslot_get(&t, ia)) == 11);
    CHECK(*((uint32_t *)zslot_get(&t, ic)) == 33);
}

static void test_stale_and_reuse(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    uint32_t v = 7;
    zslot_id id = zslot_insert(&t, &v);
    uint32_t idx = zslot_id_index(id);
    CHECK(zslot_remove(&t, id));
    uint32_t w = 8;
    zslot_id id2 = zslot_insert(&t, &w);
    CHECK(id2 != ZSLOT_INVALID);
    CHECK(zslot_id_index(id2) == idx);
    CHECK(zslot_id_generation(id2) == zslot_id_generation(id) + 2);
    CHECK(zslot_get(&t, id) == NULL); /* stale generation */
    CHECK(*((uint32_t *)zslot_get(&t, id2)) == 8);
}

static void test_exhaust_and_null(void)
{
    unsigned char tiny[64];
    zslot t;
    CHECK(zslot_init(&t, tiny, sizeof(tiny), sizeof(uint32_t)));
    uint32_t cap = zslot_cap(&t);
    CHECK(cap >= 1 && cap <= 8);
    zslot_id ids[8];
    uint32_t val = 1;
    uint32_t n = 0;
    for (; n < cap; n++) {
        val = n + 1;
        ids[n] = zslot_insert(&t, &val);
        CHECK(ids[n] != ZSLOT_INVALID);
    }
    CHECK(zslot_insert(&t, &val) == ZSLOT_INVALID);
    CHECK(zslot_live(&t) == cap);
    CHECK(zslot_insert(NULL, &val) == ZSLOT_INVALID);
    CHECK(zslot_insert(&t, NULL) == ZSLOT_INVALID);
    CHECK(!zslot_remove(NULL, ids[0]));
    CHECK(!zslot_remove(&t, ZSLOT_INVALID));
    CHECK(!zslot_remove(&t, ((zslot_id)1 << 32) | 999u));
    CHECK(zslot_get(NULL, ids[0]) == NULL);
    CHECK(zslot_contains(NULL, ids[0]) == false);
}

static uint32_t visit_sum;
static uint32_t visit_n;

static void visit_add(zslot_id id, void *value, void *ctx)
{
    (void)id;
    (void)ctx;
    visit_n++;
    visit_sum += *(uint32_t *)value;
}

static void test_each(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    uint32_t a = 1, b = 2, c = 4;
    zslot_id ia = zslot_insert(&t, &a);
    zslot_id ib = zslot_insert(&t, &b);
    zslot_id ic = zslot_insert(&t, &c);
    CHECK(zslot_remove(&t, ib));
    visit_sum = 0;
    visit_n = 0;
    uint32_t n = zslot_each(&t, visit_add, NULL);
    CHECK(n == 2 && visit_n == 2 && visit_sum == 5);
    CHECK(zslot_each(NULL, visit_add, NULL) == 0);
    CHECK(zslot_each(&t, NULL, NULL) == 2);
    (void)ia;
    (void)ic;
}

static void test_zero_size_tokens(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), 0));
    zslot_id a = zslot_insert(&t, NULL);
    zslot_id b = zslot_insert(&t, NULL);
    CHECK(a != ZSLOT_INVALID && b != ZSLOT_INVALID && a != b);
    CHECK(zslot_contains(&t, a) && zslot_contains(&t, b));
    CHECK(zslot_get(&t, a) != NULL);
    CHECK(zslot_remove(&t, a));
    CHECK(!zslot_contains(&t, a));
    CHECK(zslot_contains(&t, b));
}

static void test_independent_payloads(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), 8));
    unsigned char x[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char y[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    zslot_id ix = zslot_insert(&t, x);
    zslot_id iy = zslot_insert(&t, y);
    CHECK(memcmp(zslot_get(&t, ix), x, 8) == 0);
    CHECK(memcmp(zslot_get(&t, iy), y, 8) == 0);
    memset(zslot_get(&t, ix), 0xAA, 8);
    CHECK(memcmp(zslot_get(&t, iy), y, 8) == 0);
}

int main(void)
{
    test_init();
    test_insert_get_remove();
    test_stale_and_reuse();
    test_exhaust_and_null();
    test_each();
    test_zero_size_tokens();
    test_independent_payloads();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zslot: all tests passed");
    return 0;
}
