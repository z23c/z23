/* Headless native acceptance for concurrent workpool execution. */
#include "util/workpool.h"

#include <stdatomic.h>
#include <stdio.h>

/* workpool.c retains the legacy auto-sizing dependency. This acceptance uses
 * an explicit worker count, but supplies the symbol so the focused link does
 * not need the unrelated general utility translation unit. */
int GetNumCores(void) { return 4; }

static _Atomic unsigned completed;

static bool increment(void *item)
{
    unsigned *value = item;
    (*value)++;
    atomic_fetch_add_explicit(&completed, 1, memory_order_relaxed);
    return true;
}

int main(void)
{
    enum { ITEM_COUNT = 4096 };
    unsigned values[ITEM_COUNT] = {0};
    void *items[ITEM_COUNT];
    for (size_t i = 0; i < ITEM_COUNT; ++i) items[i] = &values[i];

    struct workpool pool;
    if (!workpool_init(&pool, 8, ITEM_COUNT, increment)) return 1;
    bool ok = workpool_run(&pool, items, ITEM_COUNT);
    workpool_destroy(&pool);
    if (!ok || atomic_load_explicit(&completed, memory_order_relaxed) !=
                   ITEM_COUNT)
        return 2;
    for (size_t i = 0; i < ITEM_COUNT; ++i)
        if (values[i] != 1) return 3;

    puts("workpool_acceptance: PASS");
    return 0;
}
