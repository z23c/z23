#include "zpq/zpq.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct zpq {
    void     **items;
    size_t     len;
    size_t     cap;
    zpq_cmp    cmp;
    void      *cmp_ctx;
    zpq_alloc  alloc;
};

static void *hosted_malloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void hosted_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

static zpq_alloc normalize(zpq_alloc a)
{
    if (!a.malloc_fn) a.malloc_fn = hosted_malloc;
    if (!a.free_fn) a.free_fn = hosted_free;
    return a;
}

static zpq *alloc_pq(zpq_cmp cmp, void *cmp_ctx, zpq_alloc alloc)
{
    if (!cmp) return NULL;
    alloc = normalize(alloc);
    zpq *pq = alloc.malloc_fn(alloc.ctx, sizeof *pq);
    if (!pq) return NULL;
    pq->items = NULL;
    pq->len = 0;
    pq->cap = 0;
    pq->cmp = cmp;
    pq->cmp_ctx = cmp_ctx;
    pq->alloc = alloc;
    return pq;
}

static void sift_down(zpq *pq, size_t i)
{
    for (;;) {
        size_t l = 2 * i + 1, r = 2 * i + 2, smallest = i;
        if (l < pq->len && pq->cmp(pq->items[l], pq->items[smallest],
                                   pq->cmp_ctx) < 0)
            smallest = l;
        if (r < pq->len && pq->cmp(pq->items[r], pq->items[smallest],
                                   pq->cmp_ctx) < 0)
            smallest = r;
        if (smallest == i) return;
        void *tmp = pq->items[i];
        pq->items[i] = pq->items[smallest];
        pq->items[smallest] = tmp;
        i = smallest;
    }
}

static void sift_up(zpq *pq, size_t i)
{
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (pq->cmp(pq->items[i], pq->items[parent], pq->cmp_ctx) >= 0)
            return;
        void *tmp = pq->items[i];
        pq->items[i] = pq->items[parent];
        pq->items[parent] = tmp;
        i = parent;
    }
}

zpq *zpq_create(zpq_cmp cmp, void *cmp_ctx, zpq_alloc alloc)
{
    return alloc_pq(cmp, cmp_ctx, alloc);
}

zpq *zpq_from(void *const *items, size_t n, zpq_cmp cmp, void *cmp_ctx,
              zpq_alloc alloc)
{
    zpq *pq = alloc_pq(cmp, cmp_ctx, alloc);
    if (!pq) return NULL;
    if (n == 0) return pq;
    if (n > SIZE_MAX / sizeof(void *)) { zpq_destroy(pq); return NULL; }
    pq->items = pq->alloc.malloc_fn(pq->alloc.ctx, n * sizeof(void *));
    if (!pq->items) { zpq_destroy(pq); return NULL; }
    memcpy(pq->items, items, n * sizeof(void *));
    pq->len = n;
    pq->cap = n;
    for (size_t i = n / 2; i-- > 0;)
        sift_down(pq, i);
    return pq;
}

void zpq_destroy(zpq *pq)
{
    if (!pq) return;
    pq->alloc.free_fn(pq->alloc.ctx, pq->items);
    pq->alloc.free_fn(pq->alloc.ctx, pq);
}

size_t zpq_len(const zpq *pq)
{
    return pq ? pq->len : 0;
}

void *zpq_peek(const zpq *pq)
{
    if (!pq || pq->len == 0) return NULL;
    return pq->items[0];
}

bool zpq_push(zpq *pq, void *item)
{
    if (!pq) return false;
    if (pq->len == pq->cap) {
        size_t new_cap = pq->cap ? pq->cap * 2 : 8;
        if (new_cap < pq->cap || new_cap > SIZE_MAX / sizeof(void *))
            return false;
        void **ni = pq->alloc.malloc_fn(pq->alloc.ctx,
                                        new_cap * sizeof(void *));
        if (!ni) return false;
        if (pq->items)
            memcpy(ni, pq->items, pq->len * sizeof(void *));
        pq->alloc.free_fn(pq->alloc.ctx, pq->items);
        pq->items = ni;
        pq->cap = new_cap;
    }
    pq->items[pq->len++] = item;
    sift_up(pq, pq->len - 1);
    return true;
}

void *zpq_pop(zpq *pq)
{
    if (!pq || pq->len == 0) return NULL;
    void *top = pq->items[0];
    pq->items[0] = pq->items[--pq->len];
    if (pq->len > 0) sift_down(pq, 0);
    return top;
}

void *zpq_replace(zpq *pq, void *item)
{
    if (!pq || pq->len == 0) return NULL;
    void *top = pq->items[0];
    pq->items[0] = item;
    sift_down(pq, 0);
    return top;
}
