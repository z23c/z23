#include "zvec/zvec.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct zvec {
    void      **items;
    size_t      len;
    size_t      cap;
    zvec_alloc  alloc;
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

static zvec_alloc normalize(zvec_alloc a)
{
    if (!a.malloc_fn) a.malloc_fn = hosted_malloc;
    if (!a.free_fn) a.free_fn = hosted_free;
    return a;
}

zvec *zvec_with_capacity(size_t initial_capacity, zvec_alloc alloc)
{
    alloc = normalize(alloc);
    zvec *v = alloc.malloc_fn(alloc.ctx, sizeof *v);
    if (!v) return NULL;
    v->len = 0;
    v->cap = 0;
    v->items = NULL;
    v->alloc = alloc;
    if (initial_capacity > 0) {
        v->items = alloc.malloc_fn(alloc.ctx,
                                   initial_capacity * sizeof(void *));
        if (!v->items) {
            alloc.free_fn(alloc.ctx, v);
            return NULL;
        }
        v->cap = initial_capacity;
    }
    return v;
}

zvec *zvec_create(zvec_alloc alloc)
{
    return zvec_with_capacity(0, alloc);
}

void zvec_destroy(zvec *v)
{
    if (!v) return;
    v->alloc.free_fn(v->alloc.ctx, v->items);
    v->alloc.free_fn(v->alloc.ctx, v);
}

size_t zvec_len(const zvec *v)
{
    return v ? v->len : 0;
}

size_t zvec_capacity(const zvec *v)
{
    return v ? v->cap : 0;
}

void *zvec_get(const zvec *v, size_t i)
{
    if (!v || i >= v->len) return NULL;
    return v->items[i];
}

void *zvec_set(zvec *v, size_t i, void *value)
{
    if (!v || i >= v->len) return NULL;
    void *old = v->items[i];
    v->items[i] = value;
    return old;
}

static bool reserve(zvec *v, size_t need)
{
    if (need <= v->cap) return true;
    size_t new_cap = v->cap ? v->cap : 8;
    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) return false;
        new_cap *= 2;
    }
    if (new_cap > SIZE_MAX / sizeof(void *)) return false;
    void **ni = v->alloc.malloc_fn(v->alloc.ctx, new_cap * sizeof(void *));
    if (!ni) return false;
    if (v->items) {
        memcpy(ni, v->items, v->len * sizeof(void *));
        v->alloc.free_fn(v->alloc.ctx, v->items);
    }
    v->items = ni;
    v->cap = new_cap;
    return true;
}

bool zvec_push(zvec *v, void *value)
{
    if (!v) return false;
    if (!reserve(v, v->len + 1)) return false;
    v->items[v->len++] = value;
    return true;
}

void *zvec_pop(zvec *v)
{
    if (!v || v->len == 0) return NULL;
    return v->items[--v->len];
}

bool zvec_insert(zvec *v, size_t i, void *value)
{
    if (!v || i > v->len) return false;
    if (!reserve(v, v->len + 1)) return false;
    memmove(v->items + i + 1, v->items + i, (v->len - i) * sizeof(void *));
    v->items[i] = value;
    v->len++;
    return true;
}

void *zvec_remove(zvec *v, size_t i)
{
    if (!v || i >= v->len) return NULL;
    void *old = v->items[i];
    memmove(v->items + i, v->items + i + 1, (v->len - i - 1) * sizeof(void *));
    v->len--;
    return old;
}

void *zvec_swap_remove(zvec *v, size_t i)
{
    if (!v || i >= v->len) return NULL;
    void *old = v->items[i];
    v->items[i] = v->items[v->len - 1];
    v->len--;
    return old;
}

void zvec_clear(zvec *v)
{
    if (v) v->len = 0;
}

bool zvec_shrink_to_fit(zvec *v)
{
    if (!v) return false;
    if (v->len == v->cap) return true;
    if (v->len == 0) {
        v->alloc.free_fn(v->alloc.ctx, v->items);
        v->items = NULL;
        v->cap = 0;
        return true;
    }
    void **ni = v->alloc.malloc_fn(v->alloc.ctx, v->len * sizeof(void *));
    if (!ni) return false;
    memcpy(ni, v->items, v->len * sizeof(void *));
    v->alloc.free_fn(v->alloc.ctx, v->items);
    v->items = ni;
    v->cap = v->len;
    return true;
}

long zvec_index_of(const zvec *v, const void *value)
{
    if (!v) return -1;
    for (size_t i = 0; i < v->len; i++)
        if (v->items[i] == value) return (long)i;
    return -1;
}
