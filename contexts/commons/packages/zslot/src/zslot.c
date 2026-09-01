/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: generational handle table (see include/zslot/zslot.h). */

#include "zslot/zslot.h"

#include <string.h>

struct zslot_hdr {
    uint32_t generation;
    uint32_t next_free;
};

static size_t align8(size_t n)
{
    if (n > SIZE_MAX - 7u)
        return 0;
    return (n + 7u) & ~(size_t)7u;
}

static uint32_t hdr_stride(size_t value_size)
{
    if (value_size > SIZE_MAX - sizeof(struct zslot_hdr))
        return 0;
    size_t n = align8(sizeof(struct zslot_hdr) + value_size);
    if (!n || n > UINT32_MAX)
        return 0;
    return (uint32_t)n;
}

size_t zslot_storage_bytes(uint32_t cap, size_t value_size)
{
    uint32_t stride = hdr_stride(value_size);
    if (!cap || !stride)
        return 0;
    if ((size_t)cap > SIZE_MAX / stride)
        return 0;
    return (size_t)cap * stride;
}

static struct zslot_hdr *slot_at(const zslot *t, uint32_t i)
{
    return (struct zslot_hdr *)(t->storage + (size_t)i * t->stride);
}

static unsigned char *payload_at(const zslot *t, uint32_t i)
{
    return (unsigned char *)slot_at(t, i) + sizeof(struct zslot_hdr);
}

static bool live_gen(uint32_t gen)
{
    return (gen & 1u) == 1u;
}

static void *lookup(const zslot *t, zslot_id id)
{
    if (!t || id == ZSLOT_INVALID)
        return NULL;
    uint32_t idx = (uint32_t)id;
    uint32_t gen = (uint32_t)(id >> 32);
    if (idx >= t->cap || !live_gen(gen))
        return NULL;
    struct zslot_hdr *h = slot_at(t, idx);
    if (h->generation != gen)
        return NULL;
    return payload_at(t, idx);
}

bool zslot_init(zslot *t, void *storage, size_t storage_bytes,
                size_t value_size)
{
    if (!t || !storage)
        return false;
    memset(t, 0, sizeof(*t));
    uint32_t stride = hdr_stride(value_size);
    if (!stride)
        return false;
    size_t cap_sz = storage_bytes / stride;
    if (!cap_sz || cap_sz > UINT32_MAX)
        return false;
    uint32_t cap = (uint32_t)cap_sz;
    t->storage = storage;
    t->cap = cap;
    t->live = 0;
    t->free_head = 0;
    t->value_size = (uint32_t)value_size;
    t->stride = stride;
    for (uint32_t i = 0; i < cap; i++) {
        struct zslot_hdr *h = slot_at(t, i);
        h->generation = 0;
        h->next_free = i + 1u == cap ? cap : i + 1u;
    }
    return true;
}

zslot_id zslot_insert(zslot *t, const void *value)
{
    if (!t || t->free_head == t->cap)
        return ZSLOT_INVALID;
    if (t->value_size != 0 && !value)
        return ZSLOT_INVALID;
    uint32_t idx = t->free_head;
    struct zslot_hdr *h = slot_at(t, idx);
    if (live_gen(h->generation))
        return ZSLOT_INVALID;
    uint32_t gen = h->generation;
    if (gen == UINT32_MAX)
        return ZSLOT_INVALID;
    gen += 1u;
    if (!live_gen(gen))
        return ZSLOT_INVALID;
    t->free_head = h->next_free;
    h->generation = gen;
    if (t->value_size != 0)
        memcpy(payload_at(t, idx), value, t->value_size);
    t->live++;
    return ((zslot_id)gen << 32) | (zslot_id)idx;
}

bool zslot_remove(zslot *t, zslot_id id)
{
    if (!lookup(t, id))
        return false;
    uint32_t idx = (uint32_t)id;
    uint32_t gen = (uint32_t)(id >> 32);
    struct zslot_hdr *h = slot_at(t, idx);
    if (gen == UINT32_MAX) {
        /* Last odd generation: retire. Generation 0 never matches a
         * live handle, and the index is not returned to the free list. */
        h->generation = 0;
        t->live--;
        return true;
    }
    h->generation = gen + 1u;
    h->next_free = t->free_head;
    t->free_head = idx;
    t->live--;
    return true;
}

void *zslot_get(zslot *t, zslot_id id)
{
    return lookup(t, id);
}

const void *zslot_get_const(const zslot *t, zslot_id id)
{
    return lookup(t, id);
}

bool zslot_contains(const zslot *t, zslot_id id)
{
    return lookup(t, id) != NULL;
}

uint32_t zslot_live(const zslot *t)
{
    return t ? t->live : 0;
}

uint32_t zslot_cap(const zslot *t)
{
    return t ? t->cap : 0;
}

uint32_t zslot_id_index(zslot_id id)
{
    return (uint32_t)id;
}

uint32_t zslot_id_generation(zslot_id id)
{
    return (uint32_t)(id >> 32);
}

uint32_t zslot_each(zslot *t, zslot_visit_fn fn, void *ctx)
{
    if (!t)
        return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < t->cap; i++) {
        struct zslot_hdr *h = slot_at(t, i);
        if (!live_gen(h->generation))
            continue;
        zslot_id id = ((zslot_id)h->generation << 32) | (zslot_id)i;
        if (fn)
            fn(id, payload_at(t, i), ctx);
        n++;
    }
    return n;
}
