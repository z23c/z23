#include "zarena/zarena.h"

void zarena_init(zarena *a, void *buf, size_t cap)
{
    a->buf = buf;
    a->cap = buf ? cap : 0;
    a->used = 0;
}

static int is_pow2(size_t v)
{
    return v && (v & (v - 1)) == 0;
}

void *zarena_alloc(zarena *a, size_t size, size_t align)
{
    size_t base, aligned;

    if (!a->buf || !is_pow2(align))
        return NULL;
    base = (size_t)a->buf + a->used;
    aligned = (base + (align - 1)) & ~(align - 1);
    size_t off = aligned - (size_t)a->buf;
    if (off > a->cap || size > a->cap - off)
        return NULL;
    a->used = off + (size ? size : 1);
    return (void *)aligned;
}

zarena_mark zarena_save(const zarena *a)
{
    zarena_mark m = {a->used};
    return m;
}

void zarena_rewind(zarena *a, zarena_mark mark)
{
    if (mark.used <= a->used)
        a->used = mark.used;
}

void zarena_clear(zarena *a)
{
    a->used = 0;
}

size_t zarena_used(const zarena *a)
{
    return a->used;
}

size_t zarena_remaining(const zarena *a)
{
    return a->cap - a->used;
}
