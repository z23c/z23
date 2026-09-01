/* zintern — string interning pool.
 *
 * Storage: one growable arena holding NUL-terminated string bytes
 * back to back, an id→(off,len) table, and an open-addressing hash
 * table mapping hash → id set (with arena bytes as the source of
 * truth for comparison). */
#include "zintern/zintern.h"

#include <stdlib.h>
#include <string.h>

struct zintern {
    zintern_alloc alloc;

    /* arena of string bytes (each NUL-terminated) */
    char  *arena;
    size_t arena_len, arena_cap;

    /* id -> offset/len into arena */
    size_t   *offs;    /* offset+1 (0 unused; ids start at 0) */
    uint32_t *lens;
    uint32_t  count, tab_cap;

    /* open addressing: hash slot -> id+1 (0 = empty) */
    uint32_t *slots;
    uint32_t  slots_cap;
    uint32_t  slots_used;
};

static void *xalloc(zintern *p, size_t n)
{
    if (p->alloc.malloc_fn) return p->alloc.malloc_fn(p->alloc.ctx, n);
    return malloc(n);
}

static void xfree(zintern *p, void *ptr)
{
    if (!ptr) return;
    if (p->alloc.free_fn) p->alloc.free_fn(p->alloc.ctx, ptr);
    else free(ptr);
}

static uint64_t fnv1a(const void *bytes, size_t len)
{
    const unsigned char *b = bytes;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < len; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

static bool arena_append(zintern *p, const void *bytes, size_t len,
                         size_t *off_out)
{
    if (p->arena_len + len + 1 > p->arena_cap) {
        size_t ncap = p->arena_cap ? p->arena_cap * 2 : 256;
        while (ncap < p->arena_len + len + 1) ncap *= 2;
        char *na = xalloc(p, ncap);
        if (!na) return false;
        if (p->arena) memcpy(na, p->arena, p->arena_len);
        xfree(p, p->arena);
        p->arena = na;
        p->arena_cap = ncap;
    }
    *off_out = p->arena_len;
    if (len) memcpy(p->arena + p->arena_len, bytes, len);
    p->arena_len += len;
    p->arena[p->arena_len++] = '\0';
    return true;
}

/* find slot for bytes; *found set when present */
static uint32_t slot_find(const zintern *p, const void *bytes, size_t len,
                          uint64_t h, bool *found)
{
    uint32_t mask = p->slots_cap - 1;
    uint32_t i = (uint32_t)h & mask;
    for (;;) {
        uint32_t e = p->slots[i];
        if (e == 0) { *found = false; return i; }
        uint32_t id = e - 1;
        if (p->lens[id] == len &&
            (len == 0 || memcmp(p->arena + p->offs[id], bytes, len) == 0)) {
            *found = true;
            return i;
        }
        i = (i + 1) & mask;
    }
}

static bool slots_grow(zintern *p)
{
    uint32_t ncap = p->slots_cap ? p->slots_cap * 2 : 64;
    uint32_t *ns = xalloc(p, (size_t)ncap * sizeof *ns);
    if (!ns) return false;
    memset(ns, 0, (size_t)ncap * sizeof *ns);

    uint32_t *old = p->slots;
    uint32_t oldcap = p->slots_cap;
    p->slots = ns;
    p->slots_cap = ncap;
    if (old) {
        for (uint32_t i = 0; i < oldcap; i++) {
            uint32_t e = old[i];
            if (e == 0) continue;
            uint32_t id = e - 1;
            uint64_t h = fnv1a(p->arena + p->offs[id], p->lens[id]);
            bool found;
            uint32_t s = slot_find(p, p->arena + p->offs[id], p->lens[id],
                                   h, &found);
            (void)found;
            p->slots[s] = e;
        }
        xfree(p, old);
    }
    return true;
}

zintern *zintern_create(zintern_alloc alloc)
{
    zintern proto;
    proto.alloc = alloc;
    zintern *p = alloc.malloc_fn ? alloc.malloc_fn(alloc.ctx, sizeof *p)
                                 : malloc(sizeof *p);
    (void)proto;
    if (!p) return NULL;
    memset(p, 0, sizeof *p);
    p->alloc = alloc;
    return p;
}

void zintern_destroy(zintern *p)
{
    if (!p) return;
    xfree(p, p->arena);
    xfree(p, p->offs);
    xfree(p, p->lens);
    xfree(p, p->slots);
    zintern_alloc a = p->alloc;
    if (a.free_fn) a.free_fn(a.ctx, p);
    else free(p);
}

uint32_t zintern_count(const zintern *p)
{
    return p ? p->count : 0;
}

uint32_t zintern_put(zintern *p, const void *bytes, size_t len)
{
    if (!p || (!bytes && len > 0)) return UINT32_MAX;
    if (p->count == UINT32_MAX) return UINT32_MAX;

    if (p->slots_cap == 0 && !slots_grow(p)) return UINT32_MAX;
    uint64_t h = fnv1a(bytes ? bytes : "", len);
    bool found;
    uint32_t s = slot_find(p, bytes, len, h, &found);
    if (found) return p->slots[s] - 1;

    /* keep load factor <= 3/4 */
    if ((p->slots_used + 1) * 4 > p->slots_cap * 3) {
        if (!slots_grow(p)) return UINT32_MAX;
        s = slot_find(p, bytes, len, h, &found);
        if (found) return p->slots[s] - 1;
    }

    if (p->count == p->tab_cap) {
        uint32_t ncap = p->tab_cap ? p->tab_cap * 2 : 64;
        size_t *no = xalloc(p, (size_t)ncap * sizeof *no);
        if (!no) return UINT32_MAX;
        uint32_t *nl = xalloc(p, (size_t)ncap * sizeof *nl);
        if (!nl) { xfree(p, no); return UINT32_MAX; }
        if (p->offs) {
            memcpy(no, p->offs, (size_t)p->count * sizeof *no);
            memcpy(nl, p->lens, (size_t)p->count * sizeof *nl);
        }
        xfree(p, p->offs);
        xfree(p, p->lens);
        p->offs = no;
        p->lens = nl;
        p->tab_cap = ncap;
    }

    size_t off;
    if (!arena_append(p, bytes, len, &off)) return UINT32_MAX;

    uint32_t id = p->count++;
    p->offs[id] = off;
    p->lens[id] = (uint32_t)len;
    p->slots[s] = id + 1;
    p->slots_used++;
    return id;
}

uint32_t zintern_get(const zintern *p, const void *bytes, size_t len)
{
    if (!p || p->slots_cap == 0 || (!bytes && len > 0)) return UINT32_MAX;
    bool found;
    uint32_t s = slot_find(p, bytes, len, fnv1a(bytes ? bytes : "", len),
                           &found);
    return found ? p->slots[s] - 1 : UINT32_MAX;
}

const char *zintern_str(const zintern *p, uint32_t id, size_t *len)
{
    if (!p || id >= p->count) return NULL;
    if (len) *len = p->lens[id];
    return p->arena + p->offs[id];
}
