#include "ztrie/ztrie.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct ztrie_node {
    struct ztrie_node *child[256];
    bool   has_value;
    void  *value;
} ztrie_node;

struct ztrie {
    ztrie_node *root;
    size_t      len;
    ztrie_alloc alloc;
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

static ztrie_alloc normalize(ztrie_alloc a)
{
    if (!a.malloc_fn) a.malloc_fn = hosted_malloc;
    if (!a.free_fn) a.free_fn = hosted_free;
    return a;
}

ztrie *ztrie_create(ztrie_alloc alloc)
{
    alloc = normalize(alloc);
    ztrie *t = alloc.malloc_fn(alloc.ctx, sizeof *t);
    if (!t) return NULL;
    t->root = NULL;
    t->len = 0;
    t->alloc = alloc;
    return t;
}

static void free_node(ztrie_alloc *a, ztrie_node *n)
{
    if (!n) return;
    for (int i = 0; i < 256; i++)
        free_node(a, n->child[i]);
    a->free_fn(a->ctx, n);
}

void ztrie_destroy(ztrie *t)
{
    if (!t) return;
    free_node(&t->alloc, t->root);
    t->alloc.free_fn(t->alloc.ctx, t);
}

size_t ztrie_len(const ztrie *t)
{
    return t ? t->len : 0;
}

static ztrie_node *find_node(const ztrie *t, const uint8_t *key,
                             size_t key_len)
{
    ztrie_node *n = t->root;
    for (size_t i = 0; i < key_len; i++) {
        if (!n) return NULL;
        n = n->child[key[i]];
    }
    return n;
}

bool ztrie_put(ztrie *t, const void *key_, size_t key_len, void *value,
               void **old_out)
{
    if (!t || (!key_ && key_len > 0)) return false;
    const uint8_t *key = key_;
    if (old_out) *old_out = NULL;

    if (!t->root) {
        t->root = t->alloc.malloc_fn(t->alloc.ctx, sizeof(ztrie_node));
        if (!t->root) return false;
        memset(t->root, 0, sizeof(ztrie_node));
    }

    ztrie_node *n = t->root;
    for (size_t i = 0; i < key_len; i++) {
        if (!n->child[key[i]]) {
            ztrie_node *c = t->alloc.malloc_fn(t->alloc.ctx,
                                               sizeof(ztrie_node));
            if (!c) return false;
            memset(c, 0, sizeof(ztrie_node));
            n->child[key[i]] = c;
        }
        n = n->child[key[i]];
    }
    if (n->has_value) {
        if (old_out) *old_out = n->value;
    } else {
        t->len++;
    }
    n->has_value = true;
    n->value = value;
    return true;
}

void *ztrie_get(const ztrie *t, const void *key, size_t key_len)
{
    if (!t || (!key && key_len > 0)) return NULL;
    ztrie_node *n = find_node(t, key, key_len);
    return (n && n->has_value) ? n->value : NULL;
}

bool ztrie_contains(const ztrie *t, const void *key, size_t key_len)
{
    if (!t || (!key && key_len > 0)) return false;
    ztrie_node *n = find_node(t, key, key_len);
    return n && n->has_value;
}

void *ztrie_longest_prefix(const ztrie *t, const void *text_,
                           size_t text_len, size_t *match_len)
{
    if (match_len) *match_len = 0;
    if (!t || (!text_ && text_len > 0)) return NULL;
    const uint8_t *text = text_;

    void *best = NULL;
    size_t best_len = 0;
    ztrie_node *n = t->root;
    if (n && n->has_value) best = n->value; /* empty key */
    for (size_t i = 0; i < text_len && n; i++) {
        n = n->child[text[i]];
        if (n && n->has_value) {
            best = n->value;
            best_len = i + 1;
        }
    }
    if (best && match_len) *match_len = best_len;
    return best;
}

static bool node_has_children(const ztrie_node *n)
{
    for (int i = 0; i < 256; i++)
        if (n->child[i]) return true;
    return false;
}

/* Recursive erase with pruning. */
static void *erase_rec(ztrie *t, ztrie_node **link, const uint8_t *key,
                       size_t key_len, size_t depth)
{
    ztrie_node *n = *link;
    if (!n) return NULL;
    void *removed = NULL;
    if (depth == key_len) {
        if (!n->has_value) return NULL;
        removed = n->value;
        n->has_value = false;
        n->value = NULL;
        t->len--;
    } else {
        removed = erase_rec(t, &n->child[key[depth]], key, key_len,
                            depth + 1);
    }
    /* Prune childless valueless nodes (never the root link here, since
     * root is managed by the caller wrapper). */
    if (!n->has_value && !node_has_children(n)) {
        t->alloc.free_fn(t->alloc.ctx, n);
        *link = NULL;
    }
    return removed;
}

void *ztrie_erase(ztrie *t, const void *key, size_t key_len)
{
    if (!t || (!key && key_len > 0)) return NULL;
    if (!t->root) return NULL;
    /* Keep the root node even if emptied. */
    if (key_len == 0) {
        if (!t->root->has_value) return NULL;
        void *v = t->root->value;
        t->root->has_value = false;
        t->root->value = NULL;
        t->len--;
        return v;
    }
    return erase_rec(t, &t->root->child[((const uint8_t *)key)[0]],
                     key, key_len, 1);
}

static bool foreach_rec(ztrie_node *n, uint8_t *buf, size_t depth,
                        bool (*fn)(const uint8_t *, size_t, void *, void *),
                        void *ctx)
{
    if (!n) return true;
    if (n->has_value)
        if (!fn(buf, depth, n->value, ctx)) return false;
    for (int i = 0; i < 256; i++) {
        if (n->child[i]) {
            buf[depth] = (uint8_t)i;
            if (!foreach_rec(n->child[i], buf, depth + 1, fn, ctx))
                return false;
        }
    }
    return true;
}

static size_t max_depth_below(const ztrie_node *n, size_t depth)
{
    size_t deepest = depth;
    for (int i = 0; i < 256; i++)
        if (n->child[i]) {
            size_t d = max_depth_below(n->child[i], depth + 1);
            if (d > deepest) deepest = d;
        }
    return deepest;
}

bool ztrie_foreach_prefix(const ztrie *t, const void *prefix,
                          size_t prefix_len,
                          bool (*fn)(const uint8_t *key, size_t key_len,
                                     void *value, void *ctx),
                          void *ctx)
{
    if (!t || !fn || (!prefix && prefix_len > 0)) return false;

    ztrie_node *start = t->root;
    for (size_t i = 0; i < prefix_len; i++) {
        if (!start) return true; /* prefix absent: empty walk */
        start = start->child[((const uint8_t *)prefix)[i]];
    }
    if (!start) return true;

    /* Size the key buffer by the deepest key below the prefix. */
    size_t cap = max_depth_below(start, prefix_len) + 1;
    uint8_t *buf = t->alloc.malloc_fn(t->alloc.ctx, cap);
    if (!buf) return false;
    memcpy(buf, prefix, prefix_len);

    bool ok = foreach_rec(start, buf, prefix_len, fn, ctx);
    t->alloc.free_fn(t->alloc.ctx, buf);
    return ok;
}
