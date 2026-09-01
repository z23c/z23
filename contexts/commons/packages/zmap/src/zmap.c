/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: open-addressing string -> void* hash map; see zmap.h for the
 *          design notes and ownership rules. */
#include "zmap/zmap.h"

#include <stdlib.h>
#include <string.h>

static constexpr size_t ZMAP_INITIAL_CAP = 16;
static constexpr size_t ZMAP_MAX_CAP = (size_t)1 << 31;
static_assert((ZMAP_INITIAL_CAP & (ZMAP_INITIAL_CAP - 1)) == 0,
              "capacity must be a power of two");

typedef enum { SLOT_EMPTY = 0, SLOT_LIVE, SLOT_TOMBSTONE } slot_state;

typedef struct {
  slot_state state;
  uint64_t hash; /* cached so rehash never recomputes and lookup skips fast */
  char *key;     /* map-owned copy */
  void *value;
} zmap_slot;

struct zmap {
  zmap_alloc alloc;
  zmap_hash_fn hash;
  zmap_slot *slots;
  size_t cap;
  size_t size;
  size_t tombstones;
};

static void *malloc_alloc(void *ctx, size_t size) {
  (void)ctx;
  return calloc(1, size);
}

static void malloc_dealloc(void *ctx, void *ptr) {
  (void)ctx;
  free(ptr);
}

zmap_alloc zmap_alloc_malloc(void) {
  return (zmap_alloc){.ctx = nullptr,
                      .alloc = malloc_alloc,
                      .dealloc = malloc_dealloc};
}

uint64_t zmap_hash_fnv1a(const char *key, size_t len) {
  uint64_t h = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < len; i++) {
    h ^= (unsigned char)key[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static void *zm_alloc(zmap *m, size_t size) {
  return m->alloc.alloc(m->alloc.ctx, size);
}

static void zm_free(zmap *m, void *ptr) {
  m->alloc.dealloc(m->alloc.ctx, ptr);
}

static zmap *create_impl(zmap_alloc alloc, zmap_hash_fn hash, size_t cap) {
  zmap *m = alloc.alloc(alloc.ctx, sizeof(*m));
  if (!m)
    return nullptr;
  m->alloc = alloc;
  m->hash = hash ? hash : zmap_hash_fnv1a;
  m->slots = zm_alloc(m, cap * sizeof(*m->slots));
  if (!m->slots) {
    zm_free(m, m);
    return nullptr;
  }
  m->cap = cap;
  m->size = 0;
  m->tombstones = 0;
  return m;
}

zmap *zmap_create(void) {
  return create_impl(zmap_alloc_malloc(), nullptr, ZMAP_INITIAL_CAP);
}

zmap *zmap_create_ex(const zmap_alloc *alloc, zmap_hash_fn hash) {
  return create_impl(alloc ? *alloc : zmap_alloc_malloc(), hash,
                     ZMAP_INITIAL_CAP);
}

/* Find the slot of `key`, or the first reusable (tombstone, else empty)
 * slot where an insert would land.  Never fails while the load bound is
 * maintained because an empty slot always exists. */
static zmap_slot *find_slot(zmap *m, const char *key, uint64_t hash) {
  size_t mask = m->cap - 1;
  size_t i = (size_t)hash & mask;
  zmap_slot *reuse = nullptr;
  for (;;) {
    zmap_slot *s = &m->slots[i];
    if (s->state == SLOT_EMPTY)
      return reuse ? reuse : s;
    if (s->state == SLOT_TOMBSTONE) {
      if (!reuse)
        reuse = s;
    } else if (s->hash == hash && strcmp(s->key, key) == 0) {
      return s;
    }
    i = (i + 1) & mask;
  }
}

static void free_slot_key(zmap *m, zmap_slot *s) {
  zm_free(m, s->key);
  s->key = nullptr;
}

/* Rehash into a fresh table of `new_cap`, dropping tombstones. */
static bool rehash(zmap *m, size_t new_cap) {
  zmap_slot *fresh = zm_alloc(m, new_cap * sizeof(*fresh));
  if (!fresh)
    return false;
  zmap_slot *old = m->slots;
  size_t old_cap = m->cap;
  m->slots = fresh;
  m->cap = new_cap;
  m->tombstones = 0;
  for (size_t i = 0; i < old_cap; i++) {
    if (old[i].state != SLOT_LIVE)
      continue;
    zmap_slot *dst = find_slot(m, old[i].key, old[i].hash);
    *dst = old[i]; /* key ownership moves to the fresh table */
  }
  zm_free(m, old);
  return true;
}

bool zmap_put(zmap *m, const char *key, void *value, void **old_value) {
  uint64_t hash = m->hash(key, strlen(key));
  zmap_slot *s = find_slot(m, key, hash);
  if (s->state == SLOT_LIVE) {
    if (old_value)
      *old_value = s->value;
    s->value = value;
    return true;
  }

  /* Rehash before inserting when the probe load (including tombstones)
   * would reach 3/4.  Prefer clearing tombstones at the current capacity;
   * double only when the live entries alone would still breach the bound,
   * so erase churn cannot grow the table without bound. */
  if ((m->size + m->tombstones + 1) * 4 >= m->cap * 3) {
    size_t new_cap = (m->size + 1) * 4 >= m->cap * 3 ? m->cap * 2 : m->cap;
    if (new_cap > ZMAP_MAX_CAP || !rehash(m, new_cap)) {
      /* Fall back to a same-size rehash before giving up. */
      if (m->tombstones == 0 || new_cap == m->cap || !rehash(m, m->cap))
        return false;
    }
    s = find_slot(m, key, hash);
  }

  size_t key_len = strlen(key);
  char *copy = zm_alloc(m, key_len + 1);
  if (!copy)
    return false;
  memcpy(copy, key, key_len + 1);

  if (s->state == SLOT_TOMBSTONE)
    m->tombstones--;
  s->state = SLOT_LIVE;
  s->hash = hash;
  s->key = copy;
  s->value = value;
  m->size++;
  return true;
}

static const zmap_slot *lookup(const zmap *m, const char *key) {
  if (m->cap == 0)
    return nullptr;
  uint64_t hash = m->hash(key, strlen(key));
  size_t mask = m->cap - 1;
  size_t i = (size_t)hash & mask;
  for (;;) {
    const zmap_slot *s = &m->slots[i];
    if (s->state == SLOT_EMPTY)
      return nullptr;
    if (s->state == SLOT_LIVE && s->hash == hash &&
        strcmp(s->key, key) == 0)
      return s;
    i = (i + 1) & mask;
  }
}

void *zmap_get(const zmap *m, const char *key) {
  const zmap_slot *s = lookup(m, key);
  return s ? s->value : nullptr;
}

bool zmap_contains(const zmap *m, const char *key) {
  return lookup(m, key) != nullptr;
}

void *zmap_erase(zmap *m, const char *key) {
  zmap_slot *s = (zmap_slot *)lookup(m, key);
  if (!s)
    return nullptr;
  void *value = s->value;
  free_slot_key(m, s);
  s->state = SLOT_TOMBSTONE;
  s->value = nullptr;
  m->size--;
  m->tombstones++;
  return value;
}

size_t zmap_size(const zmap *m) { return m->size; }

size_t zmap_capacity(const zmap *m) { return m->cap; }

void zmap_clear(zmap *m, zmap_destroy_fn dtor, void *ctx) {
  for (size_t i = 0; i < m->cap; i++) {
    zmap_slot *s = &m->slots[i];
    if (s->state != SLOT_LIVE)
      continue;
    if (dtor)
      dtor(ctx, s->key, s->value);
    free_slot_key(m, s);
    s->state = SLOT_EMPTY; /* reset fully; capacity is kept */
    s->value = nullptr;
  }
  m->size = 0;
  m->tombstones = 0;
}

void zmap_destroy(zmap *m, zmap_destroy_fn dtor, void *ctx) {
  if (!m)
    return;
  zmap_clear(m, dtor, ctx);
  zm_free(m, m->slots);
  zm_free(m, m);
}

bool zmap_next(const zmap *m, zmap_iter *it, const char **key, void **value) {
  while (it->next_slot < m->cap) {
    const zmap_slot *s = &m->slots[it->next_slot++];
    if (s->state == SLOT_LIVE) {
      if (key)
        *key = s->key;
      if (value)
        *value = s->value;
      return true;
    }
  }
  return false;
}
