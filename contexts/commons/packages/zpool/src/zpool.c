/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fixed-block pool allocator (see the header).
 *
 * Free-state is tracked exactly: the free list lives inside free
 * blocks, and zpool_free()/zpool_owns() walk it (O(n) in the number of
 * free blocks) to reject double-frees exactly. Pools are small and
 * bounded by construction; if O(n) free ever hurts, the arena was
 * mis-sized. No metadata is stored inside live blocks. */
#include "zpool/zpool.h"

#include <stdint.h>
#include <string.h>

static size_t round_up(size_t v, size_t to) {
  if (v > SIZE_MAX - (to - 1))
    return 0; /* overflow */
  return (v + to - 1) / to * to;
}

bool zpool_init(zpool *pool, void *arena, size_t arena_len,
                size_t block_size) {
  if (!pool || !arena)
    return false;
  memset(pool, 0, sizeof(*pool));
  size_t align = _Alignof(max_align_t);
  if (block_size < sizeof(void *))
    block_size = sizeof(void *);
  block_size = round_up(block_size, align);
  if (!block_size)
    return false;
  if ((uintptr_t)arena % align)
    return false; /* arena must be max_align_t-aligned */
  size_t count = arena_len / block_size;
  if (!count)
    return false;

  pool->arena = arena;
  pool->block_size = block_size;
  pool->block_count = count;
  pool->free_count = count;
  /* Thread the free list through the free blocks. */
  for (size_t i = 0; i < count; i++) {
    unsigned char *b = pool->arena + i * block_size;
    void *next = i + 1 < count ? pool->arena + (i + 1) * block_size : NULL;
    memcpy(b, &next, sizeof(next));
  }
  pool->free_head = arena;
  return true;
}

void *zpool_alloc(zpool *pool) {
  if (!pool || !pool->free_head)
    return NULL;
  unsigned char *b = pool->free_head;
  void *next;
  memcpy(&next, b, sizeof(next));
  pool->free_head = next;
  pool->free_count--;
  return b;
}

static bool block_index_of(const zpool *pool, const void *ptr,
                           size_t *index_out) {
  const unsigned char *p = ptr;
  if (p < pool->arena ||
      (size_t)(p - pool->arena) >= pool->block_count * pool->block_size)
    return false;
  size_t off = (size_t)(p - pool->arena);
  if (off % pool->block_size)
    return false;
  *index_out = off / pool->block_size;
  return true;
}

/* True when ptr is on the free list. O(free blocks). */
static bool is_free(const zpool *pool, const void *ptr) {
  for (void *cur = pool->free_head; cur;) {
    if (cur == ptr)
      return true;
    void *next;
    memcpy(&next, cur, sizeof(next));
    /* A corrupt link can only point into the arena or NULL without
     * double-free corruption, which is exactly what we detect. */
    if (next && (next < (void *)pool->arena ||
                 (size_t)((unsigned char *)next - pool->arena) >=
                     pool->block_count * pool->block_size))
      return false; /* corrupted by a scribble; stop walking */
    cur = next;
  }
  return false;
}

bool zpool_free(zpool *pool, void *ptr) {
  if (!pool || !ptr || !pool->arena)
    return false;
  size_t index;
  if (!block_index_of(pool, ptr, &index))
    return false;
  (void)index;
  if (is_free(pool, ptr))
    return false; /* double free: refuse */
  memcpy(ptr, &pool->free_head, sizeof(void *));
  pool->free_head = ptr;
  pool->free_count++;
  return true;
}

size_t zpool_available(const zpool *pool) {
  return pool ? pool->free_count : 0;
}

bool zpool_owns(const zpool *pool, const void *ptr) {
  if (!pool || !ptr || !pool->arena)
    return false;
  size_t index;
  if (!block_index_of(pool, ptr, &index))
    return false;
  (void)index;
  return !is_free(pool, ptr);
}
