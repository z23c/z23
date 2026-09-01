/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: open-addressing string -> void* hash map with caller-injected
 *          allocation.
 *
 * Design notes:
 *  - Hash: FNV-1a 64-bit by default (zmap_hash_fnv1a).  Simple, portable,
 *    and good enough for string keys; callers needing a different function
 *    (including tests that want forced collisions) inject one via
 *    zmap_create_ex().
 *  - Probing: linear probing over a power-of-two table.  Erased slots become
 *    tombstones so probe chains stay valid; the table rehashes (dropping all
 *    tombstones) when (size + tombstones) reaches 3/4 of capacity, so erase
 *    churn alone cannot grow the table without bound.
 *  - Keys are duplicated with the map's allocator at put time; the map owns
 *    its key copies.  Values are opaque void* and never owned: the caller
 *    decides their lifetime and may pass a destructor to zmap_clear() /
 *    zmap_destroy() to be invoked once per live entry.
 *  - No global mutable state; every map carries its own allocator.
 */
#ifndef ZMAP_H
#define ZMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct zmap zmap;

/* Allocator interface.  alloc must return zeroed memory on success or NULL
 * on failure; dealloc must accept NULL. */
typedef struct {
  void *ctx;
  void *(*alloc)(void *ctx, size_t size);
  void (*dealloc)(void *ctx, void *ptr);
} zmap_alloc;

/* malloc/calloc-backed default allocator. */
zmap_alloc zmap_alloc_malloc(void);

/* Hash function type and the default FNV-1a 64-bit implementation. */
typedef uint64_t (*zmap_hash_fn)(const char *key, size_t len);
uint64_t zmap_hash_fnv1a(const char *key, size_t len);

/* Optional destructor invoked once per live entry by zmap_clear() and
 * zmap_destroy().  key points at the map-owned key copy; do not retain it. */
typedef void (*zmap_destroy_fn)(void *ctx, const char *key, void *value);

/* Create a map using the malloc-backed default allocator and FNV-1a. */
[[nodiscard]] zmap *zmap_create(void);

/* Create a map with an explicit allocator and/or hash function; either may
 * be NULL to select the default. */
[[nodiscard]] zmap *zmap_create_ex(const zmap_alloc *alloc,
                                   zmap_hash_fn hash);

/* Insert or replace.  On replace, *old_value (when non-NULL) receives the
 * displaced value and the map does not call any destructor for it.  Returns
 * false only when the allocator fails; the map is unchanged in that case. */
[[nodiscard]] bool zmap_put(zmap *m, const char *key, void *value,
                            void **old_value);

/* Lookup; returns NULL when absent (so storing NULL values is
 * indistinguishable from absence — see zmap_contains()). */
void *zmap_get(const zmap *m, const char *key);
bool zmap_contains(const zmap *m, const char *key);

/* Remove and return the value, or NULL when absent.  The map-owned key copy
 * is released; the value's lifetime stays with the caller. */
void *zmap_erase(zmap *m, const char *key);

size_t zmap_size(const zmap *m);

/* Current table capacity; exposed for tests and diagnostics. */
size_t zmap_capacity(const zmap *m);

/* Remove every entry (invoking dtor per entry when given) but keep the map
 * allocated with its initial capacity. */
void zmap_clear(zmap *m, zmap_destroy_fn dtor, void *ctx);

/* Destroy the map, releasing all key copies and the map itself. */
void zmap_destroy(zmap *m, zmap_destroy_fn dtor, void *ctx);

/* Iteration.  Zero-initialize the iterator (or use ZMAP_ITER_INIT), then
 * call zmap_next() until it returns false.  Order is unspecified and stable
 * only while the map is not mutated.  The key pointer borrows the map-owned
 * copy; do not free or retain it past the next mutation. */
typedef struct {
  size_t next_slot;
} zmap_iter;

#define ZMAP_ITER_INIT ((zmap_iter){.next_slot = 0})

bool zmap_next(const zmap *m, zmap_iter *it, const char **key, void **value);

#endif /* ZMAP_H */
