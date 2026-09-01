/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded LRU cache for C23, built on zmap.
 *          String keys, opaque values, caller-injected allocation, and a
 *          hard entry bound: inserting past capacity evicts the
 *          least-recently-used entry. Get and put both count as use.
 *
 * Design notes:
 *  - zmap holds key -> node; a doubly-linked list orders nodes from
 *    most- to least-recently used. Both directions are O(1). Each list
 *    node owns its own key copy (zmap also keeps one), so the cache
 *    never depends on zmap's internal storage stability.
 *  - Values are opaque void* and never owned; an optional destructor
 *    runs once per evicted/cleared entry.
 *  - No global mutable state; every cache carries its own allocator
 *    (forwarded to zmap and used for list nodes).
 */
#ifndef ZLRU_H
#define ZLRU_H

#include "zmap/zmap.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct zlru zlru;

/* Invoked once when an entry leaves the cache (eviction, replace, or
 * destroy). key points at the cache-owned copy; do not retain it. */
typedef void (*zlru_destroy_fn)(void *ctx, const char *key, void *value);

/* Create a cache holding at most capacity entries. allocator may be
 * NULL to select the default. destroy_fn may be NULL. Returns NULL on
 * allocation failure or capacity == 0. */
zlru *zlru_create(size_t capacity, zlru_destroy_fn destroy_fn,
                  void *destroy_ctx, zmap_alloc allocator);

/* Destroy the cache, running the destructor on every live entry. */
void zlru_destroy(zlru *cache);

/* Look up key, promoting it to most-recently-used. Returns NULL when
 * absent. */
void *zlru_get(zlru *cache, const char *key);

/* Insert or replace key -> value, promoting it. On replace the
 * destructor runs on the OLD value. At capacity the LRU entry is
 * evicted (destructor runs). Returns false on allocation failure; the
 * cache is unchanged in that case. */
bool zlru_put(zlru *cache, const char *key, void *value);

/* Remove key if present; the destructor runs on its value. */
void zlru_erase(zlru *cache, const char *key);

/* Current entry count and the configured bound. */
size_t zlru_size(const zlru *cache);
size_t zlru_capacity(const zlru *cache);

/* Iteration in recency order (MRU first) without promoting entries.
 * The callback receives the node-owned key and must not mutate the
 * cache; returning false stops the walk early. */
typedef bool (*zlru_visit_fn)(void *ctx, const char *key, void *value);
void zlru_visit_mru_first(const zlru *cache, zlru_visit_fn visit,
                         void *ctx);

#endif /* ZLRU_H */
