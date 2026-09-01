/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fixed-block pool allocator for C23 over a caller-supplied
 *          arena. No malloc: the pool carves the arena into equal
 *          blocks, threads a free list through the free blocks
 *          themselves, and hands them out in O(1).
 *
 * Properties:
 *  - Bounded and total: the arena is fixed at init; allocation failure
 *    is NULL, never growth. block_size is rounded up to
 *    alignof(max_align_t) so every block is fully aligned.
 *  - Frees are validated exactly: a pointer outside the arena,
 *    misaligned, or already free is rejected with false instead of
 *    corrupting the list (double-free detection walks the free list,
 *    O(free blocks)). No metadata lives inside live blocks.
 *  - No global state; the zpool struct is caller-owned and may live
 *    anywhere (including inside the arena is NOT allowed — keep it
 *    separate).
 */
#ifndef ZPOOL_H
#define ZPOOL_H

#include <stdbool.h>
#include <stddef.h>

typedef struct zpool zpool;

struct zpool {
  unsigned char *arena;
  size_t block_size;  /* as rounded up at init */
  size_t block_count;
  size_t free_count;
  void *free_head;    /* first free block, NULL when exhausted */
};

/* Initialize over arena[0..arena_len). False on NULL/overflow or when
 * not even one aligned block fits. block_size may be smaller than a
 * pointer; it is rounded up to hold the free-list link. */
bool zpool_init(zpool *pool, void *arena, size_t arena_len,
                size_t block_size);

/* Take one block, or NULL when exhausted. */
void *zpool_alloc(zpool *pool);

/* Return a block. False (and no state change) when ptr is NULL,
 * outside the arena, not block-aligned, or already free. */
bool zpool_free(zpool *pool, void *ptr);

/* Blocks currently available. */
size_t zpool_available(const zpool *pool);

/* True when ptr names a live (allocated, aligned, in-arena) block. */
bool zpool_owns(const zpool *pool, const void *ptr);

#endif /* ZPOOL_H */
