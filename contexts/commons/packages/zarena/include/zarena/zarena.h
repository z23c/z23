/* zarena — bump (linear) arena allocator for C23.
 *
 * An arena hands out variable-size, aligned slices from one
 * caller-owned buffer in O(1) with no per-object free.  Memory is
 * reclaimed wholesale with zarena_clear(), or in LIFO order with
 * mark/rewind pairs.  Ideal for parse trees, per-request scratch,
 * and test fixtures where every object dies together.
 *
 * Properties:
 *  - No malloc: the buffer is caller-supplied; exhaustion returns
 *    NULL, never growth.
 *  - Alignment is explicit per allocation (pass alignof of the type);
 *    align must be a power of two, or the call fails with NULL.
 *  - The zarena struct is caller-owned and must live outside the
 *    buffer it manages.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZARENA_H
#define ZARENA_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned char *buf;
    size_t cap;
    size_t used;
} zarena;

/* Saved allocation frontier for zarena_rewind(). */
typedef struct {
    size_t used;
} zarena_mark;

void zarena_init(zarena *a, void *buf, size_t cap);

/* Allocate size bytes aligned to align (power of two, >= 1).
 * size == 0 yields a valid minimal allocation.  Returns NULL when
 * the space is not available or align is not a power of two. */
void *zarena_alloc(zarena *a, size_t size, size_t align);

/* Current frontier; rewind() returns the arena to it.  Marks must be
 * rewound in LIFO order. */
zarena_mark zarena_save(const zarena *a);
void zarena_rewind(zarena *a, zarena_mark mark);

/* Free everything. */
void zarena_clear(zarena *a);

size_t zarena_used(const zarena *a);
size_t zarena_remaining(const zarena *a);

#ifdef __cplusplus
}
#endif

#endif /* ZARENA_H */
