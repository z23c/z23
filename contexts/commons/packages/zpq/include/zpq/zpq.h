/* zpq — binary-heap priority queue (C23).
 *
 * Min-heap over void* with a ctx-carrying comparator and
 * caller-injected allocation. push/pop/peek in O(log n)/O(1),
 * build-heap in O(n), and honest allocation failure (vector
 * unchanged).
 *
 * Values are never owned.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZPQ_H
#define ZPQ_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *(*malloc_fn)(void *ctx, size_t size);
    void  (*free_fn)(void *ctx, void *ptr);
    void   *ctx;
} zpq_alloc;

/* Strict three-way comparison; negative means a pops before b. */
typedef int (*zpq_cmp)(const void *a, const void *b, void *ctx);

typedef struct zpq zpq;

/* Create a heap. cmp must be non-NULL. A zeroed zpq_alloc selects the
 * hosted malloc/free. Returns NULL on allocation failure. */
zpq *zpq_create(zpq_cmp cmp, void *cmp_ctx, zpq_alloc alloc);

/* Create from an existing array (copied, heapified in O(n)). */
zpq *zpq_from(void *const *items, size_t n, zpq_cmp cmp, void *cmp_ctx,
              zpq_alloc alloc);

void zpq_destroy(zpq *pq); /* frees the array, not the values */

size_t zpq_len(const zpq *pq);

/* Smallest element, or NULL when empty. */
void *zpq_peek(const zpq *pq);

/* Insert; false on allocation failure (heap unchanged). */
bool zpq_push(zpq *pq, void *item);

/* Remove and return the smallest element; NULL when empty. */
void *zpq_pop(zpq *pq);

/* Replace the smallest element with item in one pass (faster than
 * pop+push); returns the old minimum, NULL when empty (item not
 * inserted). */
void *zpq_replace(zpq *pq, void *item);

#ifdef __cplusplus
}
#endif

#endif /* ZPQ_H */
