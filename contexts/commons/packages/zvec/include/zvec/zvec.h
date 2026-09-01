/* zvec — growable pointer vector (C23).
 *
 * A dynamic array of void* with caller-injected allocation, geometric
 * growth, and honest failure: every mutating call returns false on
 * allocation failure with the vector unchanged.
 *
 * Values are never owned — destroying the vector frees only the array.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZVEC_H
#define ZVEC_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *(*malloc_fn)(void *ctx, size_t size);
    void  (*free_fn)(void *ctx, void *ptr);
    void   *ctx;
} zvec_alloc;

typedef struct zvec zvec;

/* Create with the given allocator. A zeroed zvec_alloc selects the
 * hosted malloc/free. Returns NULL on allocation failure. */
zvec *zvec_create(zvec_alloc alloc);

/* Create with at least `initial_capacity` slots reserved. */
zvec *zvec_with_capacity(size_t initial_capacity, zvec_alloc alloc);

/* Free the array, not the values. NULL-safe. */
void zvec_destroy(zvec *v);

size_t zvec_len(const zvec *v);
size_t zvec_capacity(const zvec *v);

/* Element access; NULL when out of range (or v is NULL). */
void *zvec_get(const zvec *v, size_t i);

/* Replace element i; returns the old value, NULL if out of range. */
void *zvec_set(zvec *v, size_t i, void *value);

/* Append; false on allocation failure (vector unchanged). */
bool zvec_push(zvec *v, void *value);

/* Remove and return the last element; NULL when empty. */
void *zvec_pop(zvec *v);

/* Insert at index (shifting right); false on bad index or allocation
 * failure. */
bool zvec_insert(zvec *v, size_t i, void *value);

/* Remove index i preserving order; returns the removed value, NULL if
 * out of range. */
void *zvec_remove(zvec *v, size_t i);

/* Remove index i by swapping the last element into its slot (O(1),
 * order not preserved). */
void *zvec_swap_remove(zvec *v, size_t i);

/* Drop all elements (capacity kept). */
void zvec_clear(zvec *v);

/* Shrink capacity to len; false on allocation failure (harmless). */
bool zvec_shrink_to_fit(zvec *v);

/* First index of value (pointer equality); -1 when absent. */
long zvec_index_of(const zvec *v, const void *value);

#ifdef __cplusplus
}
#endif

#endif /* ZVEC_H */
