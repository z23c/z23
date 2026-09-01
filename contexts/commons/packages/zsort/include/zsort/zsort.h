/*
 * zsort — comparison sorting with a context pointer, stable sorting,
 * and argsort (index permutation), in freestanding C23.
 *
 * ISO C qsort has no context pointer; POSIX qsort_r exists in two
 * incompatible argument orders.  zsort provides one portable,
 * deterministic API:
 *
 *   zsort(base, n, size, cmp, ctx)        in-place, unstable, O(n log n)
 *   zsort_stable(base, n, size, cmp, ctx, scratch)
 *                                         in-place, stable merge sort;
 *                                         scratch must hold n*size bytes
 *   zargsort(perm, base, n, size, cmp, ctx)
 *                                         fills perm[0..n) with the
 *                                         index permutation that sorts;
 *                                         base is not modified; stable
 *
 * The comparator returns <0, 0, >0 like qsort's, and receives ctx:
 *   int cmp(const void *a, const void *b, void *ctx)
 *
 * All functions reject n > 1 with NULL base (no-op for n <= 1), and
 * zsort_stable/zargsort reject NULL scratch/perm.  No allocation, no
 * globals, recursion depth bounded by log2(n).
 */
#ifndef ZSORT_H
#define ZSORT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*zsort_cmp)(const void *a, const void *b, void *ctx);

/* In-place unstable sort (introspective: quicksort with heapsort
 * fallback, insertion sort for small runs). */
void zsort(void *base, size_t n, size_t size, zsort_cmp cmp, void *ctx);

/* In-place stable merge sort.  scratch must point to at least
 * n * size writable bytes; returns 0 on bad arguments (1 on success).
 * For n <= 1 scratch may be NULL. */
int zsort_stable(void *base, size_t n, size_t size, zsort_cmp cmp,
                 void *ctx, void *scratch);

/* Stable argsort: perm[i] becomes the index of the i-th smallest
 * element (ties keep original index order).  base is never written.
 * Returns 0 on bad arguments, 1 on success. */
int zargsort(size_t *perm, const void *base, size_t n, size_t size,
             zsort_cmp cmp, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZSORT_H */
