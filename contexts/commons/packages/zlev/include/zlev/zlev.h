/* zlev — bounded Levenshtein distance and similarity
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Classic Levenshtein (insert/delete/substitute, unit cost) over raw
 * bytes, computed with two rows of a caller- or internal-sized DP
 * table. Two entry points:
 *
 *   zlev_distance(a, na, b, nb)      — full distance, SIZE_MAX on bad
 *                                      input or when the inputs exceed
 *                                      ZLEV_MAX.
 *   zlev_distance_bounded(a, na, b, nb, limit)
 *                                    — early exit: returns limit+1
 *                                      when the true distance exceeds
 *                                      limit (still exact below it).
 *
 * O(min(na,nb)) memory, O(na*nb) time worst case. With `limit`, runs
 * in O((na+nb)*limit) time via banded DP.
 */
#ifndef ZLEV_H
#define ZLEV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZLEV_MAX
#define ZLEV_MAX 4096u /* per-input byte bound */
#endif

/* Full Levenshtein distance. SIZE_MAX when either input is NULL with
 * nonzero length, or either length exceeds ZLEV_MAX. */
size_t zlev_distance(const void *a, size_t na, const void *b, size_t nb);

/* Banded distance with early exit. When the true distance exceeds
 * `limit`, returns limit + 1 without computing the exact value.
 * `limit` above ZLEV_MAX is treated as ZLEV_MAX. */
size_t zlev_distance_bounded(const void *a, size_t na, const void *b,
                             size_t nb, size_t limit);

/* Similarity in [0, 1000]: 1000 * (1 - dist / max(na, nb)), with
 * identical-empty defined as 1000. Returns -1 on bad input. */
int zlev_similarity_milli(const void *a, size_t na, const void *b,
                          size_t nb);

#ifdef __cplusplus
}
#endif

#endif /* ZLEV_H */
