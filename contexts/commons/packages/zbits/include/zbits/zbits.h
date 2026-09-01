/* zbits — fixed-size bitset over caller storage
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Operations over a caller-provided word array: set/clear/test,
 * bulk set-all/clear-all/flip, popcount, find-first-set/clear,
 * union/intersection/difference into a third set, and rank
 * (number of set bits below index). All index errors are reported,
 * never silent.
 */
#ifndef ZBITS_H
#define ZBITS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZBITS_MAX
#define ZBITS_MAX 4194304u /* bits */
#endif

typedef enum {
  ZBITS_OK = 0,
  ZBITS_ERR_ARG = 1,   /* NULL argument or zero bits */
  ZBITS_ERR_RANGE = 2  /* index >= nbits, or nbits > ZBITS_MAX */
} zbits_err;

/* Words of storage needed for nbits. SIZE_MAX when out of range. */
size_t zbits_words(size_t nbits);

/* Initialize over caller storage (zbits_words(nbits) words). */
zbits_err zbits_init(uint64_t *w, size_t nbits); /* sets all to 0 */

zbits_err zbits_set(uint64_t *w, size_t nbits, size_t i);
zbits_err zbits_clear(uint64_t *w, size_t nbits, size_t i);
zbits_err zbits_flip(uint64_t *w, size_t nbits, size_t i);

/* 0/1 for the bit, -1 on error. */
int zbits_test(const uint64_t *w, size_t nbits, size_t i);

zbits_err zbits_set_all(uint64_t *w, size_t nbits);
zbits_err zbits_clear_all(uint64_t *w, size_t nbits);
zbits_err zbits_flip_all(uint64_t *w, size_t nbits);

/* Popcount. SIZE_MAX on error. */
size_t zbits_count(const uint64_t *w, size_t nbits);

/* Number of set bits at indexes < i. SIZE_MAX on error. */
size_t zbits_rank(const uint64_t *w, size_t nbits, size_t i);

/* First set/clear bit index; SIZE_MAX when none (or on error). */
size_t zbits_first_set(const uint64_t *w, size_t nbits);
size_t zbits_first_clear(const uint64_t *w, size_t nbits);

/* dst = a OP b. All three must have the same nbits; dst may alias
 * a or b. */
zbits_err zbits_or(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                   size_t nbits);
zbits_err zbits_and(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                    size_t nbits);
zbits_err zbits_andnot(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                       size_t nbits); /* a & ~b */

const char *zbits_err_str(zbits_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZBITS_H */
