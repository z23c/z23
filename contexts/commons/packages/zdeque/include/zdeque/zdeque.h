/* zdeque — fixed-capacity double-ended queue of void pointers
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * A bounded deque over caller-provided storage: O(1) push/pop at both
 * ends, indexed access, and forward iteration. The caller owns the
 * backing array of `void *`; the deque never allocates and never
 * grows. All capacity and index errors are reported, never silent.
 *
 * Distinct from zring (a single-producer/single-consumer byte FIFO)
 * and zvec (a growable element vector): zdeque is a fixed-capacity
 * pointer container with two-ended access.
 */
#ifndef ZDEQUE_H
#define ZDEQUE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ZDEQUE_OK = 0,
  ZDEQUE_ERR_ARG = 1,    /* NULL argument or zero capacity */
  ZDEQUE_ERR_FULL = 2,   /* push into a full deque */
  ZDEQUE_ERR_EMPTY = 3,  /* pop/peek from an empty deque */
  ZDEQUE_ERR_RANGE = 4   /* index >= size */
} zdeque_err;

typedef struct {
  void **slots;   /* caller-owned array of `cap` pointers */
  size_t cap;     /* total slots */
  size_t head;    /* slot index of the front element */
  size_t len;     /* number of queued elements */
} zdeque;

/* Bind the deque to caller storage: `slots` must point to an array
 * of `cap` void pointers. */
zdeque_err zdeque_init(zdeque *dq, void **slots, size_t cap);

size_t zdeque_size(const zdeque *dq);
size_t zdeque_capacity(const zdeque *dq);
int    zdeque_empty(const zdeque *dq);
int    zdeque_full(const zdeque *dq);

zdeque_err zdeque_push_back(zdeque *dq, void *ptr);
zdeque_err zdeque_push_front(zdeque *dq, void *ptr);
/* Pop into *out (out may be NULL to discard). */
zdeque_err zdeque_pop_back(zdeque *dq, void **out);
zdeque_err zdeque_pop_front(zdeque *dq, void **out);
zdeque_err zdeque_peek_back(const zdeque *dq, void **out);
zdeque_err zdeque_peek_front(const zdeque *dq, void **out);

/* Indexed access: index 0 is the front, size-1 is the back. */
zdeque_err zdeque_at(const zdeque *dq, size_t index, void **out);

/* Drop all elements (O(1); storage is not cleared). */
void zdeque_clear(zdeque *dq);

const char *zdeque_err_str(zdeque_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZDEQUE_H */
