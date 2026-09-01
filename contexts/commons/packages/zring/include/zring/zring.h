/* zring — fixed-capacity byte ring buffer
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * A single-producer/single-consumer-safe byte ring over caller
 * storage. All operations are O(1) except bulk read/write which are
 * O(n) with two-segment wrap handling. No dynamic memory; the caller
 * owns the backing array.
 *
 * Capacity semantics: the ring can hold exactly `cap` bytes (the
 * backing array is used fully — count is tracked explicitly, not via
 * a wasted slot).
 */
#ifndef ZRING_H
#define ZRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  unsigned char *buf; /* caller storage, cap bytes */
  size_t cap;         /* backing size (0 = unusable, all ops fail) */
  size_t head;        /* read position */
  size_t count;       /* bytes currently stored */
} zring;

typedef enum {
  ZRING_OK = 0,
  ZRING_ERR_ARG = 1,  /* NULL argument */
  ZRING_ERR_FULL = 2, /* no room */
  ZRING_ERR_EMPTY = 3 /* no data */
} zring_err;

/* Initialize over caller storage. `cap` may be any size; storage must
 * be writable for cap bytes. */
zring_err zring_init(zring *r, void *storage, size_t cap);

zring_err zring_reset(zring *r);
size_t zring_len(const zring *r);      /* bytes stored */
size_t zring_avail(const zring *r);    /* free bytes */
int zring_is_empty(const zring *r);
int zring_is_full(const zring *r);

/* Single byte. FULL/EMPTY when the ring cannot accept/provide. */
zring_err zring_put(zring *r, unsigned char b);
zring_err zring_get(zring *r, unsigned char *out);

/* Peek without consuming. */
zring_err zring_peek(const zring *r, unsigned char *out);

/* Bulk: returns bytes actually moved (short on full/empty). NULL data
 * with n > 0 yields 0 without touching the ring. */
size_t zring_write(zring *r, const void *data, size_t n);
size_t zring_read(zring *r, void *data, size_t n);

/* Bulk peek: copy up to n bytes starting at `skip` from the head
 * without consuming. Returns bytes copied. */
size_t zring_peek_at(const zring *r, size_t skip, void *data, size_t n);

/* Drop n bytes from the head; returns bytes actually dropped. */
size_t zring_drop(zring *r, size_t n);

const char *zring_err_str(zring_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZRING_H */
