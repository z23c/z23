/* zring — fixed-capacity byte ring buffer. See include/zring/zring.h. */
#include "zring/zring.h"

#include <string.h>

const char *zring_err_str(zring_err e) {
  switch (e) {
  case ZRING_OK: return "ok";
  case ZRING_ERR_ARG: return "invalid argument";
  case ZRING_ERR_FULL: return "ring full";
  case ZRING_ERR_EMPTY: return "ring empty";
  }
  return "unknown error";
}

zring_err zring_init(zring *r, void *storage, size_t cap) {
  if (r == NULL || (storage == NULL && cap != 0)) return ZRING_ERR_ARG;
  r->buf = storage;
  r->cap = cap;
  r->head = 0;
  r->count = 0;
  return ZRING_OK;
}

zring_err zring_reset(zring *r) {
  if (r == NULL) return ZRING_ERR_ARG;
  r->head = 0;
  r->count = 0;
  return ZRING_OK;
}

size_t zring_len(const zring *r) { return r == NULL ? 0 : r->count; }

size_t zring_avail(const zring *r) {
  return r == NULL ? 0 : r->cap - r->count;
}

int zring_is_empty(const zring *r) { return r == NULL || r->count == 0; }

int zring_is_full(const zring *r) {
  return r != NULL && r->cap != 0 && r->count == r->cap;
}

/* Tail (write) position. */
static size_t zring__tail(const zring *r) {
  size_t t = r->head + r->count;
  return t >= r->cap ? t - r->cap : t; /* head+count < 2*cap always */
}

zring_err zring_put(zring *r, unsigned char b) {
  if (r == NULL) return ZRING_ERR_ARG;
  if (r->cap == 0 || r->count == r->cap) return ZRING_ERR_FULL;
  if (r->buf == NULL) return ZRING_ERR_ARG;
  r->buf[zring__tail(r)] = b;
  r->count++;
  return ZRING_OK;
}

zring_err zring_get(zring *r, unsigned char *out) {
  if (r == NULL || out == NULL) return ZRING_ERR_ARG;
  if (r->count == 0) return ZRING_ERR_EMPTY;
  if (r->buf == NULL) return ZRING_ERR_ARG;
  *out = r->buf[r->head];
  r->head++;
  if (r->head == r->cap) r->head = 0;
  r->count--;
  return ZRING_OK;
}

zring_err zring_peek(const zring *r, unsigned char *out) {
  if (r == NULL || out == NULL) return ZRING_ERR_ARG;
  if (r->count == 0) return ZRING_ERR_EMPTY;
  if (r->buf == NULL) return ZRING_ERR_ARG;
  *out = r->buf[r->head];
  return ZRING_OK;
}

size_t zring_write(zring *r, const void *data, size_t n) {
  const unsigned char *p = data;
  size_t room, take, first;
  if (r == NULL || r->buf == NULL || (p == NULL && n != 0)) return 0;
  room = r->cap - r->count;
  take = n < room ? n : room;
  if (take == 0) return 0;
  first = r->cap - zring__tail(r); /* space to the wrap point */
  if (first > take) first = take;
  memcpy(r->buf + zring__tail(r), p, first);
  memcpy(r->buf, p + first, take - first); /* wrap segment (may be 0) */
  r->count += take;
  return take;
}

size_t zring_read(zring *r, void *data, size_t n) {
  unsigned char *p = data;
  size_t take, first;
  if (r == NULL || r->buf == NULL || (p == NULL && n != 0)) return 0;
  take = n < r->count ? n : r->count;
  if (take == 0) return 0;
  first = r->cap - r->head;
  if (first > take) first = take;
  memcpy(p, r->buf + r->head, first);
  memcpy(p + first, r->buf, take - first);
  r->head += take;
  if (r->head >= r->cap) r->head -= r->cap;
  r->count -= take;
  return take;
}

size_t zring_peek_at(const zring *r, size_t skip, void *data, size_t n) {
  unsigned char *p = data;
  size_t avail, take, pos, first;
  if (r == NULL || r->buf == NULL || (p == NULL && n != 0)) return 0;
  if (skip >= r->count) return 0;
  avail = r->count - skip;
  take = n < avail ? n : avail;
  if (take == 0) return 0;
  pos = r->head + skip;
  if (pos >= r->cap) pos -= r->cap; /* head+skip < 2*cap */
  first = r->cap - pos;
  if (first > take) first = take;
  memcpy(p, r->buf + pos, first);
  memcpy(p + first, r->buf, take - first);
  return take;
}

size_t zring_drop(zring *r, size_t n) {
  size_t take;
  if (r == NULL || r->buf == NULL) return 0;
  take = n < r->count ? n : r->count;
  r->head += take;
  if (r->head >= r->cap) r->head -= r->cap; /* head < 2*cap */
  r->count -= take;
  return take;
}
