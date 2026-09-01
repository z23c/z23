/* zbuf — bounded growable byte buffer. See include/zbuf/zbuf.h. */
#include "zbuf/zbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *zbuf_err_str(zbuf_err e) {
  switch (e) {
  case ZBUF_OK: return "ok";
  case ZBUF_ERR_ARG: return "invalid argument";
  case ZBUF_ERR_FULL: return "buffer bound reached";
  case ZBUF_ERR_OOM: return "out of memory";
  }
  return "unknown error";
}

zbuf_err zbuf_init(zbuf *b, size_t max) {
  if (b == NULL) return ZBUF_ERR_ARG;
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
  b->max = max;
  b->err = ZBUF_OK;
  return ZBUF_OK;
}

void zbuf_free(zbuf *b) {
  if (b == NULL) return;
  free(b->data);
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
  b->err = ZBUF_OK;
}

void zbuf_clear(zbuf *b) {
  if (b == NULL) return;
  b->len = 0;
  b->err = ZBUF_OK;
}

/* Ensure room for `extra` more bytes (plus a NUL scratch slot). */
static zbuf_err zbuf__reserve(zbuf *b, size_t extra) {
  size_t need, ncap;
  unsigned char *nd;
  if (b->err != ZBUF_OK) return b->err;
  if (extra > b->max - b->len) { /* also catches len > max */
    b->err = ZBUF_ERR_FULL;
    return b->err;
  }
  need = b->len + extra + 1; /* +1: NUL scratch */
  if (need <= b->cap) return ZBUF_OK;
  ncap = b->cap == 0 ? 64 : b->cap;
  while (ncap < need) {
    size_t next = ncap * 2;
    if (next < ncap) { /* overflow guard */
      ncap = need;
      break;
    }
    ncap = next;
  }
  if (ncap > b->max + 1) ncap = b->max + 1;
  nd = realloc(b->data, ncap);
  if (nd == NULL) {
    b->err = ZBUF_ERR_OOM;
    return b->err;
  }
  b->data = nd;
  b->cap = ncap;
  return ZBUF_OK;
}

zbuf_err zbuf_write(zbuf *b, const void *data, size_t n) {
  zbuf_err e;
  if (b == NULL || (data == NULL && n != 0)) return ZBUF_ERR_ARG;
  e = zbuf__reserve(b, n);
  if (e != ZBUF_OK) return e;
  if (n != 0) memcpy(b->data + b->len, data, n);
  b->len += n;
  b->data[b->len] = '\0';
  return ZBUF_OK;
}

zbuf_err zbuf_put(zbuf *b, unsigned char byte) {
  return zbuf_write(b, &byte, 1);
}

zbuf_err zbuf_str(zbuf *b, const char *cstr) {
  if (cstr == NULL) return ZBUF_ERR_ARG;
  return zbuf_write(b, cstr, strlen(cstr));
}

zbuf_err zbuf_vprintf(zbuf *b, const char *fmt, va_list ap) {
  va_list aq;
  int need;
  zbuf_err e;
  if (b == NULL || fmt == NULL) return ZBUF_ERR_ARG;
  if (b->err != ZBUF_OK) return b->err;
  va_copy(aq, ap);
  need = vsnprintf(NULL, 0, fmt, aq);
  va_end(aq);
  if (need < 0) {
    b->err = ZBUF_ERR_FULL;
    return b->err;
  }
  e = zbuf__reserve(b, (size_t)need);
  if (e != ZBUF_OK) return e;
  vsnprintf((char *)b->data + b->len, b->cap - b->len, fmt, ap);
  b->len += (size_t)need;
  return ZBUF_OK;
}

zbuf_err zbuf_printf(zbuf *b, const char *fmt, ...) {
  va_list ap;
  zbuf_err e;
  va_start(ap, fmt);
  e = zbuf_vprintf(b, fmt, ap);
  va_end(ap);
  return e;
}

const char *zbuf_cstr(zbuf *b) {
  if (b == NULL || b->data == NULL) return "";
  b->data[b->len] = '\0';
  return (const char *)b->data;
}

size_t zbuf_len(const zbuf *b) { return b == NULL ? 0 : b->len; }

zbuf_err zbuf_status(const zbuf *b) {
  return b == NULL ? ZBUF_ERR_ARG : b->err;
}
