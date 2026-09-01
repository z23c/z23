/* zbits — fixed-size bitset. See include/zbits/zbits.h. */
#include "zbits/zbits.h"

#include <stdbit.h>

const char *zbits_err_str(zbits_err e) {
  switch (e) {
  case ZBITS_OK: return "ok";
  case ZBITS_ERR_ARG: return "invalid argument";
  case ZBITS_ERR_RANGE: return "index out of range";
  }
  return "unknown error";
}

size_t zbits_words(size_t nbits) {
  if (nbits == 0 || nbits > ZBITS_MAX) return SIZE_MAX;
  return (nbits + 63) / 64;
}

static int zbits__valid(const uint64_t *w, size_t nbits) {
  return w != NULL && nbits != 0 && nbits <= ZBITS_MAX;
}

/* Mask off the tail bits beyond nbits in the last word. */
static void zbits__trim(uint64_t *w, size_t nbits) {
  size_t rem = nbits % 64;
  if (rem != 0)
    w[nbits / 64] &= (UINT64_C(1) << rem) - 1;
}

zbits_err zbits_init(uint64_t *w, size_t nbits) {
  size_t i, nw;
  if (!zbits__valid(w, nbits)) return ZBITS_ERR_ARG;
  nw = zbits_words(nbits);
  for (i = 0; i < nw; i++) w[i] = 0;
  return ZBITS_OK;
}

zbits_err zbits_set(uint64_t *w, size_t nbits, size_t i) {
  if (!zbits__valid(w, nbits)) return ZBITS_ERR_ARG;
  if (i >= nbits) return ZBITS_ERR_RANGE;
  w[i / 64] |= UINT64_C(1) << (i % 64);
  return ZBITS_OK;
}

zbits_err zbits_clear(uint64_t *w, size_t nbits, size_t i) {
  if (!zbits__valid(w, nbits)) return ZBITS_ERR_ARG;
  if (i >= nbits) return ZBITS_ERR_RANGE;
  w[i / 64] &= ~(UINT64_C(1) << (i % 64));
  return ZBITS_OK;
}

zbits_err zbits_flip(uint64_t *w, size_t nbits, size_t i) {
  if (!zbits__valid(w, nbits)) return ZBITS_ERR_ARG;
  if (i >= nbits) return ZBITS_ERR_RANGE;
  w[i / 64] ^= UINT64_C(1) << (i % 64);
  return ZBITS_OK;
}

int zbits_test(const uint64_t *w, size_t nbits, size_t i) {
  if (!zbits__valid(w, nbits)) return -1;
  if (i >= nbits) return -1;
  return (int)((w[i / 64] >> (i % 64)) & 1);
}

zbits_err zbits_set_all(uint64_t *w, size_t nbits) {
  size_t i, nw;
  if (!zbits__valid(w, nbits)) return ZBITS_ERR_ARG;
  nw = zbits_words(nbits);
  for (i = 0; i < nw; i++) w[i] = UINT64_MAX;
  zbits__trim(w, nbits);
  return ZBITS_OK;
}

zbits_err zbits_clear_all(uint64_t *w, size_t nbits) {
  return zbits_init(w, nbits);
}

zbits_err zbits_flip_all(uint64_t *w, size_t nbits) {
  size_t i, nw;
  if (!zbits__valid(w, nbits)) return ZBITS_ERR_ARG;
  nw = zbits_words(nbits);
  for (i = 0; i < nw; i++) w[i] = ~w[i];
  zbits__trim(w, nbits);
  return ZBITS_OK;
}

size_t zbits_count(const uint64_t *w, size_t nbits) {
  size_t i, nw, total = 0;
  if (!zbits__valid(w, nbits)) return SIZE_MAX;
  nw = zbits_words(nbits);
  for (i = 0; i < nw; i++) total += (size_t)stdc_count_ones_ull(w[i]);
  return total;
}

size_t zbits_rank(const uint64_t *w, size_t nbits, size_t i) {
  size_t full, rem, total = 0, j;
  if (!zbits__valid(w, nbits)) return SIZE_MAX;
  if (i > nbits) return SIZE_MAX;
  full = i / 64;
  rem = i % 64;
  for (j = 0; j < full; j++)
    total += (size_t)stdc_count_ones_ull(w[j]);
  if (rem != 0)
    total += (size_t)stdc_count_ones_ull(w[full] &
                                         ((UINT64_C(1) << rem) - 1));
  return total;
}

static size_t zbits__first(const uint64_t *w, size_t nbits, int want_set) {
  size_t i, nw;
  if (!zbits__valid(w, nbits)) return SIZE_MAX;
  nw = zbits_words(nbits);
  for (i = 0; i < nw; i++) {
    uint64_t x = want_set ? w[i] : ~w[i];
    if (x != 0) {
      size_t bit = i * 64 + (size_t)stdc_trailing_zeros_ull(x);
      return bit < nbits ? bit : SIZE_MAX;
    }
  }
  return SIZE_MAX;
}

size_t zbits_first_set(const uint64_t *w, size_t nbits) {
  return zbits__first(w, nbits, 1);
}

size_t zbits_first_clear(const uint64_t *w, size_t nbits) {
  return zbits__first(w, nbits, 0);
}

static zbits_err zbits__op(uint64_t *dst, const uint64_t *a,
                           const uint64_t *b, size_t nbits, int op) {
  size_t i, nw;
  if (!zbits__valid(dst, nbits) || !zbits__valid(a, nbits) ||
      !zbits__valid(b, nbits))
    return ZBITS_ERR_ARG;
  nw = zbits_words(nbits);
  for (i = 0; i < nw; i++) {
    uint64_t x = op == 0 ? (a[i] | b[i])
                 : op == 1 ? (a[i] & b[i])
                           : (a[i] & ~b[i]);
    dst[i] = x;
  }
  zbits__trim(dst, nbits);
  return ZBITS_OK;
}

zbits_err zbits_or(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                   size_t nbits) {
  return zbits__op(dst, a, b, nbits, 0);
}

zbits_err zbits_and(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                    size_t nbits) {
  return zbits__op(dst, a, b, nbits, 1);
}

zbits_err zbits_andnot(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                       size_t nbits) {
  return zbits__op(dst, a, b, nbits, 2);
}
