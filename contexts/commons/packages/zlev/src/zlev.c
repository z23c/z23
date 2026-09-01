/* zlev — bounded Levenshtein distance. See include/zlev/zlev.h. */
#include "zlev/zlev.h"

#include <string.h>

/* Standard two-row DP over bytes; `a` walks the rows, `b` the
 * columns. Internal fixed tables keep this allocation-free. */
size_t zlev_distance(const void *a, size_t na, const void *b, size_t nb) {
  const unsigned char *pa = a, *pb = b;
  static _Thread_local unsigned short row[ZLEV_MAX + 1];
  static _Thread_local unsigned short prev[ZLEV_MAX + 1];
  size_t i, j;
  if ((pa == NULL && na != 0) || (pb == NULL && nb != 0)) return SIZE_MAX;
  if (na > ZLEV_MAX || nb > ZLEV_MAX) return SIZE_MAX;
  /* Make b the shorter side (columns) to bound memory. */
  if (nb > na) {
    const unsigned char *tp = pa;
    size_t tn;
    pa = pb;
    pb = tp;
    tn = na;
    na = nb;
    nb = tn;
  }
  for (j = 0; j <= nb; j++) prev[j] = (unsigned short)j;
  for (i = 1; i <= na; i++) {
    row[0] = (unsigned short)i;
    for (j = 1; j <= nb; j++) {
      size_t cost = pa[i - 1] == pb[j - 1] ? 0 : 1;
      size_t del = prev[j] + 1, ins = row[j - 1] + 1,
             sub = prev[j - 1] + cost;
      size_t m = del < ins ? del : ins;
      if (sub < m) m = sub;
      row[j] = (unsigned short)m;
    }
    memcpy(prev, row, (nb + 1) * sizeof(unsigned short));
  }
  return prev[nb];
}

size_t zlev_distance_bounded(const void *a, size_t na, const void *b,
                             size_t nb, size_t limit) {
  const unsigned char *pa = a, *pb = b;
  static _Thread_local unsigned short row[ZLEV_MAX + 1];
  static _Thread_local unsigned short prev[ZLEV_MAX + 1];
  size_t i, j;
  if ((pa == NULL && na != 0) || (pb == NULL && nb != 0)) return SIZE_MAX;
  if (na > ZLEV_MAX || nb > ZLEV_MAX) return SIZE_MAX;
  if (limit > ZLEV_MAX) limit = ZLEV_MAX;
  /* |na - nb| is a lower bound on the distance. */
  {
    size_t d = na > nb ? na - nb : nb - na;
    if (d > limit) return limit + 1;
  }
  if (nb > na) {
    const unsigned char *tp = pa;
    size_t tn;
    pa = pb;
    pb = tp;
    tn = na;
    na = nb;
    nb = tn;
  }
  for (j = 0; j <= nb; j++) prev[j] = (unsigned short)j;
  for (i = 1; i <= na; i++) {
    /* Banded window: cells [lo, hi]; cells outside are > limit away.
     * Column 0 stays in the band while i <= limit. */
    size_t lo = i > limit ? i - limit : 0;
    size_t hi = i + limit < nb ? i + limit : nb;
    size_t row_min = lo == 0 ? i : (size_t)ZLEV_MAX + 1;
    size_t jfrom = lo == 0 ? 1 : lo;
    row[0] = (unsigned short)i;
    if (lo > 1) row[lo - 1] = (unsigned short)(limit + 1); /* wall */
    for (j = jfrom; j <= hi; j++) {
      size_t cost = pa[i - 1] == pb[j - 1] ? 0 : 1;
      size_t del = prev[j] + 1, ins = row[j - 1] + 1,
             sub = prev[j - 1] + cost;
      size_t m = del < ins ? del : ins;
      if (sub < m) m = sub;
      if (m > limit + 1) m = limit + 1; /* saturate */
      row[j] = (unsigned short)m;
      if (m < row_min) row_min = m;
    }
    /* Cells past hi are unreachable-within-limit: saturate prev so
     * the next row sees the wall. */
    for (j = hi + 1; j <= nb; j++) row[j] = (unsigned short)(limit + 1);
    if (row_min > limit && hi == nb) return limit + 1; /* row escaped */
    memcpy(prev, row, (nb + 1) * sizeof(unsigned short));
  }
  return prev[nb] > limit ? limit + 1 : prev[nb];
}

int zlev_similarity_milli(const void *a, size_t na, const void *b,
                          size_t nb) {
  size_t d = zlev_distance(a, na, b, nb);
  size_t m = na > nb ? na : nb;
  if (d == SIZE_MAX) return -1;
  if (m == 0) return 1000;
  return (int)(1000u - (1000u * d) / m);
}
