/* zsort CLI: sort integers from stdin; --stable and --index modes. */

#include "zsort/zsort.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

static int cmp_ll(const void *a, const void *b, void *ctx) {
  long long x = *(const long long *)a, y = *(const long long *)b;
  (void)ctx;
  return (x > y) - (x < y);
}

static int read_magnitude(int *look, unsigned long long limit,
                          unsigned long long *result) {
  unsigned long long magnitude = 0;
  do {
    unsigned digit = (unsigned)(*look - '0');
    if (magnitude > (limit - digit) / 10) return -1;
    magnitude = magnitude * 10 + digit;
    *look = fgetc(stdin);
  } while (*look >= '0' && *look <= '9');
  if (*look == EOF && ferror(stdin)) return -2;
  *result = magnitude;
  return 1;
}

static long long signed_value(unsigned long long magnitude, bool negative) {
  if (negative && magnitude == (unsigned long long)LLONG_MAX + 1u) return LLONG_MIN;
  return negative ? -(long long)magnitude : (long long)magnitude;
}

/* One character of lookahead preserves scanf's adjacent signed decimals.
 * 1=value, 0=clean EOF, -1=invalid integer, -2=input error. */
static int read_integer(int *look, long long *value) {
  while (*look != EOF && isspace((unsigned char)*look)) *look = fgetc(stdin);
  if (*look == EOF) return ferror(stdin) ? -2 : 0;
  bool negative = *look == '-';
  if (*look == '-' || *look == '+') *look = fgetc(stdin);
  if (*look == EOF && ferror(stdin)) return -2;
  if (*look < '0' || *look > '9') return -1;
  unsigned long long magnitude;
  unsigned long long limit = (unsigned long long)LLONG_MAX + (negative ? 1u : 0u);
  int rc = read_magnitude(look, limit, &magnitude);
  if (rc < 0) return rc;
  *value = signed_value(magnitude, negative);
  return 1;
}

static int read_values(long long *v, size_t capacity, size_t *n) {
  int look = fgetc(stdin);
  for (;;) {
    long long value;
    int rc = read_integer(&look, &value);
    if (rc == 0) return 0;
    if (rc == -2) {
      fprintf(stderr, "zsort: input read failed\n");
      return 1;
    }
    if (rc < 0 || *n == capacity) {
      fprintf(stderr, "zsort: invalid integer or input capacity exceeded\n");
      return 2;
    }
    v[(*n)++] = value;
  }
}

static int print_values(const long long *v, const size_t *perm, size_t n) {
  for (size_t k = 0; k < n; k++) {
    if (printf("%lld\n", v[perm ? perm[k] : k]) < 0) goto failed;
  }
  if (!n || (fflush(stdout) == 0 && !ferror(stdout))) return 0;
failed:
  fprintf(stderr, "zsort: output write failed\n");
  return 1;
}

int main(int argc, char **argv) {
  static long long v[1 << 20];
  static long long scratch[1 << 20];
  static size_t perm[1 << 20];
  size_t n = 0;
  int stable = 0, index = 0;
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stable") == 0) {
      stable = 1;
    } else if (strcmp(argv[i], "--index") == 0) {
      index = 1;
    } else {
      fprintf(stderr, "usage: zsort [--stable] [--index] < ints\n");
      return 2;
    }
  }
  int rc = read_values(v, sizeof v / sizeof v[0], &n);
  if (rc) return rc;
  if (index) {
    if (!zargsort(perm, v, n, sizeof v[0], cmp_ll, NULL)) return 1;
  } else if (stable) {
    if (!zsort_stable(v, n, sizeof v[0], cmp_ll, NULL, scratch)) return 1;
  } else {
    zsort(v, n, sizeof v[0], cmp_ll, NULL);
  }
  return print_values(v, index ? perm : NULL, n);
}
