/* zsort CLI: sort integers from stdin; --stable and --index modes. */

#include "zsort/zsort.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_ll(const void *a, const void *b, void *ctx) {
  long long x = *(const long long *)a, y = *(const long long *)b;
  (void)ctx;
  return (x > y) - (x < y);
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
  while (n < (sizeof v / sizeof v[0]) && scanf("%lld", &v[n]) == 1) n++;
  if (index) {
    size_t k;
    if (!zargsort(perm, v, n, sizeof v[0], cmp_ll, NULL)) return 1;
    for (k = 0; k < n; k++) printf("%lld\n", v[perm[k]]);
  } else if (stable) {
    if (!zsort_stable(v, n, sizeof v[0], cmp_ll, NULL, scratch)) return 1;
    for (size_t k = 0; k < n; k++) printf("%lld\n", v[k]);
  } else {
    zsort(v, n, sizeof v[0], cmp_ll, NULL);
    for (size_t k = 0; k < n; k++) printf("%lld\n", v[k]);
  }
  return 0;
}
