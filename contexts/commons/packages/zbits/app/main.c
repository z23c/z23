/* zbits CLI: set algebra over 0/1 bit strings from argv/stdin.
 *
 * Usage: zbits count <bits>          — popcount
 *        zbits rank <bits> <i>       — set bits below index i
 *        zbits first-set <bits>
 *        zbits first-clear <bits>
 *        zbits <or|and|andnot|xor-not> A B   — bitwise op, prints bits
 *        zbits flip-all <bits>
 * Bits are given as strings of '0'/'1' (index 0 leftmost). This is
 * the package's real consumer. */
#include "zbits/zbits.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXB 4096

static int parse_bits(const char *s, uint64_t *w, size_t *nbits) {
  size_t n = strlen(s), i;
  if (n == 0 || n > MAXB) return -1;
  if (zbits_init(w, n) != ZBITS_OK) return -1;
  for (i = 0; i < n; i++) {
    if (s[i] != '0' && s[i] != '1') return -1;
    if (s[i] == '1') zbits_set(w, n, i);
  }
  *nbits = n;
  return 0;
}

static void print_bits(const uint64_t *w, size_t nbits) {
  size_t i;
  for (i = 0; i < nbits; i++) putchar(zbits_test(w, nbits, i) ? '1' : '0');
  putchar('\n');
}

int main(int argc, char **argv) {
  static uint64_t a[MAXB / 64 + 1], b[MAXB / 64 + 1], d[MAXB / 64 + 1];
  size_t na, nb;
  if (argc < 3) goto usage;
  if (parse_bits(argv[2], a, &na) != 0) goto bad;
  if (strcmp(argv[1], "count") == 0 && argc == 3) {
    printf("%zu\n", zbits_count(a, na));
    return 0;
  }
  if (strcmp(argv[1], "first-set") == 0 && argc == 3) {
    size_t r = zbits_first_set(a, na);
    if (r == SIZE_MAX) {
      printf("none\n");
      return 1;
    }
    printf("%zu\n", r);
    return 0;
  }
  if (strcmp(argv[1], "first-clear") == 0 && argc == 3) {
    size_t r = zbits_first_clear(a, na);
    if (r == SIZE_MAX) {
      printf("none\n");
      return 1;
    }
    printf("%zu\n", r);
    return 0;
  }
  if (strcmp(argv[1], "rank") == 0 && argc == 4) {
    char *end = NULL;
    long i = strtol(argv[3], &end, 10);
    size_t r;
    if (end == argv[3] || *end != '\0' || i < 0) goto bad;
    r = zbits_rank(a, na, (size_t)i);
    if (r == SIZE_MAX) goto bad;
    printf("%zu\n", r);
    return 0;
  }
  if (strcmp(argv[1], "flip-all") == 0 && argc == 3) {
    zbits_flip_all(a, na);
    print_bits(a, na);
    return 0;
  }
  if (argc == 4 && (strcmp(argv[1], "or") == 0 ||
                    strcmp(argv[1], "and") == 0 ||
                    strcmp(argv[1], "andnot") == 0)) {
    zbits_err e;
    if (parse_bits(argv[3], b, &nb) != 0 || nb != na) goto bad;
    e = strcmp(argv[1], "or") == 0    ? zbits_or(d, a, b, na)
        : strcmp(argv[1], "and") == 0 ? zbits_and(d, a, b, na)
                                      : zbits_andnot(d, a, b, na);
    if (e != ZBITS_OK) goto bad;
    print_bits(d, na);
    return 0;
  }
usage:
  fprintf(stderr,
          "usage: zbits <count|first-set|first-clear|flip-all> BITS\n"
          "       zbits rank BITS I\n"
          "       zbits <or|and|andnot> A B\n");
  return 2;
bad:
  fprintf(stderr, "zbits: bad input\n");
  return 1;
}
