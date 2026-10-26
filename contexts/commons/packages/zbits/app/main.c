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

static int finish_output(int written, int status) {
  if (written < 0 || fflush(stdout) != 0 || ferror(stdout)) {
    fputs("zbits: output write failed\n", stderr);
    return 1;
  }
  return status;
}

static int print_bits(const uint64_t *w, size_t nbits) {
  size_t i;
  for (i = 0; i < nbits; i++)
    if (putchar(zbits_test(w, nbits, i) ? '1' : '0') == EOF)
      return finish_output(EOF, 0);
  return finish_output(putchar('\n'), 0);
}

int main(int argc, char **argv) {
  static uint64_t a[MAXB / 64 + 1], b[MAXB / 64 + 1], d[MAXB / 64 + 1];
  size_t na, nb;
  if (argc < 3) goto usage;
  if (parse_bits(argv[2], a, &na) != 0) goto bad;
  if (strcmp(argv[1], "count") == 0 && argc == 3) {
    return finish_output(printf("%zu\n", zbits_count(a, na)), 0);
  }
  if (strcmp(argv[1], "first-set") == 0 && argc == 3) {
    size_t r = zbits_first_set(a, na);
    if (r == SIZE_MAX) {
      return finish_output(printf("none\n"), 1);
    }
    return finish_output(printf("%zu\n", r), 0);
  }
  if (strcmp(argv[1], "first-clear") == 0 && argc == 3) {
    size_t r = zbits_first_clear(a, na);
    if (r == SIZE_MAX) {
      return finish_output(printf("none\n"), 1);
    }
    return finish_output(printf("%zu\n", r), 0);
  }
  if (strcmp(argv[1], "rank") == 0 && argc == 4) {
    char *end = NULL;
    long i = strtol(argv[3], &end, 10);
    size_t r;
    if (end == argv[3] || *end != '\0' || i < 0) goto bad;
    r = zbits_rank(a, na, (size_t)i);
    if (r == SIZE_MAX) goto bad;
    return finish_output(printf("%zu\n", r), 0);
  }
  if (strcmp(argv[1], "flip-all") == 0 && argc == 3) {
    zbits_flip_all(a, na);
    return print_bits(a, na);
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
    return print_bits(d, na);
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
