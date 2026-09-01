/* zlev CLI: edit distance and similarity between strings.
 *
 * Usage: zlev [--limit N] A B
 *        zlev --sim A B
 * Prints the distance (or LIMIT+1 when bounded and exceeded), or with
 * --sim the milli-similarity. This is the package's real consumer. */
#include "zlev/zlev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  int sim = 0;
  long limit = -1;
  int i = 1;
  for (; i < argc - 2; i++) {
    if (strcmp(argv[i], "--sim") == 0) {
      sim = 1;
    } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc - 2) {
      char *end = NULL;
      limit = strtol(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || limit < 0) {
        fprintf(stderr, "zlev: bad --limit value\n");
        return 2;
      }
    } else {
      break;
    }
  }
  if (argc - i != 2) {
    fprintf(stderr, "usage: zlev [--sim] [--limit N] A B\n");
    return 2;
  }
  {
    const char *a = argv[i], *b = argv[i + 1];
    size_t na = strlen(a), nb = strlen(b);
    if (sim) {
      int m = zlev_similarity_milli(a, na, b, nb);
      if (m < 0) {
        fprintf(stderr, "zlev: input too long\n");
        return 1;
      }
      printf("%d.%03d\n", m / 1000, m % 1000);
      return 0;
    }
    {
      size_t d = limit >= 0 ? zlev_distance_bounded(a, na, b, nb,
                                                    (size_t)limit)
                            : zlev_distance(a, na, b, nb);
      if (d == SIZE_MAX) {
        fprintf(stderr, "zlev: input too long\n");
        return 1;
      }
      printf("%zu\n", d);
      return 0;
    }
  }
}
