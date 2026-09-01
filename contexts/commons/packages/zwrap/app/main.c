/* zwrap CLI: wrap stdin to a width (default 72). */

#include "zwrap/zwrap.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  static char in[1 << 20];
  static char out[1 << 21];
  size_t n = 0;
  zwrap_opts o = zwrap_default_opts();
  if (argc > 1) {
    o.width = (size_t)atoi(argv[1]);
    if (o.width == 0) {
      fprintf(stderr, "usage: zwrap [WIDTH] < text\n");
      return 2;
    }
  }
  while (n < sizeof in) {
    size_t r = fread(in + n, 1, sizeof in - n, stdin);
    if (r == 0) break;
    n += r;
  }
  if (ferror(stdin)) {
    fprintf(stderr, "zwrap: read error\n");
    return 1;
  }
  zwrap(in, n, out, sizeof out, &o);
  fputs(out, stdout);
  return 0;
}
