/* zbuf CLI: build a report from stdin lines to exercise the buffer.
 *
 * Usage: zbuf [MAX]
 * Reads stdin, prepends line numbers into a MAX-bounded buffer
 * (default 1 MiB), and prints it. Demonstrates append, printf, and
 * the sticky-error path (exit 1 with "bound reached"). This is the
 * package's real consumer. */
#include "zbuf/zbuf.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  size_t max = 1u << 20;
  zbuf b;
  char line[4096];
  size_t n = 0;
  if (argc > 1) {
    char *end = NULL;
    long m = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || m < 0) {
      fprintf(stderr, "zbuf: bad max\n");
      return 2;
    }
    max = (size_t)m;
  }
  zbuf_init(&b, max);
  while (fgets(line, sizeof(line), stdin) != NULL) {
    n++;
    if (zbuf_printf(&b, "%6zu\t%s", n, line) != ZBUF_OK) {
      fprintf(stderr, "zbuf: %s after %zu bytes (line %zu)\n",
              zbuf_err_str(zbuf_status(&b)), zbuf_len(&b), n);
      zbuf_free(&b);
      return 1;
    }
  }
  if (ferror(stdin)) {
    fprintf(stderr, "zbuf: error reading stdin\n");
    zbuf_free(&b);
    return 1;
  }
  if (fwrite(zbuf_cstr(&b), 1, zbuf_len(&b), stdout) != zbuf_len(&b)) {
    fprintf(stderr, "zbuf: write error\n");
    zbuf_free(&b);
    return 1;
  }
  fprintf(stderr, "ok: %zu lines, %zu bytes\n", n, zbuf_len(&b));
  zbuf_free(&b);
  return 0;
}
