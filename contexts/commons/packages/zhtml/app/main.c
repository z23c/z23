/* zhtml CLI: escape or unescape argv strings / stdin.
 *
 * Usage: zhtml <escape|unescape> [STRING...]
 * With no STRING, processes stdin. Exit 1 on malformed input, 2 on
 * usage error. This is the package's real consumer. */
#include "zhtml/zhtml.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int do_stream(int un) {
  char in[8192];
  char out[sizeof(in) * 6 + 1];
  size_t n;
  while ((n = fread(in, 1, sizeof(in), stdin)) > 0) {
    size_t need = un ? zhtml_unescape(out, sizeof(out), in, n)
                     : zhtml_escape(out, sizeof(out), in, n);
    if (need == SIZE_MAX || need >= sizeof(out)) {
      fprintf(stderr, "zhtml: %s: %s\n", un ? "unescape" : "escape",
              un ? "malformed entity" : "output overflow");
      return 1;
    }
    if (fwrite(out, 1, need, stdout) != need) {
      fprintf(stderr, "zhtml: write error\n");
      return 1;
    }
  }
  if (ferror(stdin)) {
    fprintf(stderr, "zhtml: error reading stdin\n");
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  int un;
  if (argc < 2) {
    fprintf(stderr, "usage: zhtml <escape|unescape> [STRING...]\n");
    return 2;
  }
  un = strcmp(argv[1], "unescape") == 0;
  if (!un && strcmp(argv[1], "escape") != 0) {
    fprintf(stderr, "zhtml: unknown op '%s'\n", argv[1]);
    return 2;
  }
  if (argc > 2) {
    int i, rc = 0;
    for (i = 2; i < argc; i++) {
      static char buf[ZHTML_MAX + 8];
      size_t n = strlen(argv[i]);
      size_t need = un ? zhtml_unescape(buf, sizeof(buf), argv[i], n)
                       : zhtml_escape(buf, sizeof(buf), argv[i], n);
      if (need == SIZE_MAX || need >= sizeof(buf)) {
        fprintf(stderr, "zhtml: %s: bad input '%s'\n",
                un ? "unescape" : "escape", argv[i]);
        rc = 1;
        continue;
      }
      if (fwrite(buf, 1, need, stdout) != need) return 1;
      putchar('\n');
    }
    return rc;
  }
  return do_stream(un);
}
