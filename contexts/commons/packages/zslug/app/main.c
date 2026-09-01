/* zslug CLI: slugify lines from stdin (or arguments). */

#include "zslug/zslug.h"

#include <stdio.h>
#include <string.h>

static void slug_line(const char *in, size_t len, char sep) {
  char buf[1024];
  zslug_opts o = zslug_default_opts();
  o.sep = sep;
  /* strip trailing newline */
  while (len > 0 && (in[len - 1] == '\n' || in[len - 1] == '\r')) len--;
  zslug(in, len, buf, sizeof buf, &o);
  puts(buf);
}

int main(int argc, char **argv) {
  char sep = '-';
  int argi = 1;
  if (argi < argc && strncmp(argv[argi], "-s", 2) == 0 &&
      strlen(argv[argi]) == 3) {
    sep = argv[argi][2];
    argi++;
  }
  if (argi < argc) {
    for (; argi < argc; argi++) slug_line(argv[argi], strlen(argv[argi]), sep);
    return 0;
  }
  {
    char line[4096];
    while (fgets(line, sizeof line, stdin)) slug_line(line, strlen(line), sep);
  }
  return 0;
}
