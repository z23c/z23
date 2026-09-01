/* zpath CLI: apply path operations to argv operands.
 *
 * Usage: zpath <op> [args...]
 *   zpath normalize PATH...
 *   zpath join A B
 *   zpath dirname PATH...
 *   zpath basename PATH [SUFFIX]
 *   zpath ext PATH...
 *   zpath isabs PATH...
 *
 * Prints one result per line; exit 1 on bad input, 2 on usage error.
 * This is the package's real consumer: it exercises every public
 * operation from the command line. */
#include "zpath/zpath.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int each1(const char *op, int argc, char **argv,
                 size_t (*fn)(char *, size_t, const char *)) {
  int i, rc = 0;
  for (i = 2; i < argc; i++) {
    char buf[ZPATH_MAX * 2 + 8];
    size_t need = fn(buf, sizeof(buf), argv[i]);
    if (need == SIZE_MAX) {
      fprintf(stderr, "zpath: %s: input too long\n", op);
      rc = 1;
      continue;
    }
    printf("%s\n", buf);
  }
  return rc;
}

static size_t norm_fn(char *b, size_t c, const char *p) {
  return zpath_normalize(b, c, p);
}
static size_t dir_fn(char *b, size_t c, const char *p) {
  return zpath_dirname(b, c, p);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr,
            "usage: zpath <normalize|join|dirname|basename|ext|isabs> "
            "[args...]\n");
    return 2;
  }
  if (strcmp(argv[1], "normalize") == 0) return each1("normalize", argc, argv, norm_fn);
  if (strcmp(argv[1], "dirname") == 0) return each1("dirname", argc, argv, dir_fn);
  if (strcmp(argv[1], "join") == 0) {
    char buf[ZPATH_MAX * 2 + 8];
    if (argc != 4) {
      fprintf(stderr, "usage: zpath join A B\n");
      return 2;
    }
    if (zpath_join(buf, sizeof(buf), argv[2], argv[3]) == SIZE_MAX) {
      fprintf(stderr, "zpath: join: input too long\n");
      return 1;
    }
    printf("%s\n", buf);
    return 0;
  }
  if (strcmp(argv[1], "basename") == 0) {
    char buf[ZPATH_MAX + 8];
    if (argc < 3 || argc > 4) {
      fprintf(stderr, "usage: zpath basename PATH [SUFFIX]\n");
      return 2;
    }
    if (zpath_basename(buf, sizeof(buf), argv[2],
                       argc == 4 ? argv[3] : NULL) == SIZE_MAX) {
      fprintf(stderr, "zpath: basename: input too long\n");
      return 1;
    }
    printf("%s\n", buf);
    return 0;
  }
  if (strcmp(argv[1], "ext") == 0) {
    int i;
    for (i = 2; i < argc; i++) {
      const char *e = zpath_ext(argv[i]);
      printf("%s\n", e != NULL ? e : "");
    }
    return 0;
  }
  if (strcmp(argv[1], "isabs") == 0) {
    int i, rc = 0;
    for (i = 2; i < argc; i++) {
      int a = zpath_isabs(argv[i]);
      printf("%s: %s\n", argv[i], a ? "absolute" : "relative");
      if (!a) rc = 1;
    }
    return rc;
  }
  fprintf(stderr, "zpath: unknown op '%s'\n", argv[1]);
  return 2;
}
