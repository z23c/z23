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

struct output_state { bool attempted, failed; };

static bool record_output(struct output_state *out, int written) {
  out->attempted = true;
  if (written < 0) out->failed = true;
  return !out->failed;
}

static int finish_output(const struct output_state *out, int result) {
  if (out->attempted && (out->failed || fflush(stdout) != 0 || ferror(stdout))) {
    fprintf(stderr, "zpath: write error\n");
    return 1;
  }
  return result;
}

static int each1(const char *op, int argc, char **argv,
                 size_t (*fn)(char *, size_t, const char *), struct output_state *out) {
  int i, rc = 0;
  for (i = 2; i < argc; i++) {
    char buf[ZPATH_MAX * 2 + 8];
    size_t need = fn(buf, sizeof(buf), argv[i]);
    if (need == SIZE_MAX) {
      fprintf(stderr, "zpath: %s: input too long\n", op);
      rc = 1;
      continue;
    }
    if (!record_output(out, printf("%s\n", buf))) return 1;
  }
  return rc;
}

static size_t norm_fn(char *b, size_t c, const char *p) {
  return zpath_normalize(b, c, p);
}
static size_t dir_fn(char *b, size_t c, const char *p) {
  return zpath_dirname(b, c, p);
}

static int join_paths(int argc, char **argv, struct output_state *out) {
  char buf[ZPATH_MAX * 2 + 8];
  if (argc != 4) {
    fprintf(stderr, "usage: zpath join A B\n");
    return 2;
  }
  if (zpath_join(buf, sizeof(buf), argv[2], argv[3]) == SIZE_MAX) {
    fprintf(stderr, "zpath: join: input too long\n");
    return 1;
  }
  record_output(out, printf("%s\n", buf));
  return 0;
}

static int basename_path(int argc, char **argv, struct output_state *out) {
  char buf[ZPATH_MAX + 8];
  if (argc < 3 || argc > 4) {
    fprintf(stderr, "usage: zpath basename PATH [SUFFIX]\n");
    return 2;
  }
  if (zpath_basename(buf, sizeof(buf), argv[2], argc == 4 ? argv[3] : NULL) == SIZE_MAX) {
    fprintf(stderr, "zpath: basename: input too long\n");
    return 1;
  }
  record_output(out, printf("%s\n", buf));
  return 0;
}

static int extensions(int argc, char **argv, struct output_state *out) {
  for (int i = 2; i < argc; i++) {
    const char *e = zpath_ext(argv[i]);
    if (!record_output(out, printf("%s\n", e != NULL ? e : ""))) return 1;
  }
  return 0;
}

static int absolute_paths(int argc, char **argv, struct output_state *out) {
  int rc = 0;
  for (int i = 2; i < argc; i++) {
    int a = zpath_isabs(argv[i]);
    if (!record_output(out, printf("%s: %s\n", argv[i], a ? "absolute" : "relative"))) return 1;
    if (!a) rc = 1;
  }
  return rc;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: zpath <normalize|join|dirname|basename|ext|isabs> [args...]\n");
    return 2;
  }
  struct output_state out = {0};
  int rc;
  if (strcmp(argv[1], "normalize") == 0) rc = each1("normalize", argc, argv, norm_fn, &out);
  else if (strcmp(argv[1], "dirname") == 0) rc = each1("dirname", argc, argv, dir_fn, &out);
  else if (strcmp(argv[1], "join") == 0) rc = join_paths(argc, argv, &out);
  else if (strcmp(argv[1], "basename") == 0) rc = basename_path(argc, argv, &out);
  else if (strcmp(argv[1], "ext") == 0) rc = extensions(argc, argv, &out);
  else if (strcmp(argv[1], "isabs") == 0) rc = absolute_paths(argc, argv, &out);
  else {
    fprintf(stderr, "zpath: unknown op '%s'\n", argv[1]);
    return 2;
  }
  return finish_output(&out, rc);
}
