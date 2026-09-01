/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: tiny find - print a directory tree in deterministic
 *          (sorted, depth-first) order.
 *
 * Usage: zwalk [-L] [-H] [-d N] DIR
 *   -L    follow symlinks (off by default; see the zwalk header)
 *   -H    skip dotfiles
 *   -d N  descend at most N levels (default 32)
 *
 * Exit 0 on success, 2 on misuse, 1 when the walk fails (unreadable
 * directory, over-long path, ...).
 */
#define _DEFAULT_SOURCE

#include "zwalk/zwalk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static zwalk_action show(void *ctx, const char *path, zwalk_type type,
                         int depth, uint64_t size) {
  (void)ctx;
  const char *name = strrchr(path, '/');
  name = name ? name + 1 : path;
  if (*name == '\0')
    name = path; /* root given with a trailing slash */
  for (int i = 0; i < depth; i++)
    fputs("  ", stdout);
  switch (type) {
  case ZWALK_DIR:
    printf("%s/\n", name);
    break;
  case ZWALK_FILE:
    printf("%s (%llu bytes)\n", name, (unsigned long long)size);
    break;
  case ZWALK_SYMLINK:
    printf("%s (symlink)\n", name);
    break;
  default:
    printf("%s (other)\n", name);
    break;
  }
  return ZWALK_GO;
}

static int usage(void) {
  fprintf(stderr, "usage: zwalk [-L] [-H] [-d N] DIR\n");
  return 2;
}

int main(int argc, char **argv) {
  struct zwalk_opts o = { ZWALK_DEFAULT_MAX_DEPTH, false, false };
  const char *dir = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-L") == 0) {
      o.follow_symlinks = true;
    } else if (strcmp(argv[i], "-H") == 0) {
      o.skip_hidden = true;
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      char *end = NULL;
      long d = strtol(argv[++i], &end, 10);
      if (!end || *end != '\0' || d < 0 || d > 1024)
        return usage();
      o.max_depth = (int)d;
    } else if (argv[i][0] != '-' && !dir) {
      dir = argv[i];
    } else {
      return usage();
    }
  }
  if (!dir)
    return usage();
  if (!zwalk(dir, &o, show, NULL)) {
    fprintf(stderr, "zwalk: walk of %s failed\n", dir);
    return 1;
  }
  if (fflush(stdout) != 0) {
    fprintf(stderr, "zwalk: flush failed\n");
    return 1;
  }
  return 0;
}
