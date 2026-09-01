/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zwalk test suite.  Builds its own fixture tree under a
 *          relative directory in the cwd (sandbox-friendly: no /tmp, no
 *          TMPDIR).  Exits nonzero on any failure. */
#define _DEFAULT_SOURCE /* getpid, symlink */

#include "zwalk/zwalk.h"

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* ---------- fixture ---------- */

static char root[256];

static void path_to(char *buf, size_t cap, const char *rel) {
  int n = snprintf(buf, cap, "%s/%s", root, rel);
  if (n < 0 || (size_t)n >= cap) {
    fprintf(stderr, "fixture path too long\n");
    exit(2);
  }
}

static void mkfile(const char *rel, const char *content) {
  char p[512];
  path_to(p, sizeof(p), rel);
  FILE *f = fopen(p, "wb");
  if (!f) {
    perror("mkfile");
    exit(2);
  }
  if (fputs(content, f) == EOF || fclose(f) != 0) {
    perror("mkfile write");
    exit(2);
  }
}

static void mkdir_rel(const char *rel) {
  char p[512];
  path_to(p, sizeof(p), rel);
  if (mkdir(p, 0700) != 0) {
    perror("mkdir");
    exit(2);
  }
}

static void symlink_rel(const char *target, const char *rel) {
  char p[512];
  path_to(p, sizeof(p), rel);
  if (symlink(target, p) != 0) {
    perror("symlink");
    exit(2);
  }
}

/* Fixture layout (sorted names at each level):
 *   root/
 *     .hidden        file "x"     (1 byte)
 *     a.txt          file "hello" (5 bytes)
 *     dlink -> sub   symlink to a directory
 *     empty/         directory
 *     sub/
 *       b.txt        file "bb"    (2 bytes)
 *       deep/
 *         c.txt      file "ccc"   (3 bytes)
 *     zlink -> a.txt symlink to a file
 */
/* Fixture root: a relative path in the current working directory, never
 * /tmp and never TMPDIR — confined verifiers scrub the environment and
 * make everything but the cwd read-only. Retry a few suffixes in case a
 * crashed earlier run left a directory behind. */
static void build_fixture(void) {
  bool made = false;
  for (int attempt = 0; !made && attempt < 100; attempt++) {
    int n = snprintf(root, sizeof(root), "zwalk-test-fixture-%ld-%d",
                     (long)getpid(), attempt);
    if (n < 0 || (size_t)n >= sizeof(root)) {
      fprintf(stderr, "fixture path too long\n");
      exit(2);
    }
    if (mkdir(root, 0700) == 0)
      made = true;
    else if (errno != EEXIST) {
      perror("mkdir fixture");
      exit(2);
    }
  }
  if (!made) {
    fprintf(stderr, "no free fixture directory name\n");
    exit(2);
  }
  mkfile(".hidden", "x");
  mkfile("a.txt", "hello");
  mkdir_rel("sub");
  symlink_rel("sub", "dlink");
  mkdir_rel("empty");
  mkfile("sub/b.txt", "bb");
  mkdir_rel("sub/deep");
  mkfile("sub/deep/c.txt", "ccc");
  symlink_rel("a.txt", "zlink");
}

static void cleanup_fixture(void) {
  char p[512];
  const char *files[] = { "sub/deep/c.txt", "sub/b.txt", "zlink", "dlink",
                          "a.txt", ".hidden" };
  const char *dirs[] = { "sub/deep", "sub", "empty" };
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    path_to(p, sizeof(p), files[i]);
    if (remove(p) != 0)
      perror("cleanup file");
  }
  for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    path_to(p, sizeof(p), dirs[i]);
    if (rmdir(p) != 0)
      perror("cleanup dir");
  }
  if (rmdir(root) != 0)
    perror("cleanup root");
}

/* ---------- recording callbacks ---------- */

#define MAX_VISITS 64
static char visits[MAX_VISITS][600];
static int nvisits;

static char type_char(zwalk_type t) {
  switch (t) {
  case ZWALK_FILE: return 'F';
  case ZWALK_DIR: return 'D';
  case ZWALK_SYMLINK: return 'S';
  default: return 'O';
  }
}

static zwalk_action record(void *ctx, const char *path, zwalk_type type,
                           int depth, uint64_t size) {
  (void)ctx;
  if (nvisits < MAX_VISITS)
    snprintf(visits[nvisits++], sizeof(visits[0]), "%c %d %llu %s",
             type_char(type), depth, (unsigned long long)size, path);
  return ZWALK_GO;
}

/* Expected-visit builder: entries are formatted with the fixture root. */
static char want[MAX_VISITS][600];
static int nwant;

#define W(...)                                                               \
  do {                                                                       \
    snprintf(want[nwant++], sizeof(want[0]), __VA_ARGS__);                   \
  } while (0)

static void check_walk(const char *what, const struct zwalk_opts *o) {
  nvisits = 0;
  if (!zwalk(root, o, record, NULL)) {
    fprintf(stderr, "FAIL %s: zwalk returned false\n", what);
    failures++;
    return;
  }
  if (nvisits != nwant) {
    fprintf(stderr, "FAIL %s: got %d visits, want %d\n", what, nvisits,
            nwant);
    failures++;
  }
  int n = nvisits < nwant ? nvisits : nwant;
  for (int i = 0; i < n; i++) {
    if (strcmp(visits[i], want[i]) != 0) {
      fprintf(stderr, "FAIL %s visit[%d]:\n  got:  %s\n  want: %s\n", what,
              i, visits[i], want[i]);
      failures++;
    }
  }
}

/* Full default walk: deterministic sorted pre-order, symlinks not
 * followed, hidden files included. */
static void test_default_walk(void) {
  nwant = 0;
  W("D 0 0 %s", root);
  W("F 1 1 %s/.hidden", root);
  W("F 1 5 %s/a.txt", root);
  W("S 1 0 %s/dlink", root);
  W("D 1 0 %s/empty", root);
  W("D 1 0 %s/sub", root);
  W("F 2 2 %s/sub/b.txt", root);
  W("D 2 0 %s/sub/deep", root);
  W("F 3 3 %s/sub/deep/c.txt", root);
  W("S 1 0 %s/zlink", root);
  check_walk("default", NULL);
}

static void test_depth_limit(void) {
  struct zwalk_opts o = { 1, false, false };
  nwant = 0;
  W("D 0 0 %s", root);
  W("F 1 1 %s/.hidden", root);
  W("F 1 5 %s/a.txt", root);
  W("S 1 0 %s/dlink", root);
  W("D 1 0 %s/empty", root);
  W("D 1 0 %s/sub", root);
  W("S 1 0 %s/zlink", root);
  check_walk("max_depth=1", &o);

  o.max_depth = 0;
  nwant = 0;
  W("D 0 0 %s", root);
  check_walk("max_depth=0", &o);
}

static void test_skip_hidden(void) {
  struct zwalk_opts o = { ZWALK_DEFAULT_MAX_DEPTH, true, false };
  nwant = 0;
  W("D 0 0 %s", root);
  W("F 1 5 %s/a.txt", root);
  W("S 1 0 %s/dlink", root);
  W("D 1 0 %s/empty", root);
  W("D 1 0 %s/sub", root);
  W("F 2 2 %s/sub/b.txt", root);
  W("D 2 0 %s/sub/deep", root);
  W("F 3 3 %s/sub/deep/c.txt", root);
  W("S 1 0 %s/zlink", root);
  check_walk("skip_hidden", &o);
}

static void test_follow_symlinks(void) {
  struct zwalk_opts o = { ZWALK_DEFAULT_MAX_DEPTH, false, true };
  nwant = 0;
  W("D 0 0 %s", root);
  W("F 1 1 %s/.hidden", root);
  W("F 1 5 %s/a.txt", root);
  W("D 1 0 %s/dlink", root); /* resolved to a directory and descended */
  W("F 2 2 %s/dlink/b.txt", root);
  W("D 2 0 %s/dlink/deep", root);
  W("F 3 3 %s/dlink/deep/c.txt", root);
  W("D 1 0 %s/empty", root);
  W("D 1 0 %s/sub", root);
  W("F 2 2 %s/sub/b.txt", root);
  W("D 2 0 %s/sub/deep", root);
  W("F 3 3 %s/sub/deep/c.txt", root);
  W("F 1 5 %s/zlink", root); /* resolved to a regular file */
  check_walk("follow_symlinks", &o);
}

/* Prune: ZWALK_SKIP on a directory keeps it visited but not descended. */
static zwalk_action prune_sub(void *ctx, const char *path, zwalk_type type,
                              int depth, uint64_t size) {
  (void)ctx;
  (void)type;
  (void)depth;
  (void)size;
  const char *base = strrchr(path, '/');
  if (base && strcmp(base, "/sub") == 0) {
    record(ctx, path, type, depth, size); /* visited, not descended */
    return ZWALK_SKIP;
  }
  return record(ctx, path, type, depth, size);
}

static void test_prune(void) {
  nvisits = 0;
  CHECK(zwalk(root, NULL, prune_sub, NULL));
  nwant = 0;
  W("D 0 0 %s", root);
  W("F 1 1 %s/.hidden", root);
  W("F 1 5 %s/a.txt", root);
  W("S 1 0 %s/dlink", root);
  W("D 1 0 %s/empty", root);
  W("D 1 0 %s/sub", root); /* visited, children skipped */
  W("S 1 0 %s/zlink", root);
  if (nvisits != nwant) {
    fprintf(stderr, "FAIL prune: got %d visits, want %d\n", nvisits, nwant);
    failures++;
  }
  int n = nvisits < nwant ? nvisits : nwant;
  for (int i = 0; i < n; i++) {
    if (strcmp(visits[i], want[i]) != 0) {
      fprintf(stderr, "FAIL prune visit[%d]:\n  got:  %s\n  want: %s\n", i,
              visits[i], want[i]);
      failures++;
    }
  }
}

/* Stop: ZWALK_STOP ends the walk early but is not an error. */
static zwalk_action stop_at_a(void *ctx, const char *path, zwalk_type type,
                              int depth, uint64_t size) {
  const char *base = strrchr(path, '/');
  if (base && strcmp(base, "/a.txt") == 0) {
    record(ctx, path, type, depth, size);
    return ZWALK_STOP;
  }
  return record(ctx, path, type, depth, size);
}

static void test_stop(void) {
  nvisits = 0;
  CHECK(zwalk(root, NULL, stop_at_a, NULL)); /* STOP: still success */
  nwant = 0;
  W("D 0 0 %s", root);
  W("F 1 1 %s/.hidden", root);
  W("F 1 5 %s/a.txt", root);
  CHECK(nvisits == nwant);
  for (int i = 0; i < nvisits && i < nwant; i++)
    CHECK(strcmp(visits[i], want[i]) == 0);
}

static void test_fail_closed(void) {
  struct zwalk_opts neg = { -1, false, false };
  struct zwalk_opts ok = { ZWALK_DEFAULT_MAX_DEPTH, false, false };
  CHECK(!zwalk(NULL, NULL, record, NULL));
  CHECK(!zwalk("", NULL, record, NULL));
  CHECK(!zwalk(root, NULL, NULL, NULL));
  CHECK(!zwalk(root, &neg, record, NULL));
  CHECK(!zwalk("/nonexistent/zwalk-test-nope", NULL, record, NULL));
  /* a plain file as root is legal: visited once at depth 0 */
  char f[512];
  path_to(f, sizeof(f), "a.txt");
  nvisits = 0;
  CHECK(zwalk(f, &ok, record, NULL));
  CHECK(nvisits == 1);
  if (nvisits == 1) {
    char w[600];
    snprintf(w, sizeof(w), "F 0 5 %s", f);
    CHECK(strcmp(visits[0], w) == 0);
  }
}

int main(void) {
  build_fixture();
  test_default_walk();
  test_depth_limit();
  test_skip_hidden();
  test_follow_symlinks();
  test_prune();
  test_stop();
  test_fail_closed();
  cleanup_fixture();
  if (failures) {
    fprintf(stderr, "zwalk: %d failure(s)\n", failures);
    return 1;
  }
  printf("zwalk: all tests passed\n");
  return 0;
}
