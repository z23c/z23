/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded recursive directory traversal (see the header for the
 *          ordering, symlink, and error contract). */
#define _DEFAULT_SOURCE /* lstat */

#include "zwalk/zwalk.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Internal tri-state: ZWALK_STOP from a callback is a graceful end, not
 * an error, so it needs its own channel out of the recursion. */
typedef enum { WK_OK = 0, WK_STOP, WK_ERR } wk_status;

/* Growable name buffer for one directory's entries (sorted later). */
struct name_list {
  char **v;
  size_t n;
  size_t cap;
};

static bool name_push(struct name_list *nl, const char *name) {
  if (nl->n >= ZWALK_MAX_ENTRIES)
    return false; /* fan-out cap: fail closed */
  if (nl->n == nl->cap) {
    size_t ncap = nl->cap ? nl->cap * 2 : 16;
    char **nv = realloc(nl->v, ncap * sizeof(*nv));
    if (!nv)
      return false;
    nl->v = nv;
    nl->cap = ncap;
  }
  size_t len = strlen(name);
  char *copy = malloc(len + 1);
  if (!copy)
    return false;
  memcpy(copy, name, len + 1);
  nl->v[nl->n++] = copy;
  return true;
}

static void name_list_free(struct name_list *nl) {
  for (size_t i = 0; i < nl->n; i++)
    free(nl->v[i]);
  free(nl->v);
  nl->v = NULL;
  nl->n = nl->cap = 0;
}

static int name_cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static zwalk_type type_of(mode_t m) {
  if (S_ISREG(m))
    return ZWALK_FILE;
  if (S_ISDIR(m))
    return ZWALK_DIR;
  if (S_ISLNK(m))
    return ZWALK_SYMLINK;
  return ZWALK_OTHER;
}

static wk_status visit_node(const char *path, int depth,
                            const struct stat *st,
                            const struct zwalk_opts *opts,
                            zwalk_visit_fn visit, void *ctx) {
  zwalk_type t = type_of(st->st_mode);
  uint64_t size = S_ISREG(st->st_mode) ? (uint64_t)st->st_size : 0;
  zwalk_action a = visit(ctx, path, t, depth, size);
  if (a == ZWALK_STOP)
    return WK_STOP;
  if (a == ZWALK_SKIP || t != ZWALK_DIR || depth >= opts->max_depth)
    return WK_OK;

  /* Collect, sort, then visit: readdir order is unspecified. */
  DIR *dir = opendir(path);
  if (!dir)
    return WK_ERR;
  struct name_list nl = { NULL, 0, 0 };
  wk_status status = WK_OK;
  errno = 0;
  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
      continue;
    if (opts->skip_hidden && de->d_name[0] == '.')
      continue;
    if (!name_push(&nl, de->d_name)) {
      status = WK_ERR;
      break;
    }
  }
  if (errno != 0)
    status = WK_ERR; /* readdir failed mid-stream */
  closedir(dir);
  if (status == WK_OK && nl.n > 0)
    qsort(nl.v, nl.n, sizeof(nl.v[0]), name_cmp);

  size_t plen = strlen(path);
  bool slash = plen > 0 && path[plen - 1] == '/';
  for (size_t i = 0; status == WK_OK && i < nl.n; i++) {
    size_t nlen = strlen(nl.v[i]);
    if (plen + (slash ? 0 : 1) + nlen + 1 > PATH_MAX) {
      status = WK_ERR; /* path over the bound: fail closed */
      break;
    }
    char child[PATH_MAX];
    memcpy(child, path, plen);
    size_t at = plen;
    if (!slash)
      child[at++] = '/';
    memcpy(child + at, nl.v[i], nlen + 1);

    struct stat cst;
    int rc = opts->follow_symlinks ? stat(child, &cst) : lstat(child, &cst);
    if (rc != 0) {
      status = WK_ERR; /* includes dangling links when following */
      break;
    }
    status = visit_node(child, depth + 1, &cst, opts, visit, ctx);
  }
  name_list_free(&nl);
  return status;
}

bool zwalk(const char *root, const struct zwalk_opts *opts,
           zwalk_visit_fn visit, void *ctx) {
  if (!root || !visit || root[0] == '\0')
    return false;
  struct zwalk_opts o = { ZWALK_DEFAULT_MAX_DEPTH, false, false };
  if (opts)
    o = *opts;
  if (o.max_depth < 0)
    return false;
  struct stat st;
  int rc = o.follow_symlinks ? stat(root, &st) : lstat(root, &st);
  if (rc != 0)
    return false;
  return visit_node(root, 0, &st, &o, visit, ctx) != WK_ERR;
}
