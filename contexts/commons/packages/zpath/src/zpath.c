/* zpath — bounded lexical path manipulation. See include/zpath/zpath.h. */
#include "zpath/zpath.h"

#include <stdint.h>
#include <string.h>

const char *zpath_err_str(zpath_err e) {
  switch (e) {
  case ZPATH_OK: return "ok";
  case ZPATH_ERR_ARG: return "invalid argument";
  case ZPATH_ERR_RANGE: return "bound exceeded";
  }
  return "unknown error";
}

/* Length of s, or SIZE_MAX when s is NULL or longer than ZPATH_MAX. */
static size_t zpath__len(const char *s) {
  size_t n = 0;
  if (s == NULL) return SIZE_MAX;
  while (s[n] != '\0') {
    if (n >= ZPATH_MAX) return SIZE_MAX;
    n++;
  }
  return n;
}

zpath_err zpath_validate(const char *path) {
  size_t n = zpath__len(path);
  if (n == SIZE_MAX) return path == NULL ? ZPATH_ERR_ARG : ZPATH_ERR_RANGE;
  return ZPATH_OK;
}

int zpath_isabs(const char *path) {
  return path != NULL && path[0] == '/';
}

/* Copy src[0..n) into dst with the measuring convention. */
static size_t zpath__emit(char *dst, size_t cap, const char *src, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    if (dst != NULL && i + 1 < cap) dst[i] = src[i];
  if (dst != NULL && cap > 0) dst[n < cap ? n : cap - 1] = '\0';
  return n;
}

size_t zpath_join(char *dst, size_t cap, const char *a, const char *b) {
  size_t na = zpath__len(a), nb = zpath__len(b);
  size_t need, pos = 0;
  if (na == SIZE_MAX || nb == SIZE_MAX) return SIZE_MAX;
  if (zpath_isabs(b) || na == 0) return zpath__emit(dst, cap, b, nb);
  /* a + optional '/' + b */
  need = na + (a[na - 1] != '/' ? 1u : 0u) + nb;
  if (need > ZPATH_MAX * 2u) return SIZE_MAX;
  {
    char tmp[ZPATH_MAX * 2u + 1u];
    memcpy(tmp, a, na);
    pos = na;
    if (a[na - 1] != '/') tmp[pos++] = '/';
    memcpy(tmp + pos, b, nb);
    pos += nb;
    return zpath__emit(dst, cap, tmp, pos);
  }
}

#define ZPATH__MAX_COMP ((ZPATH_MAX / 2u) + 2u)

size_t zpath_normalize(char *dst, size_t cap, const char *path) {
  size_t n = zpath__len(path);
  unsigned short starts[ZPATH__MAX_COMP], lens[ZPATH__MAX_COMP];
  size_t ncomp = 0, i;
  int absolute;
  char tmp[ZPATH_MAX + 2u];
  size_t out = 0;
  if (n == SIZE_MAX) return SIZE_MAX;
  if (n == 0) return zpath__emit(dst, cap, ".", 1);
  absolute = path[0] == '/';
  i = 0;
  while (i < n) {
    size_t s, e;
    while (i < n && path[i] == '/') i++;
    if (i >= n) break;
    s = i;
    while (i < n && path[i] != '/') i++;
    e = i;
    if (e - s == 1 && path[s] == '.') continue;
    if (e - s == 2 && path[s] == '.' && path[s + 1] == '.') {
      if (ncomp > 0 &&
          !(lens[ncomp - 1] == 2 && path[starts[ncomp - 1]] == '.' &&
            path[starts[ncomp - 1] + 1] == '.')) {
        ncomp--; /* pop the previous real component */
      } else if (absolute) {
        /* ".." at the root stays at the root: drop it */
      } else {
        starts[ncomp] = (unsigned short)s;
        lens[ncomp] = 2;
        ncomp++;
      }
      continue;
    }
    starts[ncomp] = (unsigned short)s;
    lens[ncomp] = (unsigned short)(e - s);
    ncomp++;
  }
  if (absolute) tmp[out++] = '/';
  for (i = 0; i < ncomp; i++) {
    if (i > 0) tmp[out++] = '/';
    memcpy(tmp + out, path + starts[i], lens[i]);
    out += lens[i];
  }
  if (out == 0) {
    tmp[0] = '.';
    out = 1;
  }
  return zpath__emit(dst, cap, tmp, out);
}

size_t zpath_basename(char *dst, size_t cap, const char *path,
                      const char *suffix) {
  size_t n = zpath__len(path);
  size_t end, beg, blen;
  if (n == SIZE_MAX) return SIZE_MAX;
  if (n == 0) return zpath__emit(dst, cap, ".", 1);
  end = n;
  while (end > 0 && path[end - 1] == '/') end--;
  if (end == 0) return zpath__emit(dst, cap, "/", 1); /* all slashes */
  beg = end;
  while (beg > 0 && path[beg - 1] != '/') beg--;
  blen = end - beg;
  if (suffix != NULL) {
    size_t ns = zpath__len(suffix);
    if (ns == SIZE_MAX) return SIZE_MAX;
    if (ns > 0 && blen > ns && memcmp(path + beg + blen - ns, suffix, ns) == 0)
      blen -= ns;
  }
  return zpath__emit(dst, cap, path + beg, blen);
}

size_t zpath_dirname(char *dst, size_t cap, const char *path) {
  size_t n = zpath__len(path);
  size_t end;
  if (n == SIZE_MAX) return SIZE_MAX;
  if (n == 0) return zpath__emit(dst, cap, ".", 1);
  end = n;
  while (end > 0 && path[end - 1] == '/') end--; /* strip trailing '/' */
  while (end > 0 && path[end - 1] != '/') end--; /* remove last comp */
  while (end > 0 && path[end - 1] == '/') end--; /* strip separators */
  if (end == 0)
    return zpath__emit(dst, cap, path[0] == '/' ? "/" : ".", 1);
  return zpath__emit(dst, cap, path, end);
}

const char *zpath_ext(const char *path) {
  size_t n, beg, i, dot = SIZE_MAX;
  if (path == NULL) return NULL;
  n = strlen(path);
  if (n == 0 || n > ZPATH_MAX) return NULL;
  beg = n;
  while (beg > 0 && path[beg - 1] != '/') beg--; /* final component start */
  if (n - beg == 1 && path[beg] == '.') return NULL; /* "." */
  if (n - beg == 2 && path[beg] == '.' && path[beg + 1] == '.')
    return NULL; /* ".." */
  for (i = n; i > beg; i--)
    if (path[i - 1] == '.') {
      dot = i - 1;
      break;
    }
  if (dot == SIZE_MAX || dot == beg) return NULL; /* none or ".hidden" */
  return path + dot;
}
