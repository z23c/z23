/* zpath — bounded lexical path manipulation (POSIX-style)
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Purely lexical operations on slash-separated paths: join, normalize
 * (resolving "." and ".." without touching the filesystem), dirname,
 * basename, extension lookup, absoluteness test. No syscalls; nothing
 * here follows symlinks or checks existence.
 *
 * All producing functions use the measuring convention: they return
 * the number of bytes the full result needs (excluding NUL). If the
 * return value is >= cap, the output was truncated; when cap > 0 the
 * output is always NUL-terminated.
 *
 * Bounds: inputs longer than ZPATH_MAX (default 4096) are rejected
 * with ZPATH_RANGE from the validate-first entry points, or treated
 * as an error (needed-length return of SIZE_MAX) by the producers.
 */
#ifndef ZPATH_H
#define ZPATH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZPATH_MAX
#define ZPATH_MAX 4096u
#endif

typedef enum {
  ZPATH_OK = 0,
  ZPATH_ERR_ARG = 1,   /* NULL argument */
  ZPATH_ERR_RANGE = 2  /* input exceeds ZPATH_MAX */
} zpath_err;

/* Nonzero when path starts with '/'. Empty path: 0. NULL: 0. */
int zpath_isabs(const char *path);

/* Join a and b with exactly one '/'. If b is absolute the result is b
 * alone (POSIX convention). If a is empty the result is b. Trailing
 * '/' on a is not duplicated. Returns needed length, or SIZE_MAX on
 * NULL/over-long input. */
size_t zpath_join(char *dst, size_t cap, const char *a, const char *b);

/* Lexically normalize: collapse "//", resolve "." and "..", drop a
 * trailing '/' (except the root "/"). ".." at the root stays at the
 * root ("/.." -> "/"); ".." past the start of a relative path is kept
 * ("../.." , "../../x"). Empty input normalizes to ".".
 * Returns needed length, or SIZE_MAX on NULL/over-long input. */
size_t zpath_normalize(char *dst, size_t cap, const char *path);

/* POSIX dirname: "/a/b" -> "/a", "a/b" -> "a", "a" -> ".",
 * "/" -> "/", "" -> ".". Returns needed length, SIZE_MAX on bad
 * input. */
size_t zpath_dirname(char *dst, size_t cap, const char *path);

/* POSIX basename: "/a/b" -> "b", "/a/" -> "a", "/" -> "/", "" -> ".".
 * If suffix is non-NULL/non-empty and the basename ends with it (and
 * is longer than it), the suffix is stripped. Returns needed length,
 * SIZE_MAX on bad input. */
size_t zpath_basename(char *dst, size_t cap, const char *path,
                      const char *suffix);

/* Extension of the final component, including the dot, as a pointer
 * into path ("a/b.txt" -> ".txt"). NULL when the final component has
 * no dot, is dot-only ("." / ".."), or begins with the dot it would
 * return (".hidden" has no extension). Never outlives path. */
const char *zpath_ext(const char *path);

/* Validate: non-NULL and length <= ZPATH_MAX. */
zpath_err zpath_validate(const char *path);

const char *zpath_err_str(zpath_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZPATH_H */
