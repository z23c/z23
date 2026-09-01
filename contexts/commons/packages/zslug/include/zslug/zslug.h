/*
 * zslug — deterministic URL/filename slug generation.
 *
 * Turns arbitrary UTF-8 text into a lowercase ASCII slug:
 *   - ASCII letters are lowercased, ASCII digits kept.
 *   - Latin-1 supplement letters (U+00C0..U+00FF) fold to their ASCII
 *     base letter (e.g. U+00E9 'e with acute' -> 'e'); the letters
 *     eth, thorn, sharp-s and ligatures fold to digraphs where that is
 *     the conventional ASCII spelling.
 *   - Every other byte or codepoint (including malformed UTF-8) acts as
 *     a word separator.
 *   - Runs of separators collapse to a single separator byte; leading
 *     and trailing separators are dropped.
 *
 * The fold is deliberately small and documented: this is not full
 * Unicode transliteration.  Input outside ASCII and the Latin-1
 * supplement is stripped to separators, never guessed at.
 *
 * Output convention mirrors snprintf: the return value is the slug
 * length that WOULD have been written given unlimited capacity
 * (excluding the NUL), so callers can detect truncation by comparing
 * the result against out_cap.  The output is always NUL-terminated
 * when out_cap > 0.  A truncated slug never ends on a separator:
 * truncation happens at a word boundary whenever possible.
 */
#ifndef ZSLUG_H
#define ZSLUG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  char sep;        /* separator byte; must be printable non-alphanumeric
                    * ASCII, else '-' is used; default '-' */
  size_t max_len;  /* hard cap on slug length; 0 means unlimited */
  int fold_case;   /* nonzero: lowercase ASCII output (default behaviour) */
} zslug_opts;

/* Default options: '-', unlimited, fold case. */
zslug_opts zslug_default_opts(void);

/*
 * Slugify in[0..in_len) into out[0..out_cap).
 * Returns the untruncated slug length (excluding NUL).  If the return
 * value is >= out_cap, or >= opts.max_len when set, the output was
 * truncated; out still holds a valid, word-boundary-trimmed slug.
 * NULL out with out_cap 0 is legal for pure length measurement.
 * NULL in with in_len > 0 returns 0 and writes an empty string.
 */
size_t zslug(const char *in, size_t in_len, char *out, size_t out_cap,
             const zslug_opts *opts);

/* Convenience: validate that a string already is a canonical slug
 * under the given options (only [a-z0-9] and single separators, no
 * leading/trailing/doubled separator, within max_len).  Returns 1 or 0. */
int zslug_is_canonical(const char *s, size_t len, const zslug_opts *opts);

#ifdef __cplusplus
}
#endif

#endif /* ZSLUG_H */
