/* zstr — bounded, honest C string utilities (C23).
 *
 * strlcpy/strlcat-style copies that always NUL-terminate and report
 * truncation, trimming, case folding, prefix/suffix tests, occurrence
 * counting, and a zero-allocation split iterator.
 *
 * All inputs are NUL-terminated strings unless a length is taken.
 * NULL is never dereferenced.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZSTR_H
#define ZSTR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Copy src into dst (capacity cap), always NUL-terminating when
 * cap > 0. Returns strlen(src); a result >= cap means truncation. */
size_t zstr_copy(char *dst, size_t cap, const char *src);

/* Append src to the NUL-terminated string in dst (capacity cap).
 * Returns the length the combined string would have had; a result
 * >= cap means truncation. */
size_t zstr_concat(char *dst, size_t cap, const char *src);

/* Trim ASCII whitespace from both ends in place; returns s. */
char *zstr_trim(char *s);

/* Lowercase/uppercase ASCII in place; returns s. */
char *zstr_to_lower(char *s);
char *zstr_to_upper(char *s);

/* Case-insensitive ASCII comparisons. */
int  zstr_casecmp(const char *a, const char *b);
bool zstr_case_equal(const char *a, const char *b);

/* Prefix/suffix tests. */
bool zstr_starts_with(const char *s, const char *prefix);
bool zstr_ends_with(const char *s, const char *suffix);

/* Count non-overlapping occurrences of needle ("zstr_count("aaaa","aa")
 * is 2). Empty needle counts 0. */
size_t zstr_count(const char *s, const char *needle);

/* Split iterator over a delimiter character (empty fields kept).
 *
 *   zstr_split_it it;
 *   zstr_split_init(&it, "a,,b", ',');
 *   zstr_span span;
 *   while (zstr_split_next(&it, &span)) use(span.ptr, span.len);
 */
typedef struct {
    const char *cur;   /* remaining input */
    char        delim;
    bool        done;
} zstr_split_it;

typedef struct {
    const char *ptr;   /* not NUL-terminated */
    size_t      len;
} zstr_span;

void zstr_split_init(zstr_split_it *it, const char *s, char delim);
bool zstr_split_next(zstr_split_it *it, zstr_span *out);

#ifdef __cplusplus
}
#endif

#endif /* ZSTR_H */
