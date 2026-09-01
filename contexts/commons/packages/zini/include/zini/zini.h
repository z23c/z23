/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: INI configuration parser over caller-supplied bytes.
 *
 * The library performs no filesystem I/O: the caller owns reading the
 * configuration and hands zini_parse() a byte span.  Parsed entries live in
 * zmap hash maps (one map of section name -> zmap* of key -> value), so
 * lookup is O(1)-ish and duplicate keys are resolved by map replacement.
 *
 * Grammar (documented, deliberately small):
 *  - Lines end on LF; a trailing CR is stripped (CRLF files work).
 *  - Blank lines and lines whose first non-space character is '#' or ';'
 *    are comments.
 *  - `[name]` opens a section; the name is trimmed of surrounding
 *    whitespace and may be empty.  Keys before any section header land in
 *    the global section, addressed by "" (or NULL in zini_get()).
 *  - `key = value`: the key is everything before the first '=', trimmed;
 *    it must be non-empty.  The value is trimmed of surrounding whitespace
 *    and may be empty.
 *  - Inline comments: a '#' or ';' inside a value starts a comment ONLY
 *    when preceded by a space or tab, so "a#b" is data but "a # b" is "a".
 *  - Duplicate keys: last wins, both within a section and across repeated
 *    sections of the same name.
 *  - No value quoting, no line continuation, no nesting.
 *
 * Iteration order: zini_foreach() visits entries in a deterministic sorted
 * order — sections lexicographically (the global section "" sorts first),
 * then keys lexicographically within each section.  It does NOT preserve
 * file order.
 *
 * Ownership: the returned zini owns copies of every section, key, and
 * value; the input bytes may be freed immediately after zini_parse().
 * zini_get() returns a pointer borrowed from the zini, valid until
 * zini_destroy().  All storage uses the malloc-backed zmap allocator.
 */
#ifndef ZINI_H
#define ZINI_H

#include <stdbool.h>
#include <stddef.h>

typedef struct zini zini;

/* Parse diagnostic.  On failure zini_parse() returns NULL and, when err is
 * non-NULL, fills it: line is 1-based, message is a short static string. */
typedef struct {
  size_t line;
  const char *message;
} zini_error;

[[nodiscard]] zini *zini_parse(const char *text, size_t len, zini_error *err);

void zini_destroy(zini *ini);

/* Lookup; section NULL means the global (pre-section) section.  Returns a
 * borrowed pointer or NULL when absent. */
const char *zini_get(const zini *ini, const char *section, const char *key);

/* Total number of key/value entries across all sections. */
size_t zini_count(const zini *ini);

/* Visit every entry in deterministic sorted order (see header notes). */
typedef void (*zini_entry_fn)(void *ctx, const char *section, const char *key,
                              const char *value);
void zini_foreach(const zini *ini, zini_entry_fn fn, void *ctx);

#endif /* ZINI_H */
