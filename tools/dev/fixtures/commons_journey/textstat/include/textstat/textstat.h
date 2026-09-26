/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * textstat — count the plain properties of a UTF-8 text buffer.
 *
 * This is the REUSABLE half of the commons-journey acceptance fixture: a
 * small, finished, dependency-free C23 package that a later application
 * finds and reuses instead of writing its own counters. It deliberately
 * does NOT know the longest line; that is the missing behavior the
 * journey has to create. */

#ifndef Z23_TEXTSTAT_H
#define Z23_TEXTSTAT_H

#include <stddef.h>

/* Number of CR, LF, or CRLF-terminated or trailing lines in [text, text+len). */
size_t textstat_lines(const char *text, size_t len);

/* Number of whitespace-separated words in [text, text+len). */
size_t textstat_words(const char *text, size_t len);

/* Number of bytes; present so a caller needs one package, not three. */
size_t textstat_bytes(const char *text, size_t len);

#endif /* Z23_TEXTSTAT_H */
