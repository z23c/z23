/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: small text helpers shared by lint gates, so each gate does not
 * carry its own copy.
 */
#ifndef LINTC_TEXT_H
#define LINTC_TEXT_H

#include <stddef.h>

/* True when s is one or more ASCII digits and nothing else. */
bool lct_is_digits(const char *s);

/* True when line, ignoring trailing whitespace, ends with ')'. */
bool lct_ends_with_paren(const char *line);

/* Read one line from rfd into buf, dropping the newline and NUL-terminating.
 * Retries EINTR. Returns 0 for a non-empty line, -1 for an empty line, end
 * of input or a read error. */
int lct_read_line_fd(int rfd, char *buf, size_t cap);

#endif
