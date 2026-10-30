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
 * Retries EINTR. Returns 0 for a non-empty line; -1 for end of input or an
 * empty line (callers that only test < 0 or != 0 need no change); -2 for a
 * non-EINTR read error; -3 when the line does not fit in cap-1 bytes (the
 * buffer is then empty, never a truncated line). */
int lct_read_line_fd(int rfd, char *buf, size_t cap);

/* mkdtemp a fresh directory "<leaf>.XXXXXX" under
 * $HOME/.local/state/zclassic23/scratch (never /tmp) into out. Returns 0, or
 * 2 after the message on stderr (HOME unset, path too long, mkdir or mkdtemp
 * failed). */
int lct_scratch_dir(char *out, size_t cap, const char *leaf);


/* True when path can be opened for reading. */
int lct_readable(const char *path);

/* True when some line of the file at path contains needle (plain substring,
 * no regex). Lines are read through a 16384-byte buffer (the larger of the
 * two buffer sizes the ported gates used before this was shared); a longer
 * line is seen as consecutive chunks. An unreadable file is 0. */
int lct_file_has(const char *path, const char *needle);

#endif
