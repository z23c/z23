/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * addnode_file.h — parse an operator-supplied "peers list" file for
 * -addnode-file=PATH. One `host[:port]` per line, '#' comments and blank
 * lines skipped silently; malformed non-blank lines are skipped with a
 * logged warning (never fatal to boot). */

#ifndef ZCL_NET_ADDNODE_FILE_H
#define ZCL_NET_ADDNODE_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Parses one line into host_out (NUL-terminated, up to host_cap bytes) and
 * *port_out (0 if no ":port" suffix was present). Returns false for a
 * blank/comment line or a malformed token (empty host, oversized host,
 * unparsable/out-of-range port) — the caller distinguishes the two via
 * addnode_file_line_is_blank(). Pure — no I/O, no logging. */
bool addnode_file_parse_line(const char *line, char *host_out,
                              size_t host_cap, uint16_t *port_out);

/* True if `line`, after leading whitespace, is empty or a '#' comment. */
bool addnode_file_line_is_blank(const char *line);

typedef void (*addnode_file_add_fn)(const char *host, uint16_t port, void *ctx);

/* Reads `path` and calls add_cb(host, port, ctx) for every valid line.
 * A missing file is a clean no-op (returns 0, not an error — the operator
 * simply didn't drop a peers list). Malformed lines are skipped with a
 * logged warning; they never abort the load. Returns the number of entries
 * successfully added, or -1 if the file exists but could not be read. */
int addnode_file_load(const char *path, addnode_file_add_fn add_cb, void *ctx);

#endif
