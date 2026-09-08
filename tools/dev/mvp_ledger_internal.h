/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: helpers shared by the mvp_ledger translation units — bounded
 *          copies, named refusals, TSV cell hygiene and the capped line
 *          reader. Not part of the tool's public contract; see
 *          tools/dev/mvp_ledger.h for that. */
#ifndef ZCL_TOOLS_DEV_MVP_LEDGER_INTERNAL_H
#define ZCL_TOOLS_DEV_MVP_LEDGER_INTERNAL_H

#include <stdio.h>

#include "mvp_ledger.h"

/* Bounded copy; always NUL-terminates, never reads past `src`. */
void mvl_copy(char *dst, size_t cap, const char *src);

/* Writes "<path>:<line_no>: <reason>" into `err`. Every refusal in this
 * tool goes through here, so every refusal names a line. */
void mvl_err(char *err, size_t cap, const char *path, size_t line_no,
             const char *reason);

/* Replaces tab, CR and LF with a space: a TSV cell can never forge a
 * column or a row. */
void mvl_sanitize(char *s);

/* Reads one line into `buf` (which must hold `cap` >= MVL_LINE_CAP + 2
 * bytes) with the trailing newline stripped. Returns 1 on a line, 0 at end
 * of file, and -1 when the line is longer than the cap allows. */
int mvl_read_line(FILE *f, char *buf, size_t cap);

/* Composes "<a><b><c><d>" into `dst`, refusing (false, `dst` emptied) when
 * the result would not fit: a truncated path is a different path, and this
 * tool never acts on one. Pass "" for the pieces a call does not need. */
bool mvl_path_of(char *dst, size_t cap, const char *a, const char *b,
                 const char *c, const char *d);

/* Refuses when `path` exists and its first line is not `want`. */
bool mvl_check_header(const char *path, const char *want, char *err,
                      size_t err_cap);

/* True when `path` has no first line yet (absent, or present and empty). */
bool mvl_ledger_is_fresh(const char *path);

/* Claims the next zeroed row of the bounded agent table. */
struct mvl_agent *mvl_next_row(struct mvl_agents *out, char *err,
                               size_t err_cap);

#endif /* ZCL_TOOLS_DEV_MVP_LEDGER_INTERNAL_H */
