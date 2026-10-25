/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for check-log-macro-return-type
 * (gate_log_macro_return_type.c and gate_log_macro_return_type_selftest.c) —
 * the C23 port of tools/lint/lintc/gate_log_macro_return_type.c.
 */
#ifndef GATE_LOG_MACRO_RETURN_TYPE_PRIV_H
#define GATE_LOG_MACRO_RETURN_TYPE_PRIV_H
#include <stddef.h>
#include "lintc.h"

/* Growable byte buffer. A failed allocation sets err and turns every later
 * append into a no-op; callers test err once at the end of a scan. */
struct lmr_buf {
    char *p;
    size_t n;
    size_t cap;
    int err;
};

void lmr_buf_free(struct lmr_buf *b);
int lmr_filesystem_selftest(void);

/* Scans one file's text. Each mismatch is appended to bad as
 * "  FILE:LINE: FUNC returns TYPE but MACRO returns VALUE\n". Returns 0, or
 * 2 when memory ran out. */
int lmr_scan_text(const char *file, const char *text, size_t len,
                  struct lmr_buf *bad);

#endif
