/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations of the check-sqlite-step-row family: the scan
 * (gate_sqlite_step_row.c), the per-file count baseline and report
 * (gate_sqlite_step_row_baseline.c) and the selftest
 * (gate_sqlite_step_row_selftest.c).
 */
#ifndef ZCL_LINTC_GATE_SQLITE_STEP_ROW_PRIV_H
#define ZCL_LINTC_GATE_SQLITE_STEP_ROW_PRIV_H

#include <stddef.h>
#include <stdio.h>

#include "lintc.h"

enum { SSR_ROWS = 2048 };

struct ssr_row {
    char path[RS_PATH];
    int count;
};

struct ssr_set {
    int n;
    struct ssr_row rows[SSR_ROWS];
};

/* Blank comments and string/char literals in place, keeping newlines. */
void ssr_blank(char *b, size_t n);
/* Count the step-to-SQLITE_ROW comparisons in an already blanked buffer. */
int ssr_count(const char *buf);
/* Walk the scan roots under `root`; record each file with a count > 0
 * (path relative to root). *files receives the number of files read. */
int ssr_collect(const char *root, struct ssr_set *live, int *files);

int ssr_set_put(struct ssr_set *s, const char *path, int count);
int ssr_set_get(const struct ssr_set *s, const char *path);
int ssr_load_baseline(struct ssr_set *s, const char *path);
int ssr_write_baseline(const struct ssr_set *live, const char *path,
                       FILE *out);
/* 0 when live matches the baseline exactly, 1 on a grown/new or stale row. */
int ssr_report(const struct ssr_set *live, const struct ssr_set *base,
               const char *base_path, int files, FILE *out);

#endif /* ZCL_LINTC_GATE_SQLITE_STEP_ROW_PRIV_H */
