/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: private live-datadir lint scan and fixture interfaces. */
#ifndef LIVE_DATADIR_ISOLATION_PRIV_H
#define LIVE_DATADIR_ISOLATION_PRIV_H
#include "lintc.h"
enum { LDI_MAX = 8192, LDI_PATH = 1024, LDI_RECORD = 65536 };
struct ldi_row { char path[LDI_PATH], comment[2048]; int count, base, pinned; };
struct ldi_rows { struct ldi_row row[LDI_MAX]; int n; };
struct ldi_scan {
    struct ldi_rows a, c, leaves;
    char b[LDI_MAX][LDI_PATH], doc_paths[LDI_MAX][LDI_PATH];
    int tests, docs, defs, unpinned;
    regex_t path, get, set;
};
int ldi_derive(const char *path, void *ctx);
int ldi_test_file(const char *path, void *ctx);
int ldi_doc_file(const char *path, void *ctx);
int ldi_patterns(struct ldi_scan *s);
#endif
