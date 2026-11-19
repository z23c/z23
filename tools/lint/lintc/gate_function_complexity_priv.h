/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by the check-cyclomatic-complexity
 * gate and its selftest.
 */
#ifndef GATE_FUNCTION_COMPLEXITY_PRIV_H
#define GATE_FUNCTION_COMPLEXITY_PRIV_H

#include <stddef.h>
#include <stdio.h>
#include "lintc.h"

enum { CYC_NAME = 96 };

/* Header written at the top of every generated baseline. */
extern const char k_cyc_base_hdr[];
/* Temp directory the selftest falls back to when TMPDIR is unset. */
extern const char cyc_tmp_default[];

/* Scans text as if it were the file at path; on_func runs once per function
 * definition, in order. */
int cyc_scan_text(const char *text, const char *path,
                  int (*on_func)(const char *, const char *, int, int,
                                 void *),
                  void *ctx);
/* The gate over root against base_path in the given mode. */
int cyc_check(const char *root, const char *base_path, const char *mode,
              int report, int tighten, FILE *out, FILE *err);
int cyc_check_with_changed(const char *root, const char *base_path,
                           const char *mode, int report, int tighten, FILE *out,
                           FILE *err, const struct lint_changed *changed);
int cyc_narrow_ok(const struct lint_changed *ch, const char *baseline);
/* Writes exact pins for every over-cap function under root. */
int cyc_write_baseline(const char *root, const char *base_path);

#endif
