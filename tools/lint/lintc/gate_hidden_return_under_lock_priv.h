/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface between gate_hidden_return_under_lock.c and its
 * selftest sibling gate_hidden_return_under_lock_selftest.c — not listed in
 * lintc.h, which declares only shared helpers and gate entry points.
 */
#ifndef GATE_HIDDEN_RETURN_UNDER_LOCK_PRIV_H
#define GATE_HIDDEN_RETURN_UNDER_LOCK_PRIV_H

#include <stdio.h>

/* Scans one C file. Each hidden-return macro used while a directly acquired
 * lock is held is reported to out as "path:line: ..." and counted in
 * *findings. Returns 0 when the file was scanned, 2 on an I/O error or a
 * source line too long to scan (fail closed). */
int hrl_scan_file(const char *path, FILE *out, int *findings);

/* Scans the production roots under root. Returns 0 clean, 1 on a finding,
 * 2 on an I/O error or a hollow scan. Reports go to out. */
int hrl_check_root(const char *root, FILE *out);

#endif
