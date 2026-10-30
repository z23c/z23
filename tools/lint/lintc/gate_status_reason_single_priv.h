/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private header of the check-status-reason-single gate, shared by
 * gate_status_reason_single.c (the gate core) and its planted-violation
 * selftest gate_status_reason_single_selftest.c. NOT a public header:
 * nothing outside tools/lint/lintc/ includes it.
 */
#ifndef GATE_STATUS_REASON_SINGLE_PRIV_H
#define GATE_STATUS_REASON_SINGLE_PRIV_H

#include <stdio.h>

/* The whole gate over the configured scan set; reports to out and err.
 * Returns 0 pass, 1 violation in FAIL mode, 2 error. */
int srs_run_core(FILE *out, FILE *err);
/* Counts the ladders in one file. 0 ok (count set), 2 error. */
int srs_scan_file(const char *path, int *count);

#endif
