/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_git_scan_a_priv — the seam between gate_git_scan_a.c
 * (check-equihash-params's regenerate-and-diff/tracked-file-scan gate
 * body) and gate_git_scan_a_selftests.c (its planted-violation
 * selftest). NOT a public header: nothing outside tools/lint/lintc/
 * includes this.
 */

#ifndef ZCL_LINTC_GATE_GIT_SCAN_A_PRIV_H
#define ZCL_LINTC_GATE_GIT_SCAN_A_PRIV_H

#include <regex.h>
#include <stdio.h>

/* check-equihash-params: path filter, regex setup, file load, line scan. */
int eqp_keep_path(const char *path);
int eqp_comp(regex_t *lit, regex_t *claim, regex_t *qual);
int eqp_load(const char *path, int *nlines);
int eqp_scan_lines(const char *disp, int nlines, const regex_t *lit,
    const regex_t *claim, const regex_t *qual, FILE *out, int *hits);

#endif
