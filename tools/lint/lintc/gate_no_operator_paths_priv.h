/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check-no-operator-paths gate port
 * (gate_no_operator_paths.c, gate_no_operator_paths_report.c and
 * gate_no_operator_paths_selftest.c). The gate never contains a literal
 * absolute home path, so it cannot flag itself: the prong A pattern is
 * assembled from separate tokens.
 */
#ifndef GATE_NO_OPERATOR_PATHS_PRIV_H
#define GATE_NO_OPERATOR_PATHS_PRIV_H

#include <stddef.h>
#include <stdio.h>

enum { NOP_ROWS = 4096, NOP_KEY = 1024, NOP_RROW = 1152 };

struct nop_cfg {
    const char *const *files;   /* NULL: env override or the git index */
    size_t nfiles;              /* valid when files != NULL */
    const char *test_identities; /* NULL: ZCL_OPERATOR_PATHS_TEST_IDENTITIES */
    int update;                 /* ZCL_LINT_MODE=UPDATE */
};

extern const char nop_gate_name[];
extern const char nop_baseline[];

/* Current counts, "<prong> <path>" keys, written by the scan core and read
 * by the report half. */
extern char nop_curk[NOP_ROWS][NOP_KEY];
extern int nop_curn[NOP_ROWS];
extern int nop_ncur;

int nop_check(const struct nop_cfg *cfg, FILE *out);
int nop_ovf(const char *what, int n);
int nop_load_baseline(void);
int nop_report(FILE *out, int override);
int nop_update(FILE *out);

#endif
