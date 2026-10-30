/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declaration for the check-golden-freshness port (gate and
 * selftest). Not installed; internal to lintc.
 */
#ifndef GATE_GOLDEN_FRESHNESS_PRIV_H
#define GATE_GOLDEN_FRESHNESS_PRIV_H

#include <stdio.h>

/* Full gate body against an explicit repo root so the selftest can point
 * at fixture table copies. Prints the same stdout lines as the shell
 * script; returns 0 SKIP/PASS, 1 FAIL, 2 fatal (bad
 * LAG_MAX). */
int gf_check_root(const char *root, FILE *out);

#endif
