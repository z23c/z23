/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_shell_host_assumptions_priv — the seam between
 * gate_shell_host_assumptions.c (the check-shell-host-assumptions gate
 * body) and gate_shell_host_assumptions_selftest.c (its selftest). NOT a
 * public header: nothing outside tools/lint/lintc/ includes this.
 */
#ifndef ZCL_LINTC_GATE_SHELL_HOST_ASSUMPTIONS_PRIV_H
#define ZCL_LINTC_GATE_SHELL_HOST_ASSUMPTIONS_PRIV_H

#include <stddef.h>

enum { SHL_PATH = 768, SHL_ROWS_MAX = 4096 };

struct shl_row { char kind[8]; char path[SHL_PATH]; int count; };
struct shl_table { struct shl_row r[SHL_ROWS_MAX]; int n; };

extern const char k_gate[];

int shl_table_find(const struct shl_table *t, const char *kind, const char *path);
int shl_load_baseline(const char *path, struct shl_table *allowed, int *present);

#endif
