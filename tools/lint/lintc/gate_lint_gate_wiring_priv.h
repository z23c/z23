/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations between gate_lint_gate_wiring.c and its
 * selftest sibling gate_lint_gate_wiring_selftest.c.
 */
#ifndef GATE_LINT_GATE_WIRING_PRIV_H
#define GATE_LINT_GATE_WIRING_PRIV_H
#include <stddef.h>
#include <stdio.h>

int lgw_check_root(const char *root, FILE *out);
int lgw_appendf_pub(char *out, size_t cap, size_t *used, const char *fmt, ...);

#endif
