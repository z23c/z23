/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check-lib-module-order gate: the selftest
 * calls the root-scoped checker directly with a fixture tree, and the gate
 * runs the link-graph tool through lmo_capture (gate_lib_module_order_proc.c).
 */
#ifndef GATE_LIB_MODULE_ORDER_PRIV_H
#define GATE_LIB_MODULE_ORDER_PRIV_H

#include <stdio.h>
#include <stddef.h>

enum { LMO_CAP_FAIL = -1, LMO_CAP_OVF = -2 };

int lmo_check_root(const char *root, FILE *out);

/* fork+execvp argv; stdout into out (cap bytes incl. NUL; NULL discards),
 * stderr to /dev/null when quiet_err. Returns the exit status, or
 * LMO_CAP_FAIL / LMO_CAP_OVF with a message already printed. */
int lmo_capture(char *const argv[], char *out, size_t cap, size_t *outn,
                int quiet_err);

#endif
