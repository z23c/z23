/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check-lib-module-order gate: the selftest
 * calls the root-scoped checker directly with a fixture tree, and the graph
 * measurement streams nm through lmo_nm_stream
 * (gate_lib_module_order_proc.c).
 */
#ifndef GATE_LIB_MODULE_ORDER_PRIV_H
#define GATE_LIB_MODULE_ORDER_PRIV_H

#include <stdio.h>
#include <stddef.h>

enum { LMO_CAP_FAIL = -1 };

int lmo_check_root(const char *root, FILE *out);

/* Selftest fixtures (gate_lib_module_order_selftest_graph.c): writes one
 * ELF object per module of spec ("a>b;c" = a references b; c stands alone)
 * under dir/lib/<mod>/src, and runs the graph-report checks in a fresh
 * fixture root. Both return 0 on success. */
int lmos_write_graph(const char *dir, const char *spec);
int lmos_graph_selftest(const char *root);

/* fork+execvp argv; stdout lines to cb (stderr discarded). Returns the exit
 * status, or LMO_CAP_FAIL with a message already printed. */
int lmo_nm_stream(char *const argv[], int (*cb)(void *ctx, char *line),
                  void *ctx);

#endif
