/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Link-graph measurement behind check-lib-module-order and the
 * `z23-lint module-linkgraph` subcommand: the symbol graph of the compiled
 * objects (nm's defined/undefined join, intra-module pairs dropped), the
 * object-tree selection rule, and the lib/ cycle analysis (Tarjan SCCs plus
 * the exact minimum feedback arc set).
 */
#ifndef GATE_LIB_MODULE_ORDER_GRAPH_H
#define GATE_LIB_MODULE_ORDER_GRAPH_H

#include <stddef.h>
#include <stdio.h>

enum lmg_mode { LMG_SUMMARY, LMG_EDGES, LMG_MODULES, LMG_FAS };

/* lmg_run results: LMG_NONE = nothing to measure (no objects, no nm),
 * LMG_USAGE = bad request, LMG_UNREADABLE = objects exist but yielded no
 * edges (slim LTO objects read without the plugin): a fail-closed state. */
enum { LMG_OK = 0, LMG_NONE = 1, LMG_USAGE = 2, LMG_UNREADABLE = 3,
       LMG_ERROR = 4 };

struct lmg_req {
    int mode;
    const char *root;     /* repo root every relative path is read against */
    const char *obj_dir;  /* measure exactly this directory, or NULL */
    const char *obj_root; /* newest epoch of this root, or NULL */
};

/* Measures the graph and writes the report for req->mode to out; every
 * diagnostic goes to diag (NULL discards). Returns an LMG_ code. */
int lmg_run(const struct lmg_req *req, FILE *out, FILE *diag);

/* The cycle report over n sorted summary lines (lmg_run's LMG_FAS stage).
 * 0 ok, 1 when no lib/ -> lib/ edge exists, 2 when the graph exceeds the
 * fixed tables (message on stderr). */
int lmg_fas(const char *const *lines, size_t n, FILE *out);

/* `z23-lint module-linkgraph [--summary|--edges|--modules|--fas]
 *  [--obj-dir DIR | --obj-root ROOT]`. */
int lmg_main(int argc, char **argv);

/* ── object-tree selection (gate_lib_module_order_objs.c) ───────────── */

struct lmg_objs {
    char **path; /* root-joined object paths, sorted */
    size_t n;
    char *dir;   /* the root-joined directory the objects were read from */
    char *dir_rel;
};

int lmg_collect(const struct lmg_req *req, struct lmg_objs *o, FILE *diag);
void lmg_objs_free(struct lmg_objs *o);

#endif
