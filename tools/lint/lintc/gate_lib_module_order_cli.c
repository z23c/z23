/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23-lint module-linkgraph`, the command line of the lib module
 * link-graph measurement (gate_lib_module_order_graph.c). Replaces
 * tools/dev/module-linkgraph.sh.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdlib.h>
#include <string.h>
#include "gate_lib_module_order_graph.h"

static const char k_lmg_usage[] =
    "usage: z23-lint module-linkgraph [--summary|--edges|--modules|--fas]\n"
    "                                 [--obj-dir DIR | --obj-root ROOT]\n"
    "  --summary   (default) one line per module->module edge:\n"
    "                <from> -> <to> <TAB> <refcount> <TAB> sym,sym,...\n"
    "  --edges     one line per reference:\n"
    "                <from_module> <TAB> <to_module> <TAB> <symbol> <TAB> "
    "<from_file>\n"
    "  --modules   one line per module that has at least one object\n"
    "  --fas       lib/ subgraph cycle structure: strongly-connected\n"
    "              components and the exact minimum feedback arc set\n"
    "  --obj-dir   measure exactly this directory of objects\n"
    "  --obj-root  measure only this object root (its newest epoch, else the\n"
    "              root itself) instead of the build/obj-first search\n"
    "Run from the repo root. With neither flag, $ZCL_LINKGRAPH_OBJ_DIR then\n"
    "the first warm of build/obj build/test-rel-obj build/test-obj\n"
    "build/test-asan-obj build/dev-obj is measured. Exit 1: nothing to\n"
    "measure; 3: objects exist but yielded no edges (slim LTO objects).\n";

static const struct { const char *flag; int mode; } k_lmg_modes[] = {
    { "--summary", LMG_SUMMARY }, { "--edges", LMG_EDGES },
    { "--modules", LMG_MODULES }, { "--fas", LMG_FAS },
};

/* Consumes argv[*i] when it is a mode flag. */
static int lmg_mode_flag(const char *a, int *mode)
{
    for (size_t k = 0; k < sizeof k_lmg_modes / sizeof k_lmg_modes[0]; k++)
        if (strcmp(a, k_lmg_modes[k].flag) == 0) {
            *mode = k_lmg_modes[k].mode;
            return 1;
        }
    return 0;
}

/* Parses argv into req; 0 ok, 2 on a bad argument, -1 after --help. */
static int lmg_parse(int argc, char **argv, struct lmg_req *rq)
{
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (lmg_mode_flag(a, &rq->mode))
            continue;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            fputs(k_lmg_usage, stdout);
            return -1;
        }
        int is_dir = strcmp(a, "--obj-dir") == 0;
        if ((is_dir || strcmp(a, "--obj-root") == 0) && i + 1 < argc) {
            const char **slot = is_dir ? &rq->obj_dir : &rq->obj_root;
            *slot = argv[++i];
            continue;
        }
        fprintf(stderr, "module-linkgraph: unknown argument: %s\n", a);
        return 2;
    }
    return 0;
}

int lmg_main(int argc, char **argv)
{
    struct lmg_req rq = { LMG_SUMMARY, ".", NULL, NULL };
    int rc = lmg_parse(argc, argv, &rq);
    if (rc)
        return rc < 0 ? 0 : rc;
    const char *env = getenv("ZCL_LINKGRAPH_OBJ_DIR");
    if (!rq.obj_dir && !rq.obj_root && env && *env)
        rq.obj_dir = env;
    if (rq.obj_dir && !*rq.obj_dir)
        rq.obj_dir = NULL;
    if (rq.obj_root && !*rq.obj_root)
        rq.obj_root = NULL;
    rc = lmg_run(&rq, stdout, stderr);
    return rc == LMG_ERROR ? 2 : rc;
}
