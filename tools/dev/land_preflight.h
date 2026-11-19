/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Cold-proof preflight: report every proof_dependencies.def artifact
 *          that is absent and not buildable by any reachable make rule. */

#ifndef ZCL_LAND_PREFLIGHT_H
#define ZCL_LAND_PREFLIGHT_H

#include <stdbool.h>
#include <stdio.h>

struct zcl_land_preflight_opts {
    /* Checkout root the artifacts live under. Default ".". */
    const char *root;
    /* The dep table to grade. Default <root>/tools/dev/proof_dependencies.def. */
    const char *def_path;
    /* The makefile scanned for rule existence (never executed).
     * Default <root>/Makefile. */
    const char *makefile;
};

/* 0 when every applicable row is present or buildable, 1 when at least one
 * row is MISSING (the fix command is printed per row), -1 on usage or IO
 * error (diagnostic on err). Per-item lines go to out. */
int zcl_land_preflight_run(const struct zcl_land_preflight_opts *opts,
                           FILE *out, FILE *err);

#endif
