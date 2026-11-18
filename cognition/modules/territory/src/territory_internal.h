/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal scorecard projection used by the territory rollup. */
#ifndef ZCL_TERRITORY_INTERNAL_H
#define ZCL_TERRITORY_INTERNAL_H

#include "territory/territory.h"

/* Rollup consumes counts and ranks, not named group metadata. */
struct territory_report *territory_scorecard_rollup(
    struct codeindex *ci, const char *root, const char *name,
    const struct territory_reach_set *rs, const struct territory_router *router);

#endif
