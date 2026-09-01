/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_schema — materialize the durable log tables read by H*.
 * Kept separate from reducer_frontier.c so that the frontier computation
 * remains strictly SELECT-only. */

#ifndef ZCL_JOBS_REDUCER_FRONTIER_SCHEMA_H
#define ZCL_JOBS_REDUCER_FRONTIER_SCHEMA_H

#include <stdbool.h>

struct sqlite3;

/* Ensure every reducer log consumed by reducer_frontier_compute_hstar().
 * Joins an existing transaction when the caller already owns one. */
bool reducer_frontier_ensure_schema(struct sqlite3 *db);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_SCHEMA_H */
