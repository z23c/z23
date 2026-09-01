/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Declare the ZCL_PV_TRACE diagnostic helpers for proof_validate. */
#ifndef ZCL_JOBS_PROOF_VALIDATE_TRACE_H
#define ZCL_JOBS_PROOF_VALIDATE_TRACE_H

#include <stdbool.h>

struct sqlite3;

/* True when ZCL_PV_TRACE is set. Cached; safe on the per-step hot path. */
bool pv_trace_enabled(void);

/* Rows script_validate has actually published, or -1 if unavailable. */
long long pv_trace_log_rows(struct sqlite3 *db);

#endif /* ZCL_JOBS_PROOF_VALIDATE_TRACE_H */
