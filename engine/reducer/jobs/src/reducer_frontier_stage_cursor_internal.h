/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private seam between reducer_frontier.c (owner of the k_logs stage->log
 * mapping) and reducer_frontier_stage_cursor.c (the F1 log-derived stage-cursor
 * reader). Not a public jobs/ header — an internal split so the derived-reader
 * machinery lives in its own translation unit. */

#ifndef ZCL_JOBS_REDUCER_FRONTIER_STAGE_CURSOR_INTERNAL_H
#define ZCL_JOBS_REDUCER_FRONTIER_STAGE_CURSOR_INTERNAL_H

#include <stdbool.h>

/* Resolve a stage cursor `name` to its success-checked *_log table, or NULL for
 * a stage with none (header_admit, body_fetch). *served_tip (when non-NULL)
 * reports the served-tip cursor convention (true only for tip_finalize).
 * Defined in reducer_frontier.c, where the k_logs table lives. */
const char *reducer_frontier_cursor_log_table(const char *name,
                                              bool *served_tip);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_STAGE_CURSOR_INTERNAL_H */
