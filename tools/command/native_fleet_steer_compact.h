/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the default fleet.steer.brief snapshot: live session and task
 *          rows and the head of each long list. `all:true` keeps the full
 *          reply. */
#ifndef ZCL_NATIVE_FLEET_STEER_COMPACT_H
#define ZCL_NATIVE_FLEET_STEER_COMPACT_H

#include <stdbool.h>

#include "json/json.h"

/* Rows each list keeps by default. Every list arrives with its live part
 * first: tasks in presentation priority, the rest newest first. */
#define ZCL_FMC_COMPACT_TASKS 5u
#define ZCL_FMC_COMPACT_CANDIDATES 3u
#define ZCL_FMC_COMPACT_LANDINGS 4u
#define ZCL_FMC_COMPACT_CHANGES 3u
#define ZCL_FMC_COMPACT_WORKERS 4u
#define ZCL_FMC_COMPACT_WORK 8u

/* Rewrite a finished snapshot `data` in place:
 *   sessions: rows whose state is "stale" are counted in stale_omitted;
 *     roles never observed (every field UNKNOWN) are named in
 *     sessions_unseen; sessions_total keeps the whole count.
 *   tasks: historical rows are left out; the live rows keep the fields the
 *     next step turns on (no nulls, no fixed reasons); tasks_dropped counts
 *     every row left out.
 *   workers: a worker whose state is unknown because its newest evidence
 *     is older than alive_window_s is counted in workers_stale_omitted.
 *   candidates, landings, workers, work and (when cap_changes) changes:
 *     the first rows above; candidates_dropped and changes_dropped grow by
 *     the rows left out, candidates_shown and landings_shown are the rows
 *     kept, landings_more, workers_truncated and changes_truncated say more
 *     exist, work_omitted counts the work lines left out.
 *   Fixed prose (directive_definition, sessions_active_basis,
 *     tasks_coverage_reason) is left out.
 * compact:true marks the reply. Returns false, leaving `data` unchanged,
 * when the copy cannot be built. */
bool zcl_fmc_brief_compact(struct json_value *data, bool cap_changes);

#endif
