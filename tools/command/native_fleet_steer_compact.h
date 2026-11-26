/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the default fleet.steer.brief snapshot: live session rows and the
 *          head of each long list. `all:true` keeps the full reply. */
#ifndef ZCL_NATIVE_FLEET_STEER_COMPACT_H
#define ZCL_NATIVE_FLEET_STEER_COMPACT_H

#include <stdbool.h>

#include "json/json.h"

/* Rows each list keeps by default. Tasks arrive in presentation priority
 * (blocked, unknown, queued, running, historical), candidates and landings
 * newest first, so the kept head is the live part. */
#define ZCL_FMC_COMPACT_TASKS 3u
#define ZCL_FMC_COMPACT_CANDIDATES 5u
#define ZCL_FMC_COMPACT_LANDINGS 4u

/* Rewrite a finished snapshot `data` in place:
 *   sessions: rows whose state is "stale" are counted in stale_omitted;
 *     roles never observed (every field UNKNOWN) are named in
 *     sessions_unseen; sessions_total keeps the whole count.
 *   tasks, candidates, landings: the first rows above; tasks_dropped and
 *     candidates_dropped grow by the rows left out, candidates_shown and
 *     landings_shown are the rows kept, landings_more says more exist.
 *   directive_definition (fixed prose) is left out.
 * compact:true marks the reply. Returns false, leaving `data` unchanged,
 * when the copy cannot be built. */
bool zcl_fmc_brief_compact(struct json_value *data);

#endif
