/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_stage_durable — sibling-private durable-tip restore helpers for
 * tip_finalize_stage.c. Public convention-aware readers are declared in
 * jobs/tip_finalize_stage.h; this header exposes only the init/restore helpers
 * needed by the stage lifecycle. */

#ifndef ZCL_JOBS_TIP_FINALIZE_STAGE_DURABLE_H
#define ZCL_JOBS_TIP_FINALIZE_STAGE_DURABLE_H

#include "util/stage.h"

#include <sqlite3.h>
#include <stdbool.h>

struct block_index;

bool tip_finalize_stage_hydrate_cursor_from_store(sqlite3 *db,
                                                  stage_t *stage,
                                                  const char *reason);
void tip_finalize_stage_publish_resolved_or_fresh_tip(
    sqlite3 *db, const struct block_index *existing_tip, const char *reason);

#endif /* ZCL_JOBS_TIP_FINALIZE_STAGE_DURABLE_H */
