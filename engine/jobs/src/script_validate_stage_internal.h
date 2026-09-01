/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sibling-private declarations shared between script_validate_stage.c (the Job
 * state owner) and script_validate_stage_dump.c (the read-only dump-state JSON
 * dump). Not a public header.
 */

#ifndef ZCL_JOBS_SCRIPT_VALIDATE_STAGE_INTERNAL_H
#define ZCL_JOBS_SCRIPT_VALIDATE_STAGE_INTERNAL_H

#include "jobs/script_validate_stage.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct script_validate_created_prevout_view {
    sqlite3 *db;
    int height;
    int frontier;
    bool have_frontier;
};

void script_validate_created_prevout_view_init(
    struct script_validate_created_prevout_view *view,
    int height);
bool script_validate_created_index_prevout(const struct outpoint *prevout,
                                           struct tx_out *out,
                                           void *user);

/* Finalize this thread's coins_kv prevout fallback statement cache. Called at
 * script_validate drain teardown (one prepared statement per completed batch). */
void script_validate_prevout_batch_reset(void);

stage_t *script_validate_stage_handle(void);
uint64_t script_validate_stage_inputs_failed_total(void);
uint64_t script_validate_stage_header_event_emit_total(void);
uint64_t script_validate_stage_header_event_emit_fail_total(void);
int64_t script_validate_stage_last_step_unix(void);
int64_t script_validate_stage_last_blocked_unix(void);
int64_t script_validate_stage_last_advance_height(void);

#endif /* ZCL_JOBS_SCRIPT_VALIDATE_STAGE_INTERNAL_H */
