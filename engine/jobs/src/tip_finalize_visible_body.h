/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Late-body reconciliation helpers for tip_finalize_stage.c. */

#ifndef ZCL_JOBS_TIP_FINALIZE_VISIBLE_BODY_H
#define ZCL_JOBS_TIP_FINALIZE_VISIBLE_BODY_H

struct block_index;
struct main_state;
struct sqlite3;
struct stage;

const char *tip_finalize_precondition_block_reason(
    const struct block_index *bi);
void tip_finalize_reconcile_visible_cursor_body(
    struct sqlite3 *db, struct stage *stage, struct main_state *ms);
void tip_finalize_visible_body_reset(void);

#endif /* ZCL_JOBS_TIP_FINALIZE_VISIBLE_BODY_H */
