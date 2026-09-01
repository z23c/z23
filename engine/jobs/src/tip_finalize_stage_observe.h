/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_stage_observe — sibling-private observability helpers for
 * tip_finalize_stage.c. Owns counters, blocked-reason state, warning throttles,
 * and the published served-tip snapshot; it never writes reducer consensus
 * rows or chooses finalization outcomes. */

#ifndef ZCL_JOBS_TIP_FINALIZE_STAGE_OBSERVE_H
#define ZCL_JOBS_TIP_FINALIZE_STAGE_OBSERVE_H

#include "util/stage.h"

#include <stdbool.h>
#include <stdint.h>

struct arith_uint256;
struct json_value;
struct sqlite3;

/* WHY the last idle/blocked tick idled. TF_BLOCKED_AT_UV_FRONTIER is the
 * healthy at-tip steady state (waiting for the next block), not a fault. */
enum tip_finalize_blocked_class {
    TIP_FINALIZE_BLOCKED_NONE = 0,
    TIP_FINALIZE_BLOCKED_UV_CURSOR_GAP,
    TIP_FINALIZE_BLOCKED_AT_UV_FRONTIER,
    TIP_FINALIZE_BLOCKED_UV_ROW_MISSING,
    TIP_FINALIZE_BLOCKED_LOOKAHEAD_MISSING,
    TIP_FINALIZE_BLOCKED_TIP_MISSING,
    TIP_FINALIZE_BLOCKED_SUCCESSOR_PENDING,
    TIP_FINALIZE_BLOCKED_CLASS_N
};

void tip_finalize_observe_init(void);
void tip_finalize_observe_shutdown(void);

void tip_finalize_observe_mark_step(void);
void tip_finalize_observe_mark_blocked(
    enum tip_finalize_blocked_class cls);
void tip_finalize_observe_note_cursor_gap(int next_h, uint64_t uv_cursor);
void tip_finalize_observe_clear_cursor_gap(void);

/* Current-tip-missing anomaly (Task A #11): the block AT next_h that finalize
 * must extend FROM could not be resolved from the active-chain window, the
 * durable finalized-hash table, OR the best-header ancestry — a genuine
 * data-availability anomaly, not the healthy at-tip wait. This sets the
 * internal g_blocked_class counter and ALSO names a
 * registry-visible TRANSIENT blocker so blocker_stall_meta_detector's safety
 * net and `core sync blockers` see it. `_clear` is called once old_tip
 * resolves. */
void tip_finalize_observe_note_tip_missing(int next_h);
void tip_finalize_observe_clear_tip_missing(void);
void tip_finalize_observe_note_reorg_rewind(void);
void tip_finalize_observe_record_precondition_block(int height,
                                                    const char *reason);

void tip_finalize_observe_update_last_advance(int height,
                                              const uint8_t hash[32]);
bool tip_finalize_observe_get_last_advance(int64_t *height,
                                           uint8_t hash[32]);
int64_t tip_finalize_observe_last_height(void);
void tip_finalize_observe_reset_last_height(void);

void tip_finalize_observe_inc_finalized(void);
void tip_finalize_observe_inc_upstream_failed(void);
void tip_finalize_observe_inc_reorg_detected(void);
void tip_finalize_observe_inc_utxo_count_diverged(void);
void tip_finalize_observe_inc_precondition_failed(void);
void tip_finalize_observe_inc_successor_pending(void);
void tip_finalize_observe_inc_header_witness(void);
void tip_finalize_observe_add_work(const struct arith_uint256 *delta);

uint64_t tip_finalize_observe_finalized_total(void);
uint64_t tip_finalize_observe_upstream_failed_total(void);
uint64_t tip_finalize_observe_reorg_detected_total(void);
uint64_t tip_finalize_observe_utxo_count_diverged_total(void);
uint64_t tip_finalize_observe_precondition_failed_total(void);
uint64_t tip_finalize_observe_successor_pending_total(void);
uint64_t tip_finalize_observe_header_witness_total(void);
uint64_t tip_finalize_observe_total_work_added_low(void);
const char *tip_finalize_observe_last_blocked_reason(void);

bool tip_finalize_observe_dump_state_json(struct json_value *out,
                                          const char *key,
                                          struct sqlite3 *db,
                                          const stage_t *stage);

#endif /* ZCL_JOBS_TIP_FINALIZE_STAGE_OBSERVE_H */
