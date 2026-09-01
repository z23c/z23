/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private observability state for reducer_frontier_reconcile_light. */

#ifndef ZCL_CONDITIONS_REDUCER_FRONTIER_LIGHT_OBSERVE_H
#define ZCL_CONDITIONS_REDUCER_FRONTIER_LIGHT_OBSERVE_H

#include <stdbool.h>

struct json_value;
struct sqlite3;
struct stage_reducer_frontier_reconcile_result;

enum rfrl_rr_phase {
    RFRL_RR_PHASE_NONE = 0,
    RFRL_RR_PHASE_DETECT = 1,
    RFRL_RR_PHASE_REMEDY = 2,
};

const char *rfrl_coin_backfill_status_label(int status);

void rfrl_snapshot_reconcile_result(
    enum rfrl_rr_phase phase,
    const struct stage_reducer_frontier_reconcile_result *rr);
bool rfrl_detail_push(struct json_value *out);

void rfrl_detect_baseline_set(int local_height, int hstar, int sweep_top);
int rfrl_hstar_at_detect(void);

bool rfrl_read_reducer_cursor(struct sqlite3 *db, const char *name, int *out);
void rfrl_snapshot_reducer_cursors(struct sqlite3 *db);

bool rfrl_read_coin_backfill_scan_cursor(struct sqlite3 *db, bool *present,
                                         int *next_height);
void rfrl_snapshot_coin_backfill_scan(struct sqlite3 *db);
int rfrl_coin_backfill_scan_next_at_detect(void);
void rfrl_set_coin_backfill_scan_snapshot(bool present, int next_height);

bool rfrl_read_tipfin_backfill_progress(struct sqlite3 *db, bool *present,
                                        int *progress);
void rfrl_snapshot_tipfin_backfill(struct sqlite3 *db);
int rfrl_tipfin_backfill_progress_at_detect(void);
void rfrl_set_tipfin_backfill_snapshot(bool present, int progress);

int rfrl_last_coin_backfill_inserted(void);
int rfrl_last_reconcile_remedy_call(void);
int rfrl_coin_backfill_insert_remedy_call_at_detect(void);
void rfrl_snapshot_coin_backfill_insert_progress(void);

void rfrl_increment_remedy_calls(void);
int rfrl_remedy_calls(void);

bool rfrl_tear_bypass_active(void);
void rfrl_set_tear_bypass_active(bool active);
void rfrl_increment_tear_bypass_warn_total(void);
int rfrl_tear_bypass_warn_total(void);

#ifdef ZCL_TESTING
void rfrl_observe_reset_for_testing(void);
#endif

#endif /* ZCL_CONDITIONS_REDUCER_FRONTIER_LIGHT_OBSERVE_H */
