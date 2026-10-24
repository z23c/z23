/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"

#include "base/serialize_le.h"
#include "chain/checkpoints.h"
#include "controllers/agent_cure_status_helpers.h"
#include "controllers/strong_params.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/consensus_db.h"    /* consensus_db_kernel_store_path */
#include "util/clientversion.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ANCHOR_MARKER_LEN 48
struct anchor_stage_view {
    const char *name;
    const char *log_table;
    int64_t cursor;
    int64_t log_count;
    int64_t min_height;
    int64_t max_height;
    bool cursor_present;
    bool log_present;
};

struct anchor_log_row_probe {
    bool table_present;
    bool row_present;
    bool ok_present;
    bool status_present;
    int64_t ok;
    char status[96];
};

struct anchor_utxo_probe {
    bool available;
    int64_t next_height;
    int64_t proof_cursor;
    int64_t previous_height;
    bool previous_row_expected;
    bool previous_row_missing_below_coin_frontier;
    bool previous_delta_missing_below_coin_frontier;
    struct anchor_log_row_probe proof_next;
    struct anchor_log_row_probe script_next;
    struct anchor_log_row_probe utxo_next;
    struct anchor_log_row_probe utxo_previous;
    struct anchor_log_row_probe delta_previous;
    const char *next_diagnosis;
    const char *history_diagnosis;
    const char *next_action;
};

static bool anchor_sql_i64(sqlite3 *db, const char *sql, int64_t bind0,
                           bool bind, int64_t *out, bool *found_out)
{
    if (out)
        *out = 0;
    if (found_out)
        *found_out = false;
    if (!db || !sql)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) // raw-controller-sql-ok:anchorstatus-progress-kv-readonly
        return false;
    if (bind)
        sqlite3_bind_int64(st, 1, (sqlite3_int64)bind0);
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-diagnostic-cli
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        if (out)
            *out = sqlite3_column_int64(st, 0);
        if (found_out)
            *found_out = true;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static bool anchor_probe_table_allowed(const char *table)
{
    return table &&
        (strcmp(table, "script_validate_log") == 0 ||
         strcmp(table, "proof_validate_log") == 0 ||
         strcmp(table, "utxo_apply_log") == 0 ||
         strcmp(table, "utxo_apply_delta") == 0);
}

static void anchor_log_row_probe_init(struct anchor_log_row_probe *p)
{
    if (!p)
        return;
    memset(p, 0, sizeof(*p));
    p->ok = -1;
}

static bool anchor_log_height_exists(sqlite3 *db, const char *table,
                                     int64_t height, bool *present_out,
                                     bool *found_out)
{
    if (present_out)
        *present_out = false;
    if (found_out)
        *found_out = false;
    if (!db || !anchor_probe_table_allowed(table))
        return false;

    char sql[160];
    snprintf(sql, sizeof(sql),
             "SELECT height FROM %s WHERE height=?1", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) // raw-controller-sql-ok:anchorstatus-progress-kv-readonly
        return false;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-diagnostic-cli
    if (present_out)
        *present_out = (rc == SQLITE_ROW || rc == SQLITE_DONE);
    if (found_out)
        *found_out = (rc == SQLITE_ROW);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static bool anchor_log_row_probe_at(sqlite3 *db, const char *table,
                                    int64_t height,
                                    struct anchor_log_row_probe *out)
{
    anchor_log_row_probe_init(out);
    if (!out || !db || !anchor_probe_table_allowed(table))
        return false;

    if (!anchor_log_height_exists(db, table, height, &out->table_present,
                                  &out->row_present))
        return false;
    if (!out->row_present)
        return true;

    char sql[192];
    snprintf(sql, sizeof(sql),
             "SELECT status, ok FROM %s WHERE height=?1", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) // raw-controller-sql-ok:anchorstatus-progress-kv-readonly
        return true; /* older diagnostic fixture: row exists, verdict columns do not */
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-diagnostic-cli
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
            const unsigned char *s = sqlite3_column_text(st, 0);
            if (s) {
                snprintf(out->status, sizeof(out->status), "%s",
                         (const char *)s);
                out->status_present = true;
            }
        }
        if (sqlite3_column_type(st, 1) != SQLITE_NULL) {
            out->ok = sqlite3_column_int64(st, 1);
            out->ok_present = true;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

/* First failing check of one validate log at the utxo cursor, or NULL when
 * the row is healthy (or the log is not yet at a failing state). */
static const char *anchor_log_next_failure(
        const struct anchor_log_row_probe *lp,
        const char *unavailable,
        const char *missing,
        const char *failed)
{
    if (!lp->table_present)
        return unavailable;
    if (!lp->row_present)
        return missing;
    if (lp->ok_present && lp->ok == 0)
        return failed;
    return NULL;
}

static const char *anchor_next_diagnosis(
        const struct anchor_utxo_probe *p,
        bool utxo_cursor_present,
        bool proof_cursor_present)
{
    const char *failure = NULL;

    if (!p || !utxo_cursor_present)
        return "utxo_apply_cursor_missing";
    if (!proof_cursor_present)
        return "proof_validate_cursor_missing";
    if (p->next_height >= p->proof_cursor)
        return "utxo_apply_caught_up_to_proof_cursor";
    failure = anchor_log_next_failure(&p->proof_next,
                                      "proof_validate_log_unavailable",
                                      "proof_validate_log_missing_at_utxo_cursor",
                                      "proof_validate_failed_at_utxo_cursor");
    if (failure)
        return failure;
    if (p->utxo_next.row_present)
        return "utxo_apply_row_exists_but_cursor_not_advanced";
    failure = anchor_log_next_failure(&p->script_next,
                                      "script_validate_log_unavailable",
                                      "script_validate_log_missing_at_utxo_cursor",
                                      "script_validate_failed_at_utxo_cursor");
    if (failure)
        return failure;
    if (p->proof_next.ok_present && p->proof_next.ok == 1)
        return "utxo_apply_idle_after_validated_row";
    return "utxo_apply_probe_inconclusive";
}

static const char *anchor_history_diagnosis(
        const struct anchor_utxo_probe *p)
{
    if (!p)
        return "utxo_apply_history_probe_unavailable";
    if (!p->previous_row_expected)
        return "utxo_apply_history_not_yet_expected";
    if (!p->utxo_previous.table_present)
        return "utxo_apply_log_unavailable";
    if (!p->utxo_previous.row_present)
        return "utxo_apply_prior_log_missing_below_coin_frontier";
    if (p->utxo_previous.ok_present && p->utxo_previous.ok == 0)
        return "utxo_apply_prior_log_failed_below_coin_frontier";
    if (p->delta_previous.table_present && !p->delta_previous.row_present)
        return "utxo_apply_prior_delta_missing_below_coin_frontier";
    return "utxo_apply_history_consistent";
}

static const char *anchor_probe_next_action(
        const struct anchor_utxo_probe *p,
        bool fold_recently_active)
{
    if (!p)
        return "inspect_anchorstatus";
    if (strcmp(p->history_diagnosis,
               "utxo_apply_prior_log_missing_below_coin_frontier") == 0)
        return "copy_probe_missing_utxo_apply_log_before_resuming_anchor_mint";
    if (strcmp(p->history_diagnosis,
               "utxo_apply_prior_log_failed_below_coin_frontier") == 0)
        return "inspect_prior_utxo_apply_failure_before_resuming_anchor_mint";
    if (strcmp(p->history_diagnosis,
               "utxo_apply_prior_delta_missing_below_coin_frontier") == 0)
        return "copy_probe_missing_utxo_apply_delta_before_resuming_anchor_mint";
    if (strcmp(p->next_diagnosis,
               "proof_validate_log_missing_at_utxo_cursor") == 0)
        return "repair_or_reseed_proof_validate_log_on_anchor_copy";
    if (strcmp(p->next_diagnosis,
               "proof_validate_failed_at_utxo_cursor") == 0)
        return "inspect_proof_validate_failure_at_utxo_cursor";
    if (strcmp(p->next_diagnosis,
               "script_validate_log_missing_at_utxo_cursor") == 0)
        return "repair_or_reseed_script_validate_log_on_anchor_copy";
    if (strcmp(p->next_diagnosis,
               "script_validate_failed_at_utxo_cursor") == 0)
        return "inspect_script_validate_failure_at_utxo_cursor";
    if (fold_recently_active &&
        strcmp(p->next_diagnosis,
               "utxo_apply_idle_after_validated_row") == 0)
        return "observe_anchor_mint_progress";
    if (strcmp(p->next_diagnosis,
               "utxo_apply_idle_after_validated_row") == 0)
        return "inspect_anchor_mint_liveness_and_durable_activity";
    return "observe_progress_or_drill_into_stage_cursors";
}

static bool anchor_utxo_probe_build(sqlite3 *db,
                                    const struct anchor_stage_view *proof,
                                    const struct anchor_stage_view *utxo,
                                    int64_t durable_frontier,
                                    bool fold_recently_active,
                                    struct anchor_utxo_probe *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->next_height = -1;
    out->proof_cursor = -1;
    out->previous_height = -1;
    out->next_diagnosis = "utxo_apply_probe_unavailable";
    out->history_diagnosis = "utxo_apply_history_probe_unavailable";
    out->next_action = "inspect_anchorstatus";
    anchor_log_row_probe_init(&out->proof_next);
    anchor_log_row_probe_init(&out->script_next);
    anchor_log_row_probe_init(&out->utxo_next);
    anchor_log_row_probe_init(&out->utxo_previous);
    anchor_log_row_probe_init(&out->delta_previous);
    if (!db || !proof || !utxo)
        return false;

    out->available = true;
    out->next_height = utxo->cursor_present ? utxo->cursor : -1;
    out->proof_cursor = proof->cursor_present ? proof->cursor : -1;
    out->previous_height = out->next_height > 0 ? out->next_height - 1 : -1;
    out->previous_row_expected = out->previous_height >= 0 &&
        durable_frontier >= out->previous_height;

    if (utxo->cursor_present) {
        (void)anchor_log_row_probe_at(db, "proof_validate_log",
                                      out->next_height, &out->proof_next);
        (void)anchor_log_row_probe_at(db, "script_validate_log",
                                      out->next_height, &out->script_next);
        (void)anchor_log_row_probe_at(db, "utxo_apply_log",
                                      out->next_height, &out->utxo_next);
    }
    if (out->previous_row_expected) {
        (void)anchor_log_row_probe_at(db, "utxo_apply_log",
                                      out->previous_height,
                                      &out->utxo_previous);
        (void)anchor_log_row_probe_at(db, "utxo_apply_delta",
                                      out->previous_height,
                                      &out->delta_previous);
    }

    out->next_diagnosis = anchor_next_diagnosis(
        out, utxo->cursor_present, proof->cursor_present);
    out->history_diagnosis = anchor_history_diagnosis(out);
    out->previous_row_missing_below_coin_frontier =
        out->previous_row_expected && out->utxo_previous.table_present &&
        !out->utxo_previous.row_present;
    out->previous_delta_missing_below_coin_frontier =
        out->delta_previous.table_present &&
        !out->delta_previous.row_present;
    out->next_action = anchor_probe_next_action(out, fold_recently_active);
    return true;
}

static void anchor_meta_blob_copy(const void *blob, int n,
                                  uint8_t *buf, size_t cap)
{
    if (blob && n > 0 && buf && cap > 0) {
        size_t copy = (size_t)n < cap ? (size_t)n : cap;
        memcpy(buf, blob, copy);
    }
}

static bool anchor_meta_blob(sqlite3 *db, const char *key,
                             uint8_t *buf, size_t cap, size_t *len_out,
                             bool *found_out)
{
    if (len_out)
        *len_out = 0;
    if (found_out)
        *found_out = false;
    if (!db || !key)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, // raw-controller-sql-ok:anchorstatus-progress-kv-readonly
            "SELECT value FROM progress_meta WHERE key=?1",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-diagnostic-cli
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (found_out)
            *found_out = true;
        if (len_out)
            *len_out = n > 0 ? (size_t)n : 0;
        anchor_meta_blob_copy(blob, n, buf, cap);
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static bool anchor_stage_cursor(sqlite3 *db, const char *name,
                                int64_t *cursor_out, bool *present_out)
{
    if (cursor_out)
        *cursor_out = 0;
    if (present_out)
        *present_out = false;
    if (!db || !name)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, // raw-controller-sql-ok:anchorstatus-progress-kv-readonly
            "SELECT cursor FROM stage_cursor WHERE name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-diagnostic-cli
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        if (cursor_out)
            *cursor_out = sqlite3_column_int64(st, 0);
        if (present_out)
            *present_out = true;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static void anchor_table_stats_fill(sqlite3_stmt *st,
                                    int64_t *count_out, int64_t *min_out,
                                    int64_t *max_out, bool *present_out)
{
    if (present_out)
        *present_out = true;
    if (count_out)
        *count_out = sqlite3_column_int64(st, 0);
    if (min_out && sqlite3_column_type(st, 1) != SQLITE_NULL)
        *min_out = sqlite3_column_int64(st, 1);
    if (max_out && sqlite3_column_type(st, 2) != SQLITE_NULL)
        *max_out = sqlite3_column_int64(st, 2);
}

static bool anchor_table_stats(sqlite3 *db, const char *table,
                               int64_t *count_out, int64_t *min_out,
                               int64_t *max_out, bool *present_out)
{
    if (count_out)
        *count_out = 0;
    if (min_out)
        *min_out = -1;
    if (max_out)
        *max_out = -1;
    if (present_out)
        *present_out = false;
    if (!db || !table)
        return false;

    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT count(*), min(height), max(height) FROM %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) // raw-controller-sql-ok:anchorstatus-progress-kv-readonly
        return true; /* older fixture without this log table */
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-diagnostic-cli
    if (rc == SQLITE_ROW)
        anchor_table_stats_fill(st, count_out, min_out, max_out, present_out);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static bool anchor_marker_matches(const uint8_t *marker, size_t len,
                                  const struct sha3_utxo_checkpoint *cp)
{
    if (!marker || len != ANCHOR_MARKER_LEN || !cp)
        return false;
    if (memcmp(marker, "ZAM1", 4) != 0)
        return false;
    if ((int32_t)zcl_read_u32_le(marker + 4) != cp->height)
        return false;
    if (zcl_read_u64_le(marker + 8) != cp->utxo_count)
        return false;
    return memcmp(marker + 16, cp->sha3_hash, 32) == 0;
}

static void anchor_push_stage_json(struct json_value *arr,
                                   const struct anchor_stage_view *s)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "name", s->name);
    json_push_kv_int(&obj, "cursor", s->cursor);
    json_push_kv_bool(&obj, "cursor_present", s->cursor_present);
    json_push_kv_str(&obj, "log_table", s->log_table);
    json_push_kv_bool(&obj, "log_present", s->log_present);
    json_push_kv_int(&obj, "log_count", s->log_count);
    json_push_kv_int(&obj, "log_min_height", s->min_height);
    json_push_kv_int(&obj, "log_max_height", s->max_height);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void anchor_push_row_probe_json(struct json_value *obj,
                                       const char *name,
                                       const struct anchor_log_row_probe *p)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    json_push_kv_bool(&row, "table_present", p && p->table_present);
    json_push_kv_bool(&row, "row_present", p && p->row_present);
    json_push_kv_bool(&row, "ok_present", p && p->ok_present);
    json_push_kv_int(&row, "ok", p ? p->ok : -1);
    json_push_kv_bool(&row, "status_present", p && p->status_present);
    json_push_kv_str(&row, "status",
                     p && p->status_present ? p->status : "");
    json_push_kv(obj, name, &row);
    json_free(&row);
}

static void anchor_push_utxo_probe_text(struct json_value *obj,
                                        const struct anchor_utxo_probe *p)
{
    json_push_kv_str(obj, "next_diagnosis",
                     p && p->next_diagnosis ? p->next_diagnosis
                                             : "utxo_apply_probe_unavailable");
    json_push_kv_str(obj, "history_diagnosis",
                     p && p->history_diagnosis ? p->history_diagnosis
                                                : "utxo_apply_history_probe_unavailable");
    json_push_kv_str(obj, "next_action",
                     p && p->next_action ? p->next_action
                                          : "inspect_anchorstatus");
}

static void anchor_push_utxo_probe_rows(struct json_value *obj,
                                        const struct anchor_utxo_probe *p)
{
    anchor_push_row_probe_json(obj, "proof_validate_at_next",
                               p ? &p->proof_next : NULL);
    anchor_push_row_probe_json(obj, "script_validate_at_next",
                               p ? &p->script_next : NULL);
    anchor_push_row_probe_json(obj, "utxo_apply_at_next",
                               p ? &p->utxo_next : NULL);
    anchor_push_row_probe_json(obj, "utxo_apply_at_previous",
                               p ? &p->utxo_previous : NULL);
    anchor_push_row_probe_json(obj, "utxo_delta_at_previous",
                               p ? &p->delta_previous : NULL);
}

static void anchor_push_utxo_probe_json(struct json_value *result,
                                        const struct anchor_utxo_probe *p)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_bool(&obj, "available", p && p->available);
    json_push_kv_int(&obj, "next_height", p ? p->next_height : -1);
    json_push_kv_int(&obj, "proof_cursor", p ? p->proof_cursor : -1);
    json_push_kv_int(&obj, "previous_height", p ? p->previous_height : -1);
    json_push_kv_bool(&obj, "previous_row_expected",
                      p && p->previous_row_expected);
    json_push_kv_bool(&obj, "previous_row_missing_below_coin_frontier",
                      p && p->previous_row_missing_below_coin_frontier);
    json_push_kv_bool(&obj, "previous_delta_missing_below_coin_frontier",
                      p && p->previous_delta_missing_below_coin_frontier);
    anchor_push_utxo_probe_text(&obj, p);
    anchor_push_utxo_probe_rows(&obj, p);
    json_push_kv(result, "utxo_apply_probe", &obj);
    json_free(&obj);
}

static bool anchor_fold_recently_active(
        bool progress_present,
        bool progress_recent,
        bool marker_matches,
        int64_t anchor_height,
        int64_t durable_frontier,
        const struct anchor_stage_view *utxo,
        const struct anchor_stage_view *tip)
{
    if (!progress_present || !progress_recent || !marker_matches)
        return false;
    if (anchor_height < 0 || durable_frontier >= anchor_height)
        return false;
    if (!utxo || !utxo->cursor_present)
        return false;
    if (utxo->cursor > 1 || durable_frontier > 0)
        return true;
    return tip && tip->cursor_present && tip->cursor > 0;
}

static const char *anchor_summary(bool progress_present, bool snapshot_present,
                                  bool marker_present, bool marker_matches,
                                  bool fold_recently_active,
                                  int64_t durable_frontier,
                                  int64_t anchor_height,
                                  int64_t validated_backlog,
                                  int64_t stale_above_anchor)
{
    if (snapshot_present)
        return "anchor_snapshot_present";
    if (!progress_present)
        return "progress_store_missing";
    if (!marker_present)
        return "mint_not_marked_in_progress";
    if (!marker_matches)
        return "mint_marker_checkpoint_mismatch";
    if (durable_frontier >= anchor_height)
        return "anchor_reached_snapshot_pending";
    if (fold_recently_active)
        return "mint_in_progress_recent";
    if (validated_backlog > 100000)
        return "mint_utxo_apply_far_behind_validated_backlog";
    if (stale_above_anchor > 0 && !marker_matches)
        return "mint_has_stale_rows_above_anchor";
    return "mint_in_progress";
}

static const char *anchor_next_action(const char *summary)
{
    if (!summary)
        return "inspect_anchorstatus";
    if (strcmp(summary, "anchor_snapshot_present") == 0)
        return "copy_prove_refold_from_anchor_then_cutover";
    if (strcmp(summary, "progress_store_missing") == 0)
        return "start_anchor_mint_on_full_history_datadir";
    if (strcmp(summary, "mint_not_marked_in_progress") == 0)
        return "restart_anchor_mint_with_checkpoint_resume_marker";
    if (strcmp(summary, "mint_marker_checkpoint_mismatch") == 0)
        return "stop_and_reseed_anchor_mint_on_a_copy_before_resume";
    if (strcmp(summary, "anchor_reached_snapshot_pending") == 0)
        return "check_snapshot_write_and_sha3_assert_logs";
    if (strcmp(summary, "mint_in_progress_recent") == 0)
        return "observe_anchor_mint_progress";
    if (strcmp(summary, "mint_utxo_apply_far_behind_validated_backlog") == 0)
        return "inspect_utxo_apply_idle_reason_before_waiting_more";
    if (strcmp(summary, "mint_has_stale_rows_above_anchor") == 0)
        return "copy_probe_progress_store_for_stale_rows_before_trusting_resume";
    return "observe_progress_or_drill_into_stage_cursors";
}

struct anchor_status_ctx {
    const char *datadir;
    char progress_path[1100]; /* kernel store = consensus.db */
    char snapshot_path[1100];
    bool progress_present;
    bool snapshot_present;
    int64_t progress_mtime;
    int64_t captured_at_unix;
    int64_t anchor_height;
    const struct sha3_utxo_checkpoint *cp;
};

struct anchor_status_metrics {
    bool marker_present;
    bool marker_matches;
    bool refold_present;
    int64_t coins_applied_height;
    int64_t durable_frontier;
    int64_t coins_ram_flushed_height;
    int64_t min_cursor;
    int64_t max_cursor;
    int64_t stale_above_anchor;
    int64_t validated_backlog;
    int64_t tip_finalize_gap;
    int64_t anchor_gap;
    bool fold_recently_active;
};

static void anchor_status_push_header(struct json_value *result,
                                      const char *datadir)
{
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.anchor_mint_status.v1");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_bool(result, "read_only", true);
    json_push_kv_bool(result, "process_identity_available", false);
    json_push_kv_str(result, "process_identity_reason",
                     "not_exposed_by_platform_facade");
    json_push_kv_str(result, "datadir", datadir);
}

static void anchor_status_push_path_error(struct json_value *result)
{
    json_push_kv_str(result, "status", "error");
    json_push_kv_str(result, "summary", "path_too_long");
    json_push_kv_str(result, "agent_next_action",
                     "use_bounded_datadir_and_snapshot_paths");
}

/* Stats both files and pushes the file-state keys. */
static void anchor_status_push_files(struct json_value *result,
                                     struct anchor_status_ctx *ctx)
{
    int64_t progress_size = 0, snapshot_size = 0, snapshot_mtime = 0;
    ctx->progress_present = agent_cure_stat_file(
        ctx->progress_path, &progress_size, &ctx->progress_mtime);
    ctx->snapshot_present = agent_cure_stat_file(
        ctx->snapshot_path, &snapshot_size, &snapshot_mtime);
    ctx->captured_at_unix = platform_time_wall_unix();
    int64_t progress_age_seconds = agent_cure_progress_age_seconds(
        ctx->progress_present, ctx->captured_at_unix, ctx->progress_mtime);
    json_push_kv_int(result, "captured_at_unix", ctx->captured_at_unix);
    json_push_kv_str(result, "progress_path", ctx->progress_path);
    json_push_kv_bool(result, "progress_present", ctx->progress_present);
    json_push_kv_int(result, "progress_size_bytes", progress_size);
    json_push_kv_int(result, "progress_mtime_unix", ctx->progress_mtime);
    json_push_kv_int(result, "progress_age_seconds", progress_age_seconds);
    json_push_kv_str(result, "snapshot_path", ctx->snapshot_path);
    json_push_kv_bool(result, "snapshot_present", ctx->snapshot_present);
    json_push_kv_int(result, "snapshot_size_bytes", snapshot_size);
    json_push_kv_int(result, "snapshot_mtime_unix", snapshot_mtime);
}

static void anchor_status_push_checkpoint(struct json_value *result,
                                          struct anchor_status_ctx *ctx)
{
    ctx->cp = get_sha3_utxo_checkpoint();
    ctx->anchor_height = ctx->cp ? ctx->cp->height : -1;
    json_push_kv_int(result, "anchor_height", ctx->anchor_height);
    json_push_kv_int(result, "anchor_utxo_count",
                     ctx->cp ? (int64_t)ctx->cp->utxo_count : 0);

    struct agent_cure_snapshot_view snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    if (ctx->snapshot_present)
        agent_cure_snapshot_inspect(ctx->snapshot_path, ctx->cp, &snapshot);
    agent_cure_push_snapshot_json(result, &snapshot);
}

/* Keys shared by the two paths that never open the progress store. */
static void anchor_status_push_unopened(struct json_value *result,
                                        const struct anchor_status_ctx *ctx)
{
    struct agent_cure_eta_view eta;
    agent_cure_eta_build(NULL, ctx->anchor_height, &eta);
    (void)agent_cure_push_activity_json(
        result, ctx->progress_path, ctx->progress_present,
        ctx->progress_mtime, ctx->captured_at_unix, &eta);
    agent_cure_push_eta_json(result, &eta);
    agent_cure_push_import_preflight_json(
        result, NULL, ctx->datadir, -1, -1, -1);
}

static void anchor_status_push_missing(struct json_value *result,
                                       const struct anchor_status_ctx *ctx)
{
    anchor_status_push_unopened(result, ctx);
    json_push_kv_str(result, "status", "missing");
    json_push_kv_bool(result, "fold_recently_active", false);
    const char *summary = anchor_summary(false, ctx->snapshot_present, false,
                                         false, false, -1,
                                         ctx->anchor_height, 0, 0);
    json_push_kv_str(result, "summary", summary);
    json_push_kv_str(result, "agent_next_action",
                     anchor_next_action(summary));
}

static void anchor_status_push_open_failed(struct json_value *result,
                                           const struct anchor_status_ctx *ctx,
                                           sqlite3 *db)
{
    anchor_status_push_unopened(result, ctx);
    json_push_kv_str(result, "status", "error");
    json_push_kv_bool(result, "fold_recently_active", false);
    json_push_kv_str(result, "summary", "progress_store_open_failed");
    json_push_kv_str(result, "agent_next_action",
                     "inspect_progress_store_permissions_or_locking");
    json_push_kv_str(result, "sqlite_error", db ? sqlite3_errmsg(db)
                                                 : "out of memory");
}

#define ANCHOR_STAGE_COUNT 8
#define ANCHOR_STAGE_PROOF 5
#define ANCHOR_STAGE_UTXO 6
#define ANCHOR_STAGE_TIP 7

static void anchor_stages_init(struct anchor_stage_view *stages)
{
    static const struct anchor_stage_view initial[ANCHOR_STAGE_COUNT] = {
        { "header_admit",     "header_admit_log",     0, 0, -1, -1, false, false },
        { "validate_headers", "validate_headers_log", 0, 0, -1, -1, false, false },
        { "body_fetch",       "body_fetch_log",       0, 0, -1, -1, false, false },
        { "body_persist",     "body_persist_log",     0, 0, -1, -1, false, false },
        { "script_validate",  "script_validate_log",  0, 0, -1, -1, false, false },
        { "proof_validate",   "proof_validate_log",   0, 0, -1, -1, false, false },
        { "utxo_apply",       "utxo_apply_log",       0, 0, -1, -1, false, false },
        { "tip_finalize",     "tip_finalize_log",     0, 0, -1, -1, false, false },
    };
    memcpy(stages, initial, sizeof(initial));
}

static void anchor_stages_read(sqlite3 *db, struct anchor_stage_view *stages,
                               struct anchor_status_metrics *m)
{
    m->min_cursor = -1;
    m->max_cursor = -1;
    for (size_t i = 0; i < ANCHOR_STAGE_COUNT; i++) {
        (void)anchor_stage_cursor(db, stages[i].name, &stages[i].cursor,
                                  &stages[i].cursor_present);
        (void)anchor_table_stats(db, stages[i].log_table,
                                 &stages[i].log_count,
                                 &stages[i].min_height,
                                 &stages[i].max_height,
                                 &stages[i].log_present);
        if (!stages[i].cursor_present)
            continue;
        if (m->min_cursor < 0 || stages[i].cursor < m->min_cursor)
            m->min_cursor = stages[i].cursor;
        if (m->max_cursor < 0 || stages[i].cursor > m->max_cursor)
            m->max_cursor = stages[i].cursor;
    }
}

/* An 8-byte little-endian meta value, or -1 when absent or mis-sized. */
static int64_t anchor_meta_height(sqlite3 *db, const char *key)
{
    uint8_t blob[8] = {0};
    size_t len = 0;
    bool present = false;
    (void)anchor_meta_blob(db, key, blob, sizeof(blob), &len, &present);
    return (present && len == 8) ? (int64_t)zcl_read_u64_le(blob) : -1;
}

static void anchor_status_read_meta(sqlite3 *db,
                                    const struct anchor_status_ctx *ctx,
                                    struct anchor_status_metrics *m)
{
    uint8_t blob[ANCHOR_MARKER_LEN] = {0};
    size_t blob_len = 0;
    m->marker_present = false;
    (void)anchor_meta_blob(db, "mint_anchor_in_progress_v1",
                           blob, sizeof(blob), &blob_len, &m->marker_present);
    m->marker_matches = anchor_marker_matches(blob, blob_len, ctx->cp);

    m->coins_applied_height = anchor_meta_height(db, "coins_applied_height");
    m->durable_frontier = m->coins_applied_height >= 0
        ? m->coins_applied_height - 1 : -1;
    m->coins_ram_flushed_height =
        anchor_meta_height(db, "coins_ram_flushed_height");

    int64_t refold_flag = 0;
    m->refold_present = false;
    (void)anchor_sql_i64(db,
        "SELECT length(value) FROM progress_meta WHERE key='refold_in_progress'",
        0, false, &refold_flag, &m->refold_present);

    bool stale_found = false;
    m->stale_above_anchor = 0;
    (void)anchor_sql_i64(db,
        "SELECT count(*) FROM header_admit_log WHERE height>?1",
        ctx->anchor_height, true, &m->stale_above_anchor, &stale_found);
}

static void anchor_status_derive_gaps(const struct anchor_status_ctx *ctx,
                                      const struct anchor_stage_view *stages,
                                      struct anchor_status_metrics *m)
{
    const struct anchor_stage_view *proof = &stages[ANCHOR_STAGE_PROOF];
    const struct anchor_stage_view *utxo = &stages[ANCHOR_STAGE_UTXO];
    const struct anchor_stage_view *tip = &stages[ANCHOR_STAGE_TIP];
    m->validated_backlog = proof->cursor_present && utxo->cursor_present &&
        proof->cursor > utxo->cursor ? proof->cursor - utxo->cursor : 0;
    m->tip_finalize_gap = utxo->cursor_present && tip->cursor_present &&
        utxo->cursor > tip->cursor ? utxo->cursor - tip->cursor : 0;
    m->anchor_gap = ctx->anchor_height >= 0 && m->durable_frontier >= 0
        ? ctx->anchor_height - m->durable_frontier : -1;
    if (m->anchor_gap < 0 && m->durable_frontier >= ctx->anchor_height)
        m->anchor_gap = 0;
}

static void anchor_status_push_metrics(struct json_value *result,
                                       const struct anchor_status_metrics *m)
{
    json_push_kv_bool(result, "mint_marker_present", m->marker_present);
    json_push_kv_bool(result, "mint_marker_matches_checkpoint",
                      m->marker_matches);
    json_push_kv_bool(result, "refold_in_progress_present",
                      m->refold_present);
    json_push_kv_int(result, "coins_applied_height", m->coins_applied_height);
    json_push_kv_int(result, "durable_applied_through_height",
                     m->durable_frontier);
    json_push_kv_int(result, "coins_ram_flushed_height",
                     m->coins_ram_flushed_height);
    json_push_kv_bool(result, "fold_recently_active",
                      m->fold_recently_active);
    json_push_kv_int(result, "anchor_gap_blocks", m->anchor_gap);
    json_push_kv_int(result, "min_stage_cursor", m->min_cursor);
    json_push_kv_int(result, "max_stage_cursor", m->max_cursor);
    json_push_kv_int(result, "validated_backlog_blocks", m->validated_backlog);
    json_push_kv_int(result, "tip_finalize_gap_blocks", m->tip_finalize_gap);
    json_push_kv_int(result, "stale_header_rows_above_anchor",
                     m->stale_above_anchor);
    json_push_kv_bool(result, "stale_rows_above_anchor",
                      m->stale_above_anchor > 0);
}

static void anchor_status_push_stages(struct json_value *result,
                                      const struct anchor_stage_view *stages)
{
    struct json_value stage_arr;
    json_init(&stage_arr);
    json_set_array(&stage_arr);
    for (size_t i = 0; i < ANCHOR_STAGE_COUNT; i++)
        anchor_push_stage_json(&stage_arr, &stages[i]);
    json_push_kv(result, "stages", &stage_arr);
    json_free(&stage_arr);
}

/* Reads the open progress store and pushes every key after "status". The
 * store is closed before the stage array is pushed. */
static void anchor_status_push_open(struct json_value *result,
                                    const struct anchor_status_ctx *ctx,
                                    sqlite3 *db)
{
    struct anchor_stage_view stages[ANCHOR_STAGE_COUNT];
    struct anchor_status_metrics m;
    anchor_stages_init(stages);
    anchor_stages_read(db, stages, &m);
    anchor_status_read_meta(db, ctx, &m);
    anchor_status_derive_gaps(ctx, stages, &m);

    struct agent_cure_eta_view eta;
    agent_cure_eta_build(db, ctx->anchor_height, &eta);
    bool progress_recent = agent_cure_push_activity_json(
        result, ctx->progress_path, true, ctx->progress_mtime,
        ctx->captured_at_unix, &eta);
    m.fold_recently_active = anchor_fold_recently_active(
        ctx->progress_present, progress_recent, m.marker_matches,
        ctx->anchor_height, m.durable_frontier,
        &stages[ANCHOR_STAGE_UTXO], &stages[ANCHOR_STAGE_TIP]);

    struct anchor_utxo_probe utxo_probe;
    (void)anchor_utxo_probe_build(db, &stages[ANCHOR_STAGE_PROOF],
                                  &stages[ANCHOR_STAGE_UTXO],
                                  m.durable_frontier, m.fold_recently_active,
                                  &utxo_probe);
    agent_cure_push_import_preflight_json(
        result, db, ctx->datadir, stages[0].cursor, stages[2].cursor,
        stages[3].cursor);
    sqlite3_close(db);

    anchor_status_push_stages(result, stages);
    anchor_status_push_metrics(result, &m);
    anchor_push_utxo_probe_json(result, &utxo_probe);
    agent_cure_push_eta_json(result, &eta);
    json_push_kv_str(result, "utxo_apply_probe_next_action",
                     utxo_probe.next_action);
    json_push_kv_str(result, "semantics",
                     "durable_applied_through_height is the persisted coins_kv/flush frontier; in-RAM overlay work is only trusted after a flush or final SHA3 snapshot assert");

    const char *summary = anchor_summary(ctx->progress_present,
                                         ctx->snapshot_present,
                                         m.marker_present, m.marker_matches,
                                         m.fold_recently_active,
                                         m.durable_frontier, ctx->anchor_height,
                                         m.validated_backlog,
                                         m.stale_above_anchor);
    json_push_kv_str(result, "summary", summary);
    json_push_kv_str(result, "agent_next_action", anchor_next_action(summary));
}

static bool anchor_status_read(const char *datadir, struct json_value *result)
{
    if (!result)
        return false;

    struct anchor_status_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = datadir && datadir[0] ? datadir : ".";
    bool paths_ok = consensus_db_kernel_store_path(
        ctx.datadir, ctx.progress_path, sizeof(ctx.progress_path));
    paths_ok = agent_cure_path_join(ctx.snapshot_path,
                                    sizeof(ctx.snapshot_path), ctx.datadir,
                                    "utxo-anchor.snapshot") && paths_ok;

    anchor_status_push_header(result, ctx.datadir);
    if (!paths_ok) {
        anchor_status_push_path_error(result);
        return true;
    }
    anchor_status_push_files(result, &ctx);
    anchor_status_push_checkpoint(result, &ctx);
    if (!ctx.progress_present) {
        anchor_status_push_missing(result, &ctx);
        return true;
    }

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(ctx.progress_path, &db, SQLITE_OPEN_READONLY, NULL) !=
        SQLITE_OK) {
        anchor_status_push_open_failed(result, &ctx, db);
        sqlite3_close(db);
        return true;
    }
    sqlite3_busy_timeout(db, 2000);
    json_push_kv_str(result, "status", "ok");
    anchor_status_push_open(result, &ctx, db);
    return true;
}

bool rpc_agent_anchor_status(const struct json_value *params, bool help,
                             struct json_value *result)
{
    RPC_HELP(help, result,
        "anchorstatus [datadir]\n"
        "\nRead a mint-anchor datadir's kernel store (consensus.db) and return the\n"
        "sovereign-anchor producer state. This is a no-cookie static command\n"
        "for offline/transient anchor mint services.\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    const char *ctx_datadir = agent_runtime_context_datadir();
    const char *datadir = rpc_permit_str(&p, 0, "datadir",
                                         ctx_datadir && ctx_datadir[0]
                                             ? ctx_datadir
                                             : ".");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }
    return anchor_status_read(datadir, result);
}
