/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_stage_dump — the native dump-state JSON view for the
 * script_validate Job. Reads the stage-owned state through sibling-private
 * accessors so the reducer step logic stays focused on validation and cursor
 * movement.
 */

#include "platform/time_compat.h"
#include "jobs/script_validate_contextual.h"
#include "jobs/script_validate_stage.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_log_rows.h"
#include "script_validate_stage_internal.h"

#include "core/uint256.h"
#include "json/json.h"
#include "script/script_error.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STAGE_NAME "script_validate"

/* Emit {blocking_height, status, reason, txid, vin} for the lowest logged
 * height with ok=0 — i.e. the first row holding the pipeline back. Reads the
 * status + first_failure_* columns persisted by step_validate and composes
 * the full typed reason (e.g. "prevout_unresolved tx=<hex> vin=<n>"), so
 * `z23 dumpstate script_validate` answers why the pipeline is stuck.
 * No-op (emits blocking_height=-1) when nothing is blocking. The caller holds
 * the (recursive) progress-store lock — acquired non-blocking at the dump entry
 * — for the whole db section, so this helper does not lock itself. */
static void dump_blocking_failure(struct json_value *out, sqlite3 *db)
{
    if (!db) {
        json_push_kv_int(out, "blocking_height", -1);
        return;
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT height, status, first_failure_txid, first_failure_vin, "
        "       first_failure_serror "
        "FROM script_validate_log WHERE ok = 0 "
        "ORDER BY height ASC LIMIT 1",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("script_validate",
                 "[script_validate] dump blocking prepare failed: %s",
                 sqlite3_errmsg(db));
        json_push_kv_int(out, "blocking_height", -1);
        return;
    }

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        json_push_kv_int(out, "blocking_height", -1);
        return;
    }

    int64_t height = sqlite3_column_int64(st, 0);
    const unsigned char *status_c = sqlite3_column_text(st, 1);
    const char *status = status_c ? (const char *)status_c : "(unknown)";

    char txhex[65] = {0};
    const void *blob = sqlite3_column_blob(st, 2);
    int blob_len = sqlite3_column_bytes(st, 2);
    bool have_txid = (blob && blob_len == 32);
    if (have_txid) {
        struct uint256 txid;
        memcpy(txid.data, blob, 32);
        uint256_get_hex(&txid, txhex);
    }

    int vin = sqlite3_column_type(st, 3) == SQLITE_NULL
                  ? -1 : sqlite3_column_int(st, 3);

    /* ScriptError is persisted only for a script-invalid verdict (NULL on
     * decode/prevout/upstream rows). Map it back to its stable string. */
    bool have_serror = sqlite3_column_type(st, 4) != SQLITE_NULL;
    int serror_code = have_serror ? sqlite3_column_int(st, 4)
                                  : (int)SCRIPT_ERR_OK;
    const char *serror_str =
        have_serror ? ScriptErrorString((ScriptError)serror_code) : "";

    /* Compose the full typed reason from the persisted token + columns. */
    char reason[224];
    if (have_txid && vin >= 0 && have_serror)
        snprintf(reason, sizeof(reason), "%s tx=%s vin=%d err=%d (%s)",
                 status, txhex, vin, serror_code, serror_str);
    else if (have_txid && vin >= 0)
        snprintf(reason, sizeof(reason), "%s tx=%s vin=%d",
                 status, txhex, vin);
    else if (have_txid)
        snprintf(reason, sizeof(reason), "%s tx=%s", status, txhex);
    else
        snprintf(reason, sizeof(reason), "%s", status);

    json_push_kv_int(out, "blocking_height", height);
    json_push_kv_str(out, "blocking_status", status);
    json_push_kv_str(out, "blocking_reason", reason);
    json_push_kv_str(out, "blocking_txid", have_txid ? txhex : "");
    json_push_kv_int(out, "blocking_vin", vin);
    json_push_kv_int(out, "blocking_serror", have_serror ? serror_code : -1);
    json_push_kv_str(out, "blocking_serror_string", serror_str);
    sqlite3_finalize(st);
}

bool script_validate_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("script_validate", "dump_state: output is NULL");
    json_set_object(out);

    sqlite3 *db = progress_store_db();
    int64_t now = platform_time_wall_unix();
    int64_t last = script_validate_stage_last_step_unix();
    stage_t *stage = script_validate_stage_handle();

    stage_dump_header(out, STAGE_NAME, stage);
    json_push_kv_int(out, "verified_total",
                     (int64_t)script_validate_stage_verified_total());
    json_push_kv_int(out, "script_invalid_total",
                     (int64_t)script_validate_stage_script_invalid_total());
    json_push_kv_int(out, "internal_error_total",
                     (int64_t)script_validate_stage_internal_error_total());
    json_push_kv_int(out, "upstream_failed_total",
                     (int64_t)script_validate_stage_upstream_failed_total());
    json_push_kv_int(out, "contextual_reject_total",
                     (int64_t)script_validate_contextual_reject_total());
    json_push_kv_int(out, "inputs_verified_total",
                     (int64_t)script_validate_stage_inputs_verified_total());
    json_push_kv_int(out, "inputs_failed_total",
                     (int64_t)script_validate_stage_inputs_failed_total());
    json_push_kv_int(out, "header_event_emit_total",
                     (int64_t)script_validate_stage_header_event_emit_total());
    json_push_kv_int(out, "header_event_emit_fail_total",
                     (int64_t)script_validate_stage_header_event_emit_fail_total());
    json_push_kv_int(out, "last_advance_height",
                     script_validate_stage_last_advance_height());
    json_push_kv_int(out, "last_step_unix", last);
    json_push_kv_int(out, "last_step_age_seconds",
                     last > 0 ? now - last : -1);
    json_push_kv_int(out, "last_blocked_unix",
                     script_validate_stage_last_blocked_unix());

    /* log_rows: the O(1) published counter (stage_log_rows.h), read lock-free so
     * it is present on BOTH the busy and free paths — never a blocking COUNT(*). */
    stage_log_rows_emit(out, "script_validate_log", "log_rows");

    /* The blocking-failure detail below is db-backed and needs the
     * progress-store lock. During catch-up the reducer owns that lock around
     * bulk folds; a blocking acquire here queues the RPC worker behind the fold
     * and makes `dumpstate script_validate` / status disappear exactly when the
     * node is busiest. Acquire non-blocking (recursive lock, held across the
     * whole db section so the helper below need not re-lock) and emit the same
     * busy/retryable marker reducer_frontier_dump uses when the fold owns the
     * lock. The lock-free counters above are always present. */
    if (db && !progress_store_tx_trylock()) {
        json_push_kv_bool(out, "snapshot_complete", false);
        json_push_kv_str(out, "snapshot_status", "progress_store_busy");
        json_push_kv_bool(out, "retryable", true);
        stage_dump_counters(out, stage);
        stage_dump_health(out, STAGE_NAME, stage);
        return true;
    }
    /* "Why is the pipeline stuck": surface the lowest ok=0 row's typed
     * reason (status + txid + vin) so dumpstate pinpoints the blocker. */
    dump_blocking_failure(out, db);
    if (db) progress_store_tx_unlock();
    stage_dump_counters(out, stage);
    stage_dump_health(out, STAGE_NAME, stage);
    return true;
}
