/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_dump — the native dump-state JSON view for the utxo_apply Job,
 * split out of utxo_apply_stage.c to keep that file under the framework
 * file-size ceiling. Reads the module state declared in
 * utxo_apply_stage_internal.h with atomic_load only (the dump runs on
 * native/RPC threads while the supervisor thread steps the stage) and
 * allocates nothing — the caller's json_value owns the buffer. */

#include "platform/time_compat.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_log_rows.h"
#include "utxo_apply_stage_internal.h"

#include "core/uint256.h"
#include "json/json.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#define STAGE_NAME "utxo_apply"

/* Surface the lowest ok=0 row (status/reason kind/txid/vout) into `out`,
 * mirroring the validate_headers_report failure-summary query convention.
 * The reason kind is utxo_apply's first_failure_kind (e.g. lookup_spend,
 * spend_unknown_utxo); the txid|vout is decoded from the 36-byte detail
 * blob. No-op if the db is unavailable or there is no failing row. The caller
 * holds the (recursive) progress-store lock — acquired non-blocking at the dump
 * entry — for the whole db section, so this helper does not lock itself. */
static void dump_first_failure(struct json_value *out, sqlite3 *db)
{
    if (!db) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT height, COALESCE(status,''), "
        "       COALESCE(first_failure_kind,''), first_failure_detail "
        "  FROM utxo_apply_log WHERE ok=0 "
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        json_push_kv_int(out, "first_failure_height",
                         sqlite3_column_int64(st, 0));
        const unsigned char *status = sqlite3_column_text(st, 1);
        const unsigned char *kind = sqlite3_column_text(st, 2);
        json_push_kv_str(out, "first_failure_status",
                         status ? (const char *)status : "");
        json_push_kv_str(out, "first_failure_kind",
                         kind ? (const char *)kind : "");
        const uint8_t *d = sqlite3_column_blob(st, 3);
        char hex[65] = {0};
        int64_t vout = -1;
        if (d && sqlite3_column_bytes(st, 3) == 36) {
            struct uint256 t;
            memcpy(t.data, d, 32);
            uint256_get_hex(&t, hex);
            vout = (int64_t)d[32] | ((int64_t)d[33] << 8) |
                   ((int64_t)d[34] << 16) | ((int64_t)d[35] << 24);
        }
        json_push_kv_str(out, "first_failure_txid", hex);
        json_push_kv_int(out, "first_failure_vout", vout);
    }
    sqlite3_finalize(st);
}

bool utxo_apply_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    sqlite3 *db = progress_store_db();
    int64_t now = platform_time_wall_unix();
    int64_t last = atomic_load(&g_ua_last_step_unix);
    stage_t *stage = utxo_apply_stage_handle();

    stage_dump_header(out, STAGE_NAME, stage);
    json_push_kv_int (out, "verified_total",
                      (int64_t)atomic_load(&g_ua_verified_total));
    json_push_kv_int (out, "spend_unknown_total",
                      (int64_t)atomic_load(&g_ua_spend_unknown_total));
    json_push_kv_int (out, "utxo_collision_total",
                      (int64_t)atomic_load(&g_ua_utxo_collision_total));
    json_push_kv_int (out, "value_overflow_total",
                      (int64_t)atomic_load(&g_ua_value_overflow_total));
    json_push_kv_int (out, "coinbase_protect_total",
                      (int64_t)atomic_load(&g_ua_coinbase_protect_total));
    json_push_kv_int (out, "bad_cb_amount_total",
                      (int64_t)atomic_load(&g_ua_bad_cb_amount_total));
    json_push_kv_int (out, "shielded_double_spend_total",
                      (int64_t)atomic_load(&g_ua_shielded_double_spend_total));
    json_push_kv_int (out, "shielded_anchor_reject_total",
                      (int64_t)atomic_load(&g_ua_shielded_anchor_reject_total));
    json_push_kv_int (out, "upstream_failed_total",
                      (int64_t)atomic_load(&g_ua_upstream_failed_total));
    json_push_kv_int (out, "internal_error_total",
                      (int64_t)atomic_load(&g_ua_internal_error_total));
    json_push_kv_int (out, "reorg_unwound_total",
                      (int64_t)atomic_load(&g_ua_reorg_unwound_total));
    json_push_kv_int (out, "outputs_added_total",
                      (int64_t)atomic_load(&g_ua_total_outputs_added));
    json_push_kv_int (out, "outputs_spent_total",
                      (int64_t)atomic_load(&g_ua_total_outputs_spent));
    json_push_kv_int (out, "last_advance_height",
                      atomic_load(&g_ua_last_advance_height));
    json_push_kv_int (out, "last_step_unix", last);
    json_push_kv_int (out, "last_step_age_seconds",
                      last > 0 ? now - last : -1);
    json_push_kv_int (out, "last_blocked_unix",
                      atomic_load(&g_ua_last_blocked_unix));
    /* FIX-4 durable-upstream-hole evidence (see the internal header): a
     * non-zero consec means the stage is idling RIGHT NOW on a missing
     * proof_validate_log row below the proof_validate cursor — the silent
     * hole-idle class this surfacing makes observable. height/first_unix
     * pin the current/last hole; total counts distinct holes. */
    json_push_kv_int (out, "upstream_hole_total",
                      (int64_t)atomic_load(&g_ua_upstream_hole_total));
    json_push_kv_int (out, "upstream_hole_height",
                      atomic_load(&g_ua_upstream_hole_height));
    json_push_kv_int (out, "upstream_hole_first_unix",
                      atomic_load(&g_ua_upstream_hole_first_unix));
    json_push_kv_int (out, "upstream_hole_consec",
                      (int64_t)atomic_load(&g_ua_upstream_hole_consec));
    /* Hash-bound verdict refusals (header height-splice class): non-zero
     * means a height-keyed script_validate_log row was provably bound to a
     * different block than the one being applied and the apply was refused
     * (typed blocker utxo_apply.label_splice carries the live evidence). */
    json_push_kv_int (out, "label_splice_total",
                      (int64_t)atomic_load(&g_ua_label_splice_total));
    json_push_kv_int (out, "window_miss_total",
                      (int64_t)atomic_load(&g_ua_window_miss_total));
    json_push_kv_int (out, "window_miss_height",
                      atomic_load(&g_ua_window_miss_height));
    json_push_kv_int (out, "hash_bound_fallback_total",
                      (int64_t)atomic_load(&g_ua_hash_bound_fallback_total));
    json_push_kv_int (out, "hash_bound_fallback_height",
                      atomic_load(&g_ua_hash_bound_fallback_height));
    int64_t select_reason = atomic_load(&g_ua_select_idle_reason);
    json_push_kv_int (out, "select_idle_total",
                      (int64_t)atomic_load(&g_ua_select_idle_total));
    json_push_kv_int (out, "select_idle_height",
                      atomic_load(&g_ua_select_idle_height));
    json_push_kv_str (out, "select_idle_reason",
                      utxo_apply_select_idle_reason_name(
                          (enum utxo_apply_select_idle_reason)select_reason));

    /* log_rows is the O(1) published counter (stage_log_rows.h) — read lock-free
     * so it is present on BOTH the busy and free paths, never a blocking
     * COUNT(*) over the ~3.18M-row utxo_apply_log. */
    stage_log_rows_emit(out, "utxo_apply_log", "log_rows");

    /* The first-failure detail + applied-frontier below are db-backed and need
     * the progress-store lock. During
     * catch-up the reducer owns that lock around bulk folds; a blocking acquire
     * here queues the RPC worker behind the fold and makes `dumpstate utxo_apply`
     * / status disappear exactly when the node is busiest. Acquire non-blocking
     * (recursive lock, held across the whole db section so the helpers below need
     * not re-lock) and emit the same busy/retryable marker reducer_frontier_dump
     * uses when the fold owns the lock. The lock-free counters above are always
     * present. */
    if (db && !progress_store_tx_trylock()) {
        json_push_kv_bool(out, "snapshot_complete", false);
        json_push_kv_str (out, "snapshot_status", "progress_store_busy");
        json_push_kv_bool(out, "retryable", true);
        stage_dump_counters(out, stage);
        return true;
    }

    /* P2 self-heal input: the contiguous applied frontier and whether it equals
     * the durable utxo_apply cursor (the invariant the co-commit sites enforce).
     * Surfaced here so `z23 dumpstate utxo_apply` shows the invariant
     * directly — frontier_eq_cursor must be true on every quiescent path.
     * coins_applied_height == -1 means ABSENT (a virgin / un-synced datadir),
     * which is a clean "unknown", not a violation. */
    if (db) {
        int32_t frontier = -1;
        bool fr_found = false;
        bool fr_ok = coins_kv_get_applied_height(db, &frontier, &fr_found);
        uint64_t ua_cursor = stage_cursor_persisted(db, STAGE_NAME, STAGE_NAME);
        json_push_kv_int(out, "coins_applied_height",
                         (fr_ok && fr_found) ? (int64_t)frontier : -1);
        json_push_kv_bool(out, "frontier_eq_cursor",
                          fr_ok && fr_found &&
                          (uint64_t)frontier == ua_cursor);
    }
    dump_first_failure(out, db);
    if (db) progress_store_tx_unlock();
    stage_dump_counters(out, stage);
    return true;
}
