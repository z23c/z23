/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_dump - native dump-state diagnostics for the reducer L0 authority.
 * Read-only: every SQLite statement is a SELECT over progress.kv. */

#include "jobs/reducer_frontier.h"

#include "reducer_frontier_rewind_bases.h"
#include "reducer_frontier_itag.h"

#include "json/json.h"
#include "net/connman.h"
#include "services/sync_monitor.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"

#include <sqlite3.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct dump_log {
    const char *stage;
    const char *log_table;
    const char *cursor_name;
    bool served_tip_cursor;
};

struct dump_frontier {
    bool cursor_ok;
    bool frontier_ok;
    int64_t raw_cursor;
    int64_t next_cursor;
    int32_t contiguous_frontier;
};

struct hstar_blocker {
    bool found;
    bool pending_edge;
    const char *stage;
    const char *log_table;
    const char *pending_stage;
    const char *pending_log_table;
    int32_t height;
    const char *kind;
    char reason[128];
    char pending_reason[128];
};

static const struct dump_log k_logs[] = {
    { "validate_headers", "validate_headers_log", "validate_headers", false },
    { "script_validate",  "script_validate_log",  "script_validate",  false },
    { "body_persist",     "body_persist_log",     "body_persist",     false },
    { "proof_validate",   "proof_validate_log",   "proof_validate",   false },
    { "utxo_apply",       "utxo_apply_log",       "utxo_apply",       false },
    { "tip_finalize",     "tip_finalize_log",     "tip_finalize",     true  },
};

static const char *const k_stage_cursors[] = {
    "header_admit",
    "validate_headers",
    "body_fetch",
    "body_persist",
    "script_validate",
    "proof_validate",
    "utxo_apply",
    "tip_finalize",
};

static int64_t next_cursor_for_dump(const struct dump_log *log, int64_t cursor)
{
    return log && log->served_tip_cursor && cursor > 0 ? cursor + 1 : cursor;
}

/* Highest height a stage cursor has already consumed. Every reducer stage step
 * reads `next_h = cursor_in` and writes `cursor_in + 1` (header_admit_stage.c,
 * body_fetch_stage.c, body_persist_stage.c, script_validate_stage.c,
 * proof_validate_stage.c, tip_finalize_stage.c), so the cursor names the NEXT
 * height and the consumed height is one below it — uniformly, tip_finalize
 * included: its live cursor sits one behind the others precisely because its
 * contiguous frontier IS H*. The served-tip +1 that next_cursor_for_dump
 * applies covers the seed-anchor stamping (a seed anchor at H stamps cursor H),
 * where this reads one height LOW. That direction is chosen deliberately: a
 * "this may be wrong" marker that under-reports the edge by one is honest,
 * while one that over-reports fires on every healthy store and gets ignored. */
static int64_t cursor_consumed_height(int64_t cursor)
{
    return cursor - 1;
}

/* Map a first-H*-blocker to the subsystem that owns its repair. Kind-keyed
 * with a reason refinement, and NEVER empty: the reason-only table this
 * replaced had no entry for kind=log_hole (missing-success-row), so the
 * 3166989 script_validate_log hole dumped repair_owner="" and the 3 h stall
 * surfaced with zero named owners. kind=ok0_failure keeps the two stored-
 * header reasons with stale_validate_headers_repair; log_hole (refill from
 * the on-disk body), hash_split (one-shot script re-derivation via
 * maybe_repair_validate_script_hash_split in try_replay_repairs), and every
 * other ok=0 reason are driven by the reducer_frontier_reconcile_light
 * condition. */
static const char *diagnostic_repair_hint(const char *kind, const char *reason)
{
    if (kind && strcmp(kind, "ok0_failure") == 0 && reason &&
        (strcmp(reason, "no-header-solution-backfill-required") == 0 ||
         strcmp(reason, "header-source-hash-mismatch") == 0))
        return "stale_validate_headers_repair";
    return "reducer_frontier_reconcile_light";
}

static bool table_exists(sqlite3 *db, const char *name, bool *out)
{
    *out = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = ? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "dump table_exists prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "dump table_exists step failed table=%s: %s",
                 name, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static bool schema_ready(sqlite3 *db, char *missing, size_t missing_sz)
{
    if (missing && missing_sz > 0)
        missing[0] = '\0';

    bool present = false;
    if (!table_exists(db, "stage_cursor", &present))
        return false;
    if (!present) {
        if (missing && missing_sz > 0)
            snprintf(missing, missing_sz, "%s", "stage_cursor");
        return true;
    }
    if (!table_exists(db, "progress_meta", &present))
        return false;
    if (!present) {
        if (missing && missing_sz > 0)
            snprintf(missing, missing_sz, "%s", "progress_meta");
        return true;
    }
    for (size_t i = 0; i < sizeof(k_logs) / sizeof(k_logs[0]); i++) {
        if (!table_exists(db, k_logs[i].log_table, &present))
            return false;
        if (!present) {
            if (missing && missing_sz > 0)
                snprintf(missing, missing_sz, "%s", k_logs[i].log_table);
            return true;
        }
    }
    return true;
}

static bool cursor_at(sqlite3 *db, const char *name, int64_t *out)
{
    *out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "dump cursor prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int64(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "dump cursor step failed stage=%s: %s",
                 name, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static bool first_validate_failure(sqlite3 *db,
                                   int32_t min_exclusive,
                                   int32_t max_inclusive,
                                   bool *found,
                                   int32_t *height,
                                   char *reason,
                                   size_t reason_sz)
{
    *found = false;
    *height = -1;
    if (reason && reason_sz > 0)
        reason[0] = '\0';

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height, COALESCE(fail_reason, '') "
            "FROM validate_headers_log "
            "WHERE height > ? AND height <= ? AND ok = 0 "
            "ORDER BY height ASC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "dump first validate failure prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, min_exclusive);
    sqlite3_bind_int(st, 2, max_inclusive);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *found = true;
        *height = (int32_t)sqlite3_column_int64(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (reason && reason_sz > 0)
            snprintf(reason, reason_sz, "%s", txt ? (const char *)txt : "");
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "dump first validate failure step failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static const char *blocker_row_sql(const struct dump_log *log)
{
    if (!log)
        return NULL;
    if (strcmp(log->log_table, "validate_headers_log") == 0)
        return "SELECT ok, COALESCE(fail_reason, '') "
               "FROM validate_headers_log WHERE height = ?";
    if (strcmp(log->log_table, "script_validate_log") == 0)
        return "SELECT ok, COALESCE(status, '') "
               "FROM script_validate_log WHERE height = ?";
    if (strcmp(log->log_table, "body_persist_log") == 0)
        return "SELECT ok, COALESCE(source, '') "
               "FROM body_persist_log WHERE height = ?";
    if (strcmp(log->log_table, "proof_validate_log") == 0)
        return "SELECT ok, '' FROM proof_validate_log WHERE height = ?";
    if (strcmp(log->log_table, "utxo_apply_log") == 0)
        return "SELECT ok, '' FROM utxo_apply_log WHERE height = ?";
    if (strcmp(log->log_table, "tip_finalize_log") == 0)
        return "SELECT ok, COALESCE(status, '') "
               "FROM tip_finalize_log WHERE height = ?";
    return NULL;
}

static bool blocker_row_at(sqlite3 *db,
                           const struct dump_log *log,
                           int32_t height,
                           bool *found,
                           bool *ok,
                           char *reason,
                           size_t reason_sz)
{
    *found = false;
    *ok = false;
    if (reason && reason_sz > 0)
        reason[0] = '\0';

    const char *sql = blocker_row_sql(log);
    if (!sql)
        LOG_FAIL("reducer", "dump blocker row has unknown log table");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "dump blocker row prepare failed table=%s: %s",
                 log->log_table, sqlite3_errmsg(db));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *found = true;
        *ok = sqlite3_column_int(st, 0) != 0;
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (reason && reason_sz > 0)
            snprintf(reason, reason_sz, "%s", txt ? (const char *)txt : "");
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "dump blocker row step failed table=%s h=%d: %s",
                 log->log_table, height, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static bool hash_split_at(sqlite3 *db, int32_t height, bool *split)
{
    *split = false;
    uint8_t validate_hash[32] = {0};
    uint8_t script_hash[32] = {0};
    bool validate_found = false;
    bool script_found = false;

    if (!reducer_frontier_log_hash_at(db, "validate_headers_log", "hash",
                                      height, validate_hash, &validate_found))
        return false;
    if (!reducer_frontier_log_hash_at(db, "script_validate_log", "block_hash",
                                      height, script_hash, &script_found))
        return false;

    *split = validate_found && script_found &&
        memcmp(validate_hash, script_hash, sizeof(validate_hash)) != 0;
    return true;
}

static bool tip_finalize_pending_edge(const struct dump_log *log,
                                      const struct dump_frontier *fr,
                                      int64_t block_height)
{
    /* tip_finalize's raw cursor is the served tip. A finalized row at H proves
     * H, then the cursor advances to H+1 while the H+1 -> H+2 transition is
     * still pending. That expected frontier edge has no row at the raw cursor
     * yet and is not a repairable log hole. Older holes below the raw cursor
     * still report as blockers. */
    return log && fr && log->served_tip_cursor &&
           fr->raw_cursor == block_height &&
           fr->contiguous_frontier + 1 == block_height;
}

static bool first_hstar_blocker(sqlite3 *db,
                                int32_t hstar,
                                const struct dump_frontier *frontiers,
                                size_t frontier_count,
                                struct hstar_blocker *out)
{
    if (!out)
        LOG_FAIL("reducer", "dump hstar blocker missing out param");
    memset(out, 0, sizeof(*out));
    out->height = -1;
    out->kind = "";
    out->stage = "";
    out->log_table = "";
    out->pending_stage = "";
    out->pending_log_table = "";

    int64_t block_height = (int64_t)hstar + 1;
    if (block_height < 0 || block_height > INT32_MAX)
        return true;
    out->height = (int32_t)block_height;

    size_t log_count = sizeof(k_logs) / sizeof(k_logs[0]);
    if (frontier_count < log_count)
        LOG_FAIL("reducer", "dump hstar blocker frontier count too small");
    for (size_t i = 0; i < log_count; i++) {
        const struct dump_frontier *fr = &frontiers[i];
        if (!fr->cursor_ok || !fr->frontier_ok)
            continue;
        if (fr->contiguous_frontier != hstar)
            continue;
        if (fr->next_cursor <= block_height)
            continue;

        bool row_found = false;
        bool row_ok = false;
        char reason[128] = "";
        if (!blocker_row_at(db, &k_logs[i], out->height, &row_found, &row_ok,
                            reason, sizeof(reason)))
            return false;
        if (!row_found) {
            if (tip_finalize_pending_edge(&k_logs[i], fr, block_height)) {
                out->pending_edge = true;
                out->pending_stage = k_logs[i].stage;
                out->pending_log_table = k_logs[i].log_table;
                snprintf(out->pending_reason, sizeof(out->pending_reason),
                         "%s", "tip-finalize-edge-pending");
                continue;
            }
            out->found = true;
            out->stage = k_logs[i].stage;
            out->log_table = k_logs[i].log_table;
            out->kind = "log_hole";
            snprintf(out->reason, sizeof(out->reason),
                     "%s", "missing-success-row");
            return true;
        }
        if (!row_ok) {
            out->found = true;
            out->stage = k_logs[i].stage;
            out->log_table = k_logs[i].log_table;
            out->kind = "ok0_failure";
            snprintf(out->reason, sizeof(out->reason),
                     "%s", reason[0] ? reason : "ok=0");
            return true;
        }
    }

    bool split = false;
    if (!hash_split_at(db, out->height, &split))
        return false;
    if (split) {
        out->found = true;
        out->stage = "script_validate";
        out->log_table = "script_validate_log";
        out->kind = "hash_split";
        snprintf(out->reason, sizeof(out->reason),
                 "%s", "validate-script-hash-mismatch");
        return true;
    }

    out->height = -1;
    return true;
}

bool reducer_frontier_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    sqlite3 *db = progress_store_db();
    json_push_kv_bool(out, "open", db != NULL);
    json_push_kv_str(out, "authority", "reducer_frontier_hstar");
    json_push_kv_int(out, "floor", reducer_frontier_floor());
    json_push_kv_int(out, "cached_provable_tip",
                     reducer_frontier_provable_tip_cached());
    if (!db) {
        json_push_kv_bool(out, "schema_ready", false);
        json_push_kv_str(out, "schema_missing", "progress_store");
        return true;
    }

    /* Diagnostics are an observational surface, not a reducer dependency.
     * A catch-up batch can legitimately own the singleton connection for long
     * enough to exceed the RPC deadline; queueing dumpstate/status requests behind
     * it made the daily operator endpoint disappear exactly while the node was
     * busiest. Return the lock-free published frontier with an explicit busy
     * durable snapshot instead. A later call can fill in the SQLite detail. */
    if (!progress_store_tx_trylock()) {
        json_push_kv_bool(out, "snapshot_complete", false);
        json_push_kv_str(out, "snapshot_status", "progress_store_busy");
        json_push_kv_bool(out, "retryable", true);
        return true;
    }
    json_push_kv_bool(out, "snapshot_complete", true);
    json_push_kv_str(out, "snapshot_status", "available");

    char missing[64] = "";
    bool ready = schema_ready(db, missing, sizeof(missing));
    if (!ready) {
        progress_store_tx_unlock();
        return false;
    }
    json_push_kv_bool(out, "schema_ready", missing[0] == '\0');
    json_push_kv_str(out, "schema_missing", missing);
    if (missing[0] != '\0') {
        progress_store_tx_unlock();
        return true;
    }

    int32_t hstar = -1;
    int32_t served_floor = -1;
    if (!reducer_frontier_compute_hstar(db, &hstar, &served_floor)) {
        progress_store_tx_unlock();
        return false;
    }
    json_push_kv_int(out, "hstar", hstar);
    json_push_kv_int(out, "served_floor", served_floor);
    json_push_kv_int(out, "served_gap",
                     served_floor > hstar ? (int64_t)served_floor - hstar : 0);
    json_push_kv_bool(out, "served_above_hstar", served_floor > hstar);
    /* Untagged-row visibility: ABSENT (NULL-itag) rows the last fold trusted but
     * flagged (UNTAGGED-ROW POLICY, reducer_frontier_itag.h). Nonzero after
     * migration means a writer is still emitting untagged rows. */
    json_push_kv_int(out, "itag_null_rows_seen",
                     (int64_t)reducer_frontier_itag_null_count());

    /* Tail-fold progress: H* against the network's best-known tip, published
     * lock-free by sync_monitor's periodic tip evaluation.  Reading the
     * cached value is deliberate: diagnostics can run during shutdown, after
     * connman has destroyed its node mutex, and must never dereference that
     * retired object. This is the one number that
     * answers "is a cured (release_assisted) node now catching the tail up
     * to the network, or stuck?" without cross-referencing a second
     * dumpstate call. -1 / not-ok before the monitor has observed a
     * handshake-complete peer. */
    int32_t network_tip = sync_monitor_peer_height_cached();
    bool network_tip_ok = network_tip >= 0;
    if (network_tip < 0)
        network_tip_ok = false;
    json_push_kv_bool(out, "network_tip_read_ok", network_tip_ok);
    json_push_kv_int(out, "network_tip", network_tip_ok ? network_tip : -1);
    json_push_kv_int(out, "hstar_to_network_tip_gap",
                     network_tip_ok && network_tip > hstar
                         ? (int64_t)network_tip - hstar
                         : 0);
    json_push_kv_bool(out, "tail_fold_in_progress",
                      network_tip_ok && network_tip > hstar);

    int32_t trusted_base_height = -1;
    bool trusted_base_found = false;
    bool trusted_base_ok = reducer_frontier_trusted_base_height_read(
        db, &trusted_base_height, &trusted_base_found);
    json_push_kv_bool(out, "trusted_base_read_ok", trusted_base_ok);
    json_push_kv_bool(out, "trusted_base_found",
                      trusted_base_ok && trusted_base_found);
    json_push_kv_int(out, "trusted_base_height",
                     (trusted_base_ok && trusted_base_found)
                         ? trusted_base_height
                         : -1);
    json_push_kv_bool(out, "trusted_base_above_hstar",
                      trusted_base_ok && trusted_base_found &&
                      trusted_base_height > hstar);
    json_push_kv_bool(out, "trusted_base_accepted",
                      trusted_base_ok && trusted_base_found &&
                      trusted_base_height <= hstar);

    int32_t coins_applied = -1;
    bool coins_found = false;
    bool coins_ok = coins_kv_get_applied_height(db, &coins_applied,
                                                &coins_found);
    json_push_kv_bool(out, "coins_applied_read_ok", coins_ok);
    json_push_kv_bool(out, "coins_applied_found", coins_ok && coins_found);
    json_push_kv_int(out, "coins_applied_height",
                     (coins_ok && coins_found) ? coins_applied : -1);
    json_push_kv_int(out, "coins_best_height",
                     (coins_ok && coins_found) ? coins_applied - 1 : -1);
    json_push_kv_bool(out, "coins_best_above_hstar",
                      coins_ok && coins_found && coins_applied - 1 > hstar);

    /* Per-cursor run-ahead marking. A cursor above H* has consumed heights
     * nothing has proven: on the 2026-07-27 one-block fork at 3195363, five
     * cursors read 3195370 while H* was 3195362 — work done over the LOSING
     * branch, every height of it clamped back by the reorg repair. The dump
     * printed those numbers bare, and a reader took them for a better height
     * than H*. Derived here at query time from (cursor, hstar), never stored:
     * a persisted copy of a comparison is a second copy of the fact. */
    struct json_value cursors = {0};
    json_set_array(&cursors);
    int64_t cursors_above = 0;
    int64_t cursors_above_max = 0;
    for (size_t i = 0;
         i < sizeof(k_stage_cursors) / sizeof(k_stage_cursors[0]);
         i++) {
        int64_t cursor = 0;
        bool ok = cursor_at(db, k_stage_cursors[i], &cursor);
        int64_t consumed = ok ? cursor_consumed_height(cursor) : -1;
        int64_t above = (ok && consumed > hstar) ? consumed - hstar : 0;
        if (above > 0) {
            cursors_above++;
            if (above > cursors_above_max)
                cursors_above_max = above;
        }
        struct json_value obj = {0};
        json_set_object(&obj);
        json_push_kv_str(&obj, "stage", k_stage_cursors[i]);
        json_push_kv_bool(&obj, "read_ok", ok);
        json_push_kv_int(&obj, "cursor", ok ? cursor : -1);
        json_push_kv_int(&obj, "consumed_height", ok ? consumed : -1);
        json_push_kv_bool(&obj, "above_hstar", above > 0);
        json_push_kv_int(&obj, "heights_above_hstar", above);
        json_push_kv_str(&obj, "trust",
                         !ok ? "unknown_cursor_unreadable"
                             : (above > 0 ? "unproven_may_be_wrong"
                                          : "within_verified_hstar"));
        json_push_back(&cursors, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "stage_cursors", &cursors);
    json_free(&cursors);
    json_push_kv_int(out, "stage_cursors_above_hstar_count", cursors_above);
    json_push_kv_int(out, "stage_cursors_above_hstar_max_depth",
                     cursors_above_max);
    json_push_kv_str(out, "stage_cursors_trust_note",
                     "hstar is the only proven height. A stage cursor with "
                     "trust=unproven_may_be_wrong has consumed heights above "
                     "hstar that nothing has verified: they can sit on a "
                     "losing fork and be clamped back by the reorg repair, so "
                     "such a cursor may be WRONG and must never be read as a "
                     "better height than hstar. One height of lead is the "
                     "normal working edge; a growing depth is run-ahead over "
                     "an unverified branch.");

    struct json_value frontiers = {0};
    json_set_array(&frontiers);
    int32_t validate_frontier = hstar;
    int32_t validate_cursor_next = INT32_MAX;
    struct dump_frontier frontier_state[
        sizeof(k_logs) / sizeof(k_logs[0])
    ];
    memset(frontier_state, 0, sizeof(frontier_state));
    for (size_t i = 0; i < sizeof(k_logs) / sizeof(k_logs[0]); i++) {
        int64_t raw_cursor = 0;
        bool cursor_ok = cursor_at(db, k_logs[i].cursor_name, &raw_cursor);
        int64_t next_cursor = cursor_ok
            ? next_cursor_for_dump(&k_logs[i], raw_cursor)
            : -1;
        int32_t frontier = -1;
        bool frontier_ok = reducer_frontier_log_frontier(
            db, k_logs[i].log_table, k_logs[i].cursor_name, &frontier);
        frontier_state[i].cursor_ok = cursor_ok;
        frontier_state[i].frontier_ok = frontier_ok;
        frontier_state[i].raw_cursor = raw_cursor;
        frontier_state[i].next_cursor = next_cursor;
        frontier_state[i].contiguous_frontier = frontier;
        if (strcmp(k_logs[i].log_table, "validate_headers_log") == 0) {
            validate_frontier = frontier_ok ? frontier : hstar;
            validate_cursor_next = (next_cursor > INT32_MAX)
                ? INT32_MAX
                : (int32_t)next_cursor;
        }

        struct json_value obj = {0};
        json_set_object(&obj);
        json_push_kv_str(&obj, "stage", k_logs[i].stage);
        json_push_kv_str(&obj, "log_table", k_logs[i].log_table);
        json_push_kv_int(&obj, "cursor", cursor_ok ? raw_cursor : -1);
        json_push_kv_int(&obj, "next_cursor", next_cursor);
        json_push_kv_bool(&obj, "served_tip_cursor",
                          k_logs[i].served_tip_cursor);
        json_push_kv_bool(&obj, "frontier_read_ok", frontier_ok);
        json_push_kv_int(&obj, "contiguous_frontier",
                         frontier_ok ? frontier : -1);
        json_push_back(&frontiers, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "success_checked_frontiers", &frontiers);
    json_free(&frontiers);

    struct hstar_blocker blocker;
    if (!first_hstar_blocker(db, hstar, frontier_state,
                             sizeof(frontier_state) /
                             sizeof(frontier_state[0]),
                             &blocker)) {
        progress_store_tx_unlock();
        return false;
    }
    int64_t hstar_next = (hstar < INT32_MAX) ? (int64_t)hstar + 1 : -1;
    json_push_kv_int(out, "hstar_next_height", hstar_next);
    json_push_kv_bool(out, "hstar_next_blocked", blocker.found);
    json_push_kv_str(out, "hstar_next_primary_kind",
                     blocker.found ? blocker.kind : "none");
    json_push_kv_str(out, "hstar_next_primary_stage",
                     blocker.found ? blocker.stage : "");
    json_push_kv_str(out, "hstar_next_primary_log_table",
                     blocker.found ? blocker.log_table : "");
    json_push_kv_str(out, "hstar_next_primary_detail",
                     blocker.found ? blocker.reason : "");
    json_push_kv_str(out, "hstar_next_primary_repair_owner",
                     blocker.found
                         ? diagnostic_repair_hint(blocker.kind,
                                                  blocker.reason)
                         : "");
    json_push_kv_bool(out, "hstar_next_pending_edge",
                      blocker.pending_edge);
    json_push_kv_str(out, "hstar_next_pending_stage",
                     blocker.pending_edge ? blocker.pending_stage : "");
    json_push_kv_str(out, "hstar_next_pending_log_table",
                     blocker.pending_edge ? blocker.pending_log_table : "");
    json_push_kv_str(out, "hstar_next_pending_detail",
                     blocker.pending_edge ? blocker.pending_reason : "");
    json_push_kv_int(out, "hstar_next_blocker_count",
                     blocker.found ? 1 : 0);
    json_push_kv_bool(out, "first_hstar_blocker_found", blocker.found);
    json_push_kv_str(out, "first_hstar_blocker_stage",
                     blocker.found ? blocker.stage : "");
    json_push_kv_str(out, "first_hstar_blocker_log_table",
                     blocker.found ? blocker.log_table : "");
    json_push_kv_int(out, "first_hstar_blocker_height",
                     blocker.found ? blocker.height : -1);
    json_push_kv_str(out, "first_hstar_blocker_kind",
                     blocker.found ? blocker.kind : "");
    json_push_kv_str(out, "first_hstar_blocker_reason",
                     blocker.found ? blocker.reason : "");
    json_push_kv_str(out, "first_hstar_blocker_repair_owner",
                     blocker.found
                         ? diagnostic_repair_hint(blocker.kind,
                                                  blocker.reason)
                         : "");

    bool fail_found = false;
    int32_t fail_height = -1;
    char fail_reason[128] = "";
    int32_t max_validate = validate_cursor_next > 0
        ? validate_cursor_next - 1
        : INT32_MAX;
    if (!first_validate_failure(db, validate_frontier, max_validate,
                                &fail_found, &fail_height,
                                fail_reason, sizeof(fail_reason))) {
        progress_store_tx_unlock();
        return false;
    }
    json_push_kv_bool(out, "first_validate_failure_found", fail_found);
    json_push_kv_int(out, "first_validate_failure_height",
                     fail_found ? fail_height : -1);
    json_push_kv_str(out, "first_validate_failure_reason",
                     fail_found ? fail_reason : "");
    json_push_kv_str(out, "first_validate_failure_repair_owner",
                     fail_found
                         ? diagnostic_repair_hint("ok0_failure", fail_reason)
                         : "");

    /* S5: active_chain_extend_window_have_data fast (best-header ancestry,
     * O(log n)) vs slow (full-map scan + pprev-walk, O(map)) path hit
     * counts. A live climb on window_extend_slow is a silent regression
     * back to the fixed ~9s/block full-map-scan pathology — see
     * chainstate.h / chainstate.c. */
    json_push_kv_int(out, "window_extend_fast",
                     (int64_t)active_chain_extend_window_have_data_fast_count());
    json_push_kv_int(out, "window_extend_slow",
                     (int64_t)active_chain_extend_window_have_data_slow_count());
    /* Heights the fast path unwedged by merging BLOCK_HAVE_DATA across a
     * bodiless best-header ancestry twin and its body-bearing block_map copy
     * (the live H+1 duplicate-object window wedge). A nonzero value is the
     * rescue firing, not a fault — see chainstate.c have_data_by_hash. */
    json_push_kv_int(out, "window_dup_data_rescued",
                     (int64_t)active_chain_extend_window_dup_data_rescued_count());

    /* Rolling self-verified rewind bases (Pillar 3): every currently-available
     * safe rewind target and the O(delta) distance from H* to the nearest
     * one — see reducer_frontier_rewind_bases.c. */
    reducer_frontier_push_rewind_bases_json(out, hstar);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * engine/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed first_hstar_blocker fields above — no new
     * health logic, just a uniform shape the rollup can walk. */
    {
        char reason_buf[192] = "";
        if (blocker.found) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "h*+1 blocked: %s at stage=%s (%s)",
                     blocker.kind, blocker.stage, blocker.reason);
        }
        diag_push_health(out, !blocker.found, reason_buf);
    }

    progress_store_tx_unlock();
    return true;
}
