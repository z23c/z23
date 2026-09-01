/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_accessors — public read accessors for the utxo_apply Job
 * (the durable succeeded_at verdict probe + the per-status counter totals),
 * split out of utxo_apply_stage.c to keep that file under the framework
 * file-size ceiling. Counter state lives in utxo_apply_stage.c and is shared
 * via utxo_apply_stage_internal.h; reads here are atomic_load only. */

#include "jobs/utxo_apply_stage.h"
#include "jobs/mint_skip_crypto.h"
#include "utxo_apply_stage_internal.h"

#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>

#define STAGE_NAME "utxo_apply"

bool utxo_apply_stage_succeeded_at(int height)
{
    if (height < 0)
        return false;
    sqlite3 *db = progress_store_db();
    if (!db)
        return false;
    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    bool ok = false;
    int rc = sqlite3_prepare_v2(db,
            "SELECT ok, status FROM utxo_apply_log WHERE height = ?",
            -1, &st, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(st, 1, height);
        if (sqlite3_step(st) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
            int status_type = sqlite3_column_type(st, 1);
            const void *status = status_type == SQLITE_TEXT
                ? sqlite3_column_text(st, 1) : NULL;
            ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                 sqlite3_column_int(st, 0) == 1 &&
                 status &&
                 mint_validation_evidence_parse(
                     status, (size_t)sqlite3_column_bytes(st, 1)) ==
                     MINT_VALIDATION_EVIDENCE_VERIFIED;
        }
        sqlite3_finalize(st);
    } else {
        /* This accessor gates reducer_pending_body_is_accepted: a silent
         * false on a store error is indistinguishable from "not applied". */
        LOG_WARN(STAGE_NAME,
                 "[utxo_apply] succeeded_at(%d): prepare failed rc=%d (%s); "
                 "reporting not-applied", height, rc, sqlite3_errmsg(db));
    }
    progress_store_tx_unlock();
    return ok;
}

uint64_t utxo_apply_stage_verified_total(void)
{
    return atomic_load(&g_ua_verified_total);
}

uint64_t utxo_apply_stage_spend_unknown_total(void)
{
    return atomic_load(&g_ua_spend_unknown_total);
}

uint64_t utxo_apply_stage_utxo_collision_total(void)
{
    return atomic_load(&g_ua_utxo_collision_total);
}

uint64_t utxo_apply_stage_value_overflow_total(void)
{
    return atomic_load(&g_ua_value_overflow_total);
}

uint64_t utxo_apply_stage_upstream_failed_total(void)
{
    return atomic_load(&g_ua_upstream_failed_total);
}

uint64_t utxo_apply_stage_internal_error_total(void)
{
    return atomic_load(&g_ua_internal_error_total);
}

uint64_t utxo_apply_stage_reorg_unwound_total(void)
{
    return atomic_load(&g_ua_reorg_unwound_total);
}

uint64_t utxo_apply_stage_outputs_added_total(void)
{
    return atomic_load(&g_ua_total_outputs_added);
}

uint64_t utxo_apply_stage_outputs_spent_total(void)
{
    return atomic_load(&g_ua_total_outputs_spent);
}

int64_t utxo_apply_stage_select_idle_height(void)
{
    return atomic_load(&g_ua_select_idle_height);
}

bool utxo_apply_stage_select_idle_is_read_failure(void)
{
    int64_t reason = atomic_load(&g_ua_select_idle_reason);
    return reason == UA_SELECT_IDLE_INDEXED_BODY_READ_FAILED ||
           reason == UA_SELECT_IDLE_STAGE_READ_FAILED;
}
