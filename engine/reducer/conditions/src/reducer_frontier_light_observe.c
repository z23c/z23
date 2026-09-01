/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Observation and detail state for reducer_frontier_reconcile_light. */

#include "conditions/reducer_frontier_reconcile_light.h"
#include "reducer_frontier_light_observe.h"

#include "framework/condition.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_repair_coin_backfill.h"
#include "json/json.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>

static _Atomic int g_local_height_at_detect = -1;
static _Atomic int g_hstar_at_detect = -1;
static _Atomic int g_sweep_top_at_detect = -1;
static _Atomic int g_validate_headers_cursor_at_detect = -1;
static _Atomic int g_body_fetch_cursor_at_detect = -1;
static _Atomic int g_body_persist_cursor_at_detect = -1;
static _Atomic int g_script_validate_cursor_at_detect = -1;
static _Atomic int g_proof_validate_cursor_at_detect = -1;
static _Atomic int g_utxo_apply_cursor_at_detect = -1;
static _Atomic int g_tip_finalize_cursor_at_detect = -1;
/* Coin-backfill scan record snapshot: -1 = no detect snapshot yet,
 * 0 = record absent at detect, 1 = record present at detect. */
static _Atomic int g_coin_backfill_scan_present_at_detect = -1;
static _Atomic int g_coin_backfill_scan_next_at_detect = -1;
static _Atomic int g_coin_backfill_insert_remedy_call_at_detect = -1;
/* tipfin backfill progress record snapshot, same convention. */
static _Atomic int g_tipfin_backfill_present_at_detect = -1;
static _Atomic int g_tipfin_backfill_progress_at_detect = -1;
static _Atomic int g_remedy_calls = 0;
static _Atomic int g_tear_bypass_warn_total = 0;
static _Atomic bool g_tear_bypass_active;

#define RFRL_RR_FIELD_LIST(X)                                             \
    X(REPAIRED, "last_reconcile_repaired", true)                         \
    X(CLAMPED_TIP_FINALIZE, "last_reconcile_clamped_tip_finalize", true) \
    X(REFUSED_COIN_TEAR, "last_reconcile_refused_coin_tear", true)       \
    X(REFUSED_COIN_UNKNOWN, "last_reconcile_refused_coin_unknown", true) \
    X(COINS_APPLIED_FOUND, "last_reconcile_coins_applied_found", true)   \
    X(HSTAR, "last_reconcile_hstar", false)                              \
    X(SERVED_FLOOR, "last_reconcile_served_floor", false)                \
    X(COINS_APPLIED_HEIGHT, "last_reconcile_coins_applied_height", false)\
    X(CLAMPED_VALIDATE_HEADERS,                                           \
      "last_reconcile_clamped_validate_headers", true)                   \
    X(VALIDATE_HEADERS_CURSOR_BEFORE,                                     \
      "last_reconcile_validate_headers_cursor_before", false)            \
    X(VALIDATE_HEADERS_CURSOR_AFTER,                                      \
      "last_reconcile_validate_headers_cursor_after", false)             \
    X(CLAMPED_BODY_FETCH, "last_reconcile_clamped_body_fetch", true)     \
    X(BODY_FETCH_CURSOR_BEFORE,                                           \
      "last_reconcile_body_fetch_cursor_before", false)                  \
    X(BODY_FETCH_CURSOR_AFTER,                                            \
      "last_reconcile_body_fetch_cursor_after", false)                   \
    X(CLAMPED_BODY_PERSIST,                                               \
      "last_reconcile_clamped_body_persist", true)                       \
    X(BODY_PERSIST_CURSOR_BEFORE,                                         \
      "last_reconcile_body_persist_cursor_before", false)                \
    X(BODY_PERSIST_CURSOR_AFTER,                                          \
      "last_reconcile_body_persist_cursor_after", false)                 \
    X(TIP_FINALIZE_CURSOR_BEFORE,                                         \
      "last_reconcile_tip_finalize_cursor_before", false)                \
    X(TIP_FINALIZE_CURSOR_AFTER,                                          \
      "last_reconcile_tip_finalize_cursor_after", false)                 \
    X(SWEEP_TOP, "last_reconcile_sweep_top", false)                      \
    X(LOWEST_HAVE_DATA_CLEARED,                                           \
      "last_reconcile_lowest_have_data_cleared", false)                  \
    X(LOWEST_VALIDATE_HEADERS_REFILL_HOLE,                                \
      "last_reconcile_lowest_validate_headers_refill_hole", false)       \
    X(LOWEST_VALIDATE_HEADERS_HASH_SPLIT,                                 \
      "last_reconcile_lowest_validate_headers_hash_split", false)        \
    X(LOWEST_SCRIPT_VALIDATE_HASH_SPLIT,                                  \
      "last_reconcile_lowest_script_validate_hash_split", false)         \
    X(LOWEST_BODY_FETCH_REFILL_HOLE,                                      \
      "last_reconcile_lowest_body_fetch_refill_hole", false)             \
    X(LOWEST_BODY_PERSIST_REFILL_HOLE,                                    \
      "last_reconcile_lowest_body_persist_refill_hole", false)           \
    X(LOWEST_SCRIPT_VALIDATE_REFILL_HOLE,                                 \
      "last_reconcile_lowest_script_validate_refill_hole", false)        \
    X(LOWEST_PROOF_VALIDATE_REFILL_HOLE,                                  \
      "last_reconcile_lowest_proof_validate_refill_hole", false)         \
    X(CLAMPED_SCRIPT_VALIDATE,                                            \
      "last_reconcile_clamped_script_validate", true)                    \
    X(CLAMPED_PROOF_VALIDATE,                                             \
      "last_reconcile_clamped_proof_validate", true)                     \
    X(SCRIPT_VALIDATE_CURSOR_BEFORE,                                      \
      "last_reconcile_script_validate_cursor_before", false)             \
    X(SCRIPT_VALIDATE_CURSOR_AFTER,                                       \
      "last_reconcile_script_validate_cursor_after", false)              \
    X(PROOF_VALIDATE_CURSOR_BEFORE,                                       \
      "last_reconcile_proof_validate_cursor_before", false)              \
    X(PROOF_VALIDATE_CURSOR_AFTER,                                        \
      "last_reconcile_proof_validate_cursor_after", false)               \
    X(PRE_REFUSAL_UNAPPLIED_CLAMP,                                        \
      "last_reconcile_pre_refusal_unapplied_clamp", true)                \
    X(SCRIPTS_SET, "last_reconcile_scripts_set", false)                  \
    X(HAVE_DATA_SET, "last_reconcile_have_data_set", false)              \
    X(HAVE_DATA_CLEARED, "last_reconcile_have_data_cleared", false)      \
    X(FAILED_MASK_CLEARED, "last_reconcile_failed_mask_cleared", false)  \
    X(HEADER_EVENTS_EMITTED, "last_reconcile_header_events_emitted", false)\
    X(STALE_SCRIPT_REPAIR_ATTEMPTED,                                      \
      "last_reconcile_stale_script_repair_attempted", true)              \
    X(STALE_SCRIPT_REPAIRED, "last_reconcile_stale_script_repaired", true)\
    X(STALE_SCRIPT_REPAIR_MARKER_SEEN,                                    \
      "last_reconcile_stale_script_repair_marker_seen", true)            \
    X(STALE_SCRIPT_REPAIR_GENUINELY_INVALID,                              \
      "last_reconcile_stale_script_repair_genuinely_invalid", true)      \
    X(STALE_SCRIPT_REPAIR_HEIGHT,                                         \
      "last_reconcile_stale_script_repair_height", false)                \
    X(STALE_SCRIPT_CURSOR_BEFORE,                                         \
      "last_reconcile_stale_script_cursor_before", false)                \
    X(STALE_SCRIPT_CURSOR_AFTER,                                          \
      "last_reconcile_stale_script_cursor_after", false)                 \
    X(STALE_SCRIPT_BACKFILL_FIRST,                                        \
      "last_reconcile_stale_script_backfill_first", false)               \
    X(STALE_SCRIPT_BACKFILL_LAST,                                         \
      "last_reconcile_stale_script_backfill_last", false)                \
    X(STALE_SCRIPT_UTXO_CURSOR_BEFORE,                                    \
      "last_reconcile_stale_script_utxo_cursor_before", false)           \
    X(STALE_SCRIPT_TIP_CURSOR_BEFORE,                                     \
      "last_reconcile_stale_script_tip_cursor_before", false)            \
    X(COIN_BACKFILL_ATTEMPTED,                                            \
      "last_reconcile_coin_backfill_attempted", true)                    \
    X(COIN_BACKFILL_STATUS, "last_reconcile_coin_backfill_status", false)\
    X(COIN_BACKFILL_HOLE_HEIGHT,                                          \
      "last_reconcile_coin_backfill_hole_height", false)                 \
    X(COIN_BACKFILL_UNRESOLVED,                                           \
      "last_reconcile_coin_backfill_unresolved", false)                  \
    X(COIN_BACKFILL_INSERTED,                                             \
      "last_reconcile_coin_backfill_inserted", false)                    \
    X(COIN_BACKFILL_SCAN_NEXT,                                            \
      "last_reconcile_coin_backfill_scan_next", false)                   \
    X(COIN_BACKFILL_OWNER_REFUSED,                                        \
      "last_reconcile_coin_backfill_owner_refused", true)                \
    X(COIN_BACKFILL_GENUINELY_INVALID,                                    \
      "last_reconcile_coin_backfill_genuinely_invalid", true)            \
    X(TIPFIN_BACKFILL_HEIGHT,                                             \
      "last_reconcile_tipfin_backfill_height", false)                    \
    X(TIPFIN_BACKFILL_COUNT,                                              \
      "last_reconcile_tipfin_backfill_count", false)                     \
    X(TIPFIN_BACKFILL_MARKER_SEEN,                                        \
      "last_reconcile_tipfin_backfill_marker_seen", true)                \
    X(TIPFIN_BACKFILL_REFUSED_REASON,                                     \
      "last_reconcile_tipfin_backfill_refused_reason", false)            \
    X(TIPFIN_BACKFILL_REFUSED_HEIGHT,                                     \
      "last_reconcile_tipfin_backfill_refused_height", false)            \
    X(TIPFIN_BACKFILL_REFUSED_LOG,                                        \
      "last_reconcile_tipfin_backfill_refused_log", false)               \
    X(NONCANONICAL_FOUND, "last_reconcile_noncanonical_found", false)    \
    X(NONCANONICAL_PURGED, "last_reconcile_noncanonical_purged", false)  \
    X(LOWEST_NONCANONICAL, "last_reconcile_lowest_noncanonical", false)  \
    X(REORG_RESIDUE_TIPFIN_FOUND,                                         \
      "last_reconcile_reorg_residue_tipfin_found", false)                \
    X(REORG_RESIDUE_TIPFIN_REPLACED,                                      \
      "last_reconcile_reorg_residue_tipfin_replaced", false)             \
    X(LOWEST_REORG_RESIDUE_TIPFIN,                                        \
      "last_reconcile_lowest_reorg_residue_tipfin", false)

enum rfrl_rr_field {
#define RFRL_RR_ENUM(id, key, is_bool) RFRL_RR_##id,
    RFRL_RR_FIELD_LIST(RFRL_RR_ENUM)
#undef RFRL_RR_ENUM
    RFRL_RR_FIELD_N
};

struct rfrl_rr_field_meta {
    const char *key;
    bool is_bool;
};

static const struct rfrl_rr_field_meta
    k_rfrl_rr_fields[RFRL_RR_FIELD_N] = {
#define RFRL_RR_META(id, key, is_bool) [RFRL_RR_##id] = { key, is_bool },
        RFRL_RR_FIELD_LIST(RFRL_RR_META)
#undef RFRL_RR_META
};

static _Atomic int g_last_rr_seen = 0;
static _Atomic int g_last_rr_phase = RFRL_RR_PHASE_NONE;
static _Atomic int g_last_rr_remedy_call = -1;
static _Atomic int g_last_rr_values[RFRL_RR_FIELD_N];

const char *rfrl_coin_backfill_status_label(int status)
{
    switch ((enum coin_backfill_status)status) {
    case COIN_BACKFILL_NOT_APPLICABLE:     return "not_applicable";
    case COIN_BACKFILL_SCANNING:           return "scanning";
    case COIN_BACKFILL_REPAIRED:           return "repaired";
    case COIN_BACKFILL_OWNER_REFUSED:      return "owner_refused";
    case COIN_BACKFILL_REFUSED_SPENT:      return "refused_spent";
    case COIN_BACKFILL_REFUSED_UNPROVABLE: return "refused_unprovable";
    case COIN_BACKFILL_MARKER_SEEN:        return "marker_seen";
    }
    return "unknown";
}

static const char *rfrl_rr_phase_label(int phase)
{
    switch ((enum rfrl_rr_phase)phase) {
    case RFRL_RR_PHASE_NONE:   return "none";
    case RFRL_RR_PHASE_DETECT: return "detect";
    case RFRL_RR_PHASE_REMEDY: return "remedy";
    }
    return "unknown";
}

#define RFRL_RR_SET_BOOL(id, value) \
    atomic_store(&g_last_rr_values[RFRL_RR_##id], (value) ? 1 : 0)
#define RFRL_RR_SET_INT(id, value) \
    atomic_store(&g_last_rr_values[RFRL_RR_##id], (value))

void rfrl_snapshot_reconcile_result(
    enum rfrl_rr_phase phase,
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (!rr)
        return;

    RFRL_RR_SET_BOOL(REPAIRED, rr->repaired);
    RFRL_RR_SET_BOOL(CLAMPED_TIP_FINALIZE, rr->clamped_tip_finalize);
    RFRL_RR_SET_BOOL(REFUSED_COIN_TEAR, rr->refused_coin_tear);
    RFRL_RR_SET_BOOL(REFUSED_COIN_UNKNOWN, rr->refused_coin_unknown);
    RFRL_RR_SET_BOOL(COINS_APPLIED_FOUND, rr->coins_applied_found);
    RFRL_RR_SET_INT(HSTAR, rr->hstar);
    RFRL_RR_SET_INT(SERVED_FLOOR, rr->served_floor);
    RFRL_RR_SET_INT(COINS_APPLIED_HEIGHT, rr->coins_applied_height);
    RFRL_RR_SET_BOOL(CLAMPED_VALIDATE_HEADERS,
                     rr->clamped_validate_headers);
    RFRL_RR_SET_INT(VALIDATE_HEADERS_CURSOR_BEFORE,
                    rr->validate_headers_cursor_before);
    RFRL_RR_SET_INT(VALIDATE_HEADERS_CURSOR_AFTER,
                    rr->validate_headers_cursor_after);
    RFRL_RR_SET_BOOL(CLAMPED_BODY_FETCH, rr->clamped_body_fetch);
    RFRL_RR_SET_INT(BODY_FETCH_CURSOR_BEFORE,
                    rr->body_fetch_cursor_before);
    RFRL_RR_SET_INT(BODY_FETCH_CURSOR_AFTER,
                    rr->body_fetch_cursor_after);
    RFRL_RR_SET_BOOL(CLAMPED_BODY_PERSIST, rr->clamped_body_persist);
    RFRL_RR_SET_INT(BODY_PERSIST_CURSOR_BEFORE,
                    rr->body_persist_cursor_before);
    RFRL_RR_SET_INT(BODY_PERSIST_CURSOR_AFTER,
                    rr->body_persist_cursor_after);
    RFRL_RR_SET_INT(TIP_FINALIZE_CURSOR_BEFORE,
                    rr->tip_finalize_cursor_before);
    RFRL_RR_SET_INT(TIP_FINALIZE_CURSOR_AFTER,
                    rr->tip_finalize_cursor_after);
    RFRL_RR_SET_INT(SWEEP_TOP, rr->sweep_top);
    RFRL_RR_SET_INT(LOWEST_HAVE_DATA_CLEARED,
                    rr->lowest_have_data_cleared);
    RFRL_RR_SET_INT(LOWEST_VALIDATE_HEADERS_REFILL_HOLE,
                    rr->lowest_validate_headers_refill_hole);
    RFRL_RR_SET_INT(LOWEST_VALIDATE_HEADERS_HASH_SPLIT,
                    rr->lowest_validate_headers_hash_split);
    RFRL_RR_SET_INT(LOWEST_SCRIPT_VALIDATE_HASH_SPLIT,
                    rr->lowest_script_validate_hash_split);
    RFRL_RR_SET_INT(LOWEST_BODY_FETCH_REFILL_HOLE,
                    rr->lowest_body_fetch_refill_hole);
    RFRL_RR_SET_INT(LOWEST_BODY_PERSIST_REFILL_HOLE,
                    rr->lowest_body_persist_refill_hole);
    RFRL_RR_SET_INT(LOWEST_SCRIPT_VALIDATE_REFILL_HOLE,
                    rr->lowest_script_validate_refill_hole);
    RFRL_RR_SET_INT(LOWEST_PROOF_VALIDATE_REFILL_HOLE,
                    rr->lowest_proof_validate_refill_hole);
    RFRL_RR_SET_BOOL(CLAMPED_SCRIPT_VALIDATE,
                     rr->clamped_script_validate);
    RFRL_RR_SET_BOOL(CLAMPED_PROOF_VALIDATE,
                     rr->clamped_proof_validate);
    RFRL_RR_SET_INT(SCRIPT_VALIDATE_CURSOR_BEFORE,
                    rr->script_validate_cursor_before);
    RFRL_RR_SET_INT(SCRIPT_VALIDATE_CURSOR_AFTER,
                    rr->script_validate_cursor_after);
    RFRL_RR_SET_INT(PROOF_VALIDATE_CURSOR_BEFORE,
                    rr->proof_validate_cursor_before);
    RFRL_RR_SET_INT(PROOF_VALIDATE_CURSOR_AFTER,
                    rr->proof_validate_cursor_after);
    RFRL_RR_SET_BOOL(PRE_REFUSAL_UNAPPLIED_CLAMP,
                     rr->pre_refusal_unapplied_clamp);
    RFRL_RR_SET_INT(SCRIPTS_SET, rr->scripts_set);
    RFRL_RR_SET_INT(HAVE_DATA_SET, rr->have_data_set);
    RFRL_RR_SET_INT(HAVE_DATA_CLEARED, rr->have_data_cleared);
    RFRL_RR_SET_INT(FAILED_MASK_CLEARED, rr->failed_mask_cleared);
    RFRL_RR_SET_INT(HEADER_EVENTS_EMITTED, rr->header_events_emitted);
    RFRL_RR_SET_BOOL(STALE_SCRIPT_REPAIR_ATTEMPTED,
                     rr->stale_script_repair_attempted);
    RFRL_RR_SET_BOOL(STALE_SCRIPT_REPAIRED,
                     rr->stale_script_repaired);
    RFRL_RR_SET_BOOL(STALE_SCRIPT_REPAIR_MARKER_SEEN,
                     rr->stale_script_repair_marker_seen);
    RFRL_RR_SET_BOOL(STALE_SCRIPT_REPAIR_GENUINELY_INVALID,
                     rr->stale_script_repair_genuinely_invalid);
    RFRL_RR_SET_INT(STALE_SCRIPT_REPAIR_HEIGHT,
                    rr->stale_script_repair_height);
    RFRL_RR_SET_INT(STALE_SCRIPT_CURSOR_BEFORE,
                    rr->stale_script_cursor_before);
    RFRL_RR_SET_INT(STALE_SCRIPT_CURSOR_AFTER,
                    rr->stale_script_cursor_after);
    RFRL_RR_SET_INT(STALE_SCRIPT_BACKFILL_FIRST,
                    rr->stale_script_backfill_first);
    RFRL_RR_SET_INT(STALE_SCRIPT_BACKFILL_LAST,
                    rr->stale_script_backfill_last);
    RFRL_RR_SET_INT(STALE_SCRIPT_UTXO_CURSOR_BEFORE,
                    rr->stale_script_utxo_cursor_before);
    RFRL_RR_SET_INT(STALE_SCRIPT_TIP_CURSOR_BEFORE,
                    rr->stale_script_tip_cursor_before);
    RFRL_RR_SET_BOOL(COIN_BACKFILL_ATTEMPTED,
                     rr->coin_backfill_attempted);
    RFRL_RR_SET_INT(COIN_BACKFILL_STATUS, rr->coin_backfill_status);
    RFRL_RR_SET_INT(COIN_BACKFILL_HOLE_HEIGHT,
                    rr->coin_backfill_hole_height);
    RFRL_RR_SET_INT(COIN_BACKFILL_UNRESOLVED,
                    rr->coin_backfill_unresolved);
    RFRL_RR_SET_INT(COIN_BACKFILL_INSERTED,
                    rr->coin_backfill_inserted);
    RFRL_RR_SET_INT(COIN_BACKFILL_SCAN_NEXT,
                    rr->coin_backfill_scan_next);
    RFRL_RR_SET_BOOL(COIN_BACKFILL_OWNER_REFUSED,
                     rr->coin_backfill_owner_refused);
    RFRL_RR_SET_BOOL(COIN_BACKFILL_GENUINELY_INVALID,
                     rr->coin_backfill_genuinely_invalid);
    RFRL_RR_SET_INT(TIPFIN_BACKFILL_HEIGHT,
                    rr->tipfin_backfill_height);
    RFRL_RR_SET_INT(TIPFIN_BACKFILL_COUNT, rr->tipfin_backfill_count);
    RFRL_RR_SET_BOOL(TIPFIN_BACKFILL_MARKER_SEEN,
                     rr->tipfin_backfill_marker_seen);
    RFRL_RR_SET_INT(TIPFIN_BACKFILL_REFUSED_REASON,
                    rr->tipfin_backfill_refused_reason);
    RFRL_RR_SET_INT(TIPFIN_BACKFILL_REFUSED_HEIGHT,
                    rr->tipfin_backfill_refused_height);
    RFRL_RR_SET_INT(TIPFIN_BACKFILL_REFUSED_LOG,
                    rr->tipfin_backfill_refused_log);
    RFRL_RR_SET_INT(NONCANONICAL_FOUND, rr->noncanonical_found);
    RFRL_RR_SET_INT(NONCANONICAL_PURGED, rr->noncanonical_purged);
    RFRL_RR_SET_INT(LOWEST_NONCANONICAL, rr->lowest_noncanonical);
    RFRL_RR_SET_INT(REORG_RESIDUE_TIPFIN_FOUND,
                    rr->reorg_residue_tipfin_found);
    RFRL_RR_SET_INT(REORG_RESIDUE_TIPFIN_REPLACED,
                    rr->reorg_residue_tipfin_replaced);
    RFRL_RR_SET_INT(LOWEST_REORG_RESIDUE_TIPFIN,
                    rr->lowest_reorg_residue_tipfin);

    atomic_store(&g_last_rr_phase, (int)phase);
    if (phase == RFRL_RR_PHASE_REMEDY)
        atomic_store(&g_last_rr_remedy_call, rfrl_remedy_calls());
    atomic_store(&g_last_rr_seen, 1);
}

#undef RFRL_RR_SET_BOOL
#undef RFRL_RR_SET_INT

void rfrl_detect_baseline_set(int local_height, int hstar, int sweep_top)
{
    atomic_store(&g_local_height_at_detect, local_height);
    atomic_store(&g_hstar_at_detect, hstar);
    atomic_store(&g_sweep_top_at_detect, sweep_top);
}

int rfrl_hstar_at_detect(void)
{
    return atomic_load(&g_hstar_at_detect);
}

bool rfrl_read_reducer_cursor(sqlite3 *db, const char *name, int *out)
{
    if (out)
        *out = -1;
    if (!db || !name || !name[0] || !out)
        return false;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] cursor "
                 "prepare failed stage=%s: %s",
                 name, sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] cursor "
                 "step failed stage=%s rc=%d: %s",
                 name, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return false;
    }

    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return true;
}

void rfrl_snapshot_reducer_cursors(sqlite3 *db)
{
    int cursor = -1;

    if (rfrl_read_reducer_cursor(db, "validate_headers", &cursor))
        atomic_store(&g_validate_headers_cursor_at_detect, cursor);
    if (rfrl_read_reducer_cursor(db, "body_fetch", &cursor))
        atomic_store(&g_body_fetch_cursor_at_detect, cursor);
    if (rfrl_read_reducer_cursor(db, "body_persist", &cursor))
        atomic_store(&g_body_persist_cursor_at_detect, cursor);
    if (rfrl_read_reducer_cursor(db, "script_validate", &cursor))
        atomic_store(&g_script_validate_cursor_at_detect, cursor);
    if (rfrl_read_reducer_cursor(db, "proof_validate", &cursor))
        atomic_store(&g_proof_validate_cursor_at_detect, cursor);
    if (rfrl_read_reducer_cursor(db, "utxo_apply", &cursor))
        atomic_store(&g_utxo_apply_cursor_at_detect, cursor);
    if (rfrl_read_reducer_cursor(db, "tip_finalize", &cursor))
        atomic_store(&g_tip_finalize_cursor_at_detect, cursor);
}

bool rfrl_read_coin_backfill_scan_cursor(sqlite3 *db, bool *present,
                                         int *next_height)
{
    if (present)
        *present = false;
    if (next_height)
        *next_height = -1;
    if (!db || !present || !next_height)
        return false;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM progress_meta "
            "WHERE key GLOB 'coin_backfill.scan.*' "
            "ORDER BY key LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] coin_backfill "
                 "scan record prepare failed: %s",
                 sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *present = true;
        const uint8_t *v = sqlite3_column_blob(st, 0);
        if (v && sqlite3_column_bytes(st, 0) >= 4)
            *next_height = (int)((uint32_t)v[0] | (uint32_t)v[1] << 8 |
                                 (uint32_t)v[2] << 16 | (uint32_t)v[3] << 24);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] coin_backfill "
                 "scan record step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return false;
    }

    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return true;
}

void rfrl_set_coin_backfill_scan_snapshot(bool present, int next_height)
{
    atomic_store(&g_coin_backfill_scan_present_at_detect, present ? 1 : 0);
    atomic_store(&g_coin_backfill_scan_next_at_detect, next_height);
}

void rfrl_snapshot_coin_backfill_scan(sqlite3 *db)
{
    bool present = false;
    int next = -1;
    if (rfrl_read_coin_backfill_scan_cursor(db, &present, &next))
        rfrl_set_coin_backfill_scan_snapshot(present, next);
}

int rfrl_coin_backfill_scan_next_at_detect(void)
{
    return atomic_load(&g_coin_backfill_scan_next_at_detect);
}

bool rfrl_read_tipfin_backfill_progress(sqlite3 *db, bool *present,
                                        int *progress)
{
    if (present)
        *present = false;
    if (progress)
        *progress = -1;
    if (!db || !present || !progress)
        return false;

    static const uint8_t zero_hash[32] = {0};
    uint8_t buf[8] = {0};
    size_t n = 0;
    bool have = false;
    if (!repair_marker_have(db, REPAIR_MARKER_KIND_TIPFIN_PROGRESS,
                            REPAIR_MARKER_TIPFIN_HEIGHT, zero_hash, &have,
                            buf, sizeof(buf), &n)) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] tipfin_backfill "
                 "progress record read failed");
        return false;
    }
    if (have) {
        if (n == 8) {
            *present = true;
            *progress = (int)((uint32_t)buf[0] | (uint32_t)buf[1] << 8 |
                              (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 24);
        } else {
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] "
                     "tipfin_backfill progress malformed len=%d "
                     "(expected 8); treating as absent",
                     (int)n);
        }
    }
    return true;
}

void rfrl_set_tipfin_backfill_snapshot(bool present, int progress)
{
    atomic_store(&g_tipfin_backfill_present_at_detect, present ? 1 : 0);
    atomic_store(&g_tipfin_backfill_progress_at_detect, progress);
}

void rfrl_snapshot_tipfin_backfill(sqlite3 *db)
{
    bool present = false;
    int progress = -1;
    if (rfrl_read_tipfin_backfill_progress(db, &present, &progress))
        rfrl_set_tipfin_backfill_snapshot(present, progress);
}

int rfrl_tipfin_backfill_progress_at_detect(void)
{
    return atomic_load(&g_tipfin_backfill_progress_at_detect);
}

int rfrl_last_coin_backfill_inserted(void)
{
    return atomic_load(&g_last_rr_values[RFRL_RR_COIN_BACKFILL_INSERTED]);
}

int rfrl_last_reconcile_remedy_call(void)
{
    return atomic_load(&g_last_rr_remedy_call);
}

int rfrl_coin_backfill_insert_remedy_call_at_detect(void)
{
    return atomic_load(&g_coin_backfill_insert_remedy_call_at_detect);
}

void rfrl_snapshot_coin_backfill_insert_progress(void)
{
    atomic_store(&g_coin_backfill_insert_remedy_call_at_detect,
                 rfrl_remedy_calls());
}

void rfrl_increment_remedy_calls(void)
{
    atomic_fetch_add(&g_remedy_calls, 1);
}

int rfrl_remedy_calls(void)
{
    return atomic_load(&g_remedy_calls);
}

bool rfrl_tear_bypass_active(void)
{
    return atomic_load(&g_tear_bypass_active);
}

void rfrl_set_tear_bypass_active(bool active)
{
    atomic_store(&g_tear_bypass_active, active);
}

void rfrl_increment_tear_bypass_warn_total(void)
{
    atomic_fetch_add(&g_tear_bypass_warn_total, 1);
}

int rfrl_tear_bypass_warn_total(void)
{
    return atomic_load(&g_tear_bypass_warn_total);
}

bool rfrl_detail_push(struct json_value *out)
{
    if (!out)
        return false;

    bool ok = true;
    int phase = atomic_load(&g_last_rr_phase);
    int coin_status =
        atomic_load(&g_last_rr_values[RFRL_RR_COIN_BACKFILL_STATUS]);

    ok = ok && json_push_kv_int(out, "local_height_at_detect",
                                atomic_load(&g_local_height_at_detect));
    ok = ok && json_push_kv_int(out, "hstar_at_detect",
                                atomic_load(&g_hstar_at_detect));
    ok = ok && json_push_kv_int(out, "sweep_top_at_detect",
                                atomic_load(&g_sweep_top_at_detect));
    ok = ok && json_push_kv_int(
        out, "validate_headers_cursor_at_detect",
        atomic_load(&g_validate_headers_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "body_fetch_cursor_at_detect",
        atomic_load(&g_body_fetch_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "body_persist_cursor_at_detect",
        atomic_load(&g_body_persist_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "script_validate_cursor_at_detect",
        atomic_load(&g_script_validate_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "proof_validate_cursor_at_detect",
        atomic_load(&g_proof_validate_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "utxo_apply_cursor_at_detect",
        atomic_load(&g_utxo_apply_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "tip_finalize_cursor_at_detect",
        atomic_load(&g_tip_finalize_cursor_at_detect));
    ok = ok && json_push_kv_int(
        out, "coin_backfill_scan_present_at_detect",
        atomic_load(&g_coin_backfill_scan_present_at_detect));
    ok = ok && json_push_kv_int(
        out, "coin_backfill_scan_next_at_detect",
        atomic_load(&g_coin_backfill_scan_next_at_detect));
    ok = ok && json_push_kv_int(
        out, "coin_backfill_insert_remedy_call_at_detect",
        atomic_load(&g_coin_backfill_insert_remedy_call_at_detect));
    ok = ok && json_push_kv_int(
        out, "tipfin_backfill_present_at_detect",
        atomic_load(&g_tipfin_backfill_present_at_detect));
    ok = ok && json_push_kv_int(
        out, "tipfin_backfill_progress_at_detect",
        atomic_load(&g_tipfin_backfill_progress_at_detect));
    ok = ok && json_push_kv_int(out, "remedy_calls",
                                atomic_load(&g_remedy_calls));
    ok = ok && json_push_kv_bool(out, "tear_bypass_active",
                                 atomic_load(&g_tear_bypass_active));
    ok = ok && json_push_kv_int(out, "tear_bypass_warn_total",
                                atomic_load(&g_tear_bypass_warn_total));

    ok = ok && json_push_kv_bool(out, "last_reconcile_seen",
                                 atomic_load(&g_last_rr_seen) != 0);
    ok = ok && json_push_kv_str(out, "last_reconcile_phase",
                                rfrl_rr_phase_label(phase));
    ok = ok && json_push_kv_int(out, "last_reconcile_remedy_call",
                                atomic_load(&g_last_rr_remedy_call));
    for (int i = 0; i < RFRL_RR_FIELD_N; i++) {
        int value = atomic_load(&g_last_rr_values[i]);
        if (k_rfrl_rr_fields[i].is_bool) {
            ok = ok && json_push_kv_bool(out, k_rfrl_rr_fields[i].key,
                                         value != 0);
        } else {
            ok = ok && json_push_kv_int(out, k_rfrl_rr_fields[i].key,
                                        value);
        }
    }
    ok = ok && json_push_kv_str(
        out, "last_reconcile_coin_backfill_status_label",
        rfrl_coin_backfill_status_label(coin_status));
    return ok;
}

#ifdef ZCL_TESTING
void rfrl_observe_reset_for_testing(void)
{
    atomic_store(&g_local_height_at_detect, -1);
    atomic_store(&g_hstar_at_detect, -1);
    atomic_store(&g_sweep_top_at_detect, -1);
    atomic_store(&g_validate_headers_cursor_at_detect, -1);
    atomic_store(&g_body_fetch_cursor_at_detect, -1);
    atomic_store(&g_body_persist_cursor_at_detect, -1);
    atomic_store(&g_script_validate_cursor_at_detect, -1);
    atomic_store(&g_proof_validate_cursor_at_detect, -1);
    atomic_store(&g_utxo_apply_cursor_at_detect, -1);
    atomic_store(&g_tip_finalize_cursor_at_detect, -1);
    atomic_store(&g_coin_backfill_scan_present_at_detect, -1);
    atomic_store(&g_coin_backfill_scan_next_at_detect, -1);
    atomic_store(&g_coin_backfill_insert_remedy_call_at_detect, -1);
    atomic_store(&g_tipfin_backfill_present_at_detect, -1);
    atomic_store(&g_tipfin_backfill_progress_at_detect, -1);
    atomic_store(&g_remedy_calls, 0);
    atomic_store(&g_tear_bypass_warn_total, 0);
    atomic_store(&g_tear_bypass_active, false);
    atomic_store(&g_last_rr_seen, 0);
    atomic_store(&g_last_rr_phase, RFRL_RR_PHASE_NONE);
    atomic_store(&g_last_rr_remedy_call, -1);
    for (int i = 0; i < RFRL_RR_FIELD_N; i++)
        atomic_store(&g_last_rr_values[i], 0);
}
#endif
