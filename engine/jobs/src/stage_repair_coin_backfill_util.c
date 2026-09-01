/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_coin_backfill_util — read-only progress.kv helpers, key
 * builders, direct refusal paging, and the native dump-state snapshot for the
 * frontier coin backfill. The orchestration + the single write transaction
 * live in stage_repair_coin_backfill.c; this TU never writes consensus
 * state. */

#include "stage_repair_coin_backfill_util.h"

#include "event/event.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_LATCH_SLOTS 8

struct page_latch {
    bool used;
    int height;
    int status;
    uint8_t hash[32];
};

/* Snapshot + page latch state. Written on the self_heal supervisor thread,
 * read by the native dump-state handler — guarded by g_state_lock;
 * monotonic counters are lock-free atomics. */
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;
static struct coin_backfill_result g_last_result;
static int64_t g_last_call_unix;
static struct page_latch g_latch[PAGE_LATCH_SLOTS];
static unsigned g_latch_next;

static _Atomic uint64_t g_calls_total;
static _Atomic uint64_t g_repaired_total;
static _Atomic uint64_t g_inserted_total;
static _Atomic uint64_t g_rebind_total;
static _Atomic uint64_t g_pages_emitted_total;
static _Atomic uint64_t g_pages_suppressed_total;

bool coin_backfill_owner_ack(void)
{
    const char *v = getenv(COIN_BACKFILL_ACK_ENV);
    return v && strcmp(v, "1") == 0;
}

const char *coin_backfill_status_name(enum coin_backfill_status st)
{
    switch (st) {
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

void coin_backfill_txid_hex(const uint8_t txid[32], char out[65])
{
    struct uint256 u;
    memcpy(u.data, txid, 32);
    uint256_get_hex(&u, out);
}

bool coin_backfill_outpoint_marker_key(char out[160], const uint8_t txid[32],
                                       uint32_t vout)
{
    char hex[65];
    coin_backfill_txid_hex(txid, hex);
    int n = snprintf(out, 160, "utxo_apply.coin_backfill.outpoint.%s:%u",
                     hex, vout);
    if (n <= 0 || n >= 160)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] outpoint marker key overflow vout=%u",
                 vout);
    return true;
}

bool coin_backfill_meta_present(struct sqlite3 *db, const char *key,
                                bool *present)
{
    uint8_t blob[8];
    size_t n = 0;
    *present = false;
    if (!progress_meta_get(db, key, blob, sizeof(blob), &n, present))
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] meta read failed key=%s", key);
    return true;
}

bool coin_backfill_refusal_marker_decode(const uint8_t *blob, size_t len,
                                         bool *out_active,
                                         bool *out_legacy_spent,
                                         bool *out_legacy_txindex_miss)
{
    if (!out_active || !out_legacy_spent || !out_legacy_txindex_miss)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] refusal marker decode NULL output");
    *out_active = false;
    *out_legacy_spent = false;
    *out_legacy_txindex_miss = false;
    if (!blob || len == 0)
        return true;

    if (len == 5 && memcmp(blob, "spent", 5) == 0) {
        *out_legacy_spent = true;
        return true;
    }
    if (len == 12 && memcmp(blob, "txindex_miss", 12) == 0) {
        *out_legacy_txindex_miss = true;
        return true;
    }

    struct marker {
        const char *value;
        size_t len;
    };
    static const struct marker active[] = {
        { COIN_BACKFILL_SPENT_MARKER_V2,
          sizeof(COIN_BACKFILL_SPENT_MARKER_V2) - 1 },
        { COIN_BACKFILL_TXINDEX_MISS_MARKER_V2,
          sizeof(COIN_BACKFILL_TXINDEX_MISS_MARKER_V2) - 1 },
        { COIN_BACKFILL_UNPROVABLE_MARKER,
          sizeof(COIN_BACKFILL_UNPROVABLE_MARKER) - 1 },
        { COIN_BACKFILL_ROUND_CAP_MARKER,
          sizeof(COIN_BACKFILL_ROUND_CAP_MARKER) - 1 },
        { COIN_BACKFILL_RELOST_MARKER,
          sizeof(COIN_BACKFILL_RELOST_MARKER) - 1 },
    };
    for (size_t i = 0; i < sizeof(active) / sizeof(active[0]); i++) {
        if (len == active[i].len &&
            memcmp(blob, active[i].value, active[i].len) == 0) {
            *out_active = true;
            return true;
        }
    }

    LOG_WARN("coin_backfill",
             "[coin_backfill] ignoring unknown refusal marker len=%zu", len);
    return true;
}

bool coin_backfill_refusal_marker_read(struct sqlite3 *db, int height,
                                       const struct uint256 *hash,
                                       bool *out_active,
                                       bool *out_legacy_spent,
                                       bool *out_legacy_txindex_miss)
{
    uint8_t blob[32];
    size_t len = 0;
    bool found = false;
    if (!out_active || !out_legacy_spent || !out_legacy_txindex_miss || !hash)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] refusal marker read NULL output");
    *out_active = false;
    *out_legacy_spent = false;
    *out_legacy_txindex_miss = false;
    if (!repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                            height, hash->data, &found, blob, sizeof(blob),
                            &len))
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] refusal marker read failed h=%d", height);
    if (!found)
        return true;
    if (len > sizeof(blob))
        len = sizeof(blob);  /* truncated into blob; decoder length-matches */
    return coin_backfill_refusal_marker_decode(blob, len, out_active,
                                               out_legacy_spent,
                                               out_legacy_txindex_miss);
}

/* STEP-2A pending-prevout HOLD signal — an IN-MEMORY trigger, NOT persisted to
 * progress.kv. It is published by script_validate's sv_hold_unresolved on a
 * JOB_IDLE HOLD (reducer drive thread). A JOB_IDLE step's progress.kv writes are
 * rolled back by the stage per-step SAVEPOINT (platform/modules/util/src/stage.c
 * stage_run_once:482 always ROLLBACK TO SAVEPOINT a non-advancing step), so a
 * durable row CANNOT be written from inside the HOLD — not in the test, not
 * live. The trigger therefore lives in RAM (guarded by g_pending_lock) and is
 * RE-DERIVED after a restart: script_validate re-runs the frozen-cursor block,
 * re-HOLDs, and re-publishes it within a tick. Read by coin_backfill's hole
 * finder + hole re-check and the boot torn gate (self_heal / boot threads). The
 * `db` params are kept for call-site symmetry but unused. */
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_pending_present;
static int g_pending_height = -1;
static struct uint256 g_pending_block_hash;
static struct uint256 g_pending_txid;
static int g_pending_vin = -1;

bool coin_backfill_pending_prevout_set(struct sqlite3 *db, int height,
                                       const struct uint256 *block_hash,
                                       const struct uint256 *fail_txid,
                                       int fail_vin)
{
    (void)db;
    if (!block_hash || !fail_txid)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] pending_prevout_set NULL input h=%d", height);
    pthread_mutex_lock(&g_pending_lock);
    g_pending_present = true;
    g_pending_height = height;
    g_pending_block_hash = *block_hash;
    g_pending_txid = *fail_txid;
    g_pending_vin = fail_vin;
    pthread_mutex_unlock(&g_pending_lock);
    return true;
}

bool coin_backfill_pending_prevout_clear(struct sqlite3 *db)
{
    (void)db;
    pthread_mutex_lock(&g_pending_lock);
    g_pending_present = false;
    g_pending_height = -1;
    g_pending_vin = -1;
    pthread_mutex_unlock(&g_pending_lock);
    return true;
}

bool coin_backfill_pending_prevout_get(struct sqlite3 *db, int *out_height,
                                       struct uint256 *out_block_hash,
                                       struct uint256 *out_txid, int *out_vin,
                                       bool *out_found)
{
    (void)db;
    if (out_height) *out_height = -1;
    if (out_vin)    *out_vin    = -1;
    if (!out_found)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] pending_prevout_get NULL out_found");
    pthread_mutex_lock(&g_pending_lock);
    bool present = g_pending_present;
    if (present) {
        if (out_height)     *out_height = g_pending_height;
        if (out_block_hash) *out_block_hash = g_pending_block_hash;
        if (out_txid)       *out_txid = g_pending_txid;
        if (out_vin)        *out_vin = g_pending_vin;
    }
    pthread_mutex_unlock(&g_pending_lock);
    *out_found = present;
    return true;
}

bool coin_backfill_rounds_read(struct sqlite3 *db, int height,
                               const struct uint256 *hash, int32_t *out)
{
    uint8_t blob[8];
    size_t n = 0;
    bool found = false;
    *out = 0;
    if (!hash)
        LOG_FAIL("coin_backfill", "[coin_backfill] rounds read NULL hash");
    if (!repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS,
                            height, hash->data, &found, blob, sizeof(blob),
                            &n))
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] rounds read failed h=%d", height);
    if (found && n >= 4)
        *out = coin_backfill_le32_get(blob);
    return true;
}

/* tx_index_complete sentinel: node.db node_state marks the txindex build
 * finished (additive build, 0 skipped blocks) at value 3
 * (snapshot_controller_txindex.c:528, read at :320). Below this a txindex_miss
 * may just be an unindexed-yet tx during IBD — transient, never terminal. */
#define COIN_BACKFILL_TXINDEX_COMPLETE_MIN 3

void coin_backfill_persist_terminal_refusal(
    struct sqlite3 *db, const struct coin_backfill_io *io,
    int height, const struct uint256 *hash,
    enum coin_backfill_terminal_class tc,
    const char *value_class)
{
    if (tc == COIN_BACKFILL_TC_RETRYABLE)
        return;
    if (tc == COIN_BACKFILL_TC_TERMINAL_IF_TXINDEX_COMPLETE) {
        int64_t complete = 0;
        if (!io || !io->ndb ||
            !node_db_state_get_int(io->ndb, "tx_index_complete", &complete) ||
            complete < COIN_BACKFILL_TXINDEX_COMPLETE_MIN)
            return; /* index still building / disabled: miss is transient */
    }
    if (!hash) {
        LOG_WARN("coin_backfill",
                 "[coin_backfill] terminal refusal skipped h=%d: NULL hash",
                 height);
        return;
    }
    if (!repair_marker_note(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                            height, hash->data, value_class,
                            strlen(value_class)))
        LOG_WARN("coin_backfill",
                 "[coin_backfill] terminal refusal marker write failed h=%d "
                 "(refusing anyway)", height);
}

bool find_lowest_prevout_unresolved_hole_unlocked(
    struct sqlite3 *db, int cursor, const char *wanted_status, int *out_height,
    char status_out[32], struct uint256 *hash_out, bool *hash_found)
{
    *out_height = -1;
    status_out[0] = '\0';
    *hash_found = false;
    if (cursor <= 0)
        return true;
    if (!wanted_status)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole scan NULL wanted_status");

    /* Scan for the lowest hole of the EXACT status the caller is verdicting on
     * (the tear/repair consumers want 'prevout_unresolved'); selecting any of
     * the umbrella triplet here would let a lower transient internal_error
     * mask a higher genuine prevout_unresolved tear. internal_error is owned
     * by the separate stale-script replay path (stale_script_hole_unlocked). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height, status, block_hash FROM script_validate_log "
            "WHERE ok = 0 "
            "  AND status = ? "
            "  AND height < ? "
            "ORDER BY height LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole prepare failed: %s",
                 sqlite3_errmsg(db));
    if (sqlite3_bind_text(st, 1, wanted_status, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_int(st, 2, cursor) != SQLITE_OK) {
        /* A NULL-bound param silently matches no rows and masks the hole. */
        sqlite3_finalize(st);
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole bind failed cursor=%d: %s",
                 cursor, sqlite3_errmsg(db));
    }

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_height = sqlite3_column_int(st, 0);
        const unsigned char *s = sqlite3_column_text(st, 1);
        snprintf(status_out, 32, "%s", s ? (const char *)s : "");
        if (sqlite3_column_bytes(st, 2) == 32 && sqlite3_column_blob(st, 2)) {
            memcpy(hash_out->data, sqlite3_column_blob(st, 2), 32);
            *hash_found = true;
        }
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);

    /* STEP-2A: ALSO consult the non-terminal pending-prevout HOLD signal. When
     * script_validate HOLDS on a transient prevout_unresolved it no longer
     * writes the terminal ok=0 row the SQL scan above looks for, so a genuinely
     * torn pre-anchor coin would be invisible to coin_backfill and the boot
     * torn gate. The signal carries the same (height, block_hash) binding and
     * frozen-cursor height; admit it as the hole when it replaces or is lower
     * than the SQL result (preserving "lowest hole" semantics). Only meaningful
     * for the prevout_unresolved verdict the tear/repair consumers want. */
    if (strcmp(wanted_status, "prevout_unresolved") == 0) {
        int pend_h = -1, pend_vin = -1;
        struct uint256 pend_hash, pend_txid;
        bool pend_found = false;
        if (!coin_backfill_pending_prevout_get(db, &pend_h, &pend_hash,
                                               &pend_txid, &pend_vin,
                                               &pend_found))
            LOG_FAIL("coin_backfill",
                     "[coin_backfill] hole scan pending_prevout read failed");
        /* `<= cursor` (NOT `< cursor` like the SQL scan): the HOLD freezes the
         * script_validate cursor AT the hole, so backfill_run calls this with
         * cursor == hole_h. A strict `<` would exclude the very frozen-cursor
         * hole the signal exists to surface; the torn gate's cursor=ceiling+1
         * keeps hole_h < cursor regardless. A pend_h ABOVE the cursor (not yet a
         * settled frontier) is still excluded. */
        if (pend_found && pend_h > 0 && pend_h <= cursor &&
            (*out_height < 0 || pend_h < *out_height)) {
            *out_height = pend_h;
            snprintf(status_out, 32, "prevout_unresolved");
            *hash_out = pend_hash;
            *hash_found = true;
        }
    }
    return true;
}

/* delta-horizon walk bound: the contiguous covered window on a wedged
 * datadir is a few thousand heights; if the walk has not found a gap after
 * this many steps the horizon is reported as unbounded (-1) and the repair
 * REFUSES rather than guessing a permissive floor. */
#define COIN_BACKFILL_HORIZON_WALK_MAX 262144

bool utxo_apply_log_contiguous_floor(struct sqlite3 *db, int cursor,
                                     int *out_floor)
{
    *out_floor = cursor;
    if (cursor <= 0)
        return true;

    sqlite3_stmt *log_st = NULL, *delta_st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM utxo_apply_log WHERE height = ?",
            -1, &log_st, NULL) != SQLITE_OK)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] horizon log prepare failed: %s",
                 sqlite3_errmsg(db));
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM utxo_apply_delta WHERE height = ?",
            -1, &delta_st, NULL) != SQLITE_OK) {
        sqlite3_finalize(log_st);
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] horizon delta prepare failed: %s",
                 sqlite3_errmsg(db));
    }

    int floor = cursor;
    bool sql_ok = true;
    for (int h = cursor - 1, steps = 0; h >= 0; h--, steps++) {
        if (steps >= COIN_BACKFILL_HORIZON_WALK_MAX) {
            floor = -1; /* unbounded walk: refuse rather than guess */
            break;
        }
        if (sqlite3_reset(log_st) != SQLITE_OK ||
            sqlite3_bind_int(log_st, 1, h) != SQLITE_OK) {
            sql_ok = false; /* a NULL-bound param would fake a gap at h */
            break;
        }
        int rc = sqlite3_step(log_st);  // raw-sql-ok:progress-kv-kernel-store
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            sql_ok = false;
            break;
        }
        bool have = rc == SQLITE_ROW;
        if (have) {
            if (sqlite3_reset(delta_st) != SQLITE_OK ||
                sqlite3_bind_int(delta_st, 1, h) != SQLITE_OK) {
                sql_ok = false;
                break;
            }
            rc = sqlite3_step(delta_st);  // raw-sql-ok:progress-kv-kernel-store
            if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
                sql_ok = false;
                break;
            }
            have = rc == SQLITE_ROW;
        }
        if (!have)
            break;
        floor = h;
    }
    sqlite3_finalize(log_st);
    sqlite3_finalize(delta_st);
    if (!sql_ok)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] horizon walk reset/bind/step failed: %s",
                 sqlite3_errmsg(db));
    *out_floor = floor;
    return true;
}

bool coin_backfill_hole_row_matches_unlocked(struct sqlite3 *db, int height,
                                             const struct uint256 *hash,
                                             bool *match)
{
    *match = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT status, block_hash FROM script_validate_log "
            "WHERE height = ? AND ok = 0",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole recheck prepare failed: %s",
                 sqlite3_errmsg(db));
    if (sqlite3_bind_int(st, 1, height) != SQLITE_OK) {
        sqlite3_finalize(st);
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole recheck bind failed h=%d: %s",
                 height, sqlite3_errmsg(db));
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const unsigned char *s = sqlite3_column_text(st, 0);
        *match = s && strcmp((const char *)s, "prevout_unresolved") == 0 &&
                 sqlite3_column_bytes(st, 1) == 32 &&
                 sqlite3_column_blob(st, 1) &&
                 memcmp(sqlite3_column_blob(st, 1), hash->data, 32) == 0;
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] hole recheck step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);

    /* STEP-2A torn case: when script_validate HOLDs on a prevout_unresolved it
     * writes NO legacy ok=0 row — the hole was surfaced via the non-terminal
     * pending-prevout signal (find_lowest_prevout_unresolved_hole admits it).
     * The re-check above then sees no row and would make backfill_run refuse
     * "hole_row_changed" on a genuinely torn coin. Accept the hole when the
     * durable signal still matches this (height, block_hash) — the same binding
     * the finder admitted. */
    if (!*match) {
        int pend_h = -1;
        struct uint256 pend_hash;
        bool pend_found = false;
        if (!coin_backfill_pending_prevout_get(db, &pend_h, &pend_hash, NULL,
                                               NULL, &pend_found))
            LOG_FAIL("coin_backfill",
                     "[coin_backfill] hole recheck pending read failed");
        if (pend_found && pend_h == height &&
            memcmp(pend_hash.data, hash->data, 32) == 0)
            *match = true;
    }
    return true;
}

/* Once-latched per (H,holehash,status); blocker_set's token bucket
 * additionally dedups the blocker itself. Direct-emit precedent:
 * engine/services/src/chain_tip_watchdog.c wd_decide_restart. The latch slot
 * is claimed only AFTER the blocker registered (CB#4): claiming it first
 * would mute the tuple until restart if blocker_init/blocker_set failed.
 * The window between the dup check and the claim is benign — writes come
 * only from the self_heal supervisor thread (see g_state_lock note). */
bool coin_backfill_page_refusal(enum coin_backfill_status st, int h,
                                const struct uint256 *hole_hash,
                                const char *reason)
{
    uint8_t hash[32] = {0};
    if (hole_hash)
        memcpy(hash, hole_hash->data, 32);

    pthread_mutex_lock(&g_state_lock);
    for (size_t i = 0; i < PAGE_LATCH_SLOTS; i++) {
        if (g_latch[i].used && g_latch[i].height == h &&
            g_latch[i].status == (int)st &&
            memcmp(g_latch[i].hash, hash, 32) == 0) {
            pthread_mutex_unlock(&g_state_lock);
            atomic_fetch_add(&g_pages_suppressed_total, 1u);
            return false;
        }
    }
    pthread_mutex_unlock(&g_state_lock);

    char id[BLOCKER_ID_MAX];
    enum blocker_class cls;
    const char *escape;
    switch (st) {
    case COIN_BACKFILL_OWNER_REFUSED:
        /* blocker-id: coin_backfill.owner_gate */
        snprintf(id, sizeof(id), "coin_backfill.owner_gate");
        cls = BLOCKER_DEPENDENCY;
        escape = "export " COIN_BACKFILL_ACK_ENV "=1 in the unit env, restart";
        break;
    case COIN_BACKFILL_REFUSED_UNPROVABLE:
        /* blocker-id: coin_backfill.unprovable.* */
        snprintf(id, sizeof(id), "coin_backfill.unprovable.%d", h);
        cls = BLOCKER_DEPENDENCY;
        escape = "fetch deep body via rebuild_recent / -cold-import";
        break;
    default: /* REFUSED_SPENT / MARKER_SEEN: refuse, never guess */
        /* blocker-id: coin_backfill.* */
        snprintf(id, sizeof(id), "coin_backfill.%d", h);
        cls = BLOCKER_PERMANENT;
        escape = "operator: investigate lost-coin class / consensus divergence";
        break;
    }
    char btext[BLOCKER_REASON_MAX];
    snprintf(btext, sizeof(btext),
             "coin_backfill h=%d status=%s reason=%s; escape: %s",
             h, coin_backfill_status_name(st), reason, escape);
    struct blocker_record rec;
    if (!blocker_init(&rec, id, "coin_backfill", cls, btext) ||
        blocker_set(&rec) < 0) { /* 1 = rate-limited dup: still a page */
        /* Emission failed (bad input / registry cap — details logged by
         * blocker_*): leave the latch UNCLAIMED so this tuple re-pages on
         * the next tick. One breadcrumb so the failure is never silent. */
        LOG_WARN("coin_backfill",
                 "[coin_backfill] page emission failed h=%d status=%s "
                 "reason=%s; latch not claimed, re-paging next tick",
                 h, coin_backfill_status_name(st), reason);
        return false;
    }
    event_emitf(EV_OPERATOR_NEEDED, 0,
                "coin_backfill h=%d status=%s reason=%s",
                h, coin_backfill_status_name(st), reason);
    atomic_fetch_add(&g_pages_emitted_total, 1u);
    LOG_WARN("coin_backfill",
             "[coin_backfill] OPERATOR NEEDED h=%d status=%s reason=%s "
             "escape=%s", h, coin_backfill_status_name(st), reason, escape);

    /* Latch ONLY now that the blocker + event went out (CB#4). */
    pthread_mutex_lock(&g_state_lock);
    struct page_latch *slot = &g_latch[g_latch_next++ % PAGE_LATCH_SLOTS];
    slot->used = true;
    slot->height = h;
    slot->status = (int)st;
    memcpy(slot->hash, hash, 32);
    pthread_mutex_unlock(&g_state_lock);
    return true;
}

void coin_backfill_stats_note_call(void)
{
    atomic_fetch_add(&g_calls_total, 1u);
}

void coin_backfill_stats_note_rebind(void)
{
    atomic_fetch_add(&g_rebind_total, 1u);
}

void coin_backfill_stats_note_repaired(int inserted)
{
    atomic_fetch_add(&g_repaired_total, 1u);
    atomic_fetch_add(&g_inserted_total, (uint64_t)(inserted > 0 ? inserted
                                                                : 0));
}

void coin_backfill_publish_result(const struct coin_backfill_result *r)
{
    if (!r)
        return; /* nothing to publish; dump keeps the previous snapshot */
    pthread_mutex_lock(&g_state_lock);
    g_last_result = *r;
    g_last_call_unix = platform_time_wall_unix();
    pthread_mutex_unlock(&g_state_lock);
}

void coin_backfill_reset_latches_for_testing(void)
{
    pthread_mutex_lock(&g_state_lock);
    memset(g_latch, 0, sizeof(g_latch));
    g_latch_next = 0;
    pthread_mutex_unlock(&g_state_lock);
    pthread_mutex_lock(&g_pending_lock);
    g_pending_present = false;
    g_pending_height = -1;
    g_pending_vin = -1;
    pthread_mutex_unlock(&g_pending_lock);
}

bool coin_backfill_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;  // raw-return-ok:dumper-null-out-no-context
    json_set_object(out);

    pthread_mutex_lock(&g_state_lock);
    struct coin_backfill_result r = g_last_result;
    int64_t last = g_last_call_unix;
    pthread_mutex_unlock(&g_state_lock);

    json_push_kv_str(out, "last_status", coin_backfill_status_name(r.status));
    json_push_kv_int(out, "hole_height", r.hole_height);
    json_push_kv_int(out, "unresolved_count", r.unresolved_count);
    json_push_kv_int(out, "inserted_count", r.inserted_count);
    json_push_kv_int(out, "scan_next_height", r.scan_next_height);
    json_push_kv_int(out, "scan_top_height", r.scan_top_height);
    json_push_kv_int(out, "creator_floor", r.creator_floor);
    json_push_kv_int(out, "delta_horizon", r.delta_horizon);
    json_push_kv_str(out, "refuse_reason", r.refuse_reason);
    json_push_kv_int(out, "last_call_unix", last);
    json_push_kv_int(out, "calls_total",
                     (int64_t)atomic_load(&g_calls_total));
    json_push_kv_int(out, "repaired_total",
                     (int64_t)atomic_load(&g_repaired_total));
    json_push_kv_int(out, "inserted_outpoints_total",
                     (int64_t)atomic_load(&g_inserted_total));
    json_push_kv_int(out, "scan_rebind_total",
                     (int64_t)atomic_load(&g_rebind_total));
    json_push_kv_int(out, "pages_emitted_total",
                     (int64_t)atomic_load(&g_pages_emitted_total));
    json_push_kv_int(out, "pages_suppressed_total",
                     (int64_t)atomic_load(&g_pages_suppressed_total));
    json_push_kv_bool(out, "owner_ack", coin_backfill_owner_ack());

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * engine/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed last_status above — the four REFUSED/
     * OWNER_REFUSED/MARKER_SEEN outcomes mean the repair could not proceed
     * and is paging or stuck, vs. NOT_APPLICABLE/SCANNING/REPAIRED which are
     * normal no-op-or-progressing outcomes. No new health logic. */
    {
        bool blocked = r.status == COIN_BACKFILL_OWNER_REFUSED ||
                       r.status == COIN_BACKFILL_REFUSED_SPENT ||
                       r.status == COIN_BACKFILL_REFUSED_UNPROVABLE ||
                       r.status == COIN_BACKFILL_MARKER_SEEN;
        char reason_buf[192] = "";
        if (blocked) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "last_status=%s hole_height=%d: %s",
                     coin_backfill_status_name(r.status), r.hole_height,
                     r.refuse_reason);
        }
        diag_push_health(out, !blocked, reason_buf);
    }
    return true;
}
