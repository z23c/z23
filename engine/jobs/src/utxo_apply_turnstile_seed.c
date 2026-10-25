/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZIP-209 pool-totals seeder. See jobs/utxo_apply_turnstile_seed.h.
 *
 * Phase A reads bodies with no lock held (at most 1024 heights, ~100 ms),
 * Phase B takes progress_store_tx_lock for one short BEGIN IMMEDIATE txn that
 * re-checks the cursor, the table's MAX and the active-chain hashes before
 * writing. The seeder never refuses or delays a block: a missing body only
 * ends the slice and raises a transient blocker. */

#include "jobs/utxo_apply_turnstile_seed.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/catchup_cadence.h"
#include "jobs/stage_helpers.h"
#include "jobs/utxo_apply_turnstile.h"
#include "primitives/block.h"
#include "platform/time_compat.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "storage/shielded_pool_kv.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/reducer_drive_guard.h"
#include "utxo_apply_stage_internal.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define STAGE_NAME "utxo_apply"
#define SEED_BODY_BLOCKER "utxo_apply.turnstile_seed_body"
#define SEED_NEG_BLOCKER "utxo_apply.turnstile_seed_negative"

struct seed_row {
    int64_t height;
    struct uint256 hash;
    int64_t sprout;
    int64_t sapling;
};

static struct seed_row g_rows[UA_TURNSTILE_SEED_MAX_ROWS];
static _Atomic int64_t g_through = -1;
static _Atomic uint64_t g_rows_written = 0;
static _Atomic uint64_t g_slices = 0;
static _Atomic int64_t g_last_slice_us = 0;
static _Atomic uint64_t g_read_us = 0;
static _Atomic int g_hold = 0;   /* 0 none, 1 body, 2 negative_total */
static _Atomic bool g_halted = false;
/* g_rows is one static slice buffer; block intake and the reducer kick can
 * both reach the drain hook, so one seeder runs and the other skips. */
static atomic_flag g_busy = ATOMIC_FLAG_INIT;
static void (*g_gap_hook)(void *) = NULL;
static void *g_gap_user = NULL;

static const char *const k_hold_names[] = { "none", "body", "negative_total" };

static void seed_body_blocker(int64_t height, const char *why)
{
    struct blocker_record rec;
    if (!blocker_init(&rec, "utxo_apply.turnstile_seed_body", STAGE_NAME, BLOCKER_TRANSIENT,
                      "turnstile seeder cannot read the block body"))
        return;
    snprintf(rec.reason, sizeof(rec.reason),
             "height=%lld: %s; turnstile seeding paused, blocks unaffected",
             (long long)height, why);
    snprintf(rec.escape_action, sizeof(rec.escape_action),
             "repair blk files or reindex");
    (void)blocker_set(&rec);
    atomic_store(&g_hold, 1);
}

static void seed_body_clear(void)
{
    if (atomic_load(&g_hold) == 1) {
        blocker_clear(SEED_BODY_BLOCKER);
        atomic_store(&g_hold, 0);
    }
}

static void seed_negative_blocker(int64_t height, const char *pool,
                                  int64_t sprout, int64_t sapling)
{
    struct blocker_record rec;
    if (!blocker_init(&rec, "utxo_apply.turnstile_seed_negative", STAGE_NAME, BLOCKER_TRANSIENT,
                      "turnstile seeder found a negative pool total"))
        return;
    snprintf(rec.reason, sizeof(rec.reason),
             "height=%lld pool=%s sprout=%lld sapling=%lld: seeding stopped",
             (long long)height, pool, (long long)sprout, (long long)sapling);
    snprintf(rec.escape_action, sizeof(rec.escape_action),
             "inspect the chain's shielded history");
    (void)blocker_set(&rec);
    atomic_store(&g_hold, 2);
    atomic_store(&g_halted, true);
}

static bool seed_body_present(const struct block_index *bi)
{
    return bi && bi->nFile >= 0 && (bi->nStatus & BLOCK_HAVE_DATA) &&
           !(bi->nDataPos == 0 && bi->nHeight > 0);
}

/* Z23 may hold no readable genesis body, and genesis carries no shielded
 * value (zclassicd reports both pools at 0 there): when its body is absent
 * or unreadable its row is zero totals under its own hash, so genesis never
 * holds the seeder. */
static bool seed_genesis_row(const struct block_index *bi, int n)
{
    if (!bi || bi->nHeight != 0 || !bi->phashBlock)
        return false;
    g_rows[n].height = 0;
    g_rows[n].hash = *bi->phashBlock;
    g_rows[n].sprout = 0;
    g_rows[n].sapling = 0;
    return true;
}

/* Phase A: remember up to `limit` rows after K. Returns the row count. */
static int seed_scan(struct main_state *ms, const char *datadir,
                     utxo_apply_turnstile_seed_reader_fn reader, void *user,
                     int64_t first, int64_t limit)
{
    int n = 0;
    int64_t t0 = platform_time_monotonic_us();
    for (int64_t h = first; h <= limit && n < UA_TURNSTILE_SEED_MAX_ROWS;
         h++) {
        if (platform_time_monotonic_us() - t0 > UA_TURNSTILE_SEED_READ_BUDGET_US)
            break;
        struct block_index *bi = active_chain_at(&ms->chain_active, (int)h);
        struct block blk;
        block_init(&blk);
        bool present = seed_body_present(bi) && bi->phashBlock;
        bool ok = present &&
                  (reader ? reader(&blk, bi, datadir, user)
                          : read_block_from_disk_index(&blk, bi, datadir));
        if (!ok && seed_genesis_row(bi, n)) {
            block_free(&blk);
            seed_body_clear();
            n++;
            continue;
        }
        if (!ok) {
            seed_body_blocker(h, present ? "body read failed"
                                         : "no committed body on the active chain");
            break;
        }
        g_rows[n].height = h;
        g_rows[n].hash = *bi->phashBlock;
        utxo_apply_turnstile_block_values(&blk, &g_rows[n].sprout,
                                          &g_rows[n].sapling);
        block_free(&blk);
        seed_body_clear();
        n++;
    }
    atomic_fetch_add(&g_read_us,
                     (uint64_t)(platform_time_monotonic_us() - t0));
    return n;
}

static bool seed_chain_matches(struct main_state *ms, int n)
{
    for (int i = 0; i < n; i++) {
        struct block_index *bi =
            active_chain_at(&ms->chain_active, (int)g_rows[i].height);
        if (!bi || !bi->phashBlock ||
            !uint256_eq(bi->phashBlock, &g_rows[i].hash))
            return false;
    }
    return true;
}

/* Write the remembered rows on top of row K's totals. Returns rows written,
 * or -1 on a store failure. A negative total stops before its row. */
static int seed_write_rows(sqlite3 *db, int64_t k, bool k_found, int n)
{
    int64_t sprout = 0, sapling = 0;
    bool found = true;
    if (k_found && (!shielded_pool_kv_get(db, k, &sprout, &sapling, &found) ||
                    !found))
        LOG_ERR(STAGE_NAME,
                "[utxo_apply] turnstile seed: row K=%lld totals read failed",
                (long long)k);
    int wrote = 0;
    for (int i = 0; i < n; i++) {
        sprout += g_rows[i].sprout;
        sapling += g_rows[i].sapling;
        if (sprout < 0 || sapling < 0) {
            seed_negative_blocker(g_rows[i].height,
                                  sprout < 0 ? "sprout" : "sapling",
                                  sprout, sapling);
            break;
        }
        if (!shielded_pool_kv_put(db, g_rows[i].height, sprout, sapling))
            LOG_ERR(STAGE_NAME,
                    "[utxo_apply] turnstile seed: put failed at height=%lld",
                    (long long)g_rows[i].height);
        wrote++;
    }
    return wrote;
}

static void seed_end_txn(sqlite3 *db, bool commit)
{
    sqlite3_exec(db, commit ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
}

/* Phase B. Returns rows written (0 when the slice was discarded). */
static int seed_commit(sqlite3 *db, struct main_state *ms, int64_t k,
                       bool k_found, int n)
{
    progress_store_tx_lock();
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        return 0;
    }
    int64_t t0 = platform_time_monotonic_us();
    int64_t cursor = (int64_t)stage_cursor_persisted(db, STAGE_NAME, STAGE_NAME);
    int64_t max2 = -1;
    bool found2 = false;
    while (n > 0 && g_rows[n - 1].height >= cursor)
        n--;
    int wrote = 0;
    bool store_ok = shielded_pool_kv_max_height(db, &max2, &found2);
    if (store_ok && n > 0 && found2 == k_found && (!found2 || max2 == k) &&
        seed_chain_matches(ms, n)) {
        wrote = seed_write_rows(db, k, k_found, n);
        store_ok = wrote >= 0;
    }
    seed_end_txn(db, store_ok);
    atomic_store(&g_last_slice_us, platform_time_monotonic_us() - t0);
    return store_ok ? wrote : 0;
}

/* The running totals live in the table; g_rows holds per-block values. */
static void seed_log_reached(sqlite3 *db, int64_t through)
{
    int64_t sprout = 0, sapling = 0;
    bool found = false;
    if (!shielded_pool_kv_get(db, through, &sprout, &sapling, &found) || !found)
        return;
    LOG_INFO(STAGE_NAME,
             "[utxo_apply] turnstile seeding reached height=%lld "
             "sprout_total=%lld sapling_total=%lld", (long long)through,
             (long long)sprout, (long long)sapling);
}

static bool seed_run_once(sqlite3 *db, struct main_state *ms,
                          const char *datadir,
                          utxo_apply_turnstile_seed_reader_fn reader,
                          void *reader_user)
{
    int64_t cursor = (int64_t)stage_cursor_persisted(db, STAGE_NAME, STAGE_NAME);
    int64_t k = -1;
    bool k_found = false;
    if (!shielded_pool_kv_max_height(db, &k, &k_found)) {
        LOG_WARN(STAGE_NAME, "[utxo_apply] turnstile seed: MAX(height) read failed");
        return false;
    }
    int64_t limit = cursor - 1;
    if (limit > k + UA_TURNSTILE_SEED_MAX_ROWS)
        limit = k + UA_TURNSTILE_SEED_MAX_ROWS;
    if (k + 1 > limit)
        return false;
    int n = seed_scan(ms, datadir, reader, reader_user, k + 1, limit);
    if (n == 0)
        return false;
    if (g_gap_hook)
        g_gap_hook(g_gap_user);
    int wrote = seed_commit(db, ms, k, k_found, n);
    if (wrote <= 0)
        return false;
    int64_t through = g_rows[wrote - 1].height;
    atomic_store(&g_through, through);
    atomic_fetch_add(&g_rows_written, (uint64_t)wrote);
    atomic_fetch_add(&g_slices, 1);
    if (through == cursor - 1)
        seed_log_reached(db, through);
    return true;
}

bool utxo_apply_turnstile_seed_run(
    sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_turnstile_seed_reader_fn reader, void *reader_user)
{
    if (!db || !ms || atomic_load(&g_halted))
        return false;
    if (atomic_flag_test_and_set(&g_busy))
        return false;
    bool ran = seed_run_once(db, ms, datadir, reader, reader_user);
    atomic_flag_clear(&g_busy);
    return ran;
}

bool utxo_apply_turnstile_seed_post_commit(void)
{
    struct main_state *ms = NULL;
    char datadir[2048];
    utxo_apply_reader_fn reader = NULL;
    void *user = NULL;
    sqlite3 *db = progress_store_db();
    if (!db || !utxo_apply_stage_handle() ||
        !utxo_apply_stage_seed_context(&ms, datadir, sizeof(datadir),
                                       &reader, &user))
        return false;
    if (catchup_cadence_active() || reducer_drive_active())
        return false;
    return utxo_apply_turnstile_seed_run(db, ms, datadir, reader, user);
}

void utxo_apply_turnstile_seed_stats_get(
    struct utxo_apply_turnstile_seed_stats *out)
{
    out->seeded_through = atomic_load(&g_through);
    out->rows_written = atomic_load(&g_rows_written);
    out->slices = atomic_load(&g_slices);
    out->last_slice_us = atomic_load(&g_last_slice_us);
    out->read_us_total = atomic_load(&g_read_us);
    out->hold = k_hold_names[atomic_load(&g_hold)];
}

void utxo_apply_turnstile_seed_set_gap_hook_for_test(void (*fn)(void *),
                                                     void *user)
{
    g_gap_hook = fn;
    g_gap_user = user;
}

void utxo_apply_turnstile_seed_reset_for_test(void)
{
    atomic_store(&g_through, -1);
    atomic_store(&g_rows_written, 0);
    atomic_store(&g_slices, 0);
    atomic_store(&g_last_slice_us, 0);
    atomic_store(&g_read_us, 0);
    atomic_store(&g_hold, 0);
    atomic_store(&g_halted, false);
    atomic_flag_clear(&g_busy);
    blocker_clear(SEED_BODY_BLOCKER);
    blocker_clear(SEED_NEG_BLOCKER);
    g_gap_hook = NULL;
    g_gap_user = NULL;
}
