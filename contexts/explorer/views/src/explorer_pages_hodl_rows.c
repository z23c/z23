/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer HODL-wave VIEW — survival-row time-series model.
 *
 * Part of the HODL-wave page split (see views/explorer_pages_hodl_internal.h):
 * this TU owns the survival-row model — block-time estimation, the per-height
 * cumulative-value walk, the history-backed and fallback survival-row builders,
 * and the survival-row cache. The page assembly lives in explorer_pages_hodl.c;
 * the snapshot cache in explorer_pages_hodl_snapshot.c; the SVG chart emitters
 * in explorer_pages_hodl_chart.c. */

#include "views/explorer_pages_hodl_internal.h"
#include "models/hodl_wave.h"
#include "services/hodl_history_service.h"
#include "util/ar_step_readonly.h"
#include "util/safe_alloc.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    HODL_CUM_MAX_ROWS = 2000000,
    HODL_GENESIS_TIME = 1478403829LL,
    HODL_BUTTERCUP_HEIGHT = 707000LL,
    HODL_PRE_BUTTERCUP_SPACING = 150LL,
    HODL_POST_BUTTERCUP_SPACING = 75LL,
    HODL_HALF_YEAR_SECONDS = 15778800LL,
    HODL_ONE_YEAR_SECONDS = 31557600LL,
    HODL_TWO_YEAR_SECONDS = 63115200LL,
    HODL_FIVE_YEAR_SECONDS = 157788000LL
};

const struct hodl_threshold_def HODL_THRESHOLDS[HODL_SURVIVAL_THRESHOLDS] = {
    { "6 months", "#ffb454", HODL_HALF_YEAR_SECONDS },
    { "1 year",   "#35d07f", HODL_ONE_YEAR_SECONDS },
    { "2 years",  "#42a5f5", HODL_TWO_YEAR_SECONDS },
    { "5 years",  "#b56cff", HODL_FIVE_YEAR_SECONDS },
};

struct hodl_cum_row {
    int64_t height;
    int64_t cumulative_zat;
};

struct hodl_survival_cache_entry {
    bool valid;
    bool history_backed;
    char datadir[HODL_VIEW_CACHE_DATADIR_MAX];
    int64_t tip_height;
    char tip_hash[HODL_VIEW_CACHE_HASH_MAX];
    int row_count;
    struct hodl_survival_row rows[HODL_SURVIVAL_MAX_ROWS];
};

static pthread_mutex_t g_hodl_survival_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hodl_survival_cache_entry g_hodl_survival_cache;

static int64_t hodl_cum_at(const struct hodl_cum_row *cum, int n,
                           int64_t target_height)
{
    int lo = 0;
    int hi = n - 1;
    int found = -1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (cum[mid].height <= target_height) {
            found = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return found >= 0 ? cum[found].cumulative_zat : 0;
}

static int64_t hodl_height_for_age(int64_t sample_height,
                                   int64_t age_seconds)
{
    if (age_seconds <= 0)
        return sample_height;
    if (sample_height >= HODL_BUTTERCUP_HEIGHT) {
        int64_t post_span =
            (sample_height - HODL_BUTTERCUP_HEIGHT) *
            HODL_POST_BUTTERCUP_SPACING;
        if (age_seconds <= post_span)
            return sample_height - age_seconds / HODL_POST_BUTTERCUP_SPACING;
        return HODL_BUTTERCUP_HEIGHT -
               (age_seconds - post_span) / HODL_PRE_BUTTERCUP_SPACING;
    }
    return sample_height - age_seconds / HODL_PRE_BUTTERCUP_SPACING;
}

int64_t hodl_estimated_block_time(int64_t height)
{
    int64_t pre = height < HODL_BUTTERCUP_HEIGHT
        ? height : HODL_BUTTERCUP_HEIGHT;
    int64_t post = height < HODL_BUTTERCUP_HEIGHT
        ? 0 : height - HODL_BUTTERCUP_HEIGHT;
    return HODL_GENESIS_TIME +
           pre * HODL_PRE_BUTTERCUP_SPACING +
           post * HODL_POST_BUTTERCUP_SPACING;
}

static int64_t hodl_block_time_lookup(sqlite3_stmt *stmt, int64_t height)
{
    int64_t out = 0;

    if (!stmt)
        return hodl_estimated_block_time(height);
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_int64(stmt, 1, height);
    if (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW)
        out = sqlite3_column_int64(stmt, 0);
    if (out <= 0)
        out = hodl_estimated_block_time(height);
    return out;
}

bool hodl_survival_cache_get(const char *datadir_key,
                             int64_t tip_height,
                             const char *tip_hash,
                             struct hodl_survival_row *rows,
                             int *row_count,
                             bool *history_backed)
{
    bool hit = false;

    if (!datadir_key || !tip_hash || !rows || !row_count)
        return false;
    pthread_mutex_lock(&g_hodl_survival_cache_lock);
    if (g_hodl_survival_cache.valid &&
        g_hodl_survival_cache.tip_height == tip_height &&
        strcmp(g_hodl_survival_cache.datadir, datadir_key) == 0 &&
        strcmp(g_hodl_survival_cache.tip_hash, tip_hash) == 0 &&
        g_hodl_survival_cache.row_count > 0 &&
        g_hodl_survival_cache.row_count <= HODL_SURVIVAL_MAX_ROWS) {
        *row_count = g_hodl_survival_cache.row_count;
        if (history_backed)
            *history_backed = g_hodl_survival_cache.history_backed;
        memcpy(rows, g_hodl_survival_cache.rows,
               (size_t)*row_count * sizeof(*rows));
        hit = true;
    }
    pthread_mutex_unlock(&g_hodl_survival_cache_lock);
    return hit;
}

void hodl_survival_cache_put(const char *datadir_key,
                             int64_t tip_height,
                             const char *tip_hash,
                             const struct hodl_survival_row *rows,
                             int row_count,
                             bool history_backed)
{
    if (!datadir_key || !tip_hash || !rows || row_count <= 0 ||
        row_count > HODL_SURVIVAL_MAX_ROWS)
        return;
    pthread_mutex_lock(&g_hodl_survival_cache_lock);
    snprintf(g_hodl_survival_cache.datadir,
             sizeof(g_hodl_survival_cache.datadir), "%s", datadir_key);
    snprintf(g_hodl_survival_cache.tip_hash,
             sizeof(g_hodl_survival_cache.tip_hash), "%s", tip_hash);
    g_hodl_survival_cache.tip_height = tip_height;
    g_hodl_survival_cache.row_count = row_count;
    g_hodl_survival_cache.history_backed = history_backed;
    memcpy(g_hodl_survival_cache.rows, rows,
           (size_t)row_count * sizeof(*rows));
    g_hodl_survival_cache.valid = true;
    pthread_mutex_unlock(&g_hodl_survival_cache_lock);
}

static int hodl_pct_x1000(int64_t older_zat, int64_t total_zat)
{
    int pct = 0;
    if (older_zat < 0)
        older_zat = 0;
    if (older_zat > total_zat)
        older_zat = total_zat;
    if (total_zat > 0)
        pct = (int)((double)older_zat / (double)total_zat * 100000.0 + 0.5);
    if (pct < 0)
        pct = 0;
    if (pct > 100000)
        pct = 100000;
    return pct;
}

static int64_t hodl_current_threshold_zat(const struct hodl_wave_snapshot *h,
                                          int threshold)
{
    int first_bucket = 0;
    int64_t total = 0;

    if (!h)
        return 0;
    switch (threshold) {
    case HODL_SURVIVAL_THRESHOLD_6M:
        first_bucket = 5;  /* 6 - 12m and older */
        break;
    case HODL_SURVIVAL_THRESHOLD_1Y:
        return h->older_than_1y_value;
    case HODL_SURVIVAL_THRESHOLD_2Y:
        first_bucket = 7;  /* 2 - 3y and older */
        break;
    case HODL_SURVIVAL_THRESHOLD_5Y:
        first_bucket = 9;  /* > 5y */
        break;
    default:
        return 0;
    }
    for (int i = first_bucket; i < HODL_WAVE_BUCKETS; i++)
        total += h->buckets[i].value;
    return total;
}

static void hodl_history_row_to_wave(const struct hodl_history_row *hist,
                                     struct hodl_survival_row *out)
{
    if (!hist || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->height = hist->height;
    out->time = hist->time;
    out->total_zat = hist->total_zat;
    out->older_zat[HODL_SURVIVAL_THRESHOLD_6M] = hist->older_6m_zat;
    out->older_zat[HODL_SURVIVAL_THRESHOLD_1Y] = hist->older_1y_zat;
    out->older_zat[HODL_SURVIVAL_THRESHOLD_2Y] = hist->older_2y_zat;
    out->older_zat[HODL_SURVIVAL_THRESHOLD_5Y] = hist->older_5y_zat;
    out->pct_x1000[HODL_SURVIVAL_THRESHOLD_6M] =
        hodl_pct_x1000(hist->older_6m_zat, hist->total_zat);
    out->pct_x1000[HODL_SURVIVAL_THRESHOLD_1Y] =
        hodl_pct_x1000(hist->older_1y_zat, hist->total_zat);
    out->pct_x1000[HODL_SURVIVAL_THRESHOLD_2Y] =
        hodl_pct_x1000(hist->older_2y_zat, hist->total_zat);
    out->pct_x1000[HODL_SURVIVAL_THRESHOLD_5Y] =
        hodl_pct_x1000(hist->older_5y_zat, hist->total_zat);
}

bool hodl_load_history_wave_rows(sqlite3 *db,
                                 const struct hodl_wave_snapshot *hodl,
                                 struct hodl_survival_row *rows,
                                 int *row_count)
{
    struct hodl_history_row *hist;
    int hist_n;
    int n = 0;

    if (!db || !hodl || !rows || !row_count)
        return false;
    hist = zcl_calloc(HODL_SURVIVAL_MAX_ROWS, sizeof(*hist),
                      "hodl_history_wave_rows");
    if (!hist)
        return false;
    hist_n = hodl_history_load_all(db, hist, HODL_SURVIVAL_MAX_ROWS - 1);
    for (int i = 0; i < hist_n && n < HODL_SURVIVAL_MAX_ROWS - 1; i++) {
        if (hist[i].height < 1 || hist[i].height > hodl->tip_height ||
            hist[i].time <= 0 || hist[i].total_zat <= 0)
            continue;
        hodl_history_row_to_wave(&hist[i], &rows[n]);
        n++;
    }
    free(hist);
    if (n == 0)
        return false;
    if (rows[n - 1].height < hodl->tip_height &&
        n < HODL_SURVIVAL_MAX_ROWS) {
        rows[n].height = hodl->tip_height;
        rows[n].time = hodl_estimated_block_time(hodl->tip_height);
        rows[n].total_zat = hodl->total_value;
        for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
            int64_t older = hodl_current_threshold_zat(hodl, t);
            rows[n].older_zat[t] = older;
            rows[n].pct_x1000[t] = hodl_pct_x1000(older, hodl->total_value);
        }
        n++;
    }
    *row_count = n;
    return n >= 2;
}

bool hodl_history_wave_rows_graphable(
    const struct hodl_survival_row *rows, int row_count)
{
    int rows_with_signal = 0;

    if (!rows || row_count < 2)
        return false;
    for (int i = 0; i < row_count; i++) {
        for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
            if (rows[i].pct_x1000[t] > 0) {
                rows_with_signal++;
                break;
            }
        }
    }
    return rows_with_signal >= 2;
}

bool hodl_build_survival_rows(sqlite3 *db,
                              const struct hodl_wave_snapshot *hodl,
                              struct hodl_survival_row *rows,
                              int *row_count)
{
    struct hodl_cum_row *cum = NULL;
    sqlite3_stmt *scan = NULL;
    sqlite3_stmt *time_lookup = NULL;
    int n_cum = 0;
    int n_rows = 0;
    int64_t running = 0;
    int64_t stride = HODL_HISTORY_SAMPLE_STRIDE;

    if (!db || !hodl || !rows || !row_count || hodl->tip_height < 1)
        return false;

    cum = zcl_calloc(HODL_CUM_MAX_ROWS, sizeof(*cum), "hodl_survival_cum");
    if (!cum)
        return false;

    if (sqlite3_prepare_v2(db,
            "SELECT height, SUM(value) FROM utxos "
            "WHERE value > 0 AND height >= 0 AND height <= ?1 "
            "GROUP BY height ORDER BY height ASC",
            -1, &scan, NULL) != SQLITE_OK || !scan) {
        free(cum);
        return false;
    }
    sqlite3_bind_int64(scan, 1, hodl->tip_height);
    while (AR_STEP_ROW_READONLY(scan) == SQLITE_ROW) {
        if (n_cum >= HODL_CUM_MAX_ROWS) {
            sqlite3_finalize(scan);
            free(cum);
            return false;
        }
        int64_t h = sqlite3_column_int64(scan, 0);
        int64_t v = sqlite3_column_int64(scan, 1);
        if (h < 0 || v <= 0)
            continue;
        running += v;
        cum[n_cum].height = h;
        cum[n_cum].cumulative_zat = running;
        n_cum++;
    }
    sqlite3_finalize(scan);
    if (n_cum < 2 || running <= 0) {
        free(cum);
        return false;
    }

    int64_t estimated_rows = hodl->tip_height / stride + 2;
    if (estimated_rows > HODL_SURVIVAL_MAX_ROWS - 1) {
        int64_t mul = (estimated_rows + HODL_SURVIVAL_MAX_ROWS - 2) /
                      (HODL_SURVIVAL_MAX_ROWS - 1);
        if (mul > 1)
            stride *= mul;
    }

    if (sqlite3_prepare_v2(db,
            "SELECT time FROM blocks WHERE height=?1 LIMIT 1",
            -1, &time_lookup, NULL) != SQLITE_OK) {
        time_lookup = NULL;
    }

    for (int64_t h = stride;
         h <= hodl->tip_height && n_rows < HODL_SURVIVAL_MAX_ROWS - 1;
         h += stride) {
        int64_t total = hodl_cum_at(cum, n_cum, h);
        if (total <= 0)
            continue;
        rows[n_rows].height = h;
        rows[n_rows].time = hodl_block_time_lookup(time_lookup, h);
        rows[n_rows].total_zat = total;
        for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
            int64_t boundary =
                hodl_height_for_age(h, HODL_THRESHOLDS[t].age_seconds);
            int64_t older = hodl_cum_at(cum, n_cum, boundary);
            rows[n_rows].older_zat[t] = older;
            rows[n_rows].pct_x1000[t] = hodl_pct_x1000(older, total);
        }
        n_rows++;
    }

    if (n_rows == 0 || rows[n_rows - 1].height < hodl->tip_height) {
        int idx = n_rows;
        if (idx < HODL_SURVIVAL_MAX_ROWS) {
            int64_t total = hodl->total_value > 0
                ? hodl->total_value : hodl_cum_at(cum, n_cum, hodl->tip_height);
            rows[idx].height = hodl->tip_height;
            rows[idx].time = hodl_block_time_lookup(time_lookup,
                                                    hodl->tip_height);
            rows[idx].total_zat = total;
            for (int t = 0; t < HODL_SURVIVAL_THRESHOLDS; t++) {
                int64_t boundary = hodl_height_for_age(
                    hodl->tip_height, HODL_THRESHOLDS[t].age_seconds);
                int64_t older = hodl_cum_at(cum, n_cum, boundary);
                rows[idx].older_zat[t] = older;
                rows[idx].pct_x1000[t] = hodl_pct_x1000(older, total);
            }
            n_rows++;
        }
    }

    if (time_lookup)
        sqlite3_finalize(time_lookup);
    free(cum);
    *row_count = n_rows;
    return n_rows >= 2;
}
