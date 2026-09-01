/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal shared declarations for the explorer HODL-wave page.
 *
 * The HODL-wave page is split for comprehension across four TUs under
 * contexts/explorer/views/src/:
 *   - explorer_pages_hodl.c          page assembly + explorer_view_hodl()
 *   - explorer_pages_hodl_snapshot.c verified-snapshot cache + bg refresh
 *   - explorer_pages_hodl_rows.c     survival-row time-series model
 *   - explorer_pages_hodl_chart.c    SVG chart emitters
 *
 * These symbols are private to that TU group. Callers outside it use the
 * public entry point explorer_view_hodl() declared in
 * views/explorer_pages_view.h. */

#ifndef ZCL_VIEWS_EXPLORER_PAGES_HODL_INTERNAL_H
#define ZCL_VIEWS_EXPLORER_PAGES_HODL_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#include "models/hodl_wave.h"

/* Cache-key buffer sizes (also used to size on-stack tip_hash / datadir_key
 * buffers in the chart and page TUs). */
#define HODL_VIEW_CACHE_DATADIR_MAX 1024
#define HODL_VIEW_CACHE_HASH_MAX 80

enum {
    HODL_SURVIVAL_THRESHOLD_6M = 0,
    HODL_SURVIVAL_THRESHOLD_1Y = 1,
    HODL_SURVIVAL_THRESHOLD_2Y = 2,
    HODL_SURVIVAL_THRESHOLD_5Y = 3,
    HODL_SURVIVAL_THRESHOLDS = 4,
    HODL_SURVIVAL_MAX_ROWS = 2048
};

struct hodl_threshold_def {
    const char *label;
    const char *color;
    int64_t age_seconds;
};

/* Defined in explorer_pages_hodl_rows.c. */
extern const struct hodl_threshold_def HODL_THRESHOLDS[HODL_SURVIVAL_THRESHOLDS];

struct hodl_survival_row {
    int64_t height;
    int64_t time;
    int64_t total_zat;
    int64_t older_zat[HODL_SURVIVAL_THRESHOLDS];
    int pct_x1000[HODL_SURVIVAL_THRESHOLDS];
};

/* ── verified-snapshot cache + background refresh
 *    (explorer_pages_hodl_snapshot.c) ── */
int64_t hodl_view_cap_to_served_tip(int64_t index_tip);
bool hodl_view_datadir_key(const char *datadir,
                           char out[HODL_VIEW_CACHE_DATADIR_MAX]);
void hodl_view_tip_hash(sqlite3 *db, int64_t tip,
                        char out[HODL_VIEW_CACHE_HASH_MAX]);
bool hodl_view_cache_get_verified(sqlite3 *db, const char *datadir_key,
                                  int64_t tip,
                                  struct hodl_wave_snapshot *out,
                                  bool *cached_snapshot);
void hodl_view_cache_put(const char *datadir_key, int64_t tip,
                         const char *tip_hash,
                         const struct hodl_wave_snapshot *snapshot);
void hodl_view_snapshot_base(struct hodl_wave_snapshot *out, int64_t tip);
bool hodl_view_disk_cache_load_verified(
    const char *datadir, sqlite3 *db, int64_t tip,
    struct hodl_wave_snapshot *out,
    char cached_hash[HODL_VIEW_CACHE_HASH_MAX],
    bool *cached_snapshot);
void hodl_view_disk_cache_save(const char *datadir, int64_t tip,
                               const char *tip_hash,
                               const struct hodl_wave_snapshot *h);
bool hodl_view_allow_sync_scan(const char *datadir);
bool hodl_view_refresh_start(const char *datadir, const char *datadir_key,
                             int64_t tip, const char *tip_hash);

/* ── survival-row time-series model (explorer_pages_hodl_rows.c) ── */
int64_t hodl_estimated_block_time(int64_t height);
bool hodl_load_history_wave_rows(sqlite3 *db,
                                 const struct hodl_wave_snapshot *hodl,
                                 struct hodl_survival_row *rows,
                                 int *row_count);
bool hodl_history_wave_rows_graphable(const struct hodl_survival_row *rows,
                                      int row_count);
bool hodl_build_survival_rows(sqlite3 *db,
                              const struct hodl_wave_snapshot *hodl,
                              struct hodl_survival_row *rows,
                              int *row_count);
bool hodl_survival_cache_get(const char *datadir_key, int64_t tip_height,
                             const char *tip_hash,
                             struct hodl_survival_row *rows,
                             int *row_count, bool *history_backed);
void hodl_survival_cache_put(const char *datadir_key, int64_t tip_height,
                             const char *tip_hash,
                             const struct hodl_survival_row *rows,
                             int row_count, bool history_backed);

/* ── SVG chart emitters (explorer_pages_hodl_chart.c) ── */
void hodl_emit_survival_chart(size_t *off, uint8_t *r, size_t max,
                              const char *datadir, const char *datadir_key,
                              const struct hodl_wave_snapshot *hodl);
void hodl_emit_age_distribution_chart(size_t *off, uint8_t *r, size_t max,
                                      const struct hodl_wave_snapshot *h,
                                      bool cached_snapshot);

#endif /* ZCL_VIEWS_EXPLORER_PAGES_HODL_INTERNAL_H */
