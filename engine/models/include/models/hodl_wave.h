/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveModel-style HODL wave read model.
 *
 * This is a computed projection of the current transparent UTXO set. It is
 * intentionally not consensus state and intentionally not a historical
 * spent-output index. */

#ifndef ZCL_MODELS_HODL_WAVE_H
#define ZCL_MODELS_HODL_WAVE_H

#include "models/activerecord.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

enum { HODL_WAVE_BUCKETS = 10 };

struct hodl_wave_bucket {
    const char *label;
    const char *html_label;
    const char *color;
    int64_t max_age_seconds;
    int64_t value;
    int64_t count;
};

struct hodl_wave_snapshot {
    int64_t tip_height;
    int64_t total_value;
    int64_t total_count;
    int64_t skipped_rows;
    int64_t older_than_1y_value;
    int64_t older_than_1y_count;
    struct hodl_wave_bucket buckets[HODL_WAVE_BUCKETS];
    char source[64];
    char metric[64];
    char status[128];
};

const struct hodl_wave_bucket *hodl_wave_bucket_defs(void);
int64_t hodl_wave_age_seconds(int64_t utxo_height, int64_t tip_height);
int hodl_wave_bucket_index(int64_t age_seconds);
bool hodl_wave_validate(const struct hodl_wave_snapshot *h,
                        struct ar_errors *errors);
bool hodl_wave_scan_current_utxos(sqlite3 *db, int64_t tip_height,
                                  struct hodl_wave_snapshot *out);
double hodl_wave_older_than_1y_percent(const struct hodl_wave_snapshot *h);

#endif /* ZCL_MODELS_HODL_WAVE_H */
