/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "models/hodl_wave.h"
#include "util/ar_step_readonly.h"
#include <stdio.h>
#include <string.h>

enum {
    HODL_BUTTERCUP_HEIGHT = 707000,
    HODL_PRE_BUTTERCUP_SPACING = 150,
    HODL_POST_BUTTERCUP_SPACING = 75,
    HODL_ONE_YEAR_SECONDS = 31557600
};

const struct hodl_wave_bucket *hodl_wave_bucket_defs(void)
{
    static const struct hodl_wave_bucket buckets[HODL_WAVE_BUCKETS] = {
        { "< 1 day",  "&lt; 1 day", "#ff4b2b",     86400LL, 0, 0 },
        { "1d - 1w",  "1d - 1w",    "#ff8c22",    604800LL, 0, 0 },
        { "1w - 1m",  "1w - 1m",    "#ffd43b",   2592000LL, 0, 0 },
        { "1 - 3m",   "1 - 3m",     "#b8e044",   7776000LL, 0, 0 },
        { "3 - 6m",   "3 - 6m",     "#5bd45e",  15552000LL, 0, 0 },
        { "6 - 12m",  "6 - 12m",    "#2fc6a3",  31557600LL, 0, 0 },
        { "1 - 2y",   "1 - 2y",     "#3399dd",  63115200LL, 0, 0 },
        { "2 - 3y",   "2 - 3y",     "#5367d8",  94672800LL, 0, 0 },
        { "3 - 5y",   "3 - 5y",     "#7646c8", 157788000LL, 0, 0 },
        { "> 5y",     "&gt; 5y",    "#4d267d",         0LL, 0, 0 },
    };
    return buckets;
}

int64_t hodl_wave_age_seconds(int64_t utxo_height, int64_t tip_height)
{
    int64_t age;
    if (utxo_height < HODL_BUTTERCUP_HEIGHT) {
        age = (HODL_BUTTERCUP_HEIGHT - utxo_height) *
              HODL_PRE_BUTTERCUP_SPACING;
        if (tip_height > HODL_BUTTERCUP_HEIGHT)
            age += (tip_height - HODL_BUTTERCUP_HEIGHT) *
                   HODL_POST_BUTTERCUP_SPACING;
    } else {
        age = (tip_height - utxo_height) * HODL_POST_BUTTERCUP_SPACING;
    }
    return age > 0 ? age : 0;
}

int hodl_wave_bucket_index(int64_t age_seconds)
{
    const struct hodl_wave_bucket *defs = hodl_wave_bucket_defs();
    for (int i = 0; i < HODL_WAVE_BUCKETS - 1; i++) {
        if (age_seconds < defs[i].max_age_seconds)
            return i;
    }
    return HODL_WAVE_BUCKETS - 1;
}

double hodl_wave_older_than_1y_percent(const struct hodl_wave_snapshot *h)
{
    if (!h || h->total_value <= 0)
        return 0.0;
    return (double)h->older_than_1y_value / (double)h->total_value * 100.0;
}

bool hodl_wave_validate(const struct hodl_wave_snapshot *h,
                        struct ar_errors *errors)
{
    int64_t bucket_value = 0;
    int64_t bucket_count = 0;

    ar_errors_clear(errors);
    validates_custom(errors, h != NULL, "hodl_wave", "can't be null");
    if (!h)
        return false;

    validates_non_negative(errors, h, tip_height);
    validates_non_negative(errors, h, total_value);
    validates_non_negative(errors, h, total_count);
    validates_non_negative(errors, h, skipped_rows);
    validates_non_negative(errors, h, older_than_1y_value);
    validates_non_negative(errors, h, older_than_1y_count);
    validates_string_present(errors, h->source, "source");
    validates_string_present(errors, h->metric, "metric");
    validates_string_present(errors, h->status, "status");

    for (int i = 0; i < HODL_WAVE_BUCKETS; i++) {
        validates_custom(errors, h->buckets[i].label != NULL, "bucket.label",
                         "can't be blank");
        validates_custom(errors, h->buckets[i].html_label != NULL,
                         "bucket.html_label", "can't be blank");
        validates_custom(errors, h->buckets[i].color != NULL, "bucket.color",
                         "can't be blank");
        validates_custom(errors, h->buckets[i].value >= 0, "bucket.value",
                         "must be non-negative");
        validates_custom(errors, h->buckets[i].count >= 0, "bucket.count",
                         "must be non-negative");
        bucket_value += h->buckets[i].value;
        bucket_count += h->buckets[i].count;
    }

    validates_custom(errors, bucket_value == h->total_value,
                     "bucket.value", "sum must match total_value");
    validates_custom(errors, bucket_count == h->total_count,
                     "bucket.count", "sum must match total_count");
    validates_custom(errors, h->older_than_1y_value <= h->total_value,
                     "older_than_1y_value", "exceeds total_value");
    validates_custom(errors, h->older_than_1y_count <= h->total_count,
                     "older_than_1y_count", "exceeds total_count");

    return !ar_errors_any(errors);
}

bool hodl_wave_scan_current_utxos(sqlite3 *db, int64_t tip_height,
                                  struct hodl_wave_snapshot *out)
{
    sqlite3_stmt *stmt = NULL;

    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->tip_height = tip_height;
    memcpy(out->buckets, hodl_wave_bucket_defs(), sizeof(out->buckets));
    snprintf(out->source, sizeof(out->source), "current_transparent_utxo_set");
    snprintf(out->metric, sizeof(out->metric), "utxo_age_distribution");

    if (!db) {
        snprintf(out->status, sizeof(out->status), "sqlite database unavailable");
        return false;
    }
    if (tip_height < 1) {
        snprintf(out->status, sizeof(out->status), "UTXO index loading");
        return false;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT height, value FROM utxos WHERE value > 0",
            -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        snprintf(out->status, sizeof(out->status), "UTXO index unavailable");
        return false;
    }

    int rc;
    while ((rc = AR_STEP_ROW_READONLY(stmt)) == SQLITE_ROW) {
        int64_t height = sqlite3_column_int64(stmt, 0);
        int64_t value = sqlite3_column_int64(stmt, 1);
        /* Reject impossible UTXOs: pre-genesis, after-tip (future-dated rows
         * would compute a negative age and clamp into the <1d bucket,
         * distorting the young-coins reading), and zero-value (consensus
         * forbids it, but a stale row could exist). */
        if (height < 0 || height > tip_height || value <= 0) {
            out->skipped_rows++;
            continue;
        }

        int64_t age = hodl_wave_age_seconds(height, tip_height);
        int bucket = hodl_wave_bucket_index(age);
        out->buckets[bucket].value += value;
        out->buckets[bucket].count++;
        out->total_value += value;
        out->total_count++;
        if (age >= HODL_ONE_YEAR_SECONDS) {
            out->older_than_1y_value += value;
            out->older_than_1y_count++;
        }
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        snprintf(out->status, sizeof(out->status), "%s",
                 rc == SQLITE_INTERRUPT ? "UTXO index scan interrupted" :
                                          "UTXO index scan failed");
        return false;
    }

    snprintf(out->status, sizeof(out->status), "ok");
    struct ar_errors errors;
    if (!hodl_wave_validate(out, &errors)) {
        snprintf(out->status, sizeof(out->status), "%s",
                 ar_errors_full(&errors));
        return false;
    }
    return true;
}
