/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet goal D6, delivery-to-verdict time. Each landed row of the
 *          landing outcomes ledger is one change: `ts` is its submit time and
 *          `landed_at` (epoch seconds) its landing time. The bar reads the
 *          95th percentile of those durations over the last 7 days.
 *
 * Rows that cannot give a duration (no landed_at, unreadable ts, landed
 * before submit) are skipped and counted in the evidence. Rows outside the
 * window are not usable and are not counted as skipped. */

#include "native_fleet_goals_feedback.h"

#include "native_fleet_objectives.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/compare.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FBK_WEEK_S (7 * 86400)
#define FBK_ROWS_MAX 4096
#define FBK_BAR_S 180
#define FBK_NEXT_MEASURED                                                    \
    "stamp the focused-test verdict time per delivery; the warm-lane clause " \
    "needs a rebuild record"
#define FBK_NEXT_UNMEASURED                                                  \
    "land changes through `dev land` so landed_at is recorded; the bar reads " \
    "the focused-test verdict time"

struct fbk_rows {
    int64_t now;
    int64_t durations[FBK_ROWS_MAX];
    size_t count;
    size_t overflow;
    size_t skipped;
};

static struct zcl_goal_result fbk_unmeasured(const char *fmt, ...)
{
    char reason[256];
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(reason, sizeof(reason), fmt, args);
    va_end(args);
    return zcl_goal_make(ZCL_GOAL_UNMEASURED, FBK_NEXT_UNMEASURED, "%s", reason);
}

static int64_t fbk_now(const struct zcl_goals_options *o)
{
    return o && o->now_unix > 0 ? o->now_unix
                                : (int64_t)platform_time_wall_time_t();
}

/* Takes one landed row: validity first, then the 7-day window. */
static void fbk_row(const struct json_value *row, void *user)
{
    struct fbk_rows *r = user;
    const struct json_value *landed_at = json_get(row, "landed_at");
    int64_t submitted = 0, landed, duration;
    if (strcmp(json_get_str(json_get(row, "state")), "landed") != 0)
        return;
    if (!landed_at || landed_at->type != JSON_INT) {
        r->skipped++;
        return;
    }
    landed = json_get_int(landed_at);
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")),
                                      &submitted)) {
        r->skipped++;
        return;
    }
    duration = landed - submitted;
    if (duration < 0) {
        r->skipped++;
        return;
    }
    if (landed > r->now || landed < r->now - FBK_WEEK_S)
        return;
    if (r->count >= FBK_ROWS_MAX) {
        r->overflow++;
        return;
    }
    r->durations[r->count++] = duration;
}

/* Nearest-rank percentile of an ascending array; n must be at least 1. */
static int64_t fbk_nearest_rank(const int64_t *sorted, size_t n, size_t pct)
{
    size_t rank = (n * pct + 99) / 100;
    return sorted[rank > 0 ? rank - 1 : 0];
}

static int64_t fbk_median(const int64_t *sorted, size_t n)
{
    if (n % 2)
        return sorted[n / 2];
    return (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
}

static enum zcl_goal_grade fbk_grade(int64_t p95_s)
{
    return p95_s <= FBK_BAR_S ? ZCL_GOAL_PARTIAL : ZCL_GOAL_FAIL;
}

static struct zcl_goal_result fbk_measured(struct fbk_rows *r)
{
    char skip[160] = "";
    int64_t median, p95;
    qsort(r->durations, r->count, sizeof(r->durations[0]), zcl_cmp_i64);
    median = fbk_median(r->durations, r->count);
    p95 = fbk_nearest_rank(r->durations, r->count, 95);
    if (r->skipped > 0)
        (void)snprintf(skip, sizeof(skip),
                       "; %zu row(s) skipped (no landed_at, unreadable ts or "
                       "landed before submit)", r->skipped);
    return zcl_goal_make(fbk_grade(p95), FBK_NEXT_MEASURED,
                         "%zu landed row(s) in the last 7 days, median %lld s, "
                         "p95 %lld s, bar %d s%s", r->count, (long long)median,
                         (long long)p95, FBK_BAR_S, skip);
}

struct zcl_goal_result zcl_goals_feedback_d6(
    const struct zcl_goals_options *options)
{
    struct zcl_objectives_options oo;
    struct fbk_rows r;
    char path[512], reason[256] = "";
    const char *use = NULL;
    memset(&oo, 0, sizeof(oo));
    memset(&r, 0, sizeof(r));
    r.now = fbk_now(options);
    oo.outcomes = options ? options->outcomes : NULL;
    if (!zcl_objectives_outcomes_path(&oo, path, sizeof(path), &use))
        return fbk_unmeasured("state root unavailable");
    if (!zcl_objectives_ledger_walk(use, fbk_row, &r, reason, sizeof(reason)))
        return fbk_unmeasured("%s", reason);
    if (r.overflow > 0)
        return fbk_unmeasured("%zu landed rows in the last 7 days exceed the "
                              "%d the reader holds; the p95 is not computed",
                              r.count + r.overflow, FBK_ROWS_MAX);
    if (r.count == 0)
        return fbk_unmeasured("0 landed row(s) in the last 7 days in %s, "
                              "%zu row(s) skipped", use, r.skipped);
    return fbk_measured(&r);
}
