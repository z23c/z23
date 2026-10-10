/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the agreed-time selector (platform/modules/util/src/time_select.c).
 *
 * Coverage:
 *   (a) 3 agreeing sources + 1 far-off source: far-off excluded, agree=3,
 *       its id in falseticker_ids
 *   (b) 2-vs-2 split: no strict majority, ok=false
 *   (c) single source: ok, interval equals its own
 *   (d) touching intervals meeting at one point: closed, so they intersect
 *   (e) known answer on 5 hand-computed intervals (lo, hi, mid exact)
 *   (f) overflow refusal at the INT64 extremes, negative-radius refusal
 *   (g) determinism: permuting the input yields a byte-identical result */

#include "test/test_core.h"
#include "util/time_select.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TS_CHECK(name, expr) do { \
    printf("time_select: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static time_select_source_t ts_src(int64_t mid, int64_t radius, uint32_t id)
{
    time_select_source_t s;
    s.midpoint_us = mid;
    s.radius_us = radius;
    s.source_id = id;
    return s;
}

/* Five sources, ids 1..5. Hand-computed:
 *   1: [70,130]   2: [100,140]   3: [100,120]   4: [75,105]   5: [495,505]
 * Deepest overlap is [100,105], covered by 1,2,3,4 -> agree=4.
 * Source 5 does not reach [100,105] -> falseticker. mid = 100 + 5/2 = 102. */
static void ts_known_set(time_select_source_t out[5])
{
    out[0] = ts_src(100, 30, 1);
    out[1] = ts_src(120, 20, 2);
    out[2] = ts_src(110, 10, 3);
    out[3] = ts_src(90, 15, 4);
    out[4] = ts_src(500, 5, 5);
}

static int ts_test_agree_and_exclude(void)
{
    int failures = 0;
    time_select_source_t s[4] = {
        ts_src(1000, 100, 11), ts_src(1050, 100, 12),
        ts_src(1020, 100, 13), ts_src(9000, 10, 14),
    };
    time_select_result_t r;
    time_select_status_t st = time_select_intersect(s, 4, &r);
    TS_CHECK("3 agree + 1 far: status ok", st == TIME_SELECT_OK && r.ok);
    TS_CHECK("3 agree + 1 far: agree_count=3", r.agree_count == 3u);
    TS_CHECK("3 agree + 1 far: interval excludes far-off", r.lo_us == 950 && r.hi_us == 1100);
    TS_CHECK("3 agree + 1 far: falseticker is id 14",
             r.n_false == 1u && r.falseticker_ids[0] == 14u);
    return failures;
}

static int ts_test_split_no_majority(void)
{
    int failures = 0;
    time_select_source_t s[4] = {
        ts_src(0, 10, 1), ts_src(0, 10, 2),
        ts_src(100, 10, 3), ts_src(100, 10, 4),
    };
    time_select_result_t r;
    time_select_status_t st = time_select_intersect(s, 4, &r);
    TS_CHECK("2 vs 2: refused as no majority", st == TIME_SELECT_REFUSE_NO_MAJORITY);
    TS_CHECK("2 vs 2: ok=false", r.ok == false);
    return failures;
}

static int ts_test_single_source(void)
{
    int failures = 0;
    time_select_source_t s[1] = { ts_src(500, 25, 7) };
    time_select_result_t r;
    time_select_status_t st = time_select_intersect(s, 1, &r);
    TS_CHECK("single: ok", st == TIME_SELECT_OK && r.ok);
    TS_CHECK("single: interval equals its own",
             r.lo_us == 475 && r.hi_us == 525 && r.mid_us == 500);
    TS_CHECK("single: agree=1, no falsetickers", r.agree_count == 1u && r.n_false == 0u);
    return failures;
}

static int ts_test_touching_closed(void)
{
    int failures = 0;
    time_select_source_t s[2] = { ts_src(5, 5, 1), ts_src(15, 5, 2) };
    time_select_result_t r;
    time_select_status_t st = time_select_intersect(s, 2, &r);
    TS_CHECK("touching: ok", st == TIME_SELECT_OK && r.ok);
    TS_CHECK("touching: intersect at the single shared point",
             r.lo_us == 10 && r.hi_us == 10 && r.mid_us == 10);
    TS_CHECK("touching: both agree", r.agree_count == 2u && r.n_false == 0u);
    return failures;
}

static int ts_test_known_answer(void)
{
    int failures = 0;
    time_select_source_t s[5];
    ts_known_set(s);
    time_select_result_t r;
    time_select_status_t st = time_select_intersect(s, 5, &r);
    TS_CHECK("known answer: ok", st == TIME_SELECT_OK && r.ok);
    TS_CHECK("known answer: lo=100 hi=105 mid=102",
             r.lo_us == 100 && r.hi_us == 105 && r.mid_us == 102);
    TS_CHECK("known answer: agree=4", r.agree_count == 4u);
    TS_CHECK("known answer: falseticker is id 5",
             r.n_false == 1u && r.falseticker_ids[0] == 5u);
    return failures;
}

static int ts_test_overflow_and_refusals(void)
{
    int failures = 0;
    time_select_result_t r;
    time_select_source_t hi_edge[1] = { ts_src(INT64_MAX, 1, 1) };
    time_select_source_t lo_edge[1] = { ts_src(INT64_MIN, 1, 1) };
    time_select_source_t exact[1] = { ts_src(INT64_MAX, 0, 1) };
    time_select_source_t neg[1] = { ts_src(0, -1, 1) };

    TS_CHECK("overflow: mid=INT64_MAX radius=1 refused",
             time_select_intersect(hi_edge, 1, &r) == TIME_SELECT_REFUSE_OVERFLOW
             && r.ok == false);
    TS_CHECK("overflow: mid=INT64_MIN radius=1 refused",
             time_select_intersect(lo_edge, 1, &r) == TIME_SELECT_REFUSE_OVERFLOW
             && r.ok == false);
    TS_CHECK("extreme: mid=INT64_MAX radius=0 accepted",
             time_select_intersect(exact, 1, &r) == TIME_SELECT_OK
             && r.lo_us == INT64_MAX && r.hi_us == INT64_MAX);
    TS_CHECK("negative radius refused",
             time_select_intersect(neg, 1, &r) == TIME_SELECT_REFUSE_NEGATIVE_RADIUS
             && r.ok == false);
    TS_CHECK("empty refused", time_select_intersect(exact, 0, &r) == TIME_SELECT_REFUSE_EMPTY);
    TS_CHECK("null out refused", time_select_intersect(exact, 1, NULL) == TIME_SELECT_REFUSE_NULL);
    return failures;
}

static int ts_test_determinism(void)
{
    int failures = 0;
    /* Known set plus two falsetickers inserted out of id order, so the
     * falseticker list must come back sorted by id regardless of input. */
    time_select_source_t base[7];
    ts_known_set(base);
    base[5] = ts_src(9000, 3, 9);
    base[6] = ts_src(8000, 3, 7);

    static const size_t perm[3][7] = {
        { 0, 1, 2, 3, 4, 5, 6 },
        { 6, 5, 4, 3, 2, 1, 0 },
        { 3, 0, 6, 1, 5, 2, 4 },
    };
    time_select_result_t ref;
    time_select_status_t st0 = time_select_intersect(base, 7, &ref);
    TS_CHECK("determinism: reference run ok", st0 == TIME_SELECT_OK && ref.n_false == 3u);
    TS_CHECK("determinism: falsetickers sorted by id",
             ref.falseticker_ids[0] == 5u && ref.falseticker_ids[1] == 7u
             && ref.falseticker_ids[2] == 9u);

    for (size_t p = 0; p < 3; p++) {
        time_select_source_t shuffled[7];
        for (size_t i = 0; i < 7; i++) {
            shuffled[i] = base[perm[p][i]];
        }
        time_select_result_t r;
        time_select_status_t st = time_select_intersect(shuffled, 7, &r);
        TS_CHECK("determinism: permutation status matches", st == st0);
        TS_CHECK("determinism: permutation output byte-identical",
                 memcmp(&r, &ref, sizeof r) == 0);
    }
    return failures;
}

int test_time_select(void);
int test_time_select(void)
{
    printf("\n=== time_select tests ===\n");
    int failures = 0;
    failures += ts_test_agree_and_exclude();
    failures += ts_test_split_no_majority();
    failures += ts_test_single_source();
    failures += ts_test_touching_closed();
    failures += ts_test_known_answer();
    failures += ts_test_overflow_and_refusals();
    failures += ts_test_determinism();
    return failures;
}
