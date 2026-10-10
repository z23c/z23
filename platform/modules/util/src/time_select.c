/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * time_select — implementation. See util/time_select.h for the contract.
 *
 * Marzullo sweep: each source contributes a start and an end endpoint. The
 * endpoints are sorted by value, with a start ordered before an end at the
 * same value so that touching closed intervals overlap at their shared
 * point. The first maximal run of open intervals is the agreed interval.
 * Every sort key is a total order over (value, kind), so the sweep is a
 * pure function of the source multiset, not of the input order. */

#include "util/time_select.h"

#include <string.h>

#define TS_ENDPOINTS_MAX (2u * TIME_SELECT_MAX_SOURCES)

typedef struct {
    int64_t value_us;
    bool is_end;
} ts_endpoint_t;

typedef struct {
    int64_t lo_us;
    int64_t hi_us;
} ts_bounds_t;

typedef struct {
    uint32_t count;
    uint32_t best;
    int64_t lo_us;
    int64_t hi_us;
    bool open;
} ts_sweep_t;

/* ── Checked interval construction ───────────────────────────────────── */

/* Refuse a negative radius or any mid±radius that leaves the int64 range.
 * With radius >= 0, INT64_MIN + radius and INT64_MAX - radius cannot
 * themselves overflow, so the comparisons below are exact. */
static time_select_status_t ts_bounds_of(const time_select_source_t *s, ts_bounds_t *b)
{
    if (s->radius_us < 0) {
        return TIME_SELECT_REFUSE_NEGATIVE_RADIUS;
    }
    if (s->midpoint_us < INT64_MIN + s->radius_us) {
        return TIME_SELECT_REFUSE_OVERFLOW;
    }
    if (s->midpoint_us > INT64_MAX - s->radius_us) {
        return TIME_SELECT_REFUSE_OVERFLOW;
    }
    b->lo_us = s->midpoint_us - s->radius_us;
    b->hi_us = s->midpoint_us + s->radius_us;
    return TIME_SELECT_OK;
}

static time_select_status_t ts_build_endpoints(const time_select_source_t *src,
                                               size_t n,
                                               ts_endpoint_t *ep,
                                               ts_bounds_t *bd)
{
    for (size_t i = 0; i < n; i++) {
        time_select_status_t st = ts_bounds_of(&src[i], &bd[i]);
        if (st != TIME_SELECT_OK) {
            return st;
        }
        ep[2u * i].value_us = bd[i].lo_us;
        ep[2u * i].is_end = false;
        ep[2u * i + 1u].value_us = bd[i].hi_us;
        ep[2u * i + 1u].is_end = true;
    }
    return TIME_SELECT_OK;
}

/* ── Deterministic sorts (insertion sort; at most 128 endpoints) ─────── */

static bool ts_endpoint_before(const ts_endpoint_t *a, const ts_endpoint_t *b)
{
    if (a->value_us != b->value_us) {
        return a->value_us < b->value_us;
    }
    /* Tie-break: a start sorts before an end at the same value. */
    return !a->is_end && b->is_end;
}

static void ts_sort_endpoints(ts_endpoint_t *ep, size_t count)
{
    for (size_t i = 1; i < count; i++) {
        ts_endpoint_t key = ep[i];
        size_t j = i;
        while (j > 0 && ts_endpoint_before(&key, &ep[j - 1])) {
            ep[j] = ep[j - 1];
            j--;
        }
        ep[j] = key;
    }
}

static void ts_sort_ids(uint32_t *ids, uint32_t count)
{
    for (uint32_t i = 1; i < count; i++) {
        uint32_t key = ids[i];
        uint32_t j = i;
        while (j > 0 && key < ids[j - 1]) {
            ids[j] = ids[j - 1];
            j--;
        }
        ids[j] = key;
    }
}

/* ── Marzullo sweep ──────────────────────────────────────────────────── */

/* Track the first maximal run. lo is set when the count first reaches a new
 * best; hi is set at the first end that drops the count from that best.
 * Later runs with an equal count do not replace the first. */
static void ts_sweep_step(ts_sweep_t *sw, const ts_endpoint_t *e)
{
    if (!e->is_end) {
        sw->count++;
        if (sw->count > sw->best) {
            sw->best = sw->count;
            sw->lo_us = e->value_us;
            sw->open = true;
        }
        return;
    }
    if (sw->open && sw->count == sw->best) {
        sw->hi_us = e->value_us;
        sw->open = false;
    }
    sw->count--;
}

static void ts_sweep(const ts_endpoint_t *ep, size_t count, ts_sweep_t *sw)
{
    memset(sw, 0, sizeof *sw);
    for (size_t i = 0; i < count; i++) {
        ts_sweep_step(sw, &ep[i]);
    }
}

/* ── Result assembly ─────────────────────────────────────────────────── */

/* Midpoint without overflow: the unsigned span hi - lo is exact, and
 * lo + span/2 stays within [lo, hi]. */
static int64_t ts_midpoint(int64_t lo_us, int64_t hi_us)
{
    uint64_t span = (uint64_t)hi_us - (uint64_t)lo_us;
    return lo_us + (int64_t)(span / 2u);
}

static void ts_collect_falsetickers(const time_select_source_t *src,
                                    const ts_bounds_t *bd,
                                    size_t n,
                                    int64_t lo_us,
                                    int64_t hi_us,
                                    time_select_result_t *out)
{
    for (size_t i = 0; i < n; i++) {
        /* Closed intervals: touching at one point still counts as overlap. */
        if (bd[i].hi_us < lo_us || bd[i].lo_us > hi_us) {
            out->falseticker_ids[out->n_false] = src[i].source_id;
            out->n_false++;
        }
    }
    ts_sort_ids(out->falseticker_ids, out->n_false);
}

static time_select_status_t ts_majority_check(uint32_t best, size_t n)
{
    if (2u * (size_t)best <= n) {
        return TIME_SELECT_REFUSE_NO_MAJORITY;
    }
    return TIME_SELECT_OK;
}

time_select_status_t time_select_intersect(const time_select_source_t *sources,
                                           size_t n,
                                           time_select_result_t *out)
{
    if (out == NULL) {
        return TIME_SELECT_REFUSE_NULL;
    }
    memset(out, 0, sizeof *out);
    if (sources == NULL) {
        return TIME_SELECT_REFUSE_NULL;
    }
    if (n == 0) {
        return TIME_SELECT_REFUSE_EMPTY;
    }
    if (n > TIME_SELECT_MAX_SOURCES) {
        return TIME_SELECT_REFUSE_TOO_MANY;
    }

    ts_endpoint_t ep[TS_ENDPOINTS_MAX];
    ts_bounds_t bd[TIME_SELECT_MAX_SOURCES];
    time_select_status_t st = ts_build_endpoints(sources, n, ep, bd);
    if (st != TIME_SELECT_OK) {
        return st;
    }

    ts_sort_endpoints(ep, 2u * n);
    ts_sweep_t sw;
    ts_sweep(ep, 2u * n, &sw);

    st = ts_majority_check(sw.best, n);
    if (st != TIME_SELECT_OK) {
        return st;
    }

    out->ok = true;
    out->lo_us = sw.lo_us;
    out->hi_us = sw.hi_us;
    out->mid_us = ts_midpoint(sw.lo_us, sw.hi_us);
    out->agree_count = sw.best;
    ts_collect_falsetickers(sources, bd, n, sw.lo_us, sw.hi_us, out);
    return TIME_SELECT_OK;
}
