/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_history — see storage/body_history.h for the design and, more
 * importantly, for why every failure path in this file lands on
 * BODY_HISTORY_UNKNOWN rather than on a zero missing count.
 *
 * one-result-type-ok:body-history-predicates — the bool returns here are
 * caller-consumed ANSWERS paired with an out-parameter that carries the
 * fail-closed UNKNOWN verdict, not error signals that need a code+message.
 * A false return always leaves *out at the pessimistic default, so a caller
 * that ignores the bool still cannot publish a cheerier state than the
 * truth. The fallible durable paths (save/load) route through LOG_FAIL. */

#include "storage/body_history.h"
#include "storage/progress_store.h"

#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/sync.h"

#include <string.h>
#include <stdlib.h>

const char *body_history_status_name(enum body_history_status s)
{
    switch (s) {
    case BODY_HISTORY_INCOMPLETE: return "incomplete";
    case BODY_HISTORY_COMPLETE:   return "complete";
    case BODY_HISTORY_UNKNOWN:    break;
    }
    /* Any value that is not positively one of the two established states —
     * including a corrupted enum — reads as "could not determine". */
    return "unknown";
}

/* Zero the verdict into the pessimistic default. Every early return in this
 * file goes through here first, so there is no path that leaves a caller's
 * verdict looking like a clean bill of health. */
static void bh_verdict_reset(struct body_history_verdict *v)
{
    if (!v)
        return;
    memset(v, 0, sizeof(*v));
    v->status = BODY_HISTORY_UNKNOWN;
    v->window_lo = -1;
    v->window_hi = -1;
    v->lowest_missing = -1;
    v->lowest_unmeasured = -1;
}

bool body_history_status_is_proven(enum body_history_status s)
{
    /* The ONE place in the tree that compares this enum against COMPLETE.
     * Every at-tip gate reaches the answer through here, so no site can
     * drift into `!= INCOMPLETE` and start accepting UNKNOWN. */
    return s == BODY_HISTORY_COMPLETE;
}

bool body_history_verdict_is_proven(const struct body_history_verdict *v)
{
    return v && body_history_status_is_proven(v->status);
}

bool body_history_evaluate(const struct body_coverage_map *held,
                           const struct body_coverage_map *measured,
                           int64_t lo, int64_t hi,
                           struct body_history_verdict *out)
{
    if (!out)
        return false;
    bh_verdict_reset(out);

    if (!held || !measured)
        return false;
    if (lo < 0 || lo > hi)
        return false;

    out->window_lo = lo;
    out->window_hi = hi;
    out->window_heights = hi - lo + 1;

    /* "Definitively probed" is `measured`, and ONLY `measured`.
     *
     * This used to union `held` in as well, on the premise that "holding a
     * body is itself proof somebody looked". That premise holds for a `held`
     * map built by probes during THIS boot. It is false for the map the node
     * actually has: body_coverage_load() restores `held` from progress.kv at
     * boot, so a datadir whose progress.kv claims coverage the block index
     * can no longer corroborate — a partial backup, a truncated or lost
     * block_index.bin, a prune that removed bodies without updating coverage
     * — published COMPLETE after zero successful probes. That is verbatim
     * the fail-open defect this module exists to remove, one level up:
     * "an unreadable block index publishes as 'no hole'".
     *
     * So probe evidence has exactly one writer (body_history_census_fold)
     * and exactly one lifetime (this boot; body_history_load restores the
     * resume cursor, never the evidence). `held` is now read for one thing
     * only: whether a height the census DID probe has its body. A height
     * that nobody probed this boot is unmeasured no matter what `held` says
     * about it.
     *
     * The walk below is a single linear merge of the two maps' range arrays.
     * It allocates nothing — the scratch union it replaces was a third copy
     * of the same ledger, built and thrown away on every census pass. */
    int64_t probed_in_w = 0;
    int64_t held_in_w = 0;
    int64_t cursor = lo;      /* first window height not yet accounted for */
    size_t h_idx = 0;         /* monotone cursor into held->ranges */

    for (size_t i = 0; i < measured->count; i++) {
        int64_t rlo = measured->ranges[i].lo;
        int64_t rhi = measured->ranges[i].hi;
        if (rhi < lo)
            continue;
        if (rlo > hi)
            break;            /* sorted: nothing further can overlap */
        if (rlo < lo) rlo = lo;
        if (rhi > hi) rhi = hi;

        /* Everything between the previous measured range and this one was
         * never probed. */
        if (rlo > cursor && out->lowest_unmeasured < 0)
            out->lowest_unmeasured = cursor;

        probed_in_w += rhi - rlo + 1;

        /* Intersect [rlo, rhi] with `held`. A gap here is a height the
         * census looked at and found no body for — a KNOWN missing body,
         * as opposed to a height nobody looked at. */
        while (h_idx < held->count && held->ranges[h_idx].hi < rlo)
            h_idx++;
        int64_t hcur = rlo;
        for (size_t j = h_idx; j < held->count; j++) {
            int64_t hlo = held->ranges[j].lo;
            int64_t hhi = held->ranges[j].hi;
            if (hlo > rhi)
                break;
            if (hhi < hcur)
                continue;
            if (hlo > hcur && out->lowest_missing < 0)
                out->lowest_missing = hcur;
            int64_t a = hlo > rlo ? hlo : rlo;
            int64_t b = hhi < rhi ? hhi : rhi;
            if (b >= a)
                held_in_w += b - a + 1;
            if (hhi + 1 > hcur)
                hcur = hhi + 1;
        }
        if (hcur <= rhi && out->lowest_missing < 0)
            out->lowest_missing = hcur;

        if (rhi + 1 > cursor)
            cursor = rhi + 1;
    }
    if (cursor <= hi && out->lowest_unmeasured < 0)
        out->lowest_unmeasured = cursor;

    out->held_count = held_in_w;
    out->missing_count = probed_in_w - held_in_w;
    out->unmeasured_count = out->window_heights - probed_in_w;

    /* held_in_w counts only heights inside probed ranges, and probed ranges
     * are clipped to the window, so both counts are non-negative by
     * construction. A negative here would mean the range algebra broke;
     * refuse to publish a verdict over it. */
    if (out->missing_count < 0 || out->unmeasured_count < 0) {
        LOG_WARN("body_history",
                 "evaluate: inconsistent counts window=[%lld..%lld] "
                 "held=%lld probed=%lld — reporting unknown",
                 (long long)lo, (long long)hi,
                 (long long)held_in_w, (long long)probed_in_w);
        bh_verdict_reset(out);
        return false;
    }

    /* Order matters and is deliberate:
     *   a positively-found hole is the strongest, most actionable fact;
     *   otherwise any unprobed height keeps us at UNKNOWN;
     *   COMPLETE requires BOTH "probed everything" and "held everything".
     * The verdict carries both counts, so INCOMPLETE never hides a
     * simultaneous unmeasured remainder. */
    if (out->missing_count > 0)
        out->status = BODY_HISTORY_INCOMPLETE;
    else if (out->unmeasured_count > 0)
        out->status = BODY_HISTORY_UNKNOWN;
    else
        out->status = BODY_HISTORY_COMPLETE;

    return true;
}

/* ── Bounded, resumable census ──────────────────────────────────── */

void body_history_census_init(struct body_history_census *c)
{
    if (!c)
        return;
    memset(c, 0, sizeof(*c));
    c->cursor = -1;
    c->cursor_valid = false;
    c->window_lo = -1;
    c->window_hi = -1;
    c->last_pass_lo = -1;
    c->last_pass_hi = -1;
}

bool body_history_census_plan(struct body_history_census *c,
                              int64_t window_lo, int64_t window_hi,
                              int64_t budget,
                              int64_t *out_lo, int64_t *out_hi)
{
    if (!c || !out_lo || !out_hi)
        return false;
    if (window_lo < 0 || window_lo > window_hi || budget <= 0)
        return false;

    /* Re-anchor ONLY when there is no cursor to keep, or when the one we
     * have no longer lies inside the window (a reorg that shortened the
     * chain, or a floor that moved up past it).
     *
     * A window whose TOP simply grew must not restart the walk. The tip
     * advances every ~75 s; a full sweep of a 3.2M-height chain needs ~65
     * minutes. Re-anchoring on tip advance therefore pins the cursor to the
     * top band forever: measured at 4096 heights per 5 s pass, the census
     * gets ~61,700 heights below the tip and then jumps back to the top,
     * having completed zero sweeps, so the history this module exists to
     * measure is never looked at. Heights added at the top while the sweep
     * is descending are picked up when it wraps, and stay counted as
     * unmeasured until then — which is the fail-closed answer, not a
     * reason to abandon the walk.
     *
     * Keeping a cursor that is merely inside the window is also what makes
     * body_history_load()'s restored cursor mean anything: window_lo /
     * window_hi are not persisted, so a "restart resumes where it stopped"
     * that compared them would throw the restored cursor away on the first
     * pass after every boot. */
    if (!c->cursor_valid) {
        c->cursor = window_hi;
        c->cursor_valid = true;
    }
    c->window_lo = window_lo;
    c->window_hi = window_hi;
    if (c->cursor < window_lo || c->cursor > window_hi)
        c->cursor = window_hi;

    int64_t hi = c->cursor;
    int64_t lo = hi - budget + 1;
    if (lo < window_lo)
        lo = window_lo;

    *out_lo = lo;
    *out_hi = hi;
    return true;
}

void body_history_census_advance(struct body_history_census *c,
                                 int64_t lo, int64_t hi)
{
    if (!c || lo < 0 || lo > hi)
        return;
    c->passes++;
    c->last_pass_lo = lo;
    c->last_pass_hi = hi;
    c->cursor = lo - 1;
    if (c->cursor < c->window_lo) {
        c->sweeps_completed++;
        c->cursor = c->window_hi;
    }
    c->cursor_valid = true;
}

size_t body_history_census_probe_window(int64_t lo, int64_t hi,
                                        body_history_probe_fn probe,
                                        void *ctx,
                                        uint8_t *classes,
                                        struct uint256 *hashes,
                                        size_t cap)
{
    if (!classes || !hashes || cap == 0)
        return 0;

    /* Pre-fill INDETERMINATE (and zero the hashes) BEFORE anything can go
     * wrong. Every slot the probe does not positively answer therefore
     * stays unmeasured, which is the whole point of this module. */
    memset(classes, BODY_HISTORY_PROBE_INDETERMINATE, cap);
    memset(hashes, 0, cap * sizeof(*hashes));

    if (!probe || lo < 0 || lo > hi)
        return 0;

    int64_t span = hi - lo + 1;
    if (span > (int64_t)cap)
        span = (int64_t)cap;

    for (int64_t i = 0; i < span; i++) {
        enum body_history_probe r = probe(lo + i, &hashes[i], ctx);
        if (r == BODY_HISTORY_PROBE_HAVE || r == BODY_HISTORY_PROBE_MISSING)
            classes[i] = (uint8_t)r;
        /* Anything else — including a probe that returns a value outside
         * the enum — stays INDETERMINATE. */
    }
    return (size_t)span;
}

bool body_history_census_fold(struct body_history_census *c,
                              struct body_coverage_map *held,
                              struct body_coverage_map *measured,
                              int64_t lo,
                              const uint8_t *classes, size_t n,
                              struct body_history_pass_result *out)
{
    struct body_history_pass_result res;
    memset(&res, 0, sizeof(res));
    res.lo = -1;
    res.hi = -1;
    if (out)
        *out = res;

    if (!c || !held || !measured || !classes)
        LOG_FAIL("body_history", "fold: null census, map or classes");
    if (lo < 0 || n == 0)
        return true; /* nothing to fold; measured stays as it was */

    res.lo = lo;
    res.hi = lo + (int64_t)n - 1;

    /* Coalesce equal-classification runs into range inserts so a contiguous
     * chain costs a couple of inserts per pass, not one per height. */
    size_t i = 0;
    while (i < n) {
        uint8_t cls = classes[i];
        size_t j = i + 1;
        while (j < n && classes[j] == cls)
            j++;
        int64_t rlo = lo + (int64_t)i;
        int64_t rhi = lo + (int64_t)j - 1;
        int64_t run = rhi - rlo + 1;

        switch (cls) {
        case BODY_HISTORY_PROBE_HAVE:
            if (!body_coverage_insert(held, rlo, rhi) ||
                !body_coverage_insert(measured, rlo, rhi))
                LOG_FAIL("body_history",
                         "fold: insert have [%lld..%lld] failed",
                         (long long)rlo, (long long)rhi);
            res.have += run;
            res.examined += run;
            break;
        case BODY_HISTORY_PROBE_MISSING:
            /* Measured — we looked and it was definitively absent. The body
             * is NOT inserted into `held`; if a stale entry claims it is
             * held, remove it so the two maps stop disagreeing.
             *
             * REMOVE FIRST, then insert. Either call can fail on allocation
             * (a remove splits a range, an insert grows the array) and this
             * function returns without unwinding. Doing it the other way
             * round leaves a half-applied fold in which the height is in
             * BOTH maps, i.e. "probed and held" — the census would report a
             * body it had just proved absent as present. This order fails to
             * "removed from held, not yet in measured", which reads as
             * unmeasured, which holds the verdict at UNKNOWN. */
            if (!body_coverage_remove(held, rlo, rhi) ||
                !body_coverage_insert(measured, rlo, rhi))
                LOG_FAIL("body_history",
                         "fold: record missing [%lld..%lld] failed",
                         (long long)rlo, (long long)rhi);
            res.missing += run;
            res.examined += run;
            break;
        default:
            /* INDETERMINATE: enters NEITHER map, and is REMOVED from
             * `measured` if an earlier pass put it there. This is the branch
             * the previous attempt at this fix got wrong — an unreadable
             * index must leave the height unmeasured, never silently
             * "covered" and never silently "clean".
             *
             * The removal is what makes the verdict expire. Without it a
             * height measured once stayed measured for the life of the
             * process, so a node that completed one good sweep and THEN lost
             * its block index went on publishing "complete, proven" while
             * every subsequent read failed — measured at 24,576 consecutive
             * failed reads with the verdict unmoved. "I checked this once,
             * an hour ago, and cannot check it now" is not the same claim as
             * "I have it", and this module exists to keep those apart.
             *
             * Only `measured` is demoted, never `held`. `held` is the shared
             * record of which bodies are on disk and drives what gets
             * downloaded; an unreadable index entry is not evidence the body
             * is gone. Clearing `measured` alone moves the height to
             * unmeasured, which holds the verdict at UNKNOWN — the honest
             * answer — without inventing a hole for the fetcher to chase. */
            if (!body_coverage_remove(measured, rlo, rhi))
                LOG_FAIL("body_history",
                         "fold: demote unreadable [%lld..%lld] failed",
                         (long long)rlo, (long long)rhi);
            res.indeterminate += run;
            break;
        }
        i = j;
    }

    c->heights_examined += (uint64_t)res.examined;
    c->heights_have += (uint64_t)res.have;
    c->heights_missing += (uint64_t)res.missing;
    c->heights_indeterminate += (uint64_t)res.indeterminate;

    if (out)
        *out = res;
    return true;
}

size_t body_history_census_collect_missing(int64_t lo,
                                           const uint8_t *classes,
                                           const struct uint256 *hashes,
                                           size_t n,
                                           struct uint256 *out_hashes,
                                           int32_t *out_heights,
                                           size_t cap)
{
    if (!classes || !hashes || !out_hashes || !out_heights || cap == 0)
        return 0;
    if (lo < 0)
        return 0;

    size_t got = 0;
    for (size_t i = 0; i < n && got < cap; i++) {
        if (classes[i] != BODY_HISTORY_PROBE_MISSING)
            continue;
        int64_t h = lo + (int64_t)i;
        if (h < 0 || h > INT32_MAX)
            continue;
        out_hashes[got] = hashes[i];
        out_heights[got] = (int32_t)h;
        got++;
    }
    return got;
}

/* ── Process-wide singleton ─────────────────────────────────────── */

static struct body_history_census  g_bh_census;
static struct body_coverage_map    g_bh_measured;
static struct body_history_verdict g_bh_verdict;
static bool                        g_bh_verdict_published = false;
static zcl_mutex_t                 g_bh_lock;
static bool                        g_bh_inited = false;

static void bh_global_init_once(void)
{
    if (g_bh_inited)
        return;
    zcl_mutex_init(&g_bh_lock);
    body_history_census_init(&g_bh_census);
    body_coverage_init(&g_bh_measured);
    bh_verdict_reset(&g_bh_verdict);
    g_bh_verdict_published = false;
    g_bh_inited = true;
}

void body_history_global_lock(void)
{
    bh_global_init_once();
    zcl_mutex_lock(&g_bh_lock);
    /* Ordered acquire: body_history then body_coverage. The census driver
     * needs both (the `held` map is body_coverage's), and this is the only
     * place the pair is taken, so the order cannot invert. */
    body_coverage_global_lock();
}

void body_history_global_unlock(void)
{
    if (!g_bh_inited)
        return;
    body_coverage_global_unlock();
    zcl_mutex_unlock(&g_bh_lock);
}

struct body_history_census *body_history_global_census(void)
{
    bh_global_init_once();
    return &g_bh_census;
}

struct body_coverage_map *body_history_global_measured(void)
{
    bh_global_init_once();
    return &g_bh_measured;
}

void body_history_publish(const struct body_history_verdict *v)
{
    bh_global_init_once();
    zcl_mutex_lock(&g_bh_lock);
    if (v) {
        g_bh_verdict = *v;
    } else {
        /* A caller with nothing to publish publishes ignorance, not the
         * last good news. */
        bh_verdict_reset(&g_bh_verdict);
    }
    g_bh_verdict_published = true;
    zcl_mutex_unlock(&g_bh_lock);
}

bool body_history_get_verdict(struct body_history_verdict *out)
{
    if (!out)
        return false;
    bh_verdict_reset(out);
    bh_global_init_once();
    zcl_mutex_lock(&g_bh_lock);
    bool published = g_bh_verdict_published;
    if (published)
        *out = g_bh_verdict;
    zcl_mutex_unlock(&g_bh_lock);
    return published;
}

bool body_history_is_proven(void)
{
    struct body_history_verdict v;
    if (!body_history_get_verdict(&v))
        return false;
    return body_history_verdict_is_proven(&v);
}

bool body_history_window_fully_measured(void)
{
    struct body_history_verdict v;
    if (!body_history_get_verdict(&v))
        return false;   /* nothing published == nothing established */
    /* A window of zero heights has not been measured, it has been skipped. */
    return v.window_heights > 0 && v.unmeasured_count == 0;
}

enum body_history_status body_history_status_now(void)
{
    struct body_history_verdict v;
    /* get_verdict resets *out to UNKNOWN before it does anything else, so an
     * unpublished verdict returns UNKNOWN without a separate branch. */
    (void)body_history_get_verdict(&v);
    return v.status;
}

void body_history_reset(void)
{
    bh_global_init_once();
    zcl_mutex_lock(&g_bh_lock);
    body_history_census_init(&g_bh_census);
    body_coverage_reset(&g_bh_measured);
    bh_verdict_reset(&g_bh_verdict);
    g_bh_verdict_published = false;
    zcl_mutex_unlock(&g_bh_lock);
}

#ifdef ZCL_TESTING
bool body_history_test_publish_proven(int64_t height)
{
    struct body_history_verdict proven;
    bh_verdict_reset(&proven);
    if (height <= 0)
        return false;
    proven.status = BODY_HISTORY_COMPLETE;
    proven.window_lo = 1;
    proven.window_hi = height;
    proven.window_heights = height;
    proven.held_count = height;
    proven.missing_count = 0;
    proven.lowest_missing = -1;
    proven.unmeasured_count = 0;
    proven.lowest_unmeasured = -1;
    body_history_reset();
    body_history_publish(&proven);
    return body_history_is_proven();
}
#endif

/* ── Durable resume ─────────────────────────────────────────────── */

/* Only ONE thing survives a restart: the descending resume cursor, which is
 * a work pointer, not evidence. Neither the verdict nor the `measured` map
 * is persisted.
 *
 * The measured map used to be. That made the boot-time promise below true
 * of the verdict FLAG only: the flag started UNKNOWN, but the evidence it
 * would be recomputed from came straight back off disk, so the very first
 * pass could republish COMPLETE having probed 4096 heights out of 3.2M. A
 * restored cursor cannot do that — wherever it points, the census still has
 * to walk the whole window before unmeasured_count reaches zero.
 *
 * (A datadir written by an older build may still hold an orphaned
 * `body_history_measured` blob in progress.kv. Nothing reads it.) */
bool body_history_save(struct sqlite3 *db)
{
    if (!db)
        LOG_FAIL("body_history", "save: null db");
    bh_global_init_once();

    zcl_mutex_lock(&g_bh_lock);
    int64_t cursor = g_bh_census.cursor_valid ? g_bh_census.cursor : -1;
    zcl_mutex_unlock(&g_bh_lock);

    if (!progress_meta_set(db, BODY_HISTORY_CURSOR_META_KEY,
                           &cursor, sizeof(cursor)))
        LOG_FAIL("body_history", "save: cursor persist failed");
    return true;
}

bool body_history_load(struct sqlite3 *db)
{
    if (!db)
        LOG_FAIL("body_history", "load: null db");
    bh_global_init_once();

    zcl_mutex_lock(&g_bh_lock);
    /* Probe evidence does not survive a restart. Clearing it here (rather
     * than trusting the caller to have reset first) is what makes "a
     * restarted node has established nothing until it runs a pass" a
     * property of the code and not of a comment. */
    body_coverage_reset(&g_bh_measured);

    int64_t cursor = -1;
    size_t got = 0;
    bool found = false;
    if (progress_meta_get(db, BODY_HISTORY_CURSOR_META_KEY,
                          &cursor, sizeof(cursor), &got, &found) &&
        found && got == sizeof(cursor) && cursor >= 0) {
        g_bh_census.cursor = cursor;
        g_bh_census.cursor_valid = true;
    }
    /* The verdict itself is NEVER restored from disk. A restarted node has
     * not established anything until it runs a pass, and a persisted
     * "complete" would be exactly the borrowed claim this module exists to
     * prevent. */
    bh_verdict_reset(&g_bh_verdict);
    g_bh_verdict_published = false;
    zcl_mutex_unlock(&g_bh_lock);
    return true;
}

/* ── Diagnostics ────────────────────────────────────────────────── */

bool body_history_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    bh_global_init_once();
    zcl_mutex_lock(&g_bh_lock);
    struct body_history_verdict v = g_bh_verdict;
    bool published = g_bh_verdict_published;
    struct body_history_census c = g_bh_census;
    int64_t measured_ranges = (int64_t)body_coverage_range_count(&g_bh_measured);
    int64_t measured_total = body_coverage_total_covered(&g_bh_measured);
    zcl_mutex_unlock(&g_bh_lock);

    /* `status` and `proven` are the two fields an operator or agent reads.
     * They are deliberately BOTH published: "unknown" is a status, not a
     * missing field, and proven=false covers unknown and incomplete alike. */
    json_push_kv_str(out, "status", body_history_status_name(v.status));
    json_push_kv_bool(out, "proven",
                      published && v.status == BODY_HISTORY_COMPLETE);
    json_push_kv_bool(out, "verdict_published", published);
    json_push_kv_str(out, "blocker_id",
                     (published && v.status == BODY_HISTORY_COMPLETE)
                         ? "" : BODY_HISTORY_UNPROVEN_BLOCKER);

    json_push_kv_int(out, "window_lo", v.window_lo);
    json_push_kv_int(out, "window_hi", v.window_hi);
    json_push_kv_int(out, "window_heights", v.window_heights);
    json_push_kv_int(out, "held_count", v.held_count);
    json_push_kv_int(out, "missing_count", v.missing_count);
    json_push_kv_int(out, "lowest_missing", v.lowest_missing);
    json_push_kv_int(out, "unmeasured_count", v.unmeasured_count);
    json_push_kv_int(out, "lowest_unmeasured", v.lowest_unmeasured);

    struct json_value census;
    json_init(&census);
    json_set_object(&census);
    json_push_kv_int(&census, "cursor", c.cursor_valid ? c.cursor : -1);
    json_push_kv_bool(&census, "cursor_valid", c.cursor_valid);
    json_push_kv_int(&census, "passes", (int64_t)c.passes);
    json_push_kv_int(&census, "sweeps_completed", (int64_t)c.sweeps_completed);
    json_push_kv_int(&census, "heights_examined", (int64_t)c.heights_examined);
    json_push_kv_int(&census, "heights_have", (int64_t)c.heights_have);
    json_push_kv_int(&census, "heights_missing", (int64_t)c.heights_missing);
    json_push_kv_int(&census, "heights_indeterminate",
                     (int64_t)c.heights_indeterminate);
    json_push_kv_int(&census, "blocks_enqueued", (int64_t)c.blocks_enqueued);
    json_push_kv_int(&census, "last_pass_lo", c.last_pass_lo);
    json_push_kv_int(&census, "last_pass_hi", c.last_pass_hi);
    json_push_kv_int(&census, "measured_ranges", measured_ranges);
    json_push_kv_int(&census, "measured_heights", measured_total);
    json_push_kv(out, "census", &census);
    json_free(&census);
    return true;
}
