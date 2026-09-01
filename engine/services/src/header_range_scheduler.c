/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Range-parallel header acquisition scheduler — see
 * services/header_range_scheduler.h for the contract and rationale.
 *
 * Pure, allocation-free, thread-safe. The span table is fixed-capacity
 * (HRS_MAX_SPANS) and every mutation is under `s->lock`. The two
 * decision helpers (hrs_should_parallelize, hrs_partition) touch no
 * scheduler state.
 */

// one-result-type-ok:header-range-scheduler-selectors — see the header:
// every exported function is a pure planner ANSWER (bool/size/index), not
// a fallible op; no I/O/DB/alloc to carry a struct zcl_result.

#include "services/header_range_scheduler.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <string.h>

/* Default per-span assignment budget: 30 s. A peer that has not driven its
 * span's frontier forward within this window is swept and demoted, and the
 * span is handed to another peer. Matches the header-stall discipline
 * cadence (HEADER_STALL_TIMEOUT_SECS is 120 s; a per-span span budget is
 * deliberately tighter so a slow span rotates well before whole-sync
 * stall detection would fire). */
#define HRS_DEFAULT_SPAN_TIMEOUT_US ((int64_t)30 * 1000 * 1000)

/* ── Pure decisions ───────────────────────────────────────────── */

bool hrs_should_parallelize(int fast_peer_count, int32_t gap, int32_t batch)
{
    if (fast_peer_count < 2)
        return false;
    if (batch <= 0)
        return false;
    return gap > batch;
}

/* Insert `v` into a sorted-ascending, deduplicated int32 array of length
 * *n (capacity cap). No-op on a full array or a duplicate. */
static void sorted_insert(int32_t *arr, size_t *n, size_t cap, int32_t v)
{
    if (*n >= cap)
        return;
    size_t i = 0;
    while (i < *n && arr[i] < v)
        i++;
    if (i < *n && arr[i] == v)
        return; /* duplicate */
    for (size_t j = *n; j > i; j--)
        arr[j] = arr[j - 1];
    arr[i] = v;
    (*n)++;
}

size_t hrs_partition(int32_t lo, int32_t hi,
                     const int32_t *anchors, size_t n_anchors,
                     struct hrs_span *out, size_t max_out)
{
    if (!out || max_out == 0 || hi <= lo)
        return 0;

    /* Build the sorted, deduplicated boundary set: lo, hi, and every
     * anchor strictly inside (lo, hi). Capacity is one more than the span
     * table so a full anchor set still yields <= HRS_MAX_SPANS spans. */
    int32_t bounds[HRS_MAX_SPANS + 1];
    size_t nb = 0;
    sorted_insert(bounds, &nb, HRS_MAX_SPANS + 1, lo);
    sorted_insert(bounds, &nb, HRS_MAX_SPANS + 1, hi);
    for (size_t i = 0; anchors && i < n_anchors; i++) {
        if (anchors[i] > lo && anchors[i] < hi)
            sorted_insert(bounds, &nb, HRS_MAX_SPANS + 1, anchors[i]);
    }

    size_t count = 0;
    for (size_t i = 0; i + 1 < nb && count < max_out; i++) {
        struct hrs_span sp = {0};
        sp.lo = bounds[i];
        sp.hi = bounds[i + 1];
        sp.peer_id = 0;
        sp.deadline_us = 0;
        sp.assigned = false;
        sp.completed = false;
        out[count++] = sp;
    }
    return count;
}

/* ── Stateful scheduler ───────────────────────────────────────── */

void hrs_init(struct header_range_scheduler *s, int64_t span_timeout_us)
{
    if (!s)
        return;
    memset(s->spans, 0, sizeof(s->spans));
    s->n_spans = 0;
    s->range_lo = 0;
    s->range_hi = 0;
    s->span_timeout_us =
        span_timeout_us > 0 ? span_timeout_us : HRS_DEFAULT_SPAN_TIMEOUT_US;
    s->stat_assigns = 0;
    s->stat_reassigns = 0;
    s->stat_completions = 0;
    s->stat_timeouts = 0;
    if (!s->inited) {
        zcl_mutex_init(&s->lock);
        s->inited = true;
    }
}

void hrs_reset(struct header_range_scheduler *s)
{
    if (!s || !s->inited)
        return;
    zcl_mutex_lock(&s->lock);
    memset(s->spans, 0, sizeof(s->spans));
    s->n_spans = 0;
    s->range_lo = 0;
    s->range_hi = 0;
    zcl_mutex_unlock(&s->lock);
}

/* Carry a matching prior span's assignment onto a freshly-partitioned one.
 * Matching key is [lo, hi]: checkpoint anchors are process-stable, so a
 * span that keeps the same endpoints across a re-plan is the same work
 * unit and must retain its in-flight peer/deadline (or completed flag). */
static void carry_over_assignment(struct hrs_span *dst,
                                  const struct hrs_span *old, size_t n_old)
{
    for (size_t i = 0; i < n_old; i++) {
        if (old[i].lo == dst->lo && old[i].hi == dst->hi) {
            dst->assigned = old[i].assigned;
            dst->completed = old[i].completed;
            dst->peer_id = old[i].peer_id;
            dst->deadline_us = old[i].deadline_us;
            return;
        }
    }
}

void hrs_plan(struct header_range_scheduler *s, int32_t lo, int32_t hi,
              const int32_t *anchors, size_t n_anchors)
{
    if (!s || !s->inited)
        return;

    struct hrs_span fresh[HRS_MAX_SPANS];
    size_t n_fresh = hrs_partition(lo, hi, anchors, n_anchors,
                                   fresh, HRS_MAX_SPANS);

    zcl_mutex_lock(&s->lock);
    struct hrs_span old[HRS_MAX_SPANS];
    size_t n_old = s->n_spans;
    memcpy(old, s->spans, sizeof(struct hrs_span) * n_old);

    for (size_t i = 0; i < n_fresh; i++)
        carry_over_assignment(&fresh[i], old, n_old);

    memcpy(s->spans, fresh, sizeof(struct hrs_span) * n_fresh);
    s->n_spans = n_fresh;
    s->range_lo = lo;
    s->range_hi = hi;
    zcl_mutex_unlock(&s->lock);
}

/* True iff `peer_id` already owns a live (assigned, not expired) span.
 * Caller holds s->lock. */
static bool peer_has_live_span_locked(const struct header_range_scheduler *s,
                                      int32_t peer_id, int64_t now_us)
{
    for (size_t i = 0; i < s->n_spans; i++) {
        if (s->spans[i].assigned && !s->spans[i].completed &&
            s->spans[i].peer_id == peer_id &&
            s->spans[i].deadline_us > now_us)
            return true;
    }
    return false;
}

int hrs_assign(struct header_range_scheduler *s, int32_t peer_id,
               int64_t now_us)
{
    if (!s || !s->inited)
        return -1; // raw-return-ok:hrs-uninitialized-no-span

    zcl_mutex_lock(&s->lock);

    if (peer_has_live_span_locked(s, peer_id, now_us)) {
        zcl_mutex_unlock(&s->lock);
        return -1; // raw-return-ok:hrs-peer-already-busy
    }

    for (size_t i = 0; i < s->n_spans; i++) {
        if (!s->spans[i].assigned && !s->spans[i].completed) {
            s->spans[i].assigned = true;
            s->spans[i].peer_id = peer_id;
            s->spans[i].deadline_us = now_us + s->span_timeout_us;
            s->stat_assigns++;
            zcl_mutex_unlock(&s->lock);
            return (int)i;
        }
    }

    zcl_mutex_unlock(&s->lock);
    return -1; // raw-return-ok:hrs-no-free-span
}

size_t hrs_note_frontier(struct header_range_scheduler *s, int32_t height)
{
    if (!s || !s->inited)
        return 0;

    size_t completed = 0;
    zcl_mutex_lock(&s->lock);
    for (size_t i = 0; i < s->n_spans; i++) {
        if (!s->spans[i].completed && s->spans[i].hi <= height) {
            s->spans[i].completed = true;
            s->spans[i].assigned = false;
            s->spans[i].peer_id = 0;
            s->spans[i].deadline_us = 0;
            s->stat_completions++;
            completed++;
        }
    }
    zcl_mutex_unlock(&s->lock);
    return completed;
}

size_t hrs_sweep_expired(struct header_range_scheduler *s, int64_t now_us,
                         int32_t *stalled, size_t max)
{
    if (!s || !s->inited)
        return 0;

    size_t n = 0;
    zcl_mutex_lock(&s->lock);
    for (size_t i = 0; i < s->n_spans; i++) {
        if (s->spans[i].assigned && !s->spans[i].completed &&
            s->spans[i].deadline_us <= now_us) {
            if (stalled && n < max)
                stalled[n] = s->spans[i].peer_id;
            /* Free the slot so another peer can take the span (reassign). */
            s->spans[i].assigned = false;
            s->spans[i].peer_id = 0;
            s->spans[i].deadline_us = 0;
            s->stat_timeouts++;
            s->stat_reassigns++;
            n++;
        }
    }
    zcl_mutex_unlock(&s->lock);
    return n;
}

bool hrs_peer_span(struct header_range_scheduler *s, int32_t peer_id,
                   int64_t now_us, int32_t *out_lo, int32_t *out_hi)
{
    if (!s || !s->inited)
        return false;

    bool found = false;
    zcl_mutex_lock(&s->lock);
    for (size_t i = 0; i < s->n_spans; i++) {
        if (s->spans[i].assigned && !s->spans[i].completed &&
            s->spans[i].peer_id == peer_id &&
            s->spans[i].deadline_us > now_us) {
            if (out_lo) *out_lo = s->spans[i].lo;
            if (out_hi) *out_hi = s->spans[i].hi;
            found = true;
            break;
        }
    }
    zcl_mutex_unlock(&s->lock);
    return found;
}

bool hrs_peer_owns_expired_span(struct header_range_scheduler *s,
                                int32_t peer_id, int64_t now_us)
{
    if (!s || !s->inited)
        return false;
    bool found = false;
    zcl_mutex_lock(&s->lock);
    for (size_t i = 0; i < s->n_spans; i++) {
        if (s->spans[i].assigned && !s->spans[i].completed &&
            s->spans[i].peer_id == peer_id &&
            s->spans[i].deadline_us <= now_us) {
            found = true;
            break;
        }
    }
    zcl_mutex_unlock(&s->lock);
    return found;
}

size_t hrs_span_count(struct header_range_scheduler *s)
{
    if (!s || !s->inited)
        return 0;
    zcl_mutex_lock(&s->lock);
    size_t n = s->n_spans;
    zcl_mutex_unlock(&s->lock);
    return n;
}

size_t hrs_free_span_count(struct header_range_scheduler *s)
{
    if (!s || !s->inited)
        return 0;
    size_t n = 0;
    zcl_mutex_lock(&s->lock);
    for (size_t i = 0; i < s->n_spans; i++) {
        if (!s->spans[i].assigned && !s->spans[i].completed)
            n++;
    }
    zcl_mutex_unlock(&s->lock);
    return n;
}

/* ── Process-global instance ──────────────────────────────────── */

static struct header_range_scheduler g_hrs;
static zcl_mutex_t g_hrs_init_lock;
static bool g_hrs_init_lock_ready = false;

/* Cheap, race-tolerant one-time init of the init lock. The first caller in
 * the process is single-threaded boot (config/boot), so this initializes
 * before any net thread touches the global. */
static void ensure_hrs_init_lock(void)
{
    if (!g_hrs_init_lock_ready) {
        zcl_mutex_init(&g_hrs_init_lock);
        g_hrs_init_lock_ready = true;
    }
}

struct header_range_scheduler *header_range_scheduler_global(void)
{
    ensure_hrs_init_lock();
    zcl_mutex_lock(&g_hrs_init_lock);
    if (!g_hrs.inited)
        hrs_init(&g_hrs, HRS_DEFAULT_SPAN_TIMEOUT_US);
    zcl_mutex_unlock(&g_hrs_init_lock);
    return &g_hrs;
}

void header_range_scheduler_reset_for_testing(void)
{
    struct header_range_scheduler *s = header_range_scheduler_global();
    hrs_reset(s);
    zcl_mutex_lock(&s->lock);
    s->stat_assigns = 0;
    s->stat_reassigns = 0;
    s->stat_completions = 0;
    s->stat_timeouts = 0;
    zcl_mutex_unlock(&s->lock);
}

bool header_range_scheduler_dump_state_json(struct json_value *out,
                                            const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct header_range_scheduler *s = header_range_scheduler_global();
    zcl_mutex_lock(&s->lock);
    size_t total = s->n_spans, assigned = 0, completed = 0, free_spans = 0;
    for (size_t i = 0; i < s->n_spans; i++) {
        if (s->spans[i].completed) completed++;
        else if (s->spans[i].assigned) assigned++;
        else free_spans++;
    }
    json_push_kv_int(out, "range_lo", s->range_lo);
    json_push_kv_int(out, "range_hi", s->range_hi);
    json_push_kv_int(out, "spans_total", (int64_t)total);
    json_push_kv_int(out, "spans_assigned", (int64_t)assigned);
    json_push_kv_int(out, "spans_completed", (int64_t)completed);
    json_push_kv_int(out, "spans_free", (int64_t)free_spans);
    json_push_kv_int(out, "span_timeout_us", s->span_timeout_us);
    json_push_kv_int(out, "stat_assigns", (int64_t)s->stat_assigns);
    json_push_kv_int(out, "stat_reassigns", (int64_t)s->stat_reassigns);
    json_push_kv_int(out, "stat_completions", (int64_t)s->stat_completions);
    json_push_kv_int(out, "stat_timeouts", (int64_t)s->stat_timeouts);
    zcl_mutex_unlock(&s->lock);
    return true;
}
