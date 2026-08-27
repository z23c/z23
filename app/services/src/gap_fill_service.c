// one-result-type-ok:gap-fill-window-predicates — the three remaining
// legacy exports (gap_fill_compute_window, gap_fill_block_needs_queue,
// gap_fill_wake_dispatch_if_idle) are pure window/queue-state predicates:
// their bool return is the caller-consumed ANSWER (has_work / needs_queue /
// did_wake), not an error signal — none of them route through LOG_FAIL/
// LOG_ERR, and their defensive NULL-arg guards return the same false a
// normal "no work" answer would, so there is no distinct failure branch to
// carry in struct zcl_result. Every fallible surface in this file
// (gap_fill_start, gap_fill_register_supervisor) already returns
// zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _GNU_SOURCE  /* pthread_timedjoin_np */

#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "services/gap_fill_service.h"

#include "supervisors/domains.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "net/download.h"
#include "services/body_backfill_service.h"
#include "storage/body_coverage.h"
#include "storage/body_history.h"
#include "storage/progress_store.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/validate_headers_stage.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "event/event.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

struct gap_fill_state {
    pthread_t              thread;
    pthread_mutex_t        mu;
    pthread_cond_t         cv;
    _Atomic bool           running;
    _Atomic bool           stop_requested;
    bool                   thread_started;

    struct main_state      *ms;
    struct download_manager *dm;
    gap_fill_dispatch_wake_fn wake_dispatch;
    void                   *wake_dispatch_ctx;

    struct gap_fill_stats  stats;
    _Atomic supervisor_child_id supervisor_id;
};

static struct gap_fill_state g_gf = {
    .mu = PTHREAD_MUTEX_INITIALIZER,
    .cv = PTHREAD_COND_INITIALIZER,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};

static struct liveness_contract g_gap_fill_contract;

static int64_t gap_fill_supervisor_deadline_secs(void)
{
    return (int64_t)GAPFILL_TICK_SECS * 3 + 30;
}

static int64_t gap_fill_progress_marker(void)
{
    struct gap_fill_stats st;
    gap_fill_get_stats(&st);
    return (int64_t)st.passes;
}

static void gap_fill_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_gf.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, gap_fill_progress_marker());
}

static void gap_fill_on_stall(struct liveness_contract *c)
{
    struct gap_fill_stats st;
    gap_fill_get_stats(&st);
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN("gap_fill",
             "[gap-fill] supervisor stall reason=%s passes=%llu "
             "enqueued=%llu idle=%llu corrupt=%llu timeout_sweeps=%llu "
             "timeouts_requeued=%llu dispatch_wakes=%llu",
             reason,
             (unsigned long long)st.passes,
             (unsigned long long)st.blocks_enqueued,
             (unsigned long long)st.passes_idle,
             (unsigned long long)st.passes_corrupt_walk,
             (unsigned long long)st.timeout_sweeps,
             (unsigned long long)st.timeouts_requeued,
             (unsigned long long)st.dispatch_wakes);
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "source=chain.gap_fill decision=worker_stall "
                "reason=%s passes=%llu enqueued=%llu idle=%llu corrupt=%llu "
                "timeout_sweeps=%llu timeouts_requeued=%llu "
                "dispatch_wakes=%llu",
                reason,
                (unsigned long long)st.passes,
                (unsigned long long)st.blocks_enqueued,
                (unsigned long long)st.passes_idle,
                (unsigned long long)st.passes_corrupt_walk,
                (unsigned long long)st.timeout_sweeps,
                (unsigned long long)st.timeouts_requeued,
                (unsigned long long)st.dispatch_wakes);
    gap_fill_kick();
}

static struct zcl_result gap_fill_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-3, "gap_fill: supervisor_start failed");

    int64_t deadline = gap_fill_supervisor_deadline_secs();
    supervisor_child_id id = atomic_load(&g_gf.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, deadline);
        supervisor_progress(id, gap_fill_progress_marker());
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_gap_fill_contract, "chain.gap_fill");
    atomic_store(&g_gap_fill_contract.period_secs, 0);
    atomic_store(&g_gap_fill_contract.deadline_secs, deadline);
    atomic_store(&g_gap_fill_contract.progress_max_quiet_us, 0);
    g_gap_fill_contract.on_stall = gap_fill_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_gap_fill_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-4, "gap_fill: supervisor_register failed");
    atomic_store(&g_gf.supervisor_id, id);
    supervisor_progress(id, gap_fill_progress_marker());
    supervisor_tick(id);
    return ZCL_OK;
}

/* Walk pprev from `start` collecting block_index pointers until we
 * reach a node whose height == stop_height_exclusive (i.e. stop_h+1
 * is the lowest included height). Returns count collected. Returns
 * -1 if a corrupt walk is detected (non-monotonic height or step
 * cap hit) — caller logs and skips this pass. */
static int collect_pprev_window(struct block_index *start,
                                int stop_height_exclusive,
                                struct block_index **out,
                                int out_cap)
{
    if (!start || out_cap <= 0) return 0;
    int count = 0;
    struct block_index *cur = start;
    int last_h = cur->nHeight + 1; /* sentinel: any valid prev_h < this */
    int steps = 0;
    while (cur && count < out_cap &&
           cur->nHeight > stop_height_exclusive) {
        if (steps++ > GAPFILL_WALK_CAP) return -1; // raw-return-ok:sentinel
        if (cur->nHeight >= last_h) return -1; // raw-return-ok:sentinel
        last_h = cur->nHeight;
        out[count++] = cur;
        cur = cur->pprev;
    }
    return count;
}

bool gap_fill_compute_window(int active_tip_h, int best_header_h,
                             uint64_t floor_cursor,
                             struct gap_fill_window *out)
{
    if (!out)
        return false;

    memset(out, 0, sizeof(*out));
    out->effective_tip_h = active_tip_h;
    out->best_h = best_header_h;
    out->lo = active_tip_h + 1;
    out->hi = active_tip_h;

    if (floor_cursor > 0 &&
        (int64_t)floor_cursor - 1 < (int64_t)out->effective_tip_h) {
        out->effective_tip_h = (int)floor_cursor - 1;
    }

    out->lo = out->effective_tip_h + 1;
    out->hi = out->effective_tip_h;
    if (best_header_h <= out->effective_tip_h)
        return false;

    int gap = best_header_h - out->effective_tip_h;
    int count = gap < GAPFILL_WINDOW ? gap : GAPFILL_WINDOW;
    out->count = count;
    out->hi = out->effective_tip_h + count;
    out->has_work = count > 0;
    return out->has_work;
}

struct block_index *gap_fill_window_walk_start(
    struct block_index *best, const struct gap_fill_window *window)
{
    if (!best || !window || !window->has_work)
        return NULL;
    if (best->nHeight <= window->hi)
        return best;

    struct block_index *walk_start = best;
    int steps = 0;
    while (walk_start && walk_start->nHeight > window->hi &&
           steps++ < GAPFILL_WALK_CAP) {
        walk_start = walk_start->pprev;
    }
    if (!walk_start || walk_start->nHeight != window->hi)
        return best;
    return walk_start;
}

bool gap_fill_block_needs_queue(const struct block_index *bi)
{
    return bi && bi->phashBlock && !(bi->nStatus & BLOCK_HAVE_DATA);
}

void gap_fill_get_stats(struct gap_fill_stats *out)
{
    if (!out)
        return;
    pthread_mutex_lock(&g_gf.mu);
    *out = g_gf.stats;
    pthread_mutex_unlock(&g_gf.mu);
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe: reuses the
 * same lock-guarded snapshot the supervisor heartbeat and RPC/agent paths
 * already read. */
bool gap_fill_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    json_push_kv_bool(out, "running", atomic_load(&g_gf.running));

    struct gap_fill_stats st;
    gap_fill_get_stats(&st);
    json_push_kv_int(out, "passes", (int64_t)st.passes);
    json_push_kv_int(out, "blocks_enqueued", (int64_t)st.blocks_enqueued);
    json_push_kv_int(out, "passes_idle", (int64_t)st.passes_idle);
    json_push_kv_int(out, "passes_corrupt_walk",
                     (int64_t)st.passes_corrupt_walk);
    json_push_kv_int(out, "timeout_sweeps", (int64_t)st.timeout_sweeps);
    json_push_kv_int(out, "timeouts_requeued",
                     (int64_t)st.timeouts_requeued);
    json_push_kv_int(out, "dispatch_wakes", (int64_t)st.dispatch_wakes);
    json_push_kv_int(out, "last_tip_h", (int64_t)st.last_tip_h);
    json_push_kv_int(out, "last_best_h", (int64_t)st.last_best_h);
    json_push_kv_int(out, "last_window_lo", (int64_t)st.last_window_lo);
    json_push_kv_int(out, "last_window_hi", (int64_t)st.last_window_hi);
    return true;
}

size_t gap_fill_sweep_download_timeouts(struct download_manager *dm,
                                        int64_t now_seconds)
{
    if (!dm)
        return 0;
    if (now_seconds <= 0)
        now_seconds = (int64_t)platform_time_wall_time_t();

    size_t timed_out = dl_check_timeouts(dm, now_seconds);
    if (timed_out > 0) {
        LOG_WARN("gap_fill",
                 "[gap-fill] download timeout sweep requeued=%zu",
                 timed_out);
        event_emitf(EV_BLOCK_REQUESTED, 0,
                    "gap_fill timeout_sweep requeued=%zu", timed_out);
    }
    return timed_out;
}

static void gap_fill_wake_dispatcher(const char *reason)
{
    uint64_t total = 0;
    gap_fill_dispatch_wake_fn fn = NULL;
    void *ctx = NULL;
    pthread_mutex_lock(&g_gf.mu);
    fn = g_gf.wake_dispatch;
    ctx = g_gf.wake_dispatch_ctx;
    pthread_mutex_unlock(&g_gf.mu);
    if (!fn)
        return;
    fn(ctx);
    pthread_mutex_lock(&g_gf.mu);
    g_gf.stats.dispatch_wakes++;
    total = g_gf.stats.dispatch_wakes;
    pthread_mutex_unlock(&g_gf.mu);
    event_emitf(EV_BLOCK_REQUESTED, 0,
                "gap_fill dispatch_wake reason=%s total=%llu",
                reason ? reason : "unknown",
                (unsigned long long)total);
}

/* Wake hook handed to the below-tip backfill so it can nudge the dispatcher
 * through gap_fill's existing bridge instead of reaching into connman. */
static void gap_fill_body_backfill_wake(void *ctx)
{
    (void)ctx;
    gap_fill_wake_dispatcher("body_backfill");
}

bool gap_fill_wake_dispatch_if_idle(struct download_manager *dm,
                                    const char *reason)
{
    if (!dm)
        return false;

    uint64_t in_flight = 0;
    uint64_t queued = 0;
    dl_get_stats(dm, NULL, NULL, NULL, &in_flight, &queued);
    if (queued == 0 || in_flight > 0)
        return false;

    gap_fill_wake_dispatcher(reason ? reason : "dispatch_idle");
    return true;
}

/* Body-coverage maintenance + gap-fill scheduler drive. Composes with the
 * download manager; never touches its peer selection. Called AFTER cs_main
 * is released, so it dereferences no block_index — the caller captures the
 * have-data heights under the lock and hands them in as plain integers.
 *
 * `needed_lo`/`needed_hi` is the range the active chain must fill
 * ([tip+1, best_header]). `enqueued_this_pass` is true when this pass handed
 * new work to the download manager. The no-source blocker fires only when a
 * coverage hole persists in the needed range AND the download pipeline is
 * fully idle (nothing queued, nothing in flight) AND this pass enqueued
 * nothing — i.e. a known gap that no source is serving. Any in-flight or
 * queued work clears the latch, so active sync never trips it. */
static void gap_fill_update_coverage(const int32_t *have_heights, int n_have,
                                     int needed_lo, int needed_hi,
                                     struct download_manager *dm,
                                     bool enqueued_this_pass)
{
    int64_t now = (int64_t)platform_time_wall_time_t();
    struct body_coverage_map *map = body_coverage_global_map();
    struct body_coverage_scheduler *s = body_coverage_global_scheduler();

    body_coverage_global_lock();
    for (int i = 0; i < n_have; i++)
        body_coverage_note_stored(map, have_heights[i]);

    struct bc_range hole;
    bool has_hole = body_coverage_scheduler_plan(s, map, needed_lo, needed_hi,
                                                 now, &hole);
    if (has_hole) {
        if (enqueued_this_pass) {
            body_coverage_scheduler_mark_enqueued(s);
        } else {
            uint64_t in_flight = 0, queued = 0;
            dl_get_stats(dm, NULL, NULL, NULL, &in_flight, &queued);
            if (in_flight == 0 && queued == 0)
                body_coverage_scheduler_mark_no_source(s, now);
            else
                body_coverage_scheduler_clear_no_source(s);
        }
    }
    body_coverage_global_unlock();
}

/* Best-effort persist of the coverage map to progress.kv. Rate-limited by
 * the caller; a NULL/unopened store is a silent skip (nothing to persist to
 * yet). */
static void gap_fill_persist_coverage(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return;
    body_coverage_global_lock();
    (void)body_coverage_save(body_coverage_global_map(), db);
    body_coverage_global_unlock();
    (void)body_history_save(db);
}

/* One pass: scan [tip+1, best_header] for missing data, queue
 * downloads. Returns number of blocks enqueued (0 = idle, -1 =
 * corrupt walk detected). */
static int gap_fill_pass(void)
{
    struct main_state *ms = g_gf.ms;
    struct download_manager *dm = g_gf.dm;
    if (!ms || !dm) return 0;

    size_t timed_out = gap_fill_sweep_download_timeouts(
        dm, (int64_t)platform_time_wall_time_t());
    pthread_mutex_lock(&g_gf.mu);
    g_gf.stats.timeout_sweeps++;
    g_gf.stats.timeouts_requeued += (uint64_t)timed_out;
    pthread_mutex_unlock(&g_gf.mu);
    if (timed_out > 0)
        gap_fill_wake_dispatcher("timeout_sweep");

    /* Snapshot tip and best_header under cs_main. We hold the lock
     * only for the pointer reads + pprev walk; the dl_queue_blocks
     * call is done outside the lock. */
    zcl_mutex_lock(&ms->cs_main);
    int tip_h = active_chain_height(&ms->chain_active);
    struct block_index *best = ms->pindex_best_header;
    int best_h = best ? best->nHeight : 0;
    /* Seed-floor raise: on a bundle/snapshot-seeded node the install
     * advances the stage cursors (body_fetch = seed+1) but never moves
     * chainactive, so active_tip_h sits far BELOW the reducer's fold
     * frontier. A window floored at active_tip_h fills dl_queue with
     * below-floor heights the fold will not consume next, and the
     * height-sorted keep-lowest eviction then actively REFUSES the
     * fold-needed successors above the seed (FORWARD_PLAN backlog #10,
     * 2026-08-01). Raise the window's bottom to the fold's next-needed
     * height. No-op on an unseeded node, where body_fetch prefetches at
     * or ahead of the active tip. The S2.4 floor below still applies
     * unchanged — it only ever LOWERS the window as a defensive
     * backstop, never behind the fold. */
    {
        uint64_t bf_cur = body_fetch_stage_cursor();
        if (bf_cur > 0 && bf_cur - 1 > (uint64_t)tip_h)
            tip_h = (int)(bf_cur - 1);
    }
    struct gap_fill_window gf_window;
    /* S2.4: floor the download window on the validate_headers cursor, not
     * body_fetch. body_fetch only advances once a body is already on disk
     * (BLOCK_HAVE_DATA); a stall there must NOT also freeze on-disk body
     * prefetch. validate_headers is header-only (Equihash + PoW, no body),
     * structurally decoupled from body availability, and normally runs far
     * ahead — so the transport keeps caching bodies forward while the
     * reducer is briefly stalled, and the reducer consumes them when it
     * advances. The floor still exists as a defensive backstop against the
     * window running past validated headers; GAPFILL_WINDOW still bounds
     * it, and gap_fill_block_needs_queue skips any block already on disk. */
    bool has_window =
        gap_fill_compute_window(tip_h, best_h, validate_headers_stage_cursor(),
                                &gf_window) && best;
    tip_h = gf_window.effective_tip_h;

    if (!has_window) {
        zcl_mutex_unlock(&ms->cs_main);
        pthread_mutex_lock(&g_gf.mu);
        g_gf.stats.last_tip_h  = tip_h;
        g_gf.stats.last_best_h = best_h;
        pthread_mutex_unlock(&g_gf.mu);
        return 0;
    }

    /* Window: collect at most GAPFILL_WINDOW indices from pprev,
     * stopping at tip_h (exclusive).
     *
     * When the gap (best_h - tip_h) exceeds GAPFILL_WINDOW, walking
     * back from `best` for GAPFILL_WINDOW steps gives us the TOP of
     * the gap (e.g. h=76094..141629 with tip=8911) — but
     * reducer activation needs the BOTTOM of the gap (h=8912..) to extend the
     * active chain. The far-ahead blocks are useless until
     * intermediates connect, and they saturate dl_queue (capacity
     * 65536), preventing the immediate successors from even being
     * queued. Result: chain wedges at the current tip.
     *
     * Walk pprev from `best` down to height `tip_h + window` FIRST
     * (discarding those entries), then collect the next `window`
     * entries which end at tip_h+1. That gives the bottom window
     * of the gap, which is what the active chain needs next. */
    int window = gf_window.count;
    struct block_index *walk_start =
        gap_fill_window_walk_start(best, &gf_window);

    struct block_index **bis = zcl_malloc((size_t)window * sizeof(*bis),
                                          "gap_fill_window");
    if (!bis) {
        zcl_mutex_unlock(&ms->cs_main);
        return 0;
    }
    int collected = collect_pprev_window(walk_start, tip_h, bis, window);
    if (collected < 0) {
        zcl_mutex_unlock(&ms->cs_main);
        free(bis);
        return -1; // raw-return-ok:sentinel
    }
    if (collected == 0) {
        zcl_mutex_unlock(&ms->cs_main);
        free(bis);
        pthread_mutex_lock(&g_gf.mu);
        g_gf.stats.last_tip_h = tip_h;
        g_gf.stats.last_best_h = best_h;
        g_gf.stats.last_window_lo = tip_h + 1;
        g_gf.stats.last_window_hi = tip_h;
        pthread_mutex_unlock(&g_gf.mu);
        return 0;
    }

    /* Filter: needs data AND not in-flight. Build parallel arrays for
     * dl_queue_blocks. We allocate up to `collected` slots. */
    struct uint256 *hashes = zcl_malloc((size_t)collected * sizeof(*hashes),
                                        "gap_fill_hashes");
    int32_t *heights = zcl_malloc((size_t)collected * sizeof(*heights),
                                  "gap_fill_heights");
    /* Body-coverage capture: heights in this window that already have their
     * body on disk. Captured here under cs_main (plain ints), fed to the
     * coverage map AFTER the lock is released so no block_index is touched
     * off-lock. */
    int32_t *have_heights = zcl_malloc((size_t)collected * sizeof(*have_heights),
                                       "gap_fill_have_heights");
    if (!hashes || !heights || !have_heights) {
        zcl_mutex_unlock(&ms->cs_main);
        free(bis); free(hashes); free(heights); free(have_heights);
        return 0;
    }

    int n_need = 0;
    int n_have = 0;
    int lo = bis[collected - 1] ? bis[collected - 1]->nHeight : tip_h + 1;
    int hi = bis[0] ? bis[0]->nHeight : tip_h;
    for (int i = 0; i < collected; i++) {
        struct block_index *bi = bis[i];
        if (bi && (bi->nStatus & BLOCK_HAVE_DATA))
            have_heights[n_have++] = bi->nHeight;
        if (!gap_fill_block_needs_queue(bi)) continue;
        if (dl_is_in_flight(dm, bi->phashBlock)) continue;
        hashes[n_need]  = *bi->phashBlock; /* value copy */
        heights[n_need] = bi->nHeight;
        n_need++;
    }
    zcl_mutex_unlock(&ms->cs_main);
    free(bis);

    int enqueued = 0;
    if (n_need > 0) {
        size_t added = dl_queue_blocks(dm, hashes, heights,
                                       (size_t)n_need);
        enqueued = (int)added;
        if (added > 0) {
            printf("[gap-fill] queued %zu blocks (window [%d..%d] "
                   "tip=%d best=%d)\n",
                   added, lo, hi, tip_h, best_h);
            event_emitf(EV_BLOCK_REQUESTED, 0,
                        "gap_fill queued=%zu lo=%d hi=%d tip=%d best=%d",
                        added, lo, hi, tip_h, best_h);
            gap_fill_wake_dispatcher("queued_blocks");
        } else {
            gap_fill_wake_dispatch_if_idle(dm, "queued_idle");
        }

        /* Explicitly front-insert (priority) the LOWEST N missing blocks
         * of the window — the connectable bottom (tip+1, tip+2, ...).
         * hashes[]/heights[] were built from bis[] which is highest-first
         * (collect_pprev_window walks pprev from the top), so the lowest
         * heights are at the END of the parallel arrays. Even though
         * dl_queue_push now keeps the queue height-sorted, this guarantees
         * the connectable bottom is queued first regardless of any later
         * far-ahead enqueue, belt-and-suspenders against starvation. */
        int prio = n_need < GAPFILL_PRIORITY_BOTTOM_N
                       ? n_need : GAPFILL_PRIORITY_BOTTOM_N;
        for (int i = 0; i < prio; i++) {
            int idx = n_need - 1 - i; /* lowest heights live at the tail */
            dl_queue_priority(dm, &hashes[idx], heights[idx]);
        }
    }

    /* Maintain the body-coverage map + drive the gap-fill scheduler over
     * the full gap [tip+1, best_header] the active chain must fill. */
    gap_fill_update_coverage(have_heights, n_have, tip_h + 1, best_h, dm,
                             enqueued > 0);

    free(hashes);
    free(heights);
    free(have_heights);

    pthread_mutex_lock(&g_gf.mu);
    g_gf.stats.last_tip_h     = tip_h;
    g_gf.stats.last_best_h    = best_h;
    g_gf.stats.last_window_lo = lo;
    g_gf.stats.last_window_hi = hi;
    pthread_mutex_unlock(&g_gf.mu);
    return enqueued;
}

/* Shutdown predicate + heartbeat the census catch-up burst calls between
 * slices, so a burst yields to `gap_fill_stop` and keeps the supervisor
 * child ticking without body_backfill_service reaching into g_gf. */
static bool gap_fill_burst_should_abort(void *ctx)
{
    (void)ctx;
    return atomic_load(&g_gf.stop_requested);
}

static void gap_fill_burst_heartbeat(void *ctx)
{
    (void)ctx;
    gap_fill_supervisor_heartbeat();
}

static void *gap_fill_thread_main(void *arg)
{
    (void)arg;
    printf("[gap-fill] service started\n");
    gap_fill_supervisor_heartbeat();
    while (!atomic_load(&g_gf.stop_requested)) {
        int n = gap_fill_pass();
        /* The below-tip census runs every tick so the coverage verdict is
         * never stale; its backfill only enqueues on a pass where the
         * above-tip window had nothing to do. */
        (void)body_backfill_pass(g_gf.ms, g_gf.dm, n > 0, false,
                                 gap_fill_body_backfill_wake, NULL);
        /* ...and then, until the whole window has been looked at once this
         * boot, keep running census slices back-to-back rather than waiting
         * 5 s for the next one. See body_backfill_catch_up. */
        (void)body_backfill_catch_up(g_gf.ms, g_gf.dm, n > 0,
                                     gap_fill_burst_should_abort, NULL,
                                     gap_fill_burst_heartbeat, NULL);
        pthread_mutex_lock(&g_gf.mu);
        g_gf.stats.passes++;
        if (n > 0) {
            g_gf.stats.blocks_enqueued += (uint64_t)n;
        } else if (n == 0) {
            g_gf.stats.passes_idle++;
        } else {
            g_gf.stats.passes_corrupt_walk++;
        }
        pthread_mutex_unlock(&g_gf.mu);
        if (n < 0) {
            LOG_WARN("gap", "[gap-fill] %s:%d %s(): corrupt pprev walk detected, " "skipping pass", __FILE__, __LINE__, __func__);
        }
        gap_fill_supervisor_heartbeat();

        /* Rate-limited durable persist of the coverage map (~every 64
         * passes) so a restart resumes from the known ranges rather than
         * an O(chain) rescan. */
        pthread_mutex_lock(&g_gf.mu);
        bool do_persist = (g_gf.stats.passes % 64) == 0;
        pthread_mutex_unlock(&g_gf.mu);
        if (do_persist)
            gap_fill_persist_coverage();

        /* Sleep until kicked or GAPFILL_TICK_SECS elapsed. */
        pthread_mutex_lock(&g_gf.mu);
        if (!atomic_load(&g_gf.stop_requested)) {
            struct timespec until;
            platform_time_realtime_timespec(&until);
            until.tv_sec += GAPFILL_TICK_SECS;
            pthread_cond_timedwait(&g_gf.cv, &g_gf.mu, &until);
        }
        pthread_mutex_unlock(&g_gf.mu);
    }
    struct gap_fill_stats st;
    gap_fill_get_stats(&st);
    printf("[gap-fill] service stopped (passes=%llu enqueued=%llu "
           "idle=%llu corrupt=%llu timeout_sweeps=%llu "
           "timeouts_requeued=%llu dispatch_wakes=%llu)\n",
           (unsigned long long)st.passes,
           (unsigned long long)st.blocks_enqueued,
           (unsigned long long)st.passes_idle,
           (unsigned long long)st.passes_corrupt_walk,
           (unsigned long long)st.timeout_sweeps,
           (unsigned long long)st.timeouts_requeued,
           (unsigned long long)st.dispatch_wakes);
    return NULL;
}

struct zcl_result gap_fill_start(struct main_state *ms, struct download_manager *dm)
{
    if (!ms || !dm)
        return ZCL_ERR(-1, "start: null ms or dm");
    if (atomic_load(&g_gf.running)) return ZCL_OK;
    g_gf.ms = ms;
    g_gf.dm = dm;
    memset(&g_gf.stats, 0, sizeof(g_gf.stats));

    /* Resume the body-coverage map from progress.kv (cheap; a fresh datadir
     * has none). Best-effort: an unopened store or malformed blob leaves the
     * map empty and the worker rebuilds coverage incrementally from its
     * window scans. */
    {
        sqlite3 *db = progress_store_db();
        if (db) {
            body_coverage_global_lock();
            (void)body_coverage_load(body_coverage_global_map(), db);
            body_coverage_global_unlock();
            /* Restores the census CURSOR and nothing else. The map loaded
             * just above is a CLAIM about what is on disk; it is not
             * evidence that anything looked, and body_history_evaluate no
             * longer treats it as any. Neither the verdict nor the measured
             * map comes back, so a node that has just booted has
             * established nothing and has to earn "complete" again by
             * probing every height — which the catch-up burst in
             * gap_fill_thread_main does within the first tick. */
            (void)body_history_load(db);
        }
    }
    atomic_store(&g_gf.stop_requested, false);
    if (thread_registry_spawn("zcl_gap_fill", gap_fill_thread_main, NULL,
                                  &g_gf.thread) != 0) {
        return ZCL_ERR(-2, "thread_registry_spawn failed: errno=%d", errno);
    }
    g_gf.thread_started = true;
    atomic_store(&g_gf.running, true);
    struct zcl_result sup_r = gap_fill_register_supervisor();
    if (!sup_r.ok) {
        atomic_store(&g_gf.stop_requested, true);
        pthread_mutex_lock(&g_gf.mu);
        pthread_cond_broadcast(&g_gf.cv);
        pthread_mutex_unlock(&g_gf.mu);
        pthread_join(g_gf.thread, NULL);
        g_gf.thread_started = false;
        atomic_store(&g_gf.running, false);
        return sup_r;
    }
    return ZCL_OK;
}

void gap_fill_stop(void)
{
    if (!atomic_load(&g_gf.running)) return;
    supervisor_child_id id = atomic_load(&g_gf.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
    atomic_store(&g_gf.stop_requested, true);
    pthread_mutex_lock(&g_gf.mu);
    pthread_cond_broadcast(&g_gf.cv);
    pthread_mutex_unlock(&g_gf.mu);
    if (g_gf.thread_started) {
        /* Five seconds is a diagnostic deadline. Retain ownership until the
         * worker exits before persisting coverage or clearing callbacks. */
        struct timespec ts;
        if (platform_time_realtime_timespec(&ts) == 0) {
            ts.tv_sec += 5;
            int rc = platform_thread_join_until(g_gf.thread, NULL, &ts);
            if (rc != 0) {
                LOG_WARN("gap_fill_stop", "gap_fill_stop: thread join exceeded deadline (rc=%d); retaining ownership", rc);
                pthread_join(g_gf.thread, NULL);
            }
        } else {
            pthread_join(g_gf.thread, NULL);
        }
        g_gf.thread_started = false;
    }
    /* Final durable persist so the next boot resumes from the known ranges. */
    gap_fill_persist_coverage();
    atomic_store(&g_gf.running, false);
    pthread_mutex_lock(&g_gf.mu);
    g_gf.wake_dispatch = NULL;
    g_gf.wake_dispatch_ctx = NULL;
    pthread_mutex_unlock(&g_gf.mu);
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_gf.supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}

void gap_fill_kick(void)
{
    if (!atomic_load(&g_gf.running)) return;
    pthread_mutex_lock(&g_gf.mu);
    pthread_cond_broadcast(&g_gf.cv);
    pthread_mutex_unlock(&g_gf.mu);
}

void gap_fill_set_dispatch_wake(gap_fill_dispatch_wake_fn fn, void *ctx)
{
    pthread_mutex_lock(&g_gf.mu);
    g_gf.wake_dispatch = fn;
    g_gf.wake_dispatch_ctx = ctx;
    pthread_mutex_unlock(&g_gf.mu);
}
