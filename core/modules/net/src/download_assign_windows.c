/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-peer assignment windows for the block download manager: in-flight
 * load measurement, window and history-room arithmetic, the tip-bias skip
 * and the batch-eligibility gate. Caller holds dm->cs. */

#include "net/download.h"
#include "download_internal.h"
#include <stddef.h>
#include <stdint.h>

/* S2.3: best known bandwidth_score among other actively-tracked,
 * non-loopback peers. Used only to decide whether *this* requester is
 * demonstrably slower than some other known peer, gating the tip-adjacent
 * bias below. Caller holds dm->cs. Bounded by DL_MAX_TRACKED_PEERS. */
static uint32_t dl_best_bandwidth_score(const struct download_manager *dm)
{
    uint32_t best = 0;
    for (size_t i = 0; i < dm->num_peers; i++) {
        const struct dl_peer_stats *ps = &dm->peers[i];
        if (!ps->active || ps->is_loopback)
            continue;
        if (ps->bandwidth_score > best)
            best = ps->bandwidth_score;
    }
    return best;
}

/* Count this peer's in-flight slots and the queued forward/history split. */
struct dl_assign_load dl_assign_measure(const struct download_manager *dm,
                                              uint32_t peer_id)
{
    struct dl_assign_load load = {0};
    for (size_t i = 0; i < dm->num_slots; i++) {
        if (!dm->slots[i].active)
            continue;
        if (dm->slots[i].work_class == DL_WORK_HISTORY) {
            load.history_global_count++;
            if (dm->slots[i].peer_id == peer_id)
                load.history_peer_count++;
        }
        if (dm->slots[i].peer_id == peer_id)
            load.peer_count++;
    }
    for (size_t i = 0; i < dm->queue_len; i++) {
        if (dm->queue_classes[i] == DL_WORK_HISTORY)
            load.history_queued++;
        else
            load.forward_queued++;
    }
    return load;
}

size_t dl_assign_peer_limit(const struct dl_peer_stats *ps)
{
    /* Adaptive per-peer limit: fast peers get larger windows.
     * bandwidth_score 0-63 → 16 slots, 64-127 → 32-64, 128+ → 64-128.
     * This naturally gives ~4x more work to 4x-faster peers. */
    size_t peer_limit = dl_get_max_in_flight_per_peer(); /* default for new peers */
    if (ps && ps->is_loopback) {
        /* K2: loopback has no WAN-fairness constraint and effectively
         * unlimited bandwidth. Use the elevated cap; the global limit
         * (DL_MAX_IN_FLIGHT_TOTAL_IBD=4096) and the consumer-side reducer
         * pipeline are the real backpressure. */
        peer_limit = DL_MAX_IN_FLIGHT_PER_LOOPBACK;
    } else if (ps && ps->bandwidth_score > 0) {
        /* Scale: score/128 * MAX, clamped to [16, MAX] */
        size_t max_peer = dl_get_max_in_flight_per_peer();
        peer_limit = (size_t)ps->bandwidth_score
                     * max_peer / 128;
        if (peer_limit < 16) peer_limit = 16;
        if (peer_limit > max_peer)
            peer_limit = max_peer;
    }
    return peer_limit;
}

static size_t dl_assign_history_room(size_t history_global_count,
                                     size_t history_peer_count,
                                     size_t history_queued)
{
    /* History owns a subordinate lane. These limits never charge forward
     * work, so a saturated history lane cannot block a new tip request. */
    size_t history_available = 0;
    if (history_global_count < DL_MAX_HISTORY_IN_FLIGHT &&
        history_peer_count < DL_MAX_HISTORY_PER_PEER) {
        history_available = DL_MAX_HISTORY_IN_FLIGHT - history_global_count;
        size_t peer_history_available =
            DL_MAX_HISTORY_PER_PEER - history_peer_count;
        if (history_available > peer_history_available)
            history_available = peer_history_available;
        if (history_available > history_queued)
            history_available = history_queued;
    }
    return history_available;
}

struct dl_assign_windows dl_assign_windows(
    const struct download_manager *dm,
    size_t peer_count, size_t peer_limit, size_t max_assign,
    size_t history_global_count, size_t history_peer_count,
    size_t forward_queued, size_t history_queued)
{
    struct dl_assign_windows w = {0};
    if (peer_count < peer_limit)
        w.available = peer_limit - peer_count;
    if (w.available > max_assign) w.available = max_assign;
    if (w.available > dm->queue_len) w.available = dm->queue_len;

    /* Also respect global limit (dynamic: aggressive during IBD).
     * num_active can legitimately EXCEED the limit (it shrinks when IBD
     * ends) — the unguarded subtraction underflowed size_t and handed
     * the pop loop a near-infinite `available`, overflowing the
     * caller's out_hashes[max_assign] buffer. */
    w.global_limit = dl_get_max_in_flight_total();
    if (dm->num_active >= w.global_limit)
        w.available = 0;
    else if (dm->num_active + w.available > w.global_limit)
        w.available = w.global_limit - dm->num_active;

    w.history_available = dl_assign_history_room(
        history_global_count, history_peer_count, history_queued);
    size_t class_available = forward_queued + w.history_available;
    if (w.available > class_available)
        w.available = class_available;
    return w;
}

/* Initial assign_result from the queue and the windows, before any pick. */
int dl_assign_prelim_result(size_t queue_before, size_t max_assign,
                                   size_t peer_count, size_t peer_limit,
                                   size_t active_before, size_t global_limit,
                                   size_t forward_queued, size_t history_queued,
                                   size_t history_available)
{
    int assign_result = DL_ASSIGN_ASSIGNED;
    if (queue_before == 0)
        assign_result = DL_ASSIGN_NO_QUEUE;
    else if (max_assign == 0)
        assign_result = DL_ASSIGN_MAX_ZERO;
    else if (peer_count >= peer_limit)
        assign_result = DL_ASSIGN_PEER_WINDOW_FULL;
    else if (active_before >= global_limit)
        assign_result = DL_ASSIGN_GLOBAL_WINDOW_FULL;
    else if (forward_queued == 0 && history_queued > 0 &&
             history_available == 0)
        assign_result = DL_ASSIGN_HISTORY_THROTTLED;
    return assign_result;
}

size_t dl_assign_tip_bias(const struct download_manager *dm,
                                 const struct dl_peer_stats *ps,
                                 size_t history_queued)
{
    /* S2.3: bias the lowest-height (tip-adjacent, most-urgent) entries
     * toward a demonstrably faster peer. The queue is height-sorted
     * ascending, so indices [0, tip_bias_skip) are the tip-adjacent
     * reserve. Skipped for loopback (already bypasses bandwidth scaling)
     * and for peers with no established score yet (score 0 — a brand-new
     * peer gets a fair first shot rather than being penalized on no
     * evidence). `available` (this peer's quota) is computed independently,
     * so a biased peer still gets its full quota, just sourced from beyond
     * the reserve when possible. */
    size_t tip_bias_skip = 0;
    if (ps && !ps->is_loopback &&
        ps->bandwidth_score > 0) {
        uint32_t best_score = dl_best_bandwidth_score(dm);
        if (best_score >= ps->bandwidth_score * 2)
            tip_bias_skip = DL_TIP_BIAS_RESERVE;
    }
    if (tip_bias_skip > dm->queue_len)
        tip_bias_skip = dm->queue_len;
    if (history_queued > 0)
        tip_bias_skip = 0;
    return tip_bias_skip;
}

/* True when one forward pass can take this batch without moving tip bias. */
bool dl_assign_can_batch(size_t available, size_t tip_bias_skip,
                                size_t queue_len)
{
    return available > 0 &&
           available <= DL_MAX_IN_FLIGHT_PER_LOOPBACK &&
           (tip_bias_skip == 0 ||
            queue_len > available + tip_bias_skip);
}

