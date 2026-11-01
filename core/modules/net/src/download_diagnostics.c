/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block download manager — read-only reporting surface.
 * Throughput, counters, and the operator diagnostics snapshot. These take
 * the same manager mutex as download.c but write nothing back, so they live
 * in their own translation unit and download.c stays about scheduling. */

#include "platform/time_compat.h"
#include "net/download.h"

void dl_get_throughput(struct download_manager *dm,
                       uint64_t *total_bytes, double *mbps_avg)
{
    zcl_mutex_lock(&dm->cs);
    if (total_bytes) *total_bytes = dm->total_bytes_received;
    if (mbps_avg) {
        if (dm->sync_start_time > 0 && dm->total_bytes_received > 0) {
            int64_t elapsed = (int64_t)platform_time_wall_time_t() - dm->sync_start_time;
            if (elapsed < 1) elapsed = 1;
            *mbps_avg = (double)dm->total_bytes_received / (1048576.0 * elapsed);
        } else {
            *mbps_avg = 0.0;
        }
    }
    zcl_mutex_unlock(&dm->cs);
}

void dl_get_stats(struct download_manager *dm,
                  uint64_t *requested, uint64_t *received,
                  uint64_t *timed_out, uint64_t *in_flight,
                  uint64_t *queued)
{
    zcl_mutex_lock(&dm->cs);
    if (requested)  *requested  = dm->total_requested;
    if (received)   *received   = dm->total_received;
    if (timed_out)  *timed_out  = dm->total_timed_out;
    if (in_flight)  *in_flight  = dm->num_active;
    if (queued)     *queued     = dm->queue_len;
    zcl_mutex_unlock(&dm->cs);
}

/* Age of a request in seconds, clamped at zero. */
static int64_t dl_slot_age_seconds(int64_t now, int64_t request_time)
{
    return now >= request_time ? now - request_time : 0;
}

/* Find a peer id in the recorded id list; NULL when absent. */
static const uint32_t *dl_find_recorded_peer_id(const uint32_t *ids,
                                                size_t count, uint32_t peer_id)
{
    for (size_t i = 0; i < count; i++) {
        if (ids[i] == peer_id)
            return &ids[i];
    }
    return NULL;
}

/* Snapshot active peer ownership into the diagnostic peer rows. */
static void dl_collect_peer_downloads(struct download_manager *dm,
                                      struct dl_diagnostics *out,
                                      int64_t now)
{
    out->peer_download_count = 0;
    out->peer_download_truncated = false;
    out->peer_download_total = 0;
    for (size_t i = 0; i < dm->num_peers; i++) {
        const struct dl_peer_stats *ps = &dm->peers[i];
        if (!ps->active)
            continue;
        out->peer_download_total++;
        if (out->peer_download_count >= DL_DIAGNOSTIC_PEER_CAP) {
            out->peer_download_truncated = true;
            continue;
        }
        struct dl_peer_diagnostic *pd =
            &out->peer_downloads[out->peer_download_count++];
        pd->peer_id = ps->peer_id;
        pd->requested = ps->blocks_requested;
        pd->received = ps->blocks_received;
        pd->timed_out = ps->blocks_timed_out;
        pd->avg_delivery_us = ps->avg_delivery_us;
        pd->last_body_age_seconds =
            ps->last_body_received_time > 0 &&
            now >= ps->last_body_received_time
                ? now - ps->last_body_received_time
                : -1;
        pd->oldest_in_flight_age_seconds = -1;
        pd->oldest_in_flight_height = -1;
        pd->bandwidth_score = ps->bandwidth_score;
        pd->is_loopback = ps->is_loopback;
    }
}

/* Count queued work classes and peer avoid-window extents. */
static void dl_scan_queue_avoid(struct download_manager *dm,
                                struct dl_diagnostics *out,
                                int64_t now)
{
    out->queued_history = 0;
    out->queued_forward = 0;
    out->queue_peer_avoid_count = 0;
    out->queue_peer_avoid_max_seconds = 0;
    for (size_t i = 0; i < dm->queue_len; i++) {
        if (dm->queue_classes[i] == DL_WORK_HISTORY)
            out->queued_history++;
        else
            out->queued_forward++;
        if (dm->queue_avoid_until[i] <= now)
            continue;
        int64_t remaining = dm->queue_avoid_until[i] - now;
        out->queue_peer_avoid_count++;
        if (remaining > out->queue_peer_avoid_max_seconds)
            out->queue_peer_avoid_max_seconds = remaining;
    }
}

/* Fold active in-flight slots into class, overdue, oldest and per-peer rows. */
static void dl_scan_in_flight_slots(struct download_manager *dm,
                                    struct dl_diagnostics *out,
                                    int64_t now, int timeout)
{
    out->in_flight_history = 0;
    out->in_flight_forward = 0;
    out->overdue_in_flight = 0;
    out->oldest_in_flight_age_seconds = -1;
    out->oldest_in_flight_height = -1;
    out->oldest_in_flight_peer_id = 0;
    out->in_flight_peer_count = 0;
    uint32_t peer_ids[DL_MAX_TRACKED_PEERS];
    size_t peer_count = 0;
    for (size_t i = 0; i < dm->num_slots; i++) {
        struct dl_in_flight *s = &dm->slots[i];
        if (!s->active)
            continue;

        if (s->work_class == DL_WORK_HISTORY)
            out->in_flight_history++;
        else
            out->in_flight_forward++;

        int64_t age = dl_slot_age_seconds(now, s->request_time);
        if (out->oldest_in_flight_age_seconds < 0 ||
            age > out->oldest_in_flight_age_seconds) {
            out->oldest_in_flight_age_seconds = age;
            out->oldest_in_flight_height = s->height;
            out->oldest_in_flight_peer_id = s->peer_id;
        }
        if (age >= timeout)
            out->overdue_in_flight++;

        for (size_t p = 0; p < out->peer_download_count; p++) {
            struct dl_peer_diagnostic *pd = &out->peer_downloads[p];
            if (pd->peer_id != s->peer_id)
                continue;
            pd->in_flight++;
            if (pd->oldest_in_flight_age_seconds < 0 ||
                age > pd->oldest_in_flight_age_seconds) {
                pd->oldest_in_flight_age_seconds = age;
                pd->oldest_in_flight_height = s->height;
            }
            break;
        }

        if (!dl_find_recorded_peer_id(peer_ids, peer_count, s->peer_id) &&
            peer_count < sizeof(peer_ids) / sizeof(peer_ids[0]))
            peer_ids[peer_count++] = s->peer_id;
    }
    out->in_flight_peer_count = (uint64_t)peer_count;
}

void dl_get_diagnostics(struct download_manager *dm,
                        struct dl_diagnostics *out)
{
    if (!out)
        return;

    struct dl_diagnostics empty = {
        .request_timeout_seconds = dl_get_request_timeout_secs(),
        .oldest_in_flight_age_seconds = -1,
        .oldest_in_flight_height = -1,
        .oldest_in_flight_peer_id = 0,
        .last_assign_result = DL_ASSIGN_NONE,
    };
    *out = empty;
    if (!dm)
        return;

    int64_t now = (int64_t)platform_time_wall_time_t();
    int timeout = dl_get_request_timeout_secs();

    zcl_mutex_lock(&dm->cs);
    out->assign_attempts = dm->assign_attempts;
    out->assign_successes = dm->assign_successes;
    out->assign_zero_results = dm->assign_zero_results;
    out->last_assign_peer_id = dm->last_assign_peer_id;
    out->last_assign_max_requested = dm->last_assign_max_requested;
    out->last_assign_available = dm->last_assign_available;
    out->last_assign_assigned = dm->last_assign_assigned;
    out->last_assign_queue_len = dm->last_assign_queue_len;
    out->last_assign_active = dm->last_assign_active;
    out->last_assign_peer_in_flight = dm->last_assign_peer_in_flight;
    out->last_assign_peer_limit = dm->last_assign_peer_limit;
    out->last_assign_global_limit = dm->last_assign_global_limit;
    out->last_assign_result = dm->last_assign_result;
    out->queue_generation = dm->queue_generation;
    out->capacity_generation = dm->capacity_generation;
    out->total_orphaned = dm->total_orphaned;
    out->requeue_suppressed_pending = dm->total_requeue_suppressed_pending;
    out->accounting_drift = (int64_t)dm->total_requested -
                            (int64_t)dm->total_received -
                            (int64_t)dm->total_timed_out -
                            (int64_t)dm->total_orphaned -
                            (int64_t)dm->num_active;

    /* Snapshot active peer ownership while the same manager lock is already
     * held. Without these rows, a full queue plus low H* could name the oldest
     * peer only; operators could not distinguish one slow peer holding the
     * urgent window from balanced network variance. */
    dl_collect_peer_downloads(dm, out, now);
    dl_scan_queue_avoid(dm, out, now);
    dl_scan_in_flight_slots(dm, out, now, timeout);
    zcl_mutex_unlock(&dm->cs);
}
